from __future__ import annotations

import asyncio
import re
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.collector.sanitizer import (
    ai_backend_kind,
    reference_id,
    sanitize_policy,
    url_api_key,
    value_kind,
)
from apim_assess.models.policy import (
    CollectionCoverage,
    GatewayMetadata,
    Inventory,
    PolicyDocument,
    ResourceMetadata,
    SubResource,
)
from apim_assess.models.snapshot import CollectionWarning, ServiceSettings

VERSION = "2024-05-01"
GATEWAY_VERSION: Literal["2025-09-01-preview"] = "2025-09-01-preview"
Kind = Literal[
    "api",
    "operation",
    "product",
    "subscription",
    "backend",
    "named_value",
    "certificate",
    "diagnostic",
    "gateway",
    "workspace",
    "logger",
    "mcp_tool",
]
COLLECTIONS: dict[str, Kind] = {
    "apis": "api",
    "products": "product",
    "subscriptions": "subscription",
    "backends": "backend",
    "namedValues": "named_value",
    "certificates": "certificate",
    "diagnostics": "diagnostic",
    "loggers": "logger",
}


class _Entity(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    properties: dict[str, object] = Field(default_factory=dict)


class _PoolService(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(
        pattern=(
            r"(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
            r"Microsoft\.ApiManagement/service/[^/]+/(?:workspaces/[^/]+/)?backends/[^/]+$"
        )
    )


def _object(value: object) -> dict[str, object]:
    if value is None:
        return {}
    return TypeAdapter(dict[str, object]).validate_python(value)


def _metadata(kind: Kind, props: dict[str, object]) -> ResourceMetadata:
    projected: dict[str, object] = {}
    if kind == "api":
        authentication = _object(props.get("authenticationSettings"))
        route = props.get("path")
        projected = {
            "subscription_required": props.get("subscriptionRequired"),
            "service_url_kind": value_kind(props.get("serviceUrl")),
            "api_type": props.get("type") or props.get("apiType"),
            "protocols": props.get("protocols"),
            "oauth_configured": bool(authentication.get("oAuth2") or authentication.get("openid")),
            "version_set": bool(props.get("apiVersionSetId")),
            "api_route_hash": (reference_id(route) if isinstance(route, str) else None),
            "ai_backend": ai_backend_kind(props.get("serviceUrl")),
            "api_key_credential": url_api_key(props.get("serviceUrl")),
        }
    elif kind == "operation":
        projected = {"method": props.get("method")}
    elif kind == "named_value":
        projected = {
            "secret": props.get("secret"),
            "key_vault": props.get("keyVault") is not None,
        }
    elif kind == "backend":
        tls = _object(props.get("tls"))
        pool = _object(props.get("pool"))
        members = (
            TypeAdapter(list[_PoolService]).validate_python(pool["services"])
            if "services" in pool
            else None
        )
        breaker = _object(props.get("circuitBreaker"))
        breaker_rules = TypeAdapter(list[dict[str, object]]).validate_python(
            breaker.get("rules", [])
        )
        covers_429 = False
        retry_after = False
        for rule in breaker_rules:
            condition = _object(rule.get("failureCondition"))
            ranges = TypeAdapter(list[dict[str, int]]).validate_python(
                condition.get("statusCodeRanges", [])
            )
            count = condition.get("count")
            percentage = condition.get("percentage")
            threshold = any(
                isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value
                for value in (count, percentage)
            )
            interval = condition.get("interval")
            trip = rule.get("tripDuration")
            durations = all(
                isinstance(value, str)
                and re.fullmatch(r"P(?=\w)(?:\d+D)?(?:T(?=\w)(?:\d+H)?(?:\d+M)?(?:\d+S)?)?", value)
                and re.search(r"[1-9]", value)
                for value in (interval, trip)
            )
            valid = (
                threshold
                and durations
                and any(part.get("min", 0) <= 429 <= part.get("max", 0) for part in ranges)
            )
            covers_429 = covers_429 or bool(valid)
            retry_after = retry_after or bool(valid and rule.get("acceptRetryAfter") is True)
        credentials = _object(props.get("credentials"))
        headers = _object(credentials.get("header"))
        queries = _object(credentials.get("query"))
        projected = {
            "service_url_kind": value_kind(props.get("url")),
            "credentials_present": bool(props.get("credentials")),
            "circuit_breaker_present": bool(_object(props.get("circuitBreaker")).get("rules")),
            "backend_pool": str(props.get("type", "")).lower() == "pool",
            "pool_member_count": (
                len({member.id.casefold() for member in members}) if members is not None else None
            ),
            "validate_certificate_chain": tls.get("validateCertificateChain"),
            "validate_certificate_name": tls.get("validateCertificateName"),
            "ai_backend": ai_backend_kind(props.get("url")),
            "api_key_credential": (
                True
                if any(
                    key.casefold() in {"api-key", "x-api-key", "key", "api_key"}
                    for key in (*headers, *queries)
                )
                else url_api_key(props.get("url"))
            ),
            "pool_member_references": (
                sorted({reference_id(member.id.casefold()) for member in members})
                if members is not None
                else None
            ),
            "breaker_429": covers_429,
            "breaker_retry_after": retry_after,
        }
    elif kind == "certificate":
        projected = {
            "certificate_expiry": props.get("expirationDate"),
            "key_vault": props.get("keyVault") is not None,
        }
    elif kind == "diagnostic":
        sizes = [
            _object(_object(_object(props.get(side)).get(direction)).get("body")).get("bytes")
            for side in ("frontend", "backend")
            for direction in ("request", "response")
        ]
        body_sizes = TypeAdapter(list[int]).validate_python(
            [size for size in sizes if size is not None]
        )
        logger = props.get("loggerId")
        projected = {
            "sampling_percentage": _object(props.get("sampling")).get("percentage"),
            "always_log_errors": props.get("alwaysLog") == "allErrors",
            "body_bytes": max(body_sizes) if body_sizes else None,
            "logger_reference_hash": reference_id(logger.rsplit("/", 1)[-1])
            if isinstance(logger, str)
            else None,
        }
    elif kind == "logger":
        logger_type = props.get("loggerType")
        projected = {
            "application_insights": (
                logger_type == "applicationInsights"
                if isinstance(logger_type, str)
                and logger_type in {"applicationInsights", "azureEventHub", "azureMonitor"}
                else None
            ),
        }
    elif kind in {"product", "subscription"}:
        projected = {"state": props.get("state")}
        if kind == "product":
            projected["subscription_required"] = props.get("subscriptionRequired")
        else:
            scope = props.get("scope")
            relative = (
                re.sub(
                    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
                    r"Microsoft\.ApiManagement/service/[^/]+(?:/workspaces/[^/]+)?",
                    "",
                    scope,
                    flags=re.I,
                )
                if isinstance(scope, str)
                else ""
            )
            projected["subscription_scope"] = (
                "all_apis"
                if relative.casefold() == "/apis"
                else "api"
                if re.fullmatch(r"/apis/[^/]+", relative, re.I)
                else "product"
                if re.fullmatch(r"/products/[^/]+", relative, re.I)
                else "unknown"
            )
    if kind == "api" and projected["api_type"] is not None:
        api_type = projected["api_type"]
        projected["api_type"] = (
            api_type.casefold()
            if isinstance(api_type, str)
            and api_type.casefold()
            in {"http", "soap", "websocket", "graphql", "odata", "grpc", "mcp", "a2a"}
            else "unknown"
        )
    return ResourceMetadata.model_validate(projected)


def _gateway(props: dict[str, object], protocol: str) -> GatewayMetadata:
    mcp = _object(props.get("mcpProperties"))
    a2a = _object(props.get("a2aProperties"))
    runtime = _object(props.get("jsonRpcProperties"))
    agent = _object(props.get("agent"))
    transport = mcp.get("transportType")
    if transport is not None and (
        not isinstance(transport, str) or transport not in {"streamable", "sse"}
    ):
        raise ValueError("Unrecognized MCP transport")
    endpoints = mcp.get("endpoints")
    if endpoints is not None and (
        not isinstance(endpoints, list) or not all(isinstance(item, dict) for item in endpoints)
    ):
        raise ValueError("Invalid MCP endpoint metadata")
    backend = props.get("backendId")

    def hashed(value: object) -> str | None:
        return reference_id(value) if isinstance(value, str) and value else None

    return GatewayMetadata.model_validate(
        {
            "mode": (
                "passthrough"
                if protocol == "mcp" and (transport or props.get("serviceUrl") or backend)
                else "unknown"
            ),
            "transport": "jsonrpc" if protocol == "a2a" else transport,
            "endpoint_count": len(endpoints) if isinstance(endpoints, list) else None,
            "runtime_url_kind": value_kind(
                runtime.get("backendUrl") if protocol == "a2a" else props.get("serviceUrl")
            ),
            "agent_card_url_kind": value_kind(a2a.get("agentCardBackendUrl")),
            "agent_card_path_hash": hashed(a2a.get("agentCardPath")),
            "runtime_path_hash": hashed(runtime.get("path")),
            "agent_id_hash": hashed(agent.get("id")),
            "backend_reference_hash": hashed(backend),
        }
    )


class SubresourceCollector:
    def __init__(
        self, reader: ArmReader, identifier: str, warnings: list[CollectionWarning]
    ) -> None:
        self.reader = reader
        self.identifier = identifier
        self.warnings = warnings
        self.inventory = Inventory(gateway_api_version=GATEWAY_VERSION)
        self.semaphore = asyncio.Semaphore(8)

    def warn(self, path: str, code: str, *, policy: bool = False) -> None:
        self.warnings.append(
            CollectionWarning(
                module="policies" if policy else "subresources",
                resource_id=self.identifier,
                code=code,
                message=(
                    f"Collection incomplete at {path or 'global'}; dependent coverage is unknown."
                ),
            )
        )

    def url(self, path: str) -> str:
        return quote(self.identifier + ("/" + path if path else ""), safe="/")

    async def setting(self, path: str, *keys: str) -> bool | None:
        try:
            async with self.semaphore:
                body = _object(await self.reader.get(self.url(path), {"api-version": VERSION}))
            props = _object(body.get("properties"))
            value: object = props
            for key in keys:
                value = _object(value).get(key)
            if not isinstance(value, bool):
                raise AzureReadError("INCOMPLETE_METADATA")
            self.inventory.collections[path] = CollectionCoverage(status="complete", count=1)
            return value
        except (AzureReadError, ValidationError) as exc:
            self.inventory.collections[path] = CollectionCoverage(status="unavailable")
            self.warn(path, str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE")
            return None

    async def settings(self, settings: ServiceSettings, *, classic: bool, portal: bool) -> None:
        if classic:
            settings.management_api_enabled = await self.setting("tenant/access", "enabled")
        if portal and settings.portal_enabled is not False:
            settings.portal_signin_required = await self.setting(
                "portalconfigs/default", "signin", "require"
            )
            settings.portal_signup_enabled = await self.setting("portalsettings/signup", "enabled")
            providers = await self.listing("identityProviders")
            if self.inventory.collections["identityProviders"].status == "complete":
                types = [entity.properties.get("type") for entity in providers]
                if all(
                    isinstance(value, str)
                    and value in {"aad", "aadB2C", "facebook", "google", "microsoft", "twitter"}
                    for value in types
                ):
                    settings.portal_entra_enabled = any(
                        value in ("aad", "aadB2C") for value in types
                    )
                else:
                    self.inventory.collections["identityProviders"].status = "partial"
                    self.warn("identityProviders", "INCOMPLETE_METADATA")

    async def listing(
        self, path: str, *, version: str = VERSION, coverage_key: str | None = None
    ) -> list[_Entity]:
        result: list[_Entity] = []
        seen: set[str] = set()
        status: Literal["complete", "partial", "unavailable"] = "complete"
        try:
            async with self.semaphore:
                async for raw in self.reader.pages(self.url(path), version):
                    entity = _Entity.model_validate(raw)
                    prefix = self.identifier + "/" + path + "/"
                    if path.endswith("/apis") and "/products/" in "/" + path:
                        canonical = self.identifier + "/" + path.split("products/")[0] + "apis/"
                        if entity.id.casefold().startswith(prefix.casefold()):
                            entity.id = canonical + entity.id[len(prefix) :]
                        prefix = canonical
                    name = entity.id[len(prefix) :]
                    if (
                        not entity.id.casefold().startswith(prefix.casefold())
                        or not re.fullmatch(r"[^/\\?#%\x00-\x1f]+", name)
                        or name in {".", ".."}
                        or entity.id.casefold() in seen
                    ):
                        raise AzureReadError("INVALID_RESOURCE_ID")
                    seen.add(entity.id.casefold())
                    result.append(entity.model_copy(update={"id": prefix + name}))
        except (AzureReadError, ValidationError) as exc:
            status = "partial" if result else "unavailable"
            self.warn(path, str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE")
        self.inventory.collections[coverage_key or path] = CollectionCoverage(
            status=status, count=len(result)
        )
        return result

    def project(self, entity: _Entity, kind: Kind, workspace: str | None) -> SubResource | None:
        path = entity.id[len(self.identifier) + 1 :]
        display_name = entity.properties.get("displayName") if kind == "named_value" else None
        name = (
            display_name.strip()
            if isinstance(display_name, str) and display_name.strip()
            else path.rsplit("/", 1)[-1]
        )
        try:
            item = SubResource(
                resource_id=entity.id,
                path=path,
                name=name,
                kind=kind,
                workspace=workspace,
                metadata=_metadata(kind, entity.properties),
            )
        except (ValidationError, ValueError):
            self.inventory.collections[path.rsplit("/", 1)[0]].status = "partial"
            self.warn(path, "INVALID_METADATA")
            return None
        self.inventory.resources.append(item)
        if kind == "api" and item.metadata.api_type == "unknown":
            self.inventory.collections[path.rsplit("/", 1)[0]].status = "partial"
            self.warn(path, "UNRECOGNIZED_API_TYPE")
        if (
            kind == "api"
            and (
                item.metadata.subscription_required is None
                or item.metadata.api_type is None
                and not item.metadata.protocols
            )
            or kind == "product"
            and item.metadata.subscription_required is None
            or kind == "operation"
            and item.metadata.method is None
        ):
            self.warn(path, "INCOMPLETE_METADATA")
        return item

    async def policy(self, scope: str, *, fragment: bool = False, version: str = VERSION) -> None:
        path = scope if fragment else (scope + "/" if scope else "") + "policies/policy"
        source = self.identifier + "/" + path
        try:
            async with self.semaphore:
                raw = await self.reader.get(
                    self.url(path),
                    {"api-version": version, "format": "xml"},
                    policy_xml=True,
                )
            if isinstance(raw, str):
                xml = raw
            else:
                body = _object(raw)
                props = _object(body.get("properties"))
                value = props.get("value")
                if not isinstance(value, str) or props.get("format", "rawxml") not in {
                    "rawxml",
                    "xml",
                }:
                    raise AzureReadError("INVALID_POLICY_RESPONSE")
                xml = value
            document = sanitize_policy(source, xml, fragment=fragment)
            if document.status == "unavailable":
                self.warn(path, document.error_code or "INVALID_XML", policy=True)
        except (AzureReadError, ValidationError) as exc:
            code = str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE"
            if code == "HTTP_404" and not fragment:
                document = PolicyDocument(source=source, status="absent")
            else:
                document = PolicyDocument(source=source, status="unavailable", error_code=code)
                self.warn(path, code, policy=True)
        if fragment:
            parent, name = scope.rsplit("/", 1)
            self.inventory.fragments[parent + "/" + reference_id(name)] = document
        else:
            self.inventory.policies[scope] = document

    async def api(self, item: SubResource) -> None:
        modern = item.metadata.api_type in {"mcp", "a2a"}
        version = GATEWAY_VERSION if modern else VERSION
        diagnostics_path = item.path + "/diagnostics"
        for diagnostic in await self.listing(diagnostics_path, version=version):
            self.project(diagnostic, "diagnostic", item.workspace)
        if modern:
            try:
                async with self.semaphore:
                    body = _object(
                        await self.reader.get(self.url(item.path), {"api-version": GATEWAY_VERSION})
                    )
                if not isinstance(body.get("properties"), dict):
                    raise AzureReadError("INVALID_RESPONSE")
                item.gateway = _gateway(_object(body["properties"]), item.metadata.api_type or "")
                self.inventory.collections[item.path] = CollectionCoverage(
                    status="complete", count=1
                )
            except (AzureReadError, ValidationError, ValueError) as exc:
                item.gateway = GatewayMetadata()
                self.inventory.collections[item.path] = CollectionCoverage(status="unavailable")
                self.warn(
                    item.path, str(exc) if isinstance(exc, AzureReadError) else "INVALID_METADATA"
                )
        if item.metadata.api_type == "mcp":
            await self.policy(item.path, version=GATEWAY_VERSION)
            tools_path = item.path + "/tools"
            if item.workspace:
                self.inventory.collections[tools_path] = CollectionCoverage(status="unavailable")
                self.warn(tools_path, "UNSUPPORTED_GATEWAY_SCOPE")
                return
            for entity in await self.listing(tools_path, version=GATEWAY_VERSION):
                tool = self.project(entity, "mcp_tool", item.workspace)
                if tool is None:
                    continue
                reference = entity.properties.get("operationId")
                path = (
                    reference[len(self.identifier) + 1 :]
                    if isinstance(reference, str)
                    and reference.casefold().startswith(self.identifier.casefold() + "/")
                    else reference.removeprefix("/")
                    if isinstance(reference, str)
                    else None
                )
                try:
                    tool.gateway = GatewayMetadata(backing_operation_path=path)
                    if path is None and item.gateway and item.gateway.mode != "passthrough":
                        raise ValueError("Missing backing operation")
                except ValidationError:
                    self.inventory.collections[tools_path].status = "partial"
                    self.warn(tool.path, "INVALID_TOOL_BINDING")
                except ValueError:
                    self.inventory.collections[tools_path].status = "partial"
                    self.warn(tool.path, "MISSING_TOOL_BINDING")
                if tool.gateway and tool.gateway.backing_operation_path and item.gateway:
                    item.gateway.mode = "rest_backed"
            return
        operations_path = item.path + "/operations"
        operations = await self.listing(operations_path, version=version)
        await self.policy(item.path, version=version)
        projected = [
            self.project(operation, "operation", item.workspace) for operation in operations
        ]
        await asyncio.gather(
            *(
                self.policy(operation.path, version=version)
                for operation in projected
                if operation is not None
            )
        )

    async def scope(self, workspace: str | None = None) -> None:
        prefix = workspace + "/" if workspace else ""
        await self.policy(workspace or "")
        apis: list[SubResource] = []
        for collection, kind in COLLECTIONS.items():
            path = prefix + collection
            if kind == "api":
                key = prefix + "gateway_apis"
                entities = await self.listing(path, version=GATEWAY_VERSION, coverage_key=key)
                gateway_coverage = self.inventory.collections[key]
                if gateway_coverage.status != "complete":
                    fallback = await self.listing(path)
                    entities = list(
                        {entity.id.casefold(): entity for entity in [*fallback, *entities]}.values()
                    )
                self.inventory.collections[path] = CollectionCoverage(
                    status=(
                        "partial"
                        if gateway_coverage.status != "complete" and entities
                        else gateway_coverage.status
                    ),
                    count=len(entities),
                )
            else:
                entities = await self.listing(path)
                if kind == "subscription":
                    entities = [
                        entity
                        for entity in entities
                        if not entity.id.casefold().endswith("/subscriptions/master")
                    ]
                    if path in self.inventory.collections:
                        self.inventory.collections[path].count = len(entities)
            for entity in entities:
                item = self.project(entity, kind, workspace)
                if item is None:
                    if kind == "api":
                        self.inventory.collections[prefix + "gateway_apis"].status = "partial"
                    continue
                if kind == "api":
                    apis.append(item)
                    if item.metadata.api_type == "unknown":
                        self.inventory.collections[prefix + "gateway_apis"].status = "partial"
                elif kind == "product":
                    membership = item.path + "/apis"
                    self.inventory.product_apis[item.path] = [
                        api.id[len(self.identifier) + 1 :] for api in await self.listing(membership)
                    ]
                    await self.policy(item.path)
        for entity in await self.listing(prefix + "policyFragments"):
            await self.policy(entity.id[len(self.identifier) + 1 :], fragment=True)
        await asyncio.gather(*(self.api(api) for api in apis))

    async def collect(self) -> Inventory:
        await self.scope()
        for entity in await self.listing("gateways"):
            self.project(entity, "gateway", None)
        workspaces = await self.listing("workspaces")
        for entity in workspaces:
            workspace = self.project(entity, "workspace", None)
            if workspace is not None:
                await self.scope(workspace.path)
        operation_paths = {
            item.path.casefold() for item in self.inventory.resources if item.kind == "operation"
        }
        for item in self.inventory.resources:
            if (
                item.kind == "mcp_tool"
                and item.gateway
                and item.gateway.backing_operation_path
                and item.gateway.backing_operation_path.casefold() not in operation_paths
            ):
                self.inventory.collections[item.path.rsplit("/", 1)[0]].status = "partial"
                self.warn(item.path, "UNRESOLVED_TOOL_BINDING")
        self.inventory.resources.sort(key=lambda item: item.path.casefold())
        self.inventory.collections = dict(sorted(self.inventory.collections.items()))
        self.inventory.policies = dict(sorted(self.inventory.policies.items()))
        self.inventory.fragments = dict(sorted(self.inventory.fragments.items()))
        self.inventory.product_apis = dict(sorted(self.inventory.product_apis.items()))
        return self.inventory
