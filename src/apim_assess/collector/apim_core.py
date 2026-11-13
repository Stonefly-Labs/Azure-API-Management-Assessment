from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, date, datetime, timedelta
from typing import Literal
from urllib.parse import quote

import httpx
from azure.identity.aio import DefaultAzureCredential
from pydantic import AwareDatetime, BaseModel, Field, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.collector.discovery import APIM_API_VERSION, discover
from apim_assess.collector.governance import collect_governance
from apim_assess.collector.networking import collect_networking
from apim_assess.collector.subresources import SubresourceCollector
from apim_assess.collector.telemetry import collect_logs, collect_metrics
from apim_assess.collector.upstream_afd import collect_afd
from apim_assess.collector.upstream_appgw import collect_appgw
from apim_assess.config import AssessmentConfig
from apim_assess.models.snapshot import (
    CollectionWarning,
    Environment,
    HostCertificate,
    Instance,
    Region,
    ResourceId,
    ServiceSettings,
    Sku,
    Snapshot,
)
from apim_assess.models.upstream import Upstream

SAFE_CUSTOM_PROPERTIES = {
    "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2",
    *(
        f"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.{side}Protocols.{protocol}"
        for side in ("", "Backend.")
        for protocol in ("Ssl30", "Tls10", "Tls11")
    ),
    *(
        "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers." + cipher
        for cipher in (
            "TripleDes168",
            "TlsRsaWithAes128CbcSha",
            "TlsRsaWithAes256CbcSha",
            "TlsRsaWithAes128CbcSha256",
            "TlsRsaWithAes256CbcSha256",
            "TlsEcdheRsaWithAes128CbcSha",
            "TlsEcdheRsaWithAes256CbcSha",
            "TlsEcdheRsaWithAes128CbcSha256",
            "TlsEcdheRsaWithAes256CbcSha384",
        )
    ),
}


class _Sku(BaseModel):
    name: str
    capacity: int | None = Field(default=None, ge=0)


class _Location(BaseModel):
    location: str | None = None
    zones: list[str] | None = None
    sku: _Sku | None = None


class _ConnectionState(BaseModel):
    status: Literal["Approved", "Pending", "Rejected", "Disconnected"] | None = None


class _ConnectionProperties(BaseModel):
    privateLinkServiceConnectionState: _ConnectionState | None = None


class _Connection(BaseModel):
    properties: _ConnectionProperties | None = None


class _Identity(BaseModel):
    type: Literal["None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"]


class _Constraint(BaseModel):
    minApiVersion: date | None = None


class _Certificate(BaseModel):
    expiry: AwareDatetime | None = None


class _Hostname(BaseModel):
    type: Literal["Proxy", "Portal", "Management", "Scm", "DeveloperPortal"]
    certificateSource: Literal["KeyVault", "Custom", "Managed", "BuiltIn"] | None = None
    keyVaultId: str | None = None
    certificate: _Certificate | None = None


class _Properties(BaseModel):
    additionalLocations: list[_Location] | None = None
    virtualNetworkType: Literal["None", "Internal", "External"] | None = None
    publicNetworkAccess: Literal["Enabled", "Disabled"] | None = None
    privateEndpointConnections: list[_Connection] | None = None
    customProperties: dict[str, object] = Field(default_factory=dict)
    apiVersionConstraint: _Constraint | None = None
    hostnameConfigurations: list[_Hostname] | None = None
    developerPortalStatus: Literal["Enabled", "Disabled"] | None = None


class _Service(BaseModel):
    id: ResourceId
    location: str | None = None
    sku: _Sku | None = None
    zones: list[str] | None = None
    identity: _Identity | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    properties: _Properties


def infer_environment(
    config: AssessmentConfig, identifier: str, service: _Service | None
) -> tuple[Environment, str]:
    override = next(
        (
            target.env
            for target in config.targets.instances
            if target.resource_id.casefold() == identifier.casefold() and target.env is not None
        ),
        None,
    )
    if override is not None:
        return override, "per-instance override"
    if config.env != "auto":
        return config.env, "global override"
    if service:
        tags = {key.casefold(): value.casefold() for key, value in service.tags.items()}
        for key in ("env", "environment"):
            if tags.get(key) in {"prod", "production"}:
                return "prod", f"{key} tag"
            if tags.get(key) in {"non-prod", "nonprod", "dev", "test", "qa", "staging"}:
                return "non-prod", f"{key} tag"
    name = identifier.rsplit("/", 1)[-1].casefold()
    tokens = set(re.split(r"[-_]", name))
    if tokens & {"prod", "production"}:
        return "prod", "resource name"
    if tokens & {"dev", "test", "qa", "staging", "nonprod"}:
        return "non-prod", "resource name"
    if service and service.sku and service.sku.name in {"Developer", "Consumption", "Basic"}:
        return "non-prod", "SKU heuristic"
    return "prod", "conservative default (no non-production signal)"


def project_service(
    identifier: str, service: _Service | None, config: AssessmentConfig
) -> Instance:
    env, source = infer_environment(config, identifier, service)
    instance = Instance(
        resource_id=identifier,
        name=identifier.rsplit("/", 1)[-1],
        environment=env,
        environment_source=source,
    )
    if service is None:
        return instance
    props = service.properties
    # Project only assessment metadata. Never serialize the raw ARM body, tags or identity IDs.
    instance.core_status = "available"
    instance.location = service.location
    instance.sku = Sku.model_validate(service.sku.model_dump()) if service.sku else None
    instance.zones = service.zones or []
    instance.additional_locations = [
        Region(
            location=region.location,
            zones=region.zones,
            capacity=region.sku.capacity if region.sku else None,
        )
        for region in (props.additionalLocations or [])
    ]
    instance.virtual_network_type = props.virtualNetworkType
    instance.public_network_access = props.publicNetworkAccess
    instance.private_endpoint_statuses = [
        (
            connection.properties.privateLinkServiceConnectionState.status or "Unknown"
            if connection.properties and connection.properties.privateLinkServiceConnectionState
            else "Unknown"
        )
        for connection in (props.privateEndpointConnections or [])
    ]
    instance.identity_type = service.identity.type if service.identity else None
    instance.custom_properties = {
        key: str(value).casefold() == "true"
        for key, value in props.customProperties.items()
        if key in SAFE_CUSTOM_PROPERTIES and str(value).casefold() in {"true", "false"}
    }
    instance.service_settings = ServiceSettings(
        minimum_api_version=(
            props.apiVersionConstraint.minApiVersion if props.apiVersionConstraint else None
        ),
        portal_enabled=(
            props.developerPortalStatus == "Enabled"
            if props.developerPortalStatus is not None
            else None
        ),
        certificates=(
            [
                HostCertificate(
                    endpoint=hostname.type,
                    source="KeyVault" if hostname.keyVaultId else hostname.certificateSource,
                    expires_at=hostname.certificate.expiry if hostname.certificate else None,
                )
                for hostname in props.hostnameConfigurations
            ]
            if props.hostnameConfigurations is not None
            else None
        ),
    )
    return instance


async def collect(config: AssessmentConfig, reader: ArmReader | None = None) -> Snapshot:
    if reader is not None:
        return await _collect(config, reader)
    # Library credential diagnostics are replaced by structured, sanitized warnings.
    logging.getLogger("azure.identity").setLevel(logging.ERROR)
    async with DefaultAzureCredential() as credential, httpx.AsyncClient(timeout=30) as client:
        return await _collect(config, ArmReader(credential, client))


async def _collect(config: AssessmentConfig, reader: ArmReader) -> Snapshot:
    now = datetime.now(UTC)
    end = now.replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=config.telemetry.lookback_days)
    warnings: list[CollectionWarning] = []
    identifiers = await discover(reader, config, warnings)
    upstream_scope = sorted(
        {*(identifier.split("/")[2] for identifier in identifiers), *config.targets.subscriptions},
        key=str.casefold,
    )
    semaphore = asyncio.Semaphore(4)

    async def one(identifier: str) -> Instance:
        async with semaphore:
            service: _Service | None = None
            body: object = None
            try:
                body = await reader.get(
                    quote(identifier, safe="/"), {"api-version": APIM_API_VERSION}
                )
                service = _Service.model_validate(body)
                if service.id.casefold() != identifier.casefold():
                    service = None
                    raise AzureReadError("RESOURCE_ID_MISMATCH")
            except (AzureReadError, ValidationError) as exc:
                warnings.append(
                    CollectionWarning(
                        module="core",
                        resource_id=identifier,
                        code=str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE",
                        message="Core service metadata was unavailable or invalid.",
                    )
                )
            instance = project_service(identifier, service, config)
            if service is not None and any(
                value is None
                for value in (
                    instance.sku,
                    instance.location,
                    instance.zones,
                    instance.additional_locations,
                    instance.virtual_network_type,
                    instance.private_endpoint_statuses,
                )
            ):
                warnings.append(
                    CollectionWarning(
                        module="core",
                        resource_id=identifier,
                        code="INCOMPLETE_METADATA",
                        message=(
                            "Some core assessment fields were omitted; "
                            "dependent rules may be unknown."
                        ),
                    )
                )
            instance.metrics = await collect_metrics(
                reader, instance, start, end, warnings, enabled=config.modules.metrics
            )
            if service is not None:
                collector = SubresourceCollector(reader, identifier, warnings)
                instance.inventory = await collector.collect()
                if instance.service_settings is not None:
                    await collector.settings(
                        instance.service_settings,
                        classic=instance.sku is not None
                        and instance.sku.name in {"Developer", "Basic", "Standard", "Premium"},
                        portal=instance.sku is not None and instance.sku.name != "Consumption",
                    )
                instance.networking = await collect_networking(
                    reader,
                    instance,
                    body,
                    warnings,
                    enabled=config.modules.networking,
                )
                instance.governance, links = await collect_governance(
                    reader,
                    instance,
                    warnings,
                    enabled=config.modules.defender_policy,
                )
                instance.log_analytics = await collect_logs(
                    reader,
                    instance,
                    links,
                    start,
                    end,
                    warnings,
                    config.telemetry,
                    enabled=config.modules.log_analytics_kql,
                )
                afd, appgw = await asyncio.gather(
                    collect_afd(
                        reader, instance, body, config.modules.afd, upstream_scope, warnings
                    ),
                    collect_appgw(
                        reader, instance, body, config.modules.appgw, upstream_scope, warnings
                    ),
                )
                instance.upstream = Upstream(afd=afd, appgw=appgw)
            return instance

    instances = await asyncio.gather(*(one(identifier) for identifier in identifiers))
    return Snapshot(
        collected_at=now,
        telemetry_start=start,
        telemetry_end=end,
        instances=instances,
        collection_warnings=sorted(
            warnings,
            key=lambda warning: (warning.resource_id.casefold(), warning.module, warning.code),
        ),
    )
