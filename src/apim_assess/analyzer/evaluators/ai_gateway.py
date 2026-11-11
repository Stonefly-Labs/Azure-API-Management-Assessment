from __future__ import annotations

from apim_assess.analyzer.evaluators.checks import Check, Context, combine
from apim_assess.analyzer.evaluators.policy import backend_routes, guaranteed
from apim_assess.analyzer.policy_resolver import inventory_complete, resolve, walk
from apim_assess.collector.sanitizer import (
    COGNITIVE_AUDIENCE,
    DYNAMIC,
    LITERAL_URL,
    REDACTED,
    REFERENCE,
    reference_id,
)
from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.findings import Evaluation, Evidence, Outcome
from apim_assess.models.policy import ControlState, EffectivePolicy, PolicyNode, SubResource

AI_KINDS = {"azure_openai", "llm"}
TOKEN_POLICIES = {"llm-token-limit", "azure-openai-token-limit"}
METRIC_POLICIES = {"llm-emit-token-metric", "azure-openai-emit-token-metric"}


def _positive(value: str | None) -> bool:
    return bool(value and value.isdigit() and int(value) > 0)


def _routes(view: EffectivePolicy) -> set[tuple[str | None, str]]:
    def mark(nodes: list[PolicyNode]) -> list[PolicyNode]:
        result = []
        for node in nodes:
            attributes = dict(node.attributes)
            if node.tag == "set-backend-service" and "base-url" in attributes:
                attributes["backend-id"] = "__AI_" + attributes.get("ai-backend-kind", "unknown")
            result.append(
                node.model_copy(update={"attributes": attributes, "children": mark(node.children)})
            )
        return result

    return backend_routes(
        view.model_copy(
            update={"sections": {section: mark(nodes) for section, nodes in view.sections.items()}}
        )
    )


def _backend_leaves(
    backend: SubResource, by_id: dict[str, SubResource], seen: frozenset[str] = frozenset()
) -> list[SubResource | None]:
    if backend.resource_id.casefold() in seen:
        return [None]
    if backend.metadata.backend_pool is not True:
        return [backend]
    members = backend.metadata.pool_member_references
    if not members:
        return [None]
    result: list[SubResource | None] = []
    for member in members:
        item = by_id.get(member)
        if item is None:
            result.append(None)
        else:
            result.extend(_backend_leaves(item, by_id, seen | {backend.resource_id.casefold()}))
    return result


def _selected(ctx: Context, view: EffectivePolicy) -> tuple[set[str], list[SubResource | None]]:
    apis = {item.path: item for item in ctx.resources("api")}
    backends = {
        (item.workspace, reference_id(item.name)): item for item in ctx.resources("backend")
    }
    by_id = {reference_id(item.resource_id.casefold()): item for item in ctx.resources("backend")}
    kinds: set[str] = set()
    selected: list[SubResource | None] = []
    for workspace, route in sorted(_routes(view), key=lambda item: (item[0] or "", item[1])):
        if route.startswith("__AI_"):
            kinds.add(route.removeprefix("__AI_"))
        elif route == LITERAL_URL:
            kinds.add(apis[view.api_path].metadata.ai_backend or "unknown")
        else:
            backend = backends.get((workspace, route))
            selected.append(backend)
            if backend is None:
                kinds.add("unknown")
            else:
                kinds.update(
                    item.metadata.ai_backend or "unknown" if item else "unknown"
                    for item in _backend_leaves(backend, by_id)
                )
    return kinds or {"unknown"}, selected


def _token(node: PolicyNode) -> bool | None:
    if node.tag not in TOKEN_POLICIES:
        return False
    attrs = node.attributes
    rate = _positive(attrs.get("tokens-per-minute"))
    quota = _positive(attrs.get("token-quota")) and attrs.get("token-quota-period") in {
        "Hourly",
        "Daily",
        "Weekly",
        "Monthly",
        "Yearly",
    }
    if attrs.get("estimate-prompt-tokens") not in {"true", "false"}:
        return None
    if not attrs.get("counter-key"):
        return None
    return True if rate or quota else None


def _managed_identity(ctx: Context, view: EffectivePolicy) -> ControlState:
    def managed(node: PolicyNode) -> bool | None:
        if node.tag != "authentication-managed-identity":
            return False
        attrs = node.attributes
        return (
            True
            if attrs.get("resource") == COGNITIVE_AUDIENCE
            and attrs.get("ignore-error", "false") == "false"
            and "output-token-variable-name" not in attrs
            and "client-id" not in attrs
            and "SystemAssigned" in (ctx.instance.identity_type or "")
            else None
        )

    nodes = view.sections["inbound"] + view.sections["backend"]
    state = guaranteed(nodes, managed)
    if any(
        node.attributes.get("ai-api-key") == "true"
        or node.tag == "set-header"
        and (
            node.attributes.get("name") == "authorization"
            or node.attributes.get("name") in {"api-key", "x-api-key"}
            and node.attributes.get("exists-action", "override") != "delete"
        )
        or node.tag == "set-query-parameter"
        and node.attributes.get("exists-action", "override") != "delete"
        for node in walk(nodes)
    ):
        return "unknown"
    return state


def _pool(ctx: Context, selected: list[SubResource | None]) -> Outcome:
    by_id = {reference_id(item.resource_id.casefold()): item for item in ctx.resources("backend")}
    if not selected or any(item is None for item in selected):
        return "unknown"
    outcomes: list[Outcome] = []
    for item in selected:
        if item is None:
            continue
        if item.metadata.backend_pool is False:
            outcomes.append("fail")
            continue
        members = item.metadata.pool_member_references
        if item.metadata.backend_pool is None or members is None:
            outcomes.append("unknown")
            continue
        if len(set(members)) < 2:
            outcomes.append("fail")
            continue
        for member in members:
            backend = by_id.get(member)
            if backend is None or backend.metadata.backend_pool is not False:
                outcomes.append("unknown")
            else:
                states = (backend.metadata.breaker_429, backend.metadata.breaker_retry_after)
                outcomes.append(
                    "fail" if False in states else "unknown" if None in states else "pass"
                )
    return "fail" if "fail" in outcomes else "unknown" if "unknown" in outcomes else "pass"


def _ai(ctx: Context, check: str) -> Evaluation:
    observations: list[tuple[Outcome, Evidence]] = []
    backends_complete = ctx.complete("backends")
    for view in ctx.views:
        kinds, selected = _selected(ctx, view)
        outcome: Outcome
        if kinds == {"other"}:
            outcome = "not_applicable"
        elif view.issues or "unknown" in kinds or not kinds <= AI_KINDS:
            outcome = "unknown"
        elif check in {"identity", "pool"} and kinds != {"azure_openai"}:
            # Third-party LLM services generally cannot accept an Azure managed identity.
            outcome = "not_applicable"
        elif ctx.instance.sku is None:
            outcome = "unknown"
        elif ctx.instance.sku.name not in CLASSIC | V2 | {"Consumption"}:
            outcome = "unsupported"
        elif check in {"token", "pool"} and ctx.instance.sku.name == "Consumption":
            outcome = "unsupported"
        elif check == "identity" and view.workspace:
            outcome = "unsupported"
        elif check == "pool":
            outcome = (
                "fail"
                if any(
                    route == LITERAL_URL or route.startswith("__AI_") for _, route in _routes(view)
                )
                else _pool(ctx, selected)
            )
        else:
            if check == "token":
                state = guaranteed(view.sections["inbound"], _token)
            elif check == "identity":
                state = _managed_identity(ctx, view)
                if any(route == LITERAL_URL for _, route in _routes(view)):
                    api = next(item for item in ctx.resources("api") if item.path == view.api_path)
                    if api.metadata.api_key_credential is True:
                        state = "absent"
                    elif state == "present" and api.metadata.api_key_credential is None:
                        state = "unknown"
                by_id = {
                    reference_id(item.resource_id.casefold()): item
                    for item in ctx.resources("backend")
                }
                leaves = [
                    leaf for item in selected if item for leaf in _backend_leaves(item, by_id)
                ]
                if any(item and item.metadata.api_key_credential is True for item in leaves):
                    state = "absent"
                elif state == "present" and any(
                    item is None or item.metadata.api_key_credential is None for item in leaves
                ):
                    state = "unknown"
            else:
                state = guaranteed(
                    view.sections["inbound"],
                    lambda node: (
                        (
                            True
                            if node.attributes.get("namespace")
                            not in {None, "", DYNAMIC, REFERENCE, REDACTED}
                            else None
                        )
                        if node.tag in METRIC_POLICIES
                        else False
                    ),
                )
                loggers = ctx.resources("logger")
                if state == "present" and not any(
                    item.workspace == view.workspace and item.metadata.application_insights is True
                    for item in loggers
                ):
                    state = "unknown"
            outcomes: dict[ControlState, Outcome] = {
                "present": "pass",
                "absent": "fail",
                "unknown": "unknown",
                "not_applicable": "not_applicable",
            }
            outcome = outcomes[state]
        observations.append(
            (
                outcome,
                Evidence(
                    source="effective_policy",
                    detail=f"{view.operation_path or view.api_path}; "
                    f"context={view.product_path or 'non-product'}; "
                    f"detected_endpoint_kinds={','.join(sorted(kinds))}; {check}={outcome}; "
                    f"referenced_backends={len(selected)}",
                    api_path=view.api_path,
                ),
            )
        )
    summaries = {
        "token": (
            "Recognized LLM endpoints require an effective positive fixed token rate or quota. "
            "Dynamic budgets stay unknown; counters are gateway-local, "
            "not a global spending guarantee."
        ),
        "identity": (
            "Azure OpenAI contexts require unconditional managed identity for the Cognitive "
            "Services audience, without static backend API-key credentials. "
            "Third-party LLM authentication is not prescribed."
        ),
        "pool": (
            "Azure OpenAI routes require a referenced pool with at least two distinct collected "
            "members, each with a positive 429 breaker accepting Retry-After. "
            "Configuration is not failover proof."
        ),
        "metric": (
            "Recognized LLM contexts require effective token metric emission and an "
            "Application Insights logger. This is not proof of ingestion, custom-metric "
            "enablement, token accuracy or chargeback completeness."
        ),
    }
    return combine(
        observations,
        complete=inventory_complete(ctx.instance.inventory) and backends_complete,
        summary=summaries[check],
    )


def graphql(ctx: Context) -> Evaluation:
    apis = {item.path: item for item in ctx.resources("api")}
    observations: list[tuple[Outcome, Evidence]] = []
    for view in resolve(ctx.instance, include_graphql=True):
        api = apis[view.api_path]
        if api.metadata.api_type != "graphql":
            outcome: Outcome = "unknown" if api.metadata.api_type is None else "not_applicable"
        elif view.workspace:
            # The policy reference and gateway support matrix disagree about workspace support.
            outcome = "unsupported"
        elif view.issues:
            outcome = "unknown"
        else:

            def validate(node: PolicyNode) -> bool | None:
                if node.tag != "validate-graphql-request":
                    return False
                if node.scope != "" and not any(
                    part in {"apis", "products", "workspaces"} for part in node.scope.split("/")
                ):
                    return None
                if "/operations/" in node.scope:
                    return None
                size = node.attributes.get("max-size")
                depth = node.attributes.get("max-depth", "6")
                return (
                    True
                    if _positive(size) and int(size or "0") <= 102400 and _positive(depth)
                    else None
                )

            state = guaranteed(view.sections["inbound"], validate)
            outcome = "pass" if state == "present" else "fail" if state == "absent" else "unknown"
        observations.append(
            (
                outcome,
                Evidence(
                    source="effective_policy",
                    detail=f"{view.api_path}; GraphQL size/depth protection={outcome}; "
                    f"context={view.product_path or 'non-product'}",
                    api_path=view.api_path,
                ),
            )
        )
    return combine(
        observations,
        complete=inventory_complete(ctx.instance.inventory),
        summary="GraphQL request validation needs a positive max-size up to 100 KiB and a positive "
        "max-depth (documented default 6). Resolver field authorization is not assessed; "
        "conflicting workspace support documentation is treated as unsupported.",
    )


AI_CHECKS: dict[str, Check] = {
    "ai_token_limit": lambda ctx: _ai(ctx, "token"),
    "ai_managed_identity": lambda ctx: _ai(ctx, "identity"),
    "ai_resilient_pool": lambda ctx: _ai(ctx, "pool"),
    "ai_token_metrics": lambda ctx: _ai(ctx, "metric"),
    "graphql_validation": graphql,
}
