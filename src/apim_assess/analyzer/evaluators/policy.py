from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from apim_assess.analyzer.policy_resolver import inventory_complete, walk
from apim_assess.collector.sanitizer import (
    DYNAMIC,
    LITERAL_ORIGIN,
    LITERAL_URL,
    REFERENCE,
    reference_id,
)
from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.findings import Evaluation, Evidence, Outcome
from apim_assess.models.policy import (
    ControlState,
    EffectivePolicy,
    PolicyCoverage,
    PolicyNode,
)
from apim_assess.models.snapshot import Instance

Check = Literal["authentication", "jwt", "rate_limit", "inheritance", "cors", "backend"]
BINDINGS: dict[str, Check] = {
    "policy_inheritance": "inheritance",
    "anonymous_access": "authentication",
    "subscription_jwt": "jwt",
    "runaway_load": "rate_limit",
    "permissive_cors": "cors",
    "backend_reference": "backend",
}
OPAQUE = {
    "unresolved-policy",
    "unrecognized-policy",
    "retry",
    "send-request",
    "send-one-way-request",
    "ip-filter",
    "check-header",
    "cache-lookup",
}


def _positive(value: str | None, maximum: int | None = None) -> bool:
    return bool(
        value and value.isdigit() and int(value) > 0 and (maximum is None or int(value) <= maximum)
    )


def _validator(node: PolicyNode, *, certificate: bool = False) -> bool | None:
    attrs = node.attributes
    if node.tag == "validate-client-certificate":
        if attrs.get("ignore-error", "false") == "true":
            return False
        return (
            True
            if all(
                attrs.get(key, "true") == "true"
                for key in ("validate-trust", "validate-not-before", "validate-not-after")
            )
            else None
        )
    if certificate:
        return False
    if node.tag == "validate-azure-ad-token":
        return True if attrs.get("tenant-id") not in {None, "", DYNAMIC, REFERENCE} else None
    if node.tag != "validate-jwt":
        return False
    source = attrs.get("header-name") or attrs.get("query-parameter-name")
    signed = attrs.get("require-signed-tokens", "true") == "true"
    expiry = attrs.get("require-expiration-time", "true") == "true"
    keys = any(
        child.tag == "openid-config"
        and child.attributes.get("url") == LITERAL_URL
        or child.tag == "issuer-signing-keys"
        and bool(child.children)
        for child in node.children
    )
    return True if source and signed and expiry and keys else None


def guaranteed(
    nodes: list[PolicyNode], predicate: Callable[[PolicyNode], bool | None]
) -> ControlState:
    def run(
        sequence: list[PolicyNode], states: list[tuple[ControlState, bool]]
    ) -> list[tuple[ControlState, bool]]:
        for node in sequence:
            updated: list[tuple[ControlState, bool]] = []
            for state, stopped in states:
                if stopped:
                    updated.append((state, True))
                elif node.tag == "choose":
                    branches = [
                        child for child in node.children if child.tag in {"when", "otherwise"}
                    ]
                    if not branches or any(
                        child.tag not in {"when", "otherwise"} for child in node.children
                    ):
                        updated.append(("unknown" if state != "present" else state, False))
                    else:
                        for branch in branches:
                            updated.extend(run(branch.children, [(state, False)]))
                        if not any(branch.tag == "otherwise" for branch in branches):
                            updated.append((state, False))
                elif node.tag == "return-response":
                    updated.append((state, True))
                else:
                    found = predicate(node)
                    if state != "present":
                        if node.tag in OPAQUE and found is not True or found is None:
                            state = "unknown"
                        elif found and state != "unknown":
                            state = "present"
                    if node.tag == "limit-concurrency":
                        updated.extend(run(node.children, [(state, False)]))
                    else:
                        updated.append((state, node.tag == "forward-request"))
            # Only six abstract states exist, regardless of the number of choose branches.
            states = list(dict.fromkeys(updated))
        return states

    states = {state for state, _ in run(nodes, [("absent", False)])}
    return states.pop() if len(states) == 1 else "unknown"


def _identity(view: EffectivePolicy, *, certificate: bool = False) -> ControlState:
    return guaranteed(
        view.sections["inbound"],
        lambda node: _validator(node, certificate=certificate),
    )


def _jwt(view: EffectivePolicy) -> ControlState:
    return guaranteed(
        view.sections["inbound"],
        lambda node: False if node.tag == "validate-client-certificate" else _validator(node),
    )


def _rate(instance: Instance, view: EffectivePolicy) -> ControlState:
    def predicate(node: PolicyNode) -> bool | None:
        attrs = node.attributes
        if node.tag == "limit-concurrency":
            return (
                True
                if _positive(attrs.get("max-count"))
                and node.section == "backend"
                and attrs.get("key")
                and any(child.tag == "forward-request" for child in node.children)
                else None
            )
        if node.tag not in {"rate-limit", "rate-limit-by-key"}:
            return False
        if node.section != "inbound":
            return None
        if node.tag == "rate-limit-by-key" and (
            instance.sku is None or instance.sku.name not in CLASSIC | V2
        ):
            return None
        if node.tag == "rate-limit":
            if view.subscription_required is not True:
                return None
            if not any(part in node.scope.split("/") for part in ("apis", "products")):
                return None
        if not (_positive(attrs.get("calls")) and _positive(attrs.get("renewal-period"), 300)):
            return None
        if node.tag == "rate-limit-by-key" and not attrs.get("counter-key"):
            return None
        if attrs.get("increment-condition") or attrs.get("increment-count", "1") != "1":
            return None
        return True

    return guaranteed(view.sections["inbound"] + view.sections["backend"], predicate)


def _cors(view: EffectivePolicy) -> ControlState:
    def first(nodes: list[PolicyNode]) -> list[PolicyNode | None]:
        possibilities: list[PolicyNode | None] = [None]
        for node in nodes:
            if None not in possibilities:
                break
            if node.tag == "cors":
                possibilities = [candidate for candidate in possibilities if candidate is not None]
                possibilities.append(node)
            elif node.tag == "choose":
                branches = [child for child in node.children if child.tag in {"when", "otherwise"}]
                possibilities = [candidate for candidate in possibilities if candidate is not None]
                for branch in branches:
                    possibilities.extend(first(branch.children))
                if not any(branch.tag == "otherwise" for branch in branches):
                    possibilities.append(None)
            elif node.tag in OPAQUE or node.tag in {"return-response", "forward-request"}:
                possibilities = [candidate for candidate in possibilities if candidate is not None]
                possibilities.append(PolicyNode(tag="unresolved-policy", source=node.source))
        return possibilities

    outcomes: set[ControlState] = set()
    for node in first(view.sections["inbound"]):
        if node is None:
            outcomes.add("not_applicable")
            continue
        if node.tag != "cors":
            outcomes.add("unknown")
            continue
        origins = [
            origin
            for child in node.children
            if child.tag == "allowed-origins"
            for origin in child.children
            if origin.tag == "origin"
        ]
        if not origins:
            outcomes.add("unknown")
        elif any(origin.text not in {"*", LITERAL_ORIGIN} for origin in origins):
            outcomes.add("unknown")
        elif any(origin.text == "*" for origin in origins):
            credentials = node.attributes.get("allow-credentials", "false")
            auth = _identity(view)
            if credentials == "true" or view.subscription_required is True or auth == "present":
                outcomes.add("absent")
            elif credentials != "false" or view.subscription_required is None or auth == "unknown":
                outcomes.add("unknown")
            else:
                outcomes.add("present")
        else:
            outcomes.add("present")
    return outcomes.pop() if len(outcomes) == 1 else "unknown"


def backend_routes(view: EffectivePolicy) -> set[tuple[str | None, str]]:
    def run(
        nodes: list[PolicyNode], paths: list[tuple[tuple[str | None, str], bool]]
    ) -> list[tuple[tuple[str | None, str], bool]]:
        for node in nodes:
            updated: list[tuple[tuple[str | None, str], bool]] = []
            for state, stopped in paths:
                if stopped:
                    updated.append((state, True))
                elif node.tag == "set-backend-service":
                    reference = node.attributes.get("backend-id")
                    url = node.attributes.get("base-url")
                    workspace = (
                        "/".join(node.scope.split("/")[:2])
                        if node.scope.startswith("workspaces/")
                        else None
                    )
                    state = (
                        workspace,
                        reference or (LITERAL_URL if url == LITERAL_URL else DYNAMIC),
                    )
                    updated.append((state, False))
                elif node.tag == "choose":
                    branches = [
                        child for child in node.children if child.tag in {"when", "otherwise"}
                    ]
                    for branch in branches:
                        updated.extend(run(branch.children, [(state, False)]))
                    if not any(branch.tag == "otherwise" for branch in branches):
                        updated.append((state, False))
                elif node.tag in {"limit-concurrency", "retry"}:
                    updated.extend(run(node.children, [(state, False)]))
                elif node.tag in {"unresolved-policy", "unrecognized-policy"}:
                    updated.extend([((None, DYNAMIC), True), (state, False)])
                else:
                    updated.append((state, node.tag in {"forward-request", "return-response"}))
            paths = list(dict.fromkeys(updated))
            if len(paths) > 128:
                return [((None, DYNAMIC), True)]
        return paths

    initial = (None, LITERAL_URL if view.service_url_kind == "literal" else DYNAMIC)
    return {
        state
        for state, _ in run(view.sections["inbound"] + view.sections["backend"], [(initial, False)])
    }


def _resolve_url_locs(instance: Instance, node: PolicyNode, sec: str, suffix: str) -> list[str]:
    scope = node.scope or "global"
    base = f"{scope}/{sec}/{suffix}"
    inventory = instance.inventory
    if inventory is None:
        return [base]
    doc = next(
        (
            d
            for d in (*inventory.policies.values(), *inventory.fragments.values())
            if d.source == node.source
        ),
        inventory.policies.get(node.scope),
    )
    if doc is None or not doc.hardcoded_urls:
        return [base]
    candidates = (
        {
            f"{sec}/set-url",
            f"{sec}/send-request/set-url",
            f"{sec}/send-one-way-request/set-url",
            "fragment/set-url",
            "fragment/send-request/set-url",
            "fragment/send-one-way-request/set-url",
        }
        if suffix == "set-url"
        else {f"{sec}/{suffix}", f"fragment/{suffix}"}
    )
    matched: list[str] = []
    for entry in doc.hardcoded_urls:
        entry_path, sep, line_tag = entry.partition(":L")
        if entry_path in candidates:
            matched.append(f"{base}:L{line_tag}" if sep and line_tag else base)
    return matched or [base]


def _policy_url_locations(instance: Instance, view: EffectivePolicy) -> list[str]:
    def run(
        nodes: list[PolicyNode], paths: list[tuple[PolicyNode | None, bool]]
    ) -> list[tuple[PolicyNode | None, bool]]:
        for node in nodes:
            updated: list[tuple[PolicyNode | None, bool]] = []
            for active_node, stopped in paths:
                if stopped:
                    updated.append((active_node, True))
                elif node.tag == "set-backend-service":
                    reference = node.attributes.get("backend-id")
                    url = node.attributes.get("base-url")
                    next_node = node if not reference and url == LITERAL_URL else None
                    updated.append((next_node, False))
                elif node.tag == "choose":
                    branches = [
                        child for child in node.children if child.tag in {"when", "otherwise"}
                    ]
                    for branch in branches:
                        updated.extend(run(branch.children, [(active_node, False)]))
                    if not any(branch.tag == "otherwise" for branch in branches):
                        updated.append((active_node, False))
                elif node.tag in {"limit-concurrency", "retry"}:
                    updated.extend(run(node.children, [(active_node, False)]))
                elif node.tag in {"unresolved-policy", "unrecognized-policy"}:
                    updated.extend([(None, True), (active_node, False)])
                else:
                    updated.append(
                        (active_node, node.tag in {"forward-request", "return-response"})
                    )
            deduped: list[tuple[PolicyNode | None, bool]] = []
            seen_keys: set[tuple[int | None, bool]] = set()
            for item_node, item_stopped in updated:
                key = (id(item_node) if item_node is not None else None, item_stopped)
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduped.append((item_node, item_stopped))
            paths = deduped
            if len(paths) > 128:
                return [(None, True)]
        return paths

    locations: list[str] = []
    for active_node, _ in run(view.sections["inbound"] + view.sections["backend"], [(None, False)]):
        if active_node is not None:
            locations.extend(
                _resolve_url_locs(
                    instance,
                    active_node,
                    active_node.section or "inbound",
                    "set-backend-service@base-url",
                )
            )
    for section, nodes in view.sections.items():
        for node in walk(nodes):
            sec = node.section or section
            if node.tag == "set-url" and node.text == LITERAL_URL:
                locations.extend(_resolve_url_locs(instance, node, sec, "set-url"))
            elif node.tag == "rewrite-uri" and node.attributes.get("template") == LITERAL_URL:
                locations.extend(_resolve_url_locs(instance, node, sec, "rewrite-uri@template"))
    return list(dict.fromkeys(locations))


def _backend(instance: Instance, view: EffectivePolicy) -> ControlState:
    inventory = instance.inventory
    if inventory is None or view.issues:
        return "unknown"
    if _policy_url_locations(instance, view):
        return "absent"
    backends = {
        (item.workspace, reference_id(item.name))
        for item in inventory.resources
        if item.kind == "backend"
    }
    outcomes: set[ControlState] = {
        "absent"
        if reference == LITERAL_URL
        else "present"
        if (workspace, reference) in backends
        else "unknown"
        for workspace, reference in backend_routes(view)
    }
    return outcomes.pop() if len(outcomes) == 1 else "unknown"


def coverage(instance: Instance, view: EffectivePolicy) -> PolicyCoverage:
    inheritance: ControlState = (
        "absent" if view.missing_base else "unknown" if view.issues else "present"
    )
    if any(issue.startswith("Protocol ") for issue in view.issues):
        inheritance = "unknown"
    cors = _cors(view)
    if instance.inventory is not None and any(
        item.path == view.operation_path and item.metadata.method == "OPTIONS"
        for item in instance.inventory.resources
    ):
        cors = "unknown"
    return PolicyCoverage(
        resource_id=instance.resource_id,
        api_path=view.api_path,
        operation_path=view.operation_path,
        product_path=view.product_path,
        subscription_required=view.subscription_required,
        http_gateway_only=view.http_gateway_only,
        authentication=_identity(view),
        jwt=_jwt(view),
        rate_limit=_rate(instance, view),
        inheritance=inheritance,
        cors=cors,
        backend=_backend(instance, view),
        issues=view.issues,
    )


def evaluate(
    binding: str, instance: Instance, views: list[EffectivePolicy], rows: list[PolicyCoverage]
) -> Evaluation:
    check = BINDINGS[binding]
    states: list[ControlState] = []
    evidence: list[Evidence] = []
    for view, row in zip(views, rows, strict=True):
        state: ControlState = getattr(row, check)
        if check == "authentication" and view.subscription_required is True:
            state = "not_applicable"
        elif check == "authentication" and view.subscription_required is None and state == "absent":
            state = "unknown"
        elif check == "jwt":
            if (
                view.subscription_required is False
                or _identity(view, certificate=True) == "present"
            ):
                state = "not_applicable"
            elif view.subscription_required is None:
                state = "unknown"
        states.append(state)
        context = view.product_path or "non-product"
        sources = sorted({node.source for nodes in view.sections.values() for node in walk(nodes)})
        detail = (
            f"{view.operation_path or view.api_path}; context={context}; "
            f"subscription_required={view.subscription_required}; "
            f"{check}={state}; sources={', '.join(sources) or 'no local policy'}"
        )
        if check == "inheritance" and view.missing_base:
            detail += "; missing base: " + ", ".join(view.missing_base)
        elif check == "backend" and state == "absent":
            url_locs = _policy_url_locations(instance, view)
            if url_locs:
                detail += "; hardcoded_urls=" + ", ".join(url_locs)
            elif view.service_url_kind == "literal":
                detail += "; hardcoded_urls=api.serviceUrl"
        evidence.append(Evidence(source="effective_policy", detail=detail, api_path=view.api_path))
    complete = inventory_complete(instance.inventory)
    outcome: Outcome
    if "absent" in states:
        outcome = "fail"
    elif not complete or "unknown" in states:
        outcome = "unknown"
    elif not states or all(state == "not_applicable" for state in states):
        outcome = "not_applicable"
    else:
        outcome = "pass"
    if (
        outcome == "unknown"
        and complete
        and views
        and all("Protocol outside HTTP policy coverage" in view.issues for view in views)
    ):
        return Evaluation(
            outcome="unsupported",
            summary="The collected protocols are outside HTTP/SOAP policy coverage.",
            evidence=evidence,
        )
    if (
        check == "rate_limit"
        and outcome == "unknown"
        and complete
        and instance.sku is not None
        and instance.sku.name == "Consumption"
        and any(
            node.tag == "rate-limit-by-key"
            for view in views
            for node in walk(view.sections["inbound"])
        )
    ):
        outcome = "unsupported"
    label = {
        "pass": "All applicable collected execution contexts satisfy this configuration check.",
        "fail": "A collected execution context does not satisfy this configuration check.",
        "unknown": "Incomplete coverage or execution semantics; enforcement is not established.",
        "not_applicable": "No applicable API execution contexts for this check.",
        "unsupported": "Rate-limit-by-key is unsupported on the Consumption gateway.",
    }[outcome]
    if not complete:
        evidence.append(
            Evidence(
                source="collection_coverage",
                detail="API, operation, product membership or workspace inventory is incomplete.",
            )
        )
    return Evaluation(outcome=outcome, summary=label, evidence=evidence)
