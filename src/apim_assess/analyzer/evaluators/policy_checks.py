import json
from collections import defaultdict

from apim_assess.analyzer.evaluators.checks import Check, Context, combine, result
from apim_assess.analyzer.evaluators.policy import OPAQUE, backend_routes, guaranteed
from apim_assess.analyzer.policy_resolver import inventory_complete, walk
from apim_assess.collector.sanitizer import DYNAMIC, REDACTED, REFERENCE, reference_id
from apim_assess.models.findings import Evaluation, Evidence, Outcome
from apim_assess.models.policy import ControlState, PolicyNode


def _positive(value: str | None) -> bool:
    return bool(value and value.isdigit() and int(value) > 0)


def _contexts(ctx: Context, check: str) -> Evaluation:
    observations: list[tuple[Outcome, Evidence]] = []
    methods = {item.path: item.metadata.method for item in ctx.resources("operation")}
    for view in ctx.views:
        state: ControlState
        if check == "error_handling":
            state = guaranteed(
                view.sections["on-error"],
                lambda node: (
                    node.tag
                    in {
                        "return-response",
                        "set-status",
                        "log-to-eventhub",
                        "trace",
                    }
                ),
            )
        elif check == "retry_timeout":

            def resilient(node: PolicyNode) -> bool | None:
                if node.tag == "forward-request":
                    timeout = node.attributes.get("timeout")
                    milliseconds = node.attributes.get("timeout-ms")
                    if timeout is None and milliseconds is None:
                        return False
                    if _positive(timeout) or _positive(milliseconds):
                        return True
                    return None
                if node.tag == "retry":
                    attrs = node.attributes
                    return (
                        True
                        if _positive(attrs.get("count"))
                        and _positive(attrs.get("interval"))
                        and attrs.get("condition")
                        and any(child.tag == "forward-request" for child in walk(node.children))
                        else None
                    )
                return False

            state = guaranteed(view.sections["backend"], resilient)
        elif check == "implementation_headers":
            states = [
                _header(view.sections["outbound"], name)
                for name in ("x-powered-by", "x-aspnet-version")
            ]
            state = (
                "absent" if "absent" in states else "unknown" if "unknown" in states else "present"
            )
        elif check == "payload_limits":
            method = methods.get(view.operation_path or "")
            if method is None:
                state = "unknown"
            elif method not in {"POST", "PUT", "PATCH"}:
                state = "not_applicable"
            else:

                def payload(node: PolicyNode) -> bool | None:
                    if node.tag != "validate-content":
                        return False
                    size = node.attributes.get("max-size")
                    action = node.attributes.get("size-exceeded-action")
                    if not _positive(size) or action not in {"prevent", "ignore", "detect"}:
                        return None
                    return (
                        int(size or "0") <= ctx.thresholds.payload_max_bytes and action == "prevent"
                    )

                state = guaranteed(view.sections["inbound"], payload)
        else:
            method = methods.get(view.operation_path or "")
            if method is None:
                state = "unknown"
            elif method != "GET":
                state = "not_applicable"
            else:
                lookup = guaranteed(
                    view.sections["inbound"], lambda node: node.tag == "cache-lookup"
                )
                store = guaranteed(
                    view.sections["outbound"],
                    lambda node: (
                        _positive(node.attributes.get("duration"))
                        if node.tag == "cache-store"
                        else False
                    ),
                )
                state = "present" if lookup == store == "present" else "unknown"
                # GET alone cannot establish high-read traffic or safe cacheability.
        if view.issues and state in {"absent", "present"}:
            state = "unknown"
        outcomes: dict[ControlState, Outcome] = {
            "present": "pass",
            "absent": "fail",
            "unknown": "unknown",
            "not_applicable": "not_applicable",
        }
        outcome = outcomes[state]
        if (
            check == "response_cache"
            and ctx.instance.sku
            and ctx.instance.sku.name == "Consumption"
        ):
            lookup_nodes = [
                node for node in walk(view.sections["inbound"]) if node.tag == "cache-lookup"
            ]
            if any(node.attributes.get("caching-type") == "internal" for node in lookup_nodes):
                outcome = "unsupported"
            elif any(
                node.attributes.get("caching-type", "prefer-external") != "external"
                for node in lookup_nodes
            ):
                outcome = "unknown"
        sources = sorted({node.source for nodes in view.sections.values() for node in walk(nodes)})
        observations.append(
            (
                outcome,
                Evidence(
                    source="effective_policy",
                    detail=f"{view.operation_path or view.api_path}; "
                    f"context={view.product_path or 'non-product'}; "
                    f"{check}={state}; sources={', '.join(sources)}",
                    api_path=view.api_path,
                ),
            )
        )
    summaries = {
        "error_handling": (
            "Configured error response or error telemetry handling per execution context; "
            "not proof of safe recovery semantics."
        ),
        "retry_timeout": (
            "An explicit positive forwarding timeout or retry enclosing forwarding is required. "
            "Retry safety, idempotency and workload-specific budgets need review."
        ),
        "implementation_headers": (
            "Check final outbound deletion of X-Powered-By and X-AspNet-Version. "
            "APIM cannot delete the Server response header; it is deliberately excluded."
        ),
        "payload_limits": (
            "POST/PUT/PATCH contexts require a preventing request size limit at most "
            f"{ctx.thresholds.payload_max_bytes} bytes. This configurable review budget is not "
            "an Azure platform maximum or schema-validity check."
        ),
        "response_cache": (
            "A configured response-cache lookup/store pair is assessed for GET operations. "
            "Uncached GETs remain unknown: high-read traffic and safe cacheability were not "
            "collected. Never cache personalized data without an isolation design."
        ),
    }
    return combine(
        observations, complete=inventory_complete(ctx.instance.inventory), summary=summaries[check]
    )


def _header(nodes: list[PolicyNode], name: str) -> ControlState:
    def run(
        sequence: list[PolicyNode], states: set[tuple[ControlState, bool]]
    ) -> set[tuple[ControlState, bool]]:
        for node in sequence:
            updated: set[tuple[ControlState, bool]] = set()
            for state, stopped in states:
                if stopped:
                    updated.add((state, True))
                elif node.tag == "choose":
                    branches = [
                        child for child in node.children if child.tag in {"when", "otherwise"}
                    ]
                    for branch in branches:
                        updated.update(run(branch.children, {(state, False)}))
                    if not any(branch.tag == "otherwise" for branch in branches):
                        updated.add((state, False))
                elif node.tag == "set-header":
                    header = node.attributes.get("name")
                    if header == name:
                        action = node.attributes.get("exists-action", "override")
                        state = (
                            "present"
                            if action == "delete"
                            else "absent"
                            if action in {"override", "append", "skip"}
                            else "unknown"
                        )
                    elif header not in {"server", "x-powered-by", "x-aspnet-version"}:
                        state = "unknown"
                    updated.add((state, False))
                elif node.tag in OPAQUE:
                    updated.update({("unknown", True), ("unknown", False)})
                else:
                    updated.add((state, node.tag in {"return-response", "forward-request"}))
            states = updated
        return states

    states = {state for state, _ in run(nodes, {("absent", False)})}
    return states.pop() if len(states) == 1 else "unknown"


def inline_secrets(ctx: Context) -> Evaluation:
    inventory = ctx.instance.inventory
    if inventory is None:
        return result("unknown", "Policy inventory was not collected.", "collection_coverage")
    documents = [*inventory.policies.values(), *inventory.fragments.values()]
    observations: list[tuple[Outcome, Evidence]] = []
    for document in documents:
        locations = (
            f"locations={', '.join(document.inline_secret_locations)}; "
            if document.inline_secret_locations
            else ""
        )
        observations.append(
            (
                "fail"
                if document.has_inline_secret_pattern
                else "unknown"
                if document.status == "unavailable"
                else "pass",
                Evidence(
                    source=document.source,
                    detail=f"status={document.status}; "
                    f"has_inline_secret_pattern={document.has_inline_secret_pattern}; "
                    f"{locations}no secret literal retained.",
                ),
            )
        )
    return combine(
        observations,
        complete=inventory_complete(inventory) and ctx.complete("policyFragments"),
        summary=(
            "Sanitizer-detected inline secret patterns warrant rotation and Key Vault review. "
            "Pattern-free documents do not prove the absence of all secrets."
        ),
    )


def pooling(ctx: Context) -> Evaluation:
    backends = {
        (item.workspace, reference_id(item.name)): item for item in ctx.resources("backend")
    }
    observations: list[tuple[Outcome, Evidence]] = []
    for view in ctx.views:
        refs = backend_routes(view)
        selected = [backends.get(ref) for ref in refs]
        outcome: Outcome = "not_applicable"
        details: list[str] = []
        if view.issues or any(item is None for item in selected):
            outcome = "unknown"
        else:
            pools = [item for item in selected if item and item.metadata.backend_pool is True]
            counts = [item.metadata.pool_member_count for item in pools]
            details = [
                f"{item.path}: pool_members={item.metadata.pool_member_count}" for item in pools
            ]
            if any(count is not None and count < 2 for count in counts):
                outcome = "fail"
            elif counts and all(count is not None and count >= 2 for count in counts):
                outcome = "pass" if len(pools) == len(selected) else "unknown"
            elif pools or len(refs) > 1:
                outcome = "unknown"
        observations.append(
            (
                outcome,
                Evidence(
                    source="effective_policy",
                    detail=f"{view.operation_path or view.api_path}; {'; '.join(details)}; "
                    f"selected_backend_refs={len(refs)}",
                    api_path=view.api_path,
                ),
            )
        )
    return combine(
        observations,
        complete=inventory_complete(ctx.instance.inventory) and ctx.complete("backends"),
        summary=(
            "Referenced pools need multiple members. Distinct conditional routes do not establish "
            "interchangeable endpoints; non-pool alternatives require design review, "
            "not an automatic pooling failure."
        ),
    )


def unused_resources(ctx: Context) -> Evaluation:
    inventory = ctx.instance.inventory
    if inventory is None:
        return result("unknown", "Inventory was not collected.", "collection_coverage")
    observations: list[tuple[Outcome, Evidence]] = []
    for workspace in ctx.resources("workspace"):
        has_apis = any(api.workspace == workspace.path for api in ctx.resources("api"))
        coverage = inventory.collections.get(workspace.path + "/apis")
        outcome: Outcome = (
            "unknown"
            if not coverage or coverage.status != "complete"
            else "pass"
            if has_apis
            else "fail"
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=workspace.resource_id,
                    detail=f"workspace_has_apis={has_apis}; "
                    "absence requires complete workspace API inventory.",
                ),
            )
        )
    for product in ctx.resources("product"):
        members = inventory.product_apis.get(product.path)
        coverage = inventory.collections.get(product.path + "/apis")
        outcome = (
            "unknown"
            if members is None or not coverage or coverage.status != "complete"
            else "pass"
            if members
            else "fail"
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=product.resource_id,
                    detail="linked_API_count="
                    f"{len(members) if members is not None else 'unknown'}; "
                    "review deliberate placeholders before removal.",
                ),
            )
        )
    if ctx.resources("backend") or ctx.resources("named_value"):
        observations.append(
            (
                "unknown",
                Evidence(
                    source="cross_reference_coverage",
                    detail="Sanitized dynamic references and automatic URL-to-backend matching "
                    "cannot establish unused backend/named-value status; "
                    "absence of an explicit policy reference is not proof.",
                ),
            )
        )
    return combine(
        observations,
        complete=inventory_complete(inventory),
        summary=(
            "Confirmed workspaces/products without APIs trigger cleanup review. "
            "No resource is changed; broader unused-resource status requires runtime "
            "and reference evidence."
        ),
    )


def repeated_blocks(ctx: Context) -> Evaluation:
    groups: dict[str, set[str]] = defaultdict(set)
    uncertain = False
    seen: set[tuple[str, str]] = set()
    for view in ctx.views:
        for section, nodes in view.sections.items():
            local = [
                node
                for node in nodes
                if node.scope == view.api_path and "/policyFragments/" not in node.source
            ]
            key = (view.api_path, section)
            if key in seen:
                continue
            seen.add(key)
            if len(walk(local)) < 3:
                continue
            if any(
                node.tag in OPAQUE
                or node.text in {REDACTED, DYNAMIC, REFERENCE}
                or any(
                    value in {REDACTED, DYNAMIC, REFERENCE} for value in node.attributes.values()
                )
                for node in walk(local)
            ):
                uncertain = True
                continue

            def shape(node: PolicyNode) -> dict[str, object]:
                return {
                    "tag": node.tag,
                    "attributes": node.attributes,
                    "text": node.text,
                    "children": [shape(child) for child in node.children],
                }

            signature = json.dumps([shape(node) for node in local], sort_keys=True)
            groups[signature].add(view.api_path.split(";rev=", 1)[0])
    repeated = [sorted(apis) for apis in groups.values() if len(apis) > 1]
    return combine(
        [
            (
                "fail",
                Evidence(
                    source="effective_policy",
                    detail=f"Identical fully inspectable API-local block across: {', '.join(apis)}",
                ),
            )
            for apis in repeated
        ]
        + (
            [
                (
                    "unknown",
                    Evidence(
                        source="sanitization_boundary",
                        detail="Redacted literals or expressions cannot be compared "
                        "for semantic duplication.",
                    ),
                )
            ]
            if uncertain
            else []
        ),
        complete=inventory_complete(ctx.instance.inventory)
        and not any(view.issues for view in ctx.views),
        summary=(
            "Only fully inspectable blocks of at least three nodes are compared. "
            "Shared inherited/fragment content and revisions do not establish duplicated "
            "inline policy."
        ),
    )


def version_sets(ctx: Context) -> Evaluation:
    grouped: dict[tuple[str | None, str], list[str]] = defaultdict(list)
    uncertain = False
    for api in ctx.resources("api"):
        metadata = api.metadata
        if metadata.version_set is True:
            continue
        if metadata.version_set is None or metadata.api_route_hash is None:
            uncertain = True
            continue
        grouped[(api.workspace, metadata.api_route_hash)].append(api.path.split(";rev=", 1)[0])
    observations: list[tuple[Outcome, Evidence]] = [
        (
            "fail",
            Evidence(
                source="ARM apis.path / apiVersionSetId",
                detail="Same route hash with multiple unversioned API identities: "
                f"{', '.join(sorted(set(paths)))}",
            ),
        )
        for paths in grouped.values()
        if len(set(paths)) > 1
    ]
    if uncertain:
        observations.append(
            (
                "unknown",
                Evidence(
                    source="ARM API metadata",
                    detail="Route or version-set metadata was omitted; "
                    "API names are not used to invent families.",
                ),
            )
        )
    if not observations and ctx.resources("api"):
        observations.append(
            (
                "pass",
                Evidence(
                    source="ARM API metadata",
                    detail="No duplicate unversioned route identities observed; "
                    "revisions are not separate versions.",
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("apis"),
        summary=(
            "Exact route equality (hashed before persistence), within a workspace namespace, "
            "is a bounded API-family heuristic. API revisions are deduplicated."
        ),
    )


POLICY_CHECKS: dict[str, Check] = {
    "backend_pooling": pooling,
    "error_handling": lambda ctx: _contexts(ctx, "error_handling"),
    "retry_timeout": lambda ctx: _contexts(ctx, "retry_timeout"),
    "inline_secrets": inline_secrets,
    "implementation_headers": lambda ctx: _contexts(ctx, "implementation_headers"),
    "unused_resources": unused_resources,
    "repeated_blocks": repeated_blocks,
    "api_version_sets": version_sets,
    "payload_limits": lambda ctx: _contexts(ctx, "payload_limits"),
    "response_cache": lambda ctx: _contexts(ctx, "response_cache"),
}
