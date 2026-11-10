from apim_assess.analyzer.evaluators.checks import Check, Context, combine, result
from apim_assess.analyzer.evaluators.policy import guaranteed
from apim_assess.analyzer.policy_resolver import inventory_complete, walk
from apim_assess.models.findings import Evaluation, Evidence, Outcome
from apim_assess.models.policy import PolicyNode


def upstream(ctx: Context, *, lockdown: bool) -> Evaluation:
    instance = ctx.instance
    if instance.public_network_access == "Disabled":
        return result(
            "not_applicable",
            "Public ingress is explicitly disabled; private reachability and "
            "private callers are outside this public upstream check.",
            "publicNetworkAccess",
        )
    if instance.virtual_network_type == "Internal":
        return result(
            "not_applicable",
            "Internal VNet gateway; public upstream/origin bypass check is "
            "not applicable. Private ingress still requires review.",
            "virtualNetworkType",
        )
    if instance.upstream is None:
        return result("unknown", "Upstream probes were not collected.", "collection_coverage")
    probes = [instance.upstream.afd, instance.upstream.appgw]
    alternative_or_gap = (
        not ctx.views
        or not inventory_complete(instance.inventory)
        or any(view.issues for view in ctx.views)
        or any(
            node.tag
            in {
                "ip-filter",
                "validate-client-certificate",
                "unrecognized-policy",
                "unresolved-policy",
                "send-request",
                "send-one-way-request",
            }
            or node.tag == "check-header"
            and node.attributes.get("name") != "x-azure-fdid"
            for view in ctx.views
            for node in walk(view.sections["inbound"])
        )
    )
    observations: list[tuple[Outcome, Evidence]] = []
    for probe in probes:
        for route in probe.routes:
            outcome: Outcome = "unknown"
            if lockdown:
                if route.network_restricted is False:
                    outcome = "unknown" if alternative_or_gap else "fail"
                elif route.network_restricted is True:
                    if route.provider == "appgw":
                        outcome = "pass"
                    elif route.front_door_id:

                        def header(
                            node: PolicyNode, expected: str | None = route.front_door_id
                        ) -> bool | None:
                            if node.tag != "check-header":
                                return False
                            if node.attributes.get("name") != "x-azure-fdid":
                                return None
                            values = [child.text for child in node.children if child.tag == "value"]
                            code = node.attributes.get("failed-check-httpcode", "")
                            return (
                                True
                                if values == [expected]
                                and code.isdigit()
                                and 400 <= int(code) <= 599
                                else None
                            )

                        states = [
                            guaranteed(view.sections["inbound"], header)
                            if not view.issues
                            and not any(
                                node.tag == "set-header"
                                and node.attributes.get("name")
                                not in {
                                    "authorization",
                                    "api-key",
                                    "x-api-key",
                                    "server",
                                    "x-powered-by",
                                    "x-aspnet-version",
                                }
                                for node in walk(view.sections["inbound"])
                            )
                            else "unknown"
                            for view in ctx.views
                        ]
                        if states and all(state == "present" for state in states):
                            outcome = "pass"
                        elif "absent" in states and not alternative_or_gap:
                            outcome = "fail"
            else:
                waf = route.waf
                if waf is not None:
                    waf_states = [waf.enabled, waf.prevention, waf.managed_rules]
                    outcome = (
                        "fail"
                        if False in waf_states
                        else "unknown"
                        if None in waf_states
                        else "pass"
                    )
            observations.append(
                (
                    outcome,
                    Evidence(
                        source="upstream_configuration",
                        detail=f"{route.provider}; route={route.reference}; "
                        f"network_restricted={route.network_restricted}; "
                        f"https_only={route.https_only}; health_probe={route.health_probe}; "
                        f"WAF={route.waf.model_dump_json() if route.waf else 'unavailable'}; "
                        f"{'public_origin_lockdown' if lockdown else 'waf_protection'}={outcome}",
                    ),
                )
            )
    complete = (
        any(probe.status == "complete" for probe in probes)
        and not any(probe.status in {"partial", "unavailable"} for probe in probes)
        and instance.public_network_access == "Enabled"
    )
    if lockdown:
        complete = complete and inventory_complete(instance.inventory)
    if not observations:
        return result(
            "unknown",
            "No matched upstream route was observed in the authorized scope. "
            "Disabled modules, inaccessible resources, DNS indirection and cross-subscription "
            "edges cannot establish absence.",
            "upstream_coverage",
        )
    return combine(
        observations,
        complete=complete,
        summary=(
            "Public origin lockdown requires observed NSG source restriction in every linked "
            "region and, for Front Door, a matching literal FDID check in every effective API "
            "context. Named-value headers, ip-filter/mTLS alternatives and private caller "
            "reachability remain unknown; configuration is not runtime proof."
            if lockdown
            else "Every observed matched route/domain needs an enabled Prevention WAF with a "
            "blocking managed ruleset. Partial associations, overrides/exclusions and "
            "unavailable evidence cannot establish full protection."
        ),
    )


UPSTREAM_CHECKS: dict[str, Check] = {
    "upstream_waf": lambda ctx: upstream(ctx, lockdown=False),
    "upstream_lockdown": lambda ctx: upstream(ctx, lockdown=True),
}
