from datetime import timedelta

from apim_assess.analyzer.evaluators.checks import Check, Context, combine, result
from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.adjacent import NsgRule
from apim_assess.models.findings import Evaluation, Evidence, Outcome

DEFENDER_REGIONS = {
    "southeastasia",
    "eastasia",
    "australiaeast",
    "australiasoutheast",
    "australiacentral",
    "australiacentral2",
    "brazilsouth",
    "brazilsoutheast",
    "canadacentral",
    "canadaeast",
    "westeurope",
    "northeurope",
    "francecentral",
    "francesouth",
    "germanywestcentral",
    "germanynorth",
    "centralindia",
    "southindia",
    "westindia",
    "italynorth",
    "japaneast",
    "japanwest",
    "koreacentral",
    "koreasouth",
    "norwayeast",
    "norwaywest",
    "southafricanorth",
    "southafricawest",
    "swedencentral",
    "swedensouth",
    "switzerlandnorth",
    "switzerlandwest",
    "uaecentral",
    "uaenorth",
    "uksouth",
    "ukwest",
    "eastus",
    "eastus2",
    "westus",
    "westus2",
    "westus3",
    "centralus",
    "northcentralus",
    "southcentralus",
    "westcentralus",
    "eastus2euap",
    "centraluseuap",
}


def matches_port(rule: NsgRule, port: int) -> bool:
    return rule.protocol in {"Tcp", "*"} and any(low <= port <= high for low, high in rule.ports)


def required_port(rules: list[NsgRule], source: str, port: int) -> Outcome:
    for rule in sorted(rules, key=lambda rule: rule.priority):
        if not matches_port(rule, port) or 4 not in rule.ip_versions:
            continue
        if source not in rule.sources and "any" not in rule.sources:
            if "specific" in rule.sources or "internet" in rule.sources:
                return "unknown"
            continue
        if rule.destination != "subnet" or not rule.source_ports_any:
            return "unknown"
        return "pass" if rule.access == "Allow" else "fail"
    return "unknown"


def gateway_exposure(rules: list[NsgRule], port: int, version: int) -> Outcome:
    ambiguous_deny = False
    ambiguous_allow = False
    for rule in sorted(rules, key=lambda rule: rule.priority):
        if not matches_port(rule, port) or version not in rule.ip_versions:
            continue
        broad = bool({"any", "internet"} & set(rule.sources)) and rule.destination == "subnet"
        if rule.access == "Deny":
            if broad and rule.source_ports_any:
                return "unknown" if ambiguous_allow else "pass"
            ambiguous_deny = True
        elif broad:
            return "unknown" if ambiguous_deny else "fail"
        elif {"any", "internet", "specific"} & set(rule.sources):
            ambiguous_allow = True
    return "unknown" if ambiguous_allow else "pass"


def subnet_nsg(ctx: Context) -> Evaluation:
    instance = ctx.instance
    if not instance.sku or instance.sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result("unknown", "Network SKU capability is unavailable.", "ARM service.sku")
    if instance.virtual_network_type is None:
        return result(
            "unknown", "Virtual network mode was not collected.", "ARM service properties"
        )
    injected = (
        instance.sku.name in {"Developer", "Premium"}
        and instance.virtual_network_type in {"Internal", "External"}
        or instance.sku.name == "PremiumV2"
        and instance.virtual_network_type == "Internal"
    )
    if not injected:
        return result(
            "not_applicable",
            "No supported injected gateway subnet. Outbound-only v2 integration is not inbound "
            "NSG isolation; private endpoint subnet controls are separate.",
            "ARM service.sku / virtualNetworkType",
        )
    network = instance.networking
    if network is None:
        return result("unknown", "Linked subnet evidence was not collected.", "networking")
    observations: list[tuple[Outcome, Evidence]] = []
    for subnet in network.subnets:
        if subnet.nsg_attached is False:
            observations.append(
                ("fail", Evidence(source=subnet.reference, detail="No attached NSG."))
            )
            continue
        if subnet.status != "complete" or subnet.nsg_attached is not True:
            observations.append(
                ("unknown", Evidence(source=subnet.reference, detail="NSG unavailable."))
            )
            continue
        for port in (80, 443):
            for version in subnet.ip_versions:
                observations.append(
                    (
                        gateway_exposure(subnet.rules, port, version),
                        Evidence(
                            source=subnet.reference,
                            detail=f"Priority-ordered public IPv{version} TCP {port} allowance; "
                            "specific CIDRs, ASGs and destination exceptions "
                            "are not reachability proof.",
                        ),
                    )
                )
        if instance.sku.name != "PremiumV2":
            for source, port in (("apim", 3443), ("load_balancer", 6390)):
                observations.append(
                    (
                        required_port(subnet.rules, source, port),
                        Evidence(
                            source=subnet.reference,
                            detail=(
                                f"Classic prerequisite: source={source}, "
                                f"TCP destination port={port}."
                            ),
                        ),
                    )
                )
    return combine(
        observations,
        complete=network.subnets_status == "complete" and bool(network.subnets),
        summary="Injected subnet NSG configuration only; not routing, WAF, or live connectivity.",
    )


def diagnostics(ctx: Context) -> Evaluation:
    if ctx.instance.sku and ctx.instance.sku.name == "Consumption":
        return result(
            "unsupported", "Consumption does not support resource logs.", "ARM service.sku"
        )
    governance = ctx.instance.governance
    if governance is None:
        return result("unknown", "Resource diagnostic settings were not collected.", "governance")
    observations = [
        Evidence(
            source=setting.reference,
            detail=(
                f"GatewayLogs enabled={setting.gateway_logs}; "
                f"destination configured={setting.destination_configured}."
            ),
        )
        for setting in governance.diagnostics
    ]
    good = any(
        setting.gateway_logs is True and setting.destination_configured
        for setting in governance.diagnostics
    )
    return Evaluation(
        outcome="pass"
        if good
        else (
            "fail"
            if governance.diagnostics_status == "complete"
            and all(setting.gateway_logs is not None for setting in governance.diagnostics)
            else "unknown"
        ),
        summary="At least one enabled GatewayLogs/allLogs setting with a destination is required. "
        "Configured delivery is not proof of ingestion, retention or logging every request.",
        evidence=observations,
    )


def autoscale(ctx: Context, *, scale_in: bool = False) -> Evaluation:
    sku = ctx.instance.sku
    if not sku or sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result("unknown", "Autoscale SKU capability is unavailable.", "ARM service.sku")
    if sku.name == "Consumption":
        return result("not_applicable", "Consumption scales automatically.", "ARM service.sku")
    if sku.name == "Developer":
        return result("unsupported", "Developer has no multi-unit autoscale.", "ARM service.sku")
    governance = ctx.instance.governance
    if governance is None:
        return result("unknown", "Autoscale settings were not collected.", "governance")
    settings = [setting for setting in governance.autoscale if setting.enabled]
    if not settings:
        return result(
            "unknown"
            if governance.autoscale_status != "complete"
            else ("not_applicable" if scale_in else "fail"),
            "No enabled autoscale setting established for this exact APIM resource. "
            "Scale-in is assessed only on configured elastic profiles.",
            "Microsoft.Insights/autoscalesettings",
        )
    observations: list[tuple[Outcome, Evidence]] = []
    for setting in settings:
        if not setting.profiles:
            observations.append(
                (
                    "unknown",
                    Evidence(
                        source=setting.reference,
                        detail="Enabled setting omitted profiles.",
                    ),
                )
            )
        for profile in setting.profiles:
            elastic = profile.maximum > profile.minimum
            outcome: Outcome = (
                "not_applicable"
                if scale_in and not elastic
                else "pass"
                if elastic
                and (profile.decrease_rules > 0 if scale_in else profile.increase_rules > 0)
                else "fail"
            )
            observations.append(
                (
                    outcome,
                    Evidence(
                        source=setting.reference,
                        detail=(
                            f"min/default/max={profile.minimum}/{profile.default}/"
                            f"{profile.maximum}; increase rules={profile.increase_rules}; "
                            f"decrease rules={profile.decrease_rules}."
                        ),
                    ),
                )
            )
    return combine(
        observations,
        complete=governance.autoscale_status == "complete",
        summary="Review every enabled profile's "
        + ("scale-in" if scale_in else "scale-out")
        + " configuration. Triggers and schedules need workload validation. Native autoscale "
        "covers the primary region only; custom secondary-region scaling is not inferred.",
    )


def scale_in(ctx: Context) -> Evaluation:
    return autoscale(ctx, scale_in=True)


def policy_compliance(ctx: Context) -> Evaluation:
    governance = ctx.instance.governance
    if governance is None:
        return result("unknown", "Azure Policy evaluations were not collected.", "governance")
    cutoff = ctx.snapshot.collected_at - timedelta(days=ctx.thresholds.policy_max_age_days)
    latest = {
        (state.assignment, state.definition, state.definition_reference): state
        for state in sorted(
            governance.policy_states,
            key=lambda state: state.timestamp,
        )
    }
    observations: list[tuple[Outcome, Evidence]] = []
    for state in governance.policy_states:
        key = (state.assignment, state.definition, state.definition_reference)
        if state.timestamp != latest[key].timestamp:
            continue
        fresh = cutoff <= state.timestamp <= ctx.snapshot.collected_at
        outcome: Outcome = (
            "unknown"
            if not fresh
            else "fail"
            if state.state == "NonCompliant"
            else "pass"
            if state.state == "Compliant"
            else "not_applicable"
            if state.state == "Exempt"
            else "unknown"
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=state.assignment,
                    detail=(
                        f"definition={state.definition}; reference={state.definition_reference}; "
                        f"state={state.state}; "
                        f"evaluated={state.timestamp.isoformat()}; fresh={fresh}."
                    ),
                ),
            )
        )
    return combine(
        observations,
        complete=governance.policy_status == "complete" and bool(latest),
        summary="Latest collected resource-scoped Azure Policy evaluations per assignment, "
        "definition and initiative reference. Conflicting latest timestamps retain all states. "
        "Empty, stale, future, conflict and error states cannot establish compliance.",
    )


def defender(ctx: Context) -> Evaluation:
    instance = ctx.instance
    sku = instance.sku
    if not sku:
        return result("unknown", "Defender SKU capability is unavailable.", "ARM service.sku")
    if sku.name in V2 | {"Consumption"}:
        return result(
            "unsupported",
            "Documented Defender for APIs support is classic tiers only.",
            "ARM service.sku",
        )
    if sku.name not in CLASSIC or not instance.location:
        return result("unknown", "Defender capability or region is unavailable.", "ARM service")
    if instance.location.replace(" ", "").casefold() not in DEFENDER_REGIONS:
        return result(
            "unsupported",
            "Primary region is outside the documented supported regions.",
            "ARM service.location",
        )
    governance = instance.governance
    if governance is None:
        return result(
            "unknown", "Defender plan/onboarding evidence was not collected.", "governance"
        )
    observations: list[tuple[Outcome, Evidence]] = []
    for api in ctx.resources("api"):
        outcome: Outcome
        if api.workspace or api.metadata.api_type in {
            "soap",
            "graphql",
            "websocket",
            "odata",
            "grpc",
        }:
            outcome = "unsupported"
        elif api.metadata.api_type != "http":
            outcome = "unknown"
        elif governance.defender_plan == "Free":
            outcome = "fail"
        elif api.path in governance.defender_api_paths and governance.defender_plan == "Standard":
            outcome = "pass"
        elif governance.defender_status == "complete" and governance.defender_plan == "Standard":
            outcome = "fail"
        else:
            outcome = "unknown"
        observations.append(
            (
                outcome,
                Evidence(
                    source="Microsoft.Security/pricings/Api / apiCollections",
                    detail=f"plan={governance.defender_plan}; API onboarded="
                    f"{api.path in governance.defender_api_paths}; REST managed gateway only; "
                    "workspace and self-hosted runtime coverage is not established.",
                    api_path=api.path,
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("apis") and governance.defender_status == "complete",
        summary=(
            "Defender subscription plan and explicit REST API onboarding are separate requirements."
        ),
    )


def log_evidence(ctx: Context) -> list[Evidence]:
    logs = ctx.instance.log_analytics
    if logs is None:
        return [Evidence(source="Log Analytics", detail="Runtime logs were not collected.")]
    evidence = [
        Evidence(
            source="Log Analytics",
            detail=f"Query coverage={logs.status}; "
            "aggregated logged sample only, not a population-wide guarantee.",
        )
    ]
    for workspace in logs.workspaces:
        evidence.append(
            Evidence(
                source=f"{workspace.workspace} / {workspace.table}",
                detail=f"status={workspace.status}; aggregates="
                f"{workspace.aggregate.model_dump() if workspace.aggregate else 'unavailable'}",
            )
        )
        evidence.extend(
            Evidence(
                source=workspace.workspace,
                api_path=hotspot.api_path,
                detail=f"API={hotspot.api_reference}; gateway5xx={hotspot.gateway_5xx}; "
                f"backend5xx={hotspot.backend_5xx}.",
            )
            for hotspot in workspace.hotspots
        )
    return evidence


def backend_health(ctx: Context) -> Evaluation:
    if ctx.instance.sku and ctx.instance.sku.name == "Consumption":
        return result(
            "unsupported", "Consumption resource logs are unsupported.", "ARM service.sku"
        )
    logs = ctx.instance.log_analytics
    observations: list[Outcome] = []
    for workspace in logs.workspaces if logs else []:
        aggregate = workspace.aggregate
        if aggregate is None or aggregate.requests == 0:
            observations.append("unknown")
            continue
        error_pct = 100 * aggregate.gateway_5xx / aggregate.requests
        if error_pct > ctx.thresholds.gateway_error_pct or (
            aggregate.backend_p95_ms is not None
            and aggregate.backend_p95_ms > ctx.thresholds.backend_latency_ms
        ):
            observations.append("fail")
        elif aggregate.response_known != aggregate.requests or (
            aggregate.backend_known == 0 or aggregate.latency_samples != aggregate.backend_known
        ):
            observations.append("unknown")
        else:
            observations.append("pass")
    outcome: Outcome = (
        "fail"
        if "fail" in observations
        else "pass"
        if observations and set(observations) == {"pass"} and logs and logs.status == "complete"
        else "unknown"
    )
    return Evaluation(
        outcome=outcome,
        summary=f"Logged backend p95 > {ctx.thresholds.backend_latency_ms:g} ms or gateway "
        f"5xx > {ctx.thresholds.gateway_error_pct:g}% triggers review; equality does not fail. "
        "No hourly Duration percentile is substituted for request-level backend latency. "
        "Workspace/table samples are assessed separately, never summed or averaged together.",
        evidence=log_evidence(ctx),
    )


ADJACENT_CHECKS: dict[str, Check] = {
    "subnet_nsg": subnet_nsg,
    "resource_diagnostics": diagnostics,
    "autoscale": autoscale,
    "scale_in": scale_in,
    "policy_compliance": policy_compliance,
    "defender": defender,
    "backend_health": backend_health,
}
