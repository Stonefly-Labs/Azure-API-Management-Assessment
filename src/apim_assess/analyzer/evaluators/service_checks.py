from datetime import date

from apim_assess.analyzer.evaluators.adjacent_checks import log_evidence
from apim_assess.analyzer.evaluators.checks import Check, Context, boolean, combine, result
from apim_assess.collector.apim_core import SAFE_CUSTOM_PROPERTIES
from apim_assess.collector.sanitizer import reference_id
from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.findings import Evaluation, Evidence, Outcome


def units(ctx: Context) -> Evaluation:
    instance = ctx.instance
    if not instance.sku or instance.sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result("unknown", "SKU capability is unavailable.", "ARM service.sku")
    if instance.sku.name == "Consumption":
        return result("unsupported", "Consumption has no dedicated scale units.", "ARM service.sku")
    observations: list[tuple[Outcome, Evidence]] = [
        (
            "unknown" if capacity is None else "fail" if capacity < 2 else "pass",
            Evidence(
                source="ARM service.sku.capacity / additionalLocations",
                detail=f"{location}: units={capacity}",
            ),
        )
        for location, capacity in [
            (instance.location, instance.sku.capacity),
            *((region.location, region.capacity) for region in instance.additional_locations or []),
        ]
    ]
    return combine(
        observations,
        complete=instance.additional_locations is not None,
        summary=(
            "At least two units per collected region is a resilience review heuristic, "
            "not an SLA or zone guarantee."
        ),
    )


def multi_region(ctx: Context) -> Evaluation:
    instance = ctx.instance
    if instance.environment != "prod":
        return result("not_applicable", "Cross-region production resilience check.", "environment")
    if not instance.sku:
        return result("unknown", "SKU was not collected.", "ARM service.sku")
    if instance.sku.name in (CLASSIC | V2 | {"Consumption"}) - {"Premium"}:
        return result(
            "unsupported",
            "Native multi-region deployment is available only on classic Premium; "
            "review external recovery options.",
            "ARM service.sku",
        )
    if (
        instance.sku.name != "Premium"
        or instance.additional_locations is None
        or not instance.location
    ):
        return result(
            "unknown",
            "Complete supported regional topology is required.",
            "ARM additionalLocations",
        )
    locations = {instance.location.replace(" ", "").casefold()}
    locations.update(
        region.location.replace(" ", "").casefold()
        for region in instance.additional_locations
        if region.location
    )
    if any(not region.location for region in instance.additional_locations):
        return result("unknown", "A secondary region name was omitted.", "ARM additionalLocations")
    return result(
        "pass" if len(locations) > 1 else "fail",
        f"{len(locations)} distinct configured region(s); "
        "business criticality and dependency failover require review.",
        "ARM service.location / additionalLocations",
    )


def circuit_breakers(ctx: Context) -> Evaluation:
    if not ctx.instance.sku or ctx.instance.sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result(
            "unknown", "Gateway circuit-breaker capability is unavailable.", "ARM service.sku"
        )
    if ctx.instance.sku.name == "Consumption":
        return result(
            "unsupported",
            "Backend circuit breakers are unsupported on Consumption.",
            "ARM service.sku",
        )
    observations: list[tuple[Outcome, Evidence]] = []
    for item in ctx.resources("backend"):
        if item.metadata.backend_pool is True:
            continue
        observations.append(
            (
                boolean(item.metadata.circuit_breaker_present),
                Evidence(
                    source=item.resource_id,
                    detail=(
                        f"circuit_breaker_rules_present={item.metadata.circuit_breaker_present}; "
                        "configuration only, not runtime trip behavior."
                    ),
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("backends"),
        summary=(
            "Review backend circuit-breaker rule configuration; "
            "pool members are assessed as backend entities."
        ),
    )


def recovery(ctx: Context) -> Evaluation:
    return result(
        "unknown",
        "APIM service metadata cannot establish external backup schedules, APIOps automation, "
        "recovery objectives or successful restore exercises. Supply an independently reviewed "
        "DR playbook; no backup action or storage secret was requested.",
        "ARM service metadata / external recovery evidence not collected",
    )


def weak_tls(ctx: Context) -> Evaluation:
    keys = sorted(
        key for key in SAFE_CUSTOM_PROPERTIES if "Protocols." in key and not key.endswith("Http2")
    )
    observed = [(key, ctx.instance.custom_properties.get(key)) for key in keys]
    evaluation = combine(
        [
            (
                boolean(value, good=False),
                Evidence(source="ARM customProperties", detail=f"{key}={value}"),
            )
            for key, value in observed
        ],
        complete=True,
        summary=(
            "Explicit legacy TLS/SSL flags are configuration evidence only. Retirement guidance "
            "and runtime negotiation must be checked separately; "
            "omitted flags have no assumed default."
        ),
    )
    logs = ctx.instance.log_analytics
    if logs is not None and any(
        workspace.aggregate is not None and workspace.aggregate.weak_tls > 0
        for workspace in logs.workspaces
    ):
        evaluation.outcome = "fail"
        evaluation.summary = (
            "Legacy TLS 1.0/1.1 requests were observed in the logged sample. "
            "A disabled service flag cannot override positive runtime evidence."
        )
    if logs is not None:
        evaluation.evidence.extend(log_evidence(ctx))
    return evaluation


def weak_ciphers(ctx: Context) -> Evaluation:
    sku = ctx.instance.sku
    if not sku or sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result("unknown", "Cipher capability is unavailable.", "ARM service.sku")
    if sku.name not in CLASSIC:
        return result(
            "unsupported",
            "This tier does not support custom cipher configuration; "
            "platform defaults were not independently verified.",
            "ARM customProperties",
        )
    keys = sorted(key for key in SAFE_CUSTOM_PROPERTIES if ".Ciphers." in key)
    return combine(
        [
            (
                boolean(ctx.instance.custom_properties.get(key), good=False),
                Evidence(
                    source="ARM customProperties",
                    detail=f"{key}={ctx.instance.custom_properties.get(key)}",
                ),
            )
            for key in keys
        ],
        complete=True,
        summary=(
            "Explicit configurable 3DES/CBC flags only; this is not a negotiated-cipher scan "
            "or a complete cryptographic audit."
        ),
    )


def protocols(ctx: Context) -> Evaluation:
    observations: list[tuple[Outcome, Evidence]] = []
    for api in ctx.resources("api"):
        values = api.metadata.protocols
        outcome: Outcome = (
            "fail"
            if values and set(values) & {"http", "ws"}
            else "pass"
            if values and all(value in {"https", "wss"} for value in values)
            else "unknown"
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=api.resource_id,
                    detail=f"configured protocols={values}",
                    api_path=api.path,
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("apis"),
        summary=(
            "API transport configuration must exclude HTTP and WS. "
            "This does not establish backend TLS or runtime reachability."
        ),
    )


def direct_management(ctx: Context) -> Evaluation:
    sku = ctx.instance.sku
    if not sku or sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result("unknown", "SKU capability is unavailable.", "ARM service.sku")
    if sku.name not in CLASSIC:
        return result(
            "not_applicable",
            "The retired direct management API applied to classic tiers.",
            "ARM service.sku",
        )
    settings = ctx.instance.service_settings
    enabled = settings.management_api_enabled if settings else None
    return result(
        boolean(enabled, good=False),
        f"Direct management access enabled={enabled}. "
        "This retired configuration flag does not prove a reachable endpoint.",
        "ARM tenant/access GET (without secrets)",
    )


def minimum_version(ctx: Context) -> Evaluation:
    settings = ctx.instance.service_settings
    version = settings.minimum_api_version if settings else None
    return result(
        "unknown" if version is None else "fail" if version < date(2019, 12, 1) else "pass",
        f"Configured minimum API version={version}; security floor=2019-12-01, "
        "not a recommendation to use an obsolete API version.",
        "ARM apiVersionConstraint.minApiVersion",
    )


def managed_identity(ctx: Context) -> Evaluation:
    identity = ctx.instance.identity_type
    return result(
        "unknown"
        if identity is None
        else "pass"
        if identity in {"SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"}
        else "fail"
        if identity == "None"
        else "unknown",
        f"Managed identity type={identity}; "
        "role assignments and dependency authorization are not established.",
        "ARM service.identity.type",
    )


def named_secrets(ctx: Context) -> Evaluation:
    inventory = ctx.instance.inventory
    observations: list[tuple[Outcome, Evidence]] = []
    for item in ctx.resources("named_value"):
        metadata = item.metadata
        outcome: Outcome = (
            "unknown"
            if metadata.secret is None
            else "not_applicable"
            if metadata.secret is False
            else "unsupported"
            if item.workspace and metadata.key_vault is not True
            else boolean(metadata.key_vault)
        )
        nv_ref = reference_id(item.name.casefold())
        referenced_by: list[str] = []
        if inventory is not None:
            for scope, doc in sorted(inventory.policies.items()):
                if (
                    item.workspace is None
                    or scope == item.workspace
                    or scope.startswith(item.workspace + "/")
                ) and nv_ref in doc.named_value_refs:
                    referenced_by.append(scope or "global")
            for key, doc in sorted(inventory.fragments.items()):
                if (
                    item.workspace is None or key.startswith(item.workspace + "/policyFragments/")
                ) and nv_ref in doc.named_value_refs:
                    referenced_by.append(key)
        refs_detail = f"referenced_by={', '.join(referenced_by)}; " if referenced_by else ""
        observations.append(
            (
                outcome,
                Evidence(
                    source=item.resource_id,
                    detail=f"name={item.name}; secret={metadata.secret}; "
                    f"key_vault_linked={metadata.key_vault}; {refs_detail}values not retrieved.",
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("namedValues"),
        summary=(
            "Secret named values should use Key Vault where supported. "
            "Workspace Key Vault integration has capability limits."
        ),
    )


def nonsecret_vault(ctx: Context) -> Evaluation:
    observations: list[tuple[Outcome, Evidence]] = []
    for item in ctx.resources("named_value"):
        meta = item.metadata
        outcome: Outcome = (
            "not_applicable"
            if meta.secret is True
            else "unknown"
            if meta.secret is None
            else boolean(meta.key_vault, good=False)
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=item.resource_id,
                    detail=f"secret={meta.secret}; key_vault_linked={meta.key_vault}; "
                    "value contents were not inspected.",
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("namedValues"),
        summary=(
            "Non-secret configuration generally should not introduce a Key Vault dependency; "
            "content sensitivity is not inferred."
        ),
    )


def certificates(ctx: Context) -> Evaluation:
    settings = ctx.instance.service_settings
    hostnames = settings.certificates if settings else None
    observations: list[tuple[Outcome, Evidence]] = []
    for index, certificate in enumerate(hostnames or []):
        if certificate.source == "BuiltIn":
            continue
        days = (
            (certificate.expires_at - ctx.snapshot.collected_at).total_seconds() / 86400
            if certificate.expires_at
            else None
        )
        outcome: Outcome = (
            "fail"
            if days is not None and days <= ctx.thresholds.cert_expiry_days
            else "fail"
            if certificate.source == "Custom"
            else "unknown"
            if days is None or certificate.source is None
            else "pass"
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=f"ARM hostnameConfigurations[{index}]",
                    detail=f"endpoint={certificate.endpoint}; source={certificate.source}; "
                    f"days_to_expiry={days}; warning_days={ctx.thresholds.cert_expiry_days}. "
                    "Platform-managed certificates are an accepted rotation alternative; "
                    "no certificate payloads retrieved.",
                ),
            )
        )
    return combine(
        observations,
        complete=hostnames is not None,
        summary=(
            "Custom-domain certificate rotation and expiry configuration, not backend/client "
            "certificate validation or proof of successful renewal."
        ),
    )


def subscription_scope(ctx: Context) -> Evaluation:
    observations: list[tuple[Outcome, Evidence]] = []
    for item in ctx.resources("subscription"):
        scope = item.metadata.subscription_scope
        observations.append(
            (
                "fail"
                if scope == "all_apis"
                else "pass"
                if scope in {"api", "product"}
                else "unknown",
                Evidence(
                    source=item.resource_id,
                    detail=f"subscription scope classification={scope}; no keys retrieved.",
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("subscriptions"),
        summary="All-API subscriptions widen key exposure; "
        "review even inactive records before reactivation.",
    )


def backend_tls(ctx: Context) -> Evaluation:
    observations: list[tuple[Outcome, Evidence]] = []
    for item in ctx.resources("backend"):
        if item.metadata.backend_pool is True:
            continue
        chain = item.metadata.validate_certificate_chain
        name = item.metadata.validate_certificate_name
        observations.append(
            (
                "fail"
                if chain is False or name is False
                else "pass"
                if chain is True and name is True
                else "unknown",
                Evidence(
                    source=item.resource_id,
                    detail=f"validate_certificate_chain={chain}; validate_certificate_name={name}; "
                    "omitted defaults are not inferred.",
                ),
            )
        )
    return combine(
        observations,
        complete=ctx.complete("backends"),
        summary="Explicit backend TLS validation flags only; "
        "no certificate negotiation was attempted.",
    )


def portal(ctx: Context) -> Evaluation:
    instance = ctx.instance
    if instance.sku and instance.sku.name == "Consumption":
        return result(
            "unsupported", "Consumption has no managed developer portal.", "ARM service.sku"
        )
    settings = instance.service_settings
    if settings and settings.portal_enabled is False:
        return result(
            "not_applicable",
            "Managed developer portal is explicitly disabled.",
            "ARM developerPortalStatus",
        )
    signin = settings.portal_signin_required if settings else None
    signup = settings.portal_signup_enabled if settings else None
    entra = settings.portal_entra_enabled if settings else None
    outcome: Outcome = (
        "fail"
        if signin is False or (signup is True and entra is False)
        else "pass"
        if signin is True and (signup is False or entra is True)
        else "unknown"
    )
    return result(
        outcome,
        f"require_signin={signin}; signup_enabled={signup}; Entra_provider={entra}. "
        "Portal authentication is separate from API caller validation; "
        "delegated registrations need review.",
        "ARM portalconfigs/default / portalsettings/signup / identityProviders",
    )


def tracing(ctx: Context) -> Evaluation:
    if ctx.instance.environment != "prod":
        return result("not_applicable", "Production tracing exposure check.", "environment")
    return result(
        "unsupported",
        "Current APIM tracing uses per-API, time-limited debug credentials. "
        "There is no persistent diagnostic enableTrace flag that establishes tracing exposure; "
        "no debug credentials or traces were requested.",
        "Microsoft APIM request-tracing contract (2023-05-01-preview and later)",
    )


def expensive_nonprod(ctx: Context) -> Evaluation:
    instance = ctx.instance
    if instance.environment == "prod":
        return result("not_applicable", "Non-production cost review only.", "environment")
    sku = instance.sku
    if not sku or sku.name not in CLASSIC | V2 | {"Consumption"}:
        return result("unknown", "SKU cost class was not established.", "ARM service.sku")
    return result(
        "fail" if sku.name in {"Standard", "Premium", "StandardV2", "PremiumV2"} else "pass",
        f"Non-production SKU={sku.name}; this is a cost-review heuristic, not proof of waste. "
        "Networking, load tests and feature parity may justify the tier.",
        "ARM service.sku / environment",
    )


def sampling(ctx: Context) -> Evaluation:
    if ctx.instance.environment != "prod":
        return result(
            "not_applicable", "Production diagnostic overhead review only.", "environment"
        )
    observations: list[tuple[Outcome, Evidence]] = []
    loggers = {
        (item.workspace, reference_id(item.name)): item.metadata.application_insights
        for item in ctx.resources("logger")
    }
    for item in ctx.resources("diagnostic"):
        meta = item.metadata
        app_insights = loggers.get((item.workspace, meta.logger_reference_hash or ""))
        if app_insights is False:
            continue
        if app_insights is None:
            observations.append(
                (
                    "unknown",
                    Evidence(
                        source=item.resource_id,
                        detail="Linked logger type is unavailable; "
                        "Application Insights is not inferred from its name.",
                    ),
                )
            )
            continue
        percentage = meta.sampling_percentage
        outcome: Outcome = (
            "fail"
            if percentage is not None and percentage > ctx.thresholds.app_insights_max_sampling_pct
            else "fail"
            if meta.always_log_errors is True
            and meta.body_bytes is not None
            and meta.body_bytes > ctx.thresholds.diagnostic_body_bytes
            else "pass"
            if percentage is not None and meta.always_log_errors is False
            else "pass"
            if percentage is not None and meta.body_bytes is not None
            else "unknown"
        )
        observations.append(
            (
                outcome,
                Evidence(
                    source=item.resource_id,
                    detail=f"sampling_pct={percentage}; "
                    f"sampling_limit={ctx.thresholds.app_insights_max_sampling_pct}; "
                    f"always_log_errors={meta.always_log_errors}; "
                    f"max_body_bytes={meta.body_bytes}; "
                    f"body_limit={ctx.thresholds.diagnostic_body_bytes}. "
                    "Configuration, not measured throughput overhead.",
                ),
            )
        )
    complete = ctx.complete("diagnostics") and ctx.complete("apis") and ctx.complete("loggers")
    inventory = ctx.instance.inventory
    if inventory:
        complete = complete and all(
            item.path + "/diagnostics" in inventory.collections
            and inventory.collections[item.path + "/diagnostics"].status == "complete"
            for item in ctx.resources("api")
        )
    return combine(
        observations,
        complete=complete,
        summary=(
            "Review diagnostic sampling and error body logging against configured budgets; "
            "missing diagnostics are not an observability pass."
        ),
    )


SERVICE_CHECKS: dict[str, Check] = {
    "scale_units": units,
    "multi_region": multi_region,
    "circuit_breakers": circuit_breakers,
    "recovery_readiness": recovery,
    "weak_tls": weak_tls,
    "weak_ciphers": weak_ciphers,
    "api_protocols": protocols,
    "direct_management": direct_management,
    "minimum_api_version": minimum_version,
    "managed_identity": managed_identity,
    "named_value_secrets": named_secrets,
    "nonsecret_key_vault": nonsecret_vault,
    "domain_certificates": certificates,
    "subscription_scope": subscription_scope,
    "backend_tls": backend_tls,
    "developer_portal": portal,
    "production_tracing": tracing,
    "nonprod_tier": expensive_nonprod,
    "diagnostic_sampling": sampling,
}
