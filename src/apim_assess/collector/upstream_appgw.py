from __future__ import annotations

from pydantic import ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.collector.upstream import (
    NAME,
    aliases,
    candidates,
    gateway_prefixes,
    get,
    host,
    link,
    network_restriction,
    obj,
    objects,
    reference,
    text,
    waf_configuration,
    warn,
)
from apim_assess.config import UpstreamModule
from apim_assess.models.snapshot import CollectionWarning, Instance
from apim_assess.models.upstream import UpstreamProbe, UpstreamRoute, WafConfiguration

APPGW_VERSION = "2026-01-01"


def _index(props: dict[str, object], key: str) -> dict[str, dict[str, object]]:
    return {
        text(item.get("id")).casefold(): obj(item.get("properties"))
        for item in objects(props.get(key, []))
    }


def _lookup(index: dict[str, dict[str, object]], value: object) -> dict[str, object]:
    result = index.get(link(value).casefold())
    if result is None:
        raise AzureReadError("UNRESOLVED_GATEWAY_REFERENCE")
    return result


async def collect_appgw(
    reader: ArmReader,
    instance: Instance,
    body: object,
    module: UpstreamModule,
    subscriptions: list[str],
    warnings: list[CollectionWarning],
) -> UpstreamProbe:
    if not module.enabled:
        return UpstreamProbe(status="disabled")
    result = UpstreamProbe(status="complete")
    try:
        matches = aliases(body)
    except (AzureReadError, ValidationError, ValueError):
        warn(warnings, instance, "APPGW_INVALID_MATCH_METADATA")
        return UpstreamProbe()
    identifiers = module.resource_ids
    try:
        identifiers = await candidates(
            reader, module, subscriptions, "microsoft.network/applicationgateways"
        )
    except AzureReadError as exc:
        result.status = "partial"
        warn(warnings, instance, "APPGW_DISCOVERY_" + str(exc))
    for identifier in sorted(set(identifiers), key=str.casefold):
        result.candidates += 1
        try:
            gateway = await get(
                reader, identifier, rf"Microsoft\.Network/applicationGateways/{NAME}", APPGW_VERSION
            )
            props = obj(gateway.get("properties"))
            if props.get("operationalState") != "Running":
                raise AzureReadError("GATEWAY_NOT_RUNNING")
            pools = _index(props, "backendAddressPools")
            listeners = _index(props, "httpListeners")
            settings = _index(props, "backendHttpSettingsCollection")
            probes = _index(props, "probes")
            path_maps = _index(props, "urlPathMaps")
            waf_cache: dict[str, WafConfiguration] = {}
            gateway_routes: list[UpstreamRoute] = []
            for rule in objects(props.get("requestRoutingRules")):
                rule_props = obj(rule.get("properties"))
                listener = _lookup(listeners, rule_props.get("httpListener"))
                paths: list[tuple[str, dict[str, object]]] = []
                if rule_props.get("ruleType") == "Basic":
                    if rule_props.get("redirectConfiguration") is None:
                        paths = [(text(rule.get("id")), rule_props)]
                elif rule_props.get("ruleType") == "PathBasedRouting":
                    path_map = _lookup(path_maps, rule_props.get("urlPathMap"))
                    if path_map.get("defaultRedirectConfiguration") is None:
                        paths.append(
                            (
                                text(rule.get("id")) + "/default",
                                {
                                    "backendAddressPool": path_map.get("defaultBackendAddressPool"),
                                    "backendHttpSettings": path_map.get(
                                        "defaultBackendHttpSettings"
                                    ),
                                    "rewriteRuleSet": path_map.get("defaultRewriteRuleSet"),
                                },
                            )
                        )
                    paths.extend(
                        (text(path.get("id")), obj(path.get("properties")))
                        for path in objects(path_map.get("pathRules"))
                        if obj(path.get("properties")).get("redirectConfiguration") is None
                    )
                else:
                    raise AzureReadError("UNSUPPORTED_ROUTING_RULE")
                for path_id, path in paths:
                    if rule_props.get("rewriteRuleSet") or path.get("rewriteRuleSet"):
                        result.status = "partial"
                        warn(warnings, instance, "APPGW_REWRITE_ROUTING_NOT_RESOLVED")
                    pool = _lookup(pools, path.get("backendAddressPool"))
                    addresses = objects(pool.get("backendAddresses"))
                    if not any(
                        host(text(address.get("fqdn") or address.get("ipAddress"))) in matches
                        for address in addresses
                    ):
                        continue
                    http = _lookup(settings, path.get("backendHttpSettings"))
                    policy = (
                        path.get("firewallPolicy")
                        or listener.get("firewallPolicy")
                        or props.get("firewallPolicy")
                    )
                    configuration: WafConfiguration | None
                    if policy is not None:
                        policy_id = link(policy)
                        if policy_id.casefold() not in waf_cache:
                            waf = await get(
                                reader,
                                policy_id,
                                rf"Microsoft\.Network/ApplicationGatewayWebApplicationFirewallPolicies/{NAME}",
                                APPGW_VERSION,
                            )
                            waf_cache[policy_id.casefold()] = waf_configuration(waf, afd=False)
                        configuration = waf_cache[policy_id.casefold()]
                    elif props.get("webApplicationFirewallConfiguration") is not None:
                        legacy = obj(props["webApplicationFirewallConfiguration"])
                        legacy_enabled = legacy.get("enabled")
                        configuration = WafConfiguration(
                            enabled=legacy_enabled if isinstance(legacy_enabled, bool) else None,
                            prevention=legacy.get("firewallMode") == "Prevention",
                            managed_rules=(
                                None
                                if legacy.get("disabledRuleGroups")
                                else legacy.get("ruleSetType") == "OWASP"
                                and bool(legacy.get("ruleSetVersion"))
                            ),
                        )
                    else:
                        configuration = WafConfiguration(enabled=False)
                    probe = _lookup(probes, http["probe"]) if http.get("probe") else {}
                    gateway_routes.append(
                        UpstreamRoute(
                            reference=reference(path_id),
                            provider="appgw",
                            waf=configuration,
                            https_only=listener.get("protocol") == "Https"
                            and http.get("protocol") == "Https",
                            health_probe=probe.get("protocol") == "Https"
                            and isinstance(probe.get("path"), str)
                            and str(probe["path"]).startswith("/"),
                        )
                    )
            result.routes.extend(gateway_routes)
            if gateway_routes:
                try:
                    allowed = await gateway_prefixes(reader, props)
                    restricted = (
                        await network_restriction(
                            reader, instance, body, afd=False, allowed=allowed
                        )
                        if allowed
                        else None
                    )
                    for route in gateway_routes:
                        route.network_restricted = restricted
                except (AzureReadError, ValidationError, ValueError):
                    warn(warnings, instance, "APPGW_LOCKDOWN_UNAVAILABLE")
        except (AzureReadError, ValidationError, ValueError) as exc:
            result.status = "partial"
            warn(
                warnings,
                instance,
                "APPGW_" + (str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE"),
            )
    return result
