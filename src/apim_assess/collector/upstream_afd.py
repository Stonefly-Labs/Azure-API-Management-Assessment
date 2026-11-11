from __future__ import annotations

from pydantic import TypeAdapter, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.collector.upstream import (
    NAME,
    aliases,
    candidates,
    get,
    host,
    link,
    listing,
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

AFD_VERSION = "2025-04-15"
WAF_VERSION = "2022-05-01"


async def collect_afd(
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
        warn(warnings, instance, "AFD_INVALID_MATCH_METADATA")
        return UpstreamProbe()
    identifiers = module.resource_ids
    try:
        identifiers = await candidates(reader, module, subscriptions, "microsoft.cdn/profiles")
    except AzureReadError as exc:
        result.status = "partial"
        warn(warnings, instance, "AFD_DISCOVERY_" + str(exc))
    for identifier in sorted(set(identifiers), key=str.casefold):
        result.candidates += 1
        try:
            profile = await get(reader, identifier, rf"Microsoft\.Cdn/profiles/{NAME}", AFD_VERSION)
            if obj(profile.get("sku")).get("name") not in {
                "Standard_AzureFrontDoor",
                "Premium_AzureFrontDoor",
            }:
                raise AzureReadError("UNSUPPORTED_SKU")
            profile_props = obj(profile.get("properties"))
            front_door_id = profile_props.get("frontDoorId")
            fingerprint = reference(text(front_door_id)) if front_door_id else None
            groups = {
                text(group.get("id")).casefold(): group
                for group in await listing(reader, identifier + "/originGroups", AFD_VERSION)
            }
            matched_groups: dict[str, bool] = {}
            for group_id, group in groups.items():
                origins = await listing(reader, text(group.get("id")) + "/origins", AFD_VERSION)
                group_matches = False
                for origin in origins:
                    props = obj(origin.get("properties"))
                    if props.get("enabledState") == "Disabled":
                        continue
                    if props.get("enabledState") != "Enabled":
                        raise AzureReadError("INCOMPLETE_ORIGIN_STATE")
                    group_matches |= host(text(props.get("hostName"))) in matches
                matched_groups[group_id] = group_matches
            policies = await listing(reader, identifier + "/securityPolicies", AFD_VERSION)
            waf_cache: dict[str, WafConfiguration] = {}
            endpoint_rows = await listing(reader, identifier + "/afdEndpoints", AFD_VERSION)
            profile_routes: list[UpstreamRoute] = []
            for endpoint in endpoint_rows:
                endpoint_id = text(endpoint.get("id"))
                endpoint_props = obj(endpoint.get("properties"))
                if endpoint_props.get("enabledState") == "Disabled":
                    continue
                if endpoint_props.get("enabledState") != "Enabled":
                    raise AzureReadError("INCOMPLETE_ENDPOINT_STATE")
                for route in await listing(reader, endpoint_id + "/routes", AFD_VERSION):
                    props = obj(route.get("properties"))
                    if props.get("enabledState") == "Disabled":
                        continue
                    if props.get("enabledState") != "Enabled":
                        raise AzureReadError("INCOMPLETE_ROUTE_STATE")
                    if props.get("ruleSets"):
                        result.status = "partial"
                        warn(warnings, instance, "AFD_RULESET_ROUTING_NOT_RESOLVED")
                    group_id = link(props.get("originGroup")).casefold()
                    if group_id not in matched_groups:
                        raise AzureReadError("UNRESOLVED_ORIGIN_GROUP")
                    if not matched_groups[group_id]:
                        continue
                    domains = [
                        link(domain).casefold()
                        for domain in objects(props.get("customDomains") or [])
                    ]
                    default = props.get("linkToDefaultDomain")
                    if default == "Enabled":
                        domains.append(endpoint_id.casefold())
                    elif default != "Disabled":
                        raise AzureReadError("INCOMPLETE_ROUTE_DOMAINS")
                    if not domains:
                        raise AzureReadError("NO_ROUTE_DOMAINS")
                    for domain in sorted(set(domains)):
                        attached: set[str] = set()
                        partial_association = False
                        for policy in policies:
                            parameters = obj(obj(policy.get("properties")).get("parameters"))
                            if parameters.get("type") != "WebApplicationFirewall":
                                continue
                            for association in objects(parameters.get("associations")):
                                associations = {
                                    link(item).casefold()
                                    for item in objects(association.get("domains"))
                                }
                                patterns = TypeAdapter(list[str]).validate_python(
                                    association.get("patternsToMatch", [])
                                )
                                if domain in associations and "/*" in patterns:
                                    attached.add(link(parameters.get("wafPolicy")))
                                elif domain in associations:
                                    partial_association = True
                        configuration: WafConfiguration | None = WafConfiguration(enabled=False)
                        if len(attached) > 1 or partial_association:
                            configuration = None
                        elif attached:
                            waf_id = next(iter(attached))
                            if waf_id.casefold() not in waf_cache:
                                waf = await get(
                                    reader,
                                    waf_id,
                                    rf"Microsoft\.Network/frontDoorWebApplicationFirewallPolicies/{NAME}",
                                    WAF_VERSION,
                                )
                                waf_cache[waf_id.casefold()] = waf_configuration(waf, afd=True)
                            configuration = waf_cache[waf_id.casefold()]
                        probe = obj(
                            obj(groups[group_id].get("properties")).get("healthProbeSettings", {})
                        )
                        profile_routes.append(
                            UpstreamRoute(
                                reference=reference(text(route.get("id")) + "|" + domain),
                                provider="afd",
                                waf=configuration,
                                https_only=(
                                    props.get("forwardingProtocol") == "HttpsOnly"
                                    if "forwardingProtocol" in props
                                    else None
                                ),
                                health_probe=(
                                    probe.get("protocol") == "Https"
                                    and probe.get("requestType") in {"GET", "HEAD"}
                                    and isinstance(probe.get("path"), str)
                                    and str(probe["path"]).startswith("/")
                                ),
                                front_door_id=fingerprint,
                            )
                        )
            result.routes.extend(profile_routes)
            if profile_routes:
                try:
                    restricted = await network_restriction(
                        reader, instance, body, afd=True, allowed=set()
                    )
                    for observation in profile_routes:
                        observation.network_restricted = restricted
                except (AzureReadError, ValidationError, ValueError):
                    warn(warnings, instance, "AFD_LOCKDOWN_UNAVAILABLE")
        except (AzureReadError, ValidationError, ValueError) as exc:
            result.status = "partial"
            warn(
                warnings,
                instance,
                "AFD_" + (str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE"),
            )
    return result
