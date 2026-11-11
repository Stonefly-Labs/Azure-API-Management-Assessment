from __future__ import annotations

from ipaddress import ip_address, ip_network
from urllib.parse import quote, urlsplit

from pydantic import TypeAdapter

from apim_assess.collector.client import ArmReader, AzureReadError, linked_resource
from apim_assess.collector.networking import NETWORK_VERSION
from apim_assess.collector.sanitizer import reference_id
from apim_assess.config import UpstreamModule
from apim_assess.models.snapshot import CollectionWarning, Instance
from apim_assess.models.upstream import WafConfiguration

NAME = r"[\w.() -]+"


def obj(value: object) -> dict[str, object]:
    return TypeAdapter(dict[str, object]).validate_python(value)


def objects(value: object) -> list[dict[str, object]]:
    return TypeAdapter(list[dict[str, object]]).validate_python(value)


def text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AzureReadError("INCOMPLETE_UPSTREAM_METADATA")
    return value


def link(value: object) -> str:
    return text(obj(value).get("id"))


def host(value: str) -> str:
    try:
        return str(ip_address(value.strip("[]")))
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.username or parsed.password or not parsed.hostname:
        raise AzureReadError("INVALID_UPSTREAM_HOST")
    try:
        return str(ip_address(parsed.hostname))
    except ValueError:
        return parsed.hostname.casefold().rstrip(".")


def aliases(body: object) -> set[str]:
    props = obj(obj(body).get("properties"))
    values = {host(text(props.get("gatewayUrl")))}
    for location in [props, *objects(props.get("additionalLocations") or [])]:
        if location.get("gatewayRegionalUrl"):
            values.add(host(text(location["gatewayRegionalUrl"])))
        for field in ("publicIPAddresses", "privateIPAddresses"):
            for value in TypeAdapter(list[str]).validate_python(location.get(field) or []):
                values.add(host(value))
    for item in objects(props.get("hostnameConfigurations", [])):
        if item.get("type") == "Proxy":
            values.add(host(text(item.get("hostName"))))
    return values


def warn(warnings: list[CollectionWarning], instance: Instance, code: str) -> None:
    warnings.append(
        CollectionWarning(
            module="upstream",
            resource_id=instance.resource_id,
            code=code,
            message="Upstream coverage is limited; routing/lockdown is not runtime proof.",
        )
    )


async def get(reader: ArmReader, identifier: str, kind: str, version: str) -> dict[str, object]:
    linked_resource(identifier, kind)
    body = obj(await reader.get(quote(identifier, safe="/"), {"api-version": version}))
    if text(body.get("id")).casefold() != identifier.casefold():
        raise AzureReadError("RESOURCE_ID_MISMATCH")
    return body


async def listing(reader: ArmReader, path: str, version: str) -> list[dict[str, object]]:
    rows = []
    seen: set[str] = set()
    async for raw in reader.pages(quote(path, safe="/"), version):
        body = obj(raw)
        identifier = text(body.get("id"))
        prefix = path.casefold() + "/"
        if (
            not identifier.casefold().startswith(prefix)
            or "/" in identifier[len(prefix) :]
            or identifier.casefold() in seen
        ):
            raise AzureReadError("OUT_OF_SCOPE_UPSTREAM_RESPONSE")
        seen.add(identifier.casefold())
        rows.append(body)
    return rows


async def candidates(
    reader: ArmReader, module: UpstreamModule, subscriptions: list[str], resource_type: str
) -> list[str]:
    result = {value.casefold(): value for value in module.resource_ids}
    if module.auto_discover:
        async for identifier in reader.graph_resources(subscriptions, resource_type):
            result[identifier.casefold()] = identifier
    return sorted(result.values(), key=str.casefold)


def waf_configuration(body: dict[str, object], *, afd: bool) -> WafConfiguration:
    props = obj(body.get("properties"))
    settings = obj(props.get("policySettings"))
    managed = obj(props.get("managedRules", {}))
    sets = objects(managed.get("managedRuleSets", managed.get("ruleSets", [])))
    protection = [
        item
        for item in sets
        if str(item.get("ruleSetType", "")).casefold()
        in {"default.ruleset", "microsoft_defaultruleset", "owasp", "defaultruleset"}
    ]
    custom_container = props.get("customRules", {})
    custom = (
        objects(custom_container)
        if isinstance(custom_container, list)
        else objects(obj(custom_container).get("rules", []))
    )
    enabled_custom = [
        item
        for item in custom
        if item.get("enabledState", item.get("state", "Enabled")) == "Enabled"
    ]
    uncertain = (
        bool(managed.get("exclusions"))
        or any(item.get("ruleGroupOverrides") or item.get("exclusions") for item in protection)
        or any(item.get("action") in {"Allow", "Log"} for item in enabled_custom)
    )
    mode = settings.get("mode")
    enabled = settings.get("enabledState") if afd else settings.get("state")
    return WafConfiguration(
        enabled=True if enabled == "Enabled" else False if enabled == "Disabled" else None,
        prevention=True if mode == "Prevention" else False if mode == "Detection" else None,
        managed_rules=(
            None
            if uncertain or "managedRules" not in props
            else any(
                item.get("ruleSetVersion") and item.get("ruleSetAction", "Block") == "Block"
                for item in protection
            )
        ),
        bot_protection=any("bot" in str(item.get("ruleSetType", "")).casefold() for item in sets),
        rate_limiting=any(item.get("ruleType") == "RateLimitRule" for item in enabled_custom),
    )


def reference(identifier: str) -> str:
    return reference_id(identifier.casefold())


def _ports(value: object) -> bool:
    values = value if isinstance(value, list) else [value]
    return all(isinstance(item, str) and item in {"*", "0-65535"} for item in values)


def restricted_rules(
    rules: list[dict[str, object]], allowed: set[str], *, afd: bool
) -> bool | None:
    properties = [obj(rule.get("properties")) for rule in rules]
    if any(rule.get("direction") not in {"Inbound", "Outbound"} for rule in properties):
        return None
    inbound = [rule for rule in properties if rule["direction"] == "Inbound"]
    priorities = [rule.get("priority") for rule in inbound]
    if any(type(priority) is not int for priority in priorities):
        return None
    inbound.sort(key=lambda rule: int(str(rule["priority"])))
    numbers = [int(str(priority)) for priority in priorities]
    if len(set(numbers)) != len(numbers) or any(
        not 100 <= priority <= 65535 for priority in numbers
    ):
        return None
    allowed_443 = False
    closed: set[int] = set()
    for rule in inbound:
        if rule.get("direction") not in {"Inbound", "Outbound"} or rule.get("protocol") not in {
            "Tcp",
            "Udp",
            "Icmp",
            "Esp",
            "Ah",
            "*",
        }:
            return None
        if rule.get("direction") != "Inbound" or rule.get("protocol") not in {"Tcp", "*"}:
            continue
        ports = rule.get("destinationPortRanges") or [rule.get("destinationPortRange")]
        port_strings = TypeAdapter(list[str]).validate_python(ports)
        for value in port_strings:
            if value == "*":
                continue
            bounds = value.split("-")
            if (
                len(bounds) not in {1, 2}
                or not all(bound.isdigit() for bound in bounds)
                or not 0 <= int(bounds[0]) <= int(bounds[-1]) <= 65535
            ):
                return None
        relevant = {
            port
            for port in (80, 443)
            if port not in closed
            and any(
                value == "*"
                or value.isdigit()
                and int(value) == port
                or "-" in value
                and all(part.isdigit() for part in value.split("-"))
                and len(value.split("-")) == 2
                and int(value.split("-")[0]) <= port <= int(value.split("-")[1])
                for value in port_strings
            )
        }
        if not relevant:
            continue
        destinations = rule.get("destinationAddressPrefixes") or [
            rule.get("destinationAddressPrefix")
        ]
        if destinations != ["*"]:
            return None
        if not _ports(rule.get("sourcePortRanges") or rule.get("sourcePortRange")):
            return None
        sources = TypeAdapter(list[str]).validate_python(
            rule.get("sourceAddressPrefixes") or [rule.get("sourceAddressPrefix")]
        )
        source_set = {value.casefold() for value in sources}
        if rule.get("access") == "Deny":
            if source_set == {"*"}:
                closed.update(relevant)
            else:
                return None
        elif rule.get("access") == "Allow":
            if source_set == {"azurefrontdoor.backend"} and afd:
                allowed_443 |= 443 in relevant
            elif not afd and source_set and source_set <= allowed:
                allowed_443 |= 443 in relevant
            elif source_set <= {"virtualnetwork", "azureloadbalancer"}:
                # Private traffic remains outside this public-origin lockdown check.
                continue
            elif (
                "*" in source_set or "internet" in source_set or source_set & {"0.0.0.0/0", "::/0"}
            ):
                return False
            else:
                return None
        else:
            return None
    return True if closed == {80, 443} and allowed_443 else None


async def network_restriction(
    reader: ArmReader, instance: Instance, body: object, *, afd: bool, allowed: set[str]
) -> bool | None:
    if instance.virtual_network_type not in {"Internal", "External"}:
        return None
    props = obj(obj(body).get("properties"))
    if "additionalLocations" not in props:
        return None
    locations = [props, *objects(props.get("additionalLocations") or [])]
    results: list[bool | None] = []
    for location in locations:
        configuration = location.get("virtualNetworkConfiguration")
        if configuration is None:
            return None
        identifier = text(obj(configuration).get("subnetResourceId"))
        subnet = await get(
            reader,
            identifier,
            rf"Microsoft\.Network/virtualNetworks/{NAME}/subnets/{NAME}",
            NETWORK_VERSION,
        )
        subnet_props = obj(subnet.get("properties"))
        if "networkSecurityGroup" not in subnet_props:
            return None
        if subnet_props["networkSecurityGroup"] is None:
            return False
        nsg = await get(
            reader,
            link(subnet_props["networkSecurityGroup"]),
            rf"Microsoft\.Network/networkSecurityGroups/{NAME}",
            NETWORK_VERSION,
        )
        nsg_props = obj(nsg.get("properties"))
        results.append(
            restricted_rules(
                objects(nsg_props.get("securityRules"))
                + objects(nsg_props.get("defaultSecurityRules")),
                allowed,
                afd=afd,
            )
        )
    return False if False in results else True if results and all(results) else None


async def gateway_prefixes(reader: ArmReader, props: dict[str, object]) -> set[str]:
    result: set[str] = set()
    for configuration in objects(props.get("gatewayIPConfigurations")):
        identifier = link(obj(configuration.get("properties")).get("subnet"))
        body = await get(
            reader,
            identifier,
            rf"Microsoft\.Network/virtualNetworks/{NAME}/subnets/{NAME}",
            NETWORK_VERSION,
        )
        subnet = obj(body.get("properties"))
        prefixes = TypeAdapter(list[str]).validate_python(
            subnet.get("addressPrefixes") or [subnet.get("addressPrefix")]
        )
        result.update(str(ip_network(prefix, strict=False)).casefold() for prefix in prefixes)
    return result
