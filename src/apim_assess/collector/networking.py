from __future__ import annotations

from ipaddress import ip_network
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, Field, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError, linked_resource
from apim_assess.collector.sanitizer import reference_id
from apim_assess.models.adjacent import (
    EndpointEvidence,
    Networking,
    NetworkSource,
    NsgRule,
    PublicIpEvidence,
    SubnetEvidence,
)
from apim_assess.models.snapshot import CollectionWarning, Instance

NETWORK_VERSION = "2026-01-01"
NAME = r"[\w.() -]+"


class _Link(BaseModel):
    id: str


class _VnetConfig(BaseModel):
    subnetResourceId: str


class _ConnectionProps(BaseModel):
    privateEndpoint: _Link | None = None


class _Connection(BaseModel):
    properties: _ConnectionProps


class _Location(BaseModel):
    virtualNetworkConfiguration: _VnetConfig | None = None
    publicIpAddressId: str | None = None


class _Topology(_Location):
    additionalLocations: list[_Location] | None = None
    privateEndpointConnections: list[_Connection] | None = None


class _Service(BaseModel):
    properties: _Topology


class _RuleProps(BaseModel):
    priority: int
    access: Literal["Allow", "Deny"]
    direction: Literal["Inbound", "Outbound"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Esp", "Ah", "*"]
    sourceAddressPrefix: str | None = None
    sourceAddressPrefixes: list[str] | None = None
    sourcePortRange: str | None = None
    sourcePortRanges: list[str] | None = None
    destinationAddressPrefix: str | None = None
    destinationAddressPrefixes: list[str] | None = None
    destinationPortRange: str | None = None
    destinationPortRanges: list[str] | None = None


class _Rule(BaseModel):
    properties: _RuleProps


class _NsgProps(BaseModel):
    securityRules: list[_Rule]
    defaultSecurityRules: list[_Rule]


class _Nsg(BaseModel):
    properties: _NsgProps


class _SubnetProps(BaseModel):
    networkSecurityGroup: _Link | None = None
    addressPrefix: str | None = None
    addressPrefixes: list[str] = Field(default_factory=list)


class _Subnet(BaseModel):
    properties: _SubnetProps


class _EndpointState(BaseModel):
    status: Literal["Approved", "Pending", "Rejected", "Disconnected"]


class _EndpointConnection(BaseModel):
    properties: _EndpointConnectionProps


class _EndpointConnectionProps(BaseModel):
    privateLinkServiceId: str
    privateLinkServiceConnectionState: _EndpointState


class _EndpointProps(BaseModel):
    subnet: _Link
    privateLinkServiceConnections: list[_EndpointConnection]
    manualPrivateLinkServiceConnections: list[_EndpointConnection] = Field(default_factory=list)


class _Endpoint(BaseModel):
    properties: _EndpointProps


class _Ddos(BaseModel):
    protectionMode: Literal["Enabled", "Disabled", "VirtualNetworkInherited"]


class _PublicIpProps(BaseModel):
    ddosSettings: _Ddos | None = None


class _PublicIp(BaseModel):
    properties: _PublicIpProps


class _VnetProps(BaseModel):
    enableDdosProtection: bool | None = None


class _Vnet(BaseModel):
    properties: _VnetProps


def warning(warnings: list[CollectionWarning], identifier: str, code: str) -> None:
    warnings.append(
        CollectionWarning(
            module="networking",
            resource_id=identifier,
            code=code,
            message=(
                "Linked network metadata is incomplete; configuration is not reachability proof."
            ),
        )
    )


async def network_get(reader: ArmReader, identifier: str, kind: str) -> object:
    linked_resource(identifier, rf"Microsoft\.Network/{kind}")
    return await reader.get(quote(identifier, safe="/"), {"api-version": NETWORK_VERSION})


def sources(values: list[str]) -> list[NetworkSource]:
    result: set[NetworkSource] = set()
    tags: dict[str, NetworkSource] = {
        "*": "any",
        "internet": "internet",
        "apimanagement": "apim",
        "azureloadbalancer": "load_balancer",
        "virtualnetwork": "virtual_network",
    }
    for value in values:
        if value.casefold() in tags:
            result.add(tags[value.casefold()])
        else:
            try:
                result.add("any" if ip_network(value, strict=False).prefixlen == 0 else "specific")
            except ValueError:
                result.add("specific")
    if not result:
        raise AzureReadError("INCOMPLETE_NSG_RULE")
    return sorted(result)


def ip_versions(values: list[str]) -> list[Literal[4, 6]]:
    versions: set[Literal[4, 6]] = set()
    for value in values:
        try:
            versions.add(ip_network(value, strict=False).version)
        except ValueError:
            versions.update((4, 6))
    return sorted(versions)


def covers(prefix: str, destination: str) -> bool:
    inner, outer = ip_network(prefix, strict=False), ip_network(destination, strict=False)
    return (
        inner.version == outer.version
        and int(outer.network_address) <= int(inner.network_address)
        and int(outer.broadcast_address) >= int(inner.broadcast_address)
    )


def project_rule(raw: _RuleProps, prefixes: list[str]) -> NsgRule:
    destinations = raw.destinationAddressPrefixes or (
        [raw.destinationAddressPrefix] if raw.destinationAddressPrefix else []
    )
    port_values = raw.destinationPortRanges or (
        [raw.destinationPortRange] if raw.destinationPortRange else []
    )
    if not destinations:
        raise AzureReadError("INCOMPLETE_NSG_RULE")
    broad = any(value.casefold() in {"*", "virtualnetwork"} for value in destinations)
    if not broad and prefixes:
        try:
            broad = all(
                any(
                    covers(prefix, value)
                    for value in destinations
                    if ip_network(value, strict=False).version
                    == ip_network(prefix, strict=False).version
                )
                for prefix in prefixes
            )
        except ValueError:
            broad = False
    ports = []
    for value in port_values:
        if value == "*":
            ports.append((0, 65535))
        else:
            parts = value.split("-")
            if not 1 <= len(parts) <= 2 or not all(part.isdigit() for part in parts):
                raise AzureReadError("INVALID_NSG_PORT")
            ports.append((int(parts[0]), int(parts[-1])))
    source_values = raw.sourceAddressPrefixes or (
        [raw.sourceAddressPrefix] if raw.sourceAddressPrefix else []
    )
    return NsgRule(
        priority=raw.priority,
        access=raw.access,
        protocol=raw.protocol,
        sources=sources(source_values),
        ip_versions=ip_versions(source_values),
        source_ports_any=raw.sourcePortRange == "*" or "*" in (raw.sourcePortRanges or []),
        destination="subnet" if broad else "specific",
        ports=ports,
    )


async def collect_networking(
    reader: ArmReader,
    instance: Instance,
    body: object,
    warnings: list[CollectionWarning],
    *,
    enabled: bool,
) -> Networking:
    result = Networking(status="complete", subnets_status="complete")
    if not enabled:
        warning(warnings, instance.resource_id, "DISABLED")
        return Networking(status="disabled", subnets_status="disabled")
    try:
        topology = _Service.model_validate(body).properties
    except ValidationError:
        warning(warnings, instance.resource_id, "INVALID_TOPOLOGY")
        return Networking()
    locations = [topology, *(topology.additionalLocations or [])]
    injected = instance.sku is not None and (
        instance.sku.name in {"Developer", "Premium"}
        and instance.virtual_network_type in {"Internal", "External"}
        or instance.sku.name == "PremiumV2"
        and instance.virtual_network_type == "Internal"
    )
    if injected and any(location.virtualNetworkConfiguration is None for location in locations):
        result.status = "partial"
        result.subnets_status = "partial"
        warning(warnings, instance.resource_id, "INCOMPLETE_SUBNET_LINKAGE")
    subnet_ids = sorted(
        {
            location.virtualNetworkConfiguration.subnetResourceId
            for location in locations
            if location.virtualNetworkConfiguration
        }
    )
    vnet_ddos: dict[str, bool | None] = {}
    for identifier in subnet_ids:
        subnet = SubnetEvidence(reference=reference_id(identifier.casefold()), status="unavailable")
        result.subnets.append(subnet)
        try:
            props = _Subnet.model_validate(
                await network_get(reader, identifier, rf"virtualNetworks/{NAME}/subnets/{NAME}")
            ).properties
            if "networkSecurityGroup" not in props.model_fields_set:
                raise AzureReadError("NSG_ASSOCIATION_UNAVAILABLE")
            subnet.nsg_attached = props.networkSecurityGroup is not None
            prefixes = props.addressPrefixes or (
                [props.addressPrefix] if props.addressPrefix else []
            )
            if not prefixes:
                raise AzureReadError("SUBNET_PREFIX_UNAVAILABLE")
            try:
                subnet.ip_versions = sorted(
                    {ip_network(prefix, strict=False).version for prefix in prefixes}
                )
            except ValueError as exc:
                raise AzureReadError("INVALID_SUBNET_PREFIX") from exc
            if props.networkSecurityGroup:
                nsg = _Nsg.model_validate(
                    await network_get(
                        reader,
                        props.networkSecurityGroup.id,
                        rf"networkSecurityGroups/{NAME}",
                    )
                )
                subnet.rules = sorted(
                    [
                        project_rule(
                            rule.properties,
                            props.addressPrefixes
                            or ([props.addressPrefix] if props.addressPrefix else []),
                        )
                        for rule in [
                            *nsg.properties.securityRules,
                            *nsg.properties.defaultSecurityRules,
                        ]
                        if rule.properties.direction == "Inbound"
                    ],
                    key=lambda rule: rule.priority,
                )
                if len({rule.priority for rule in subnet.rules}) != len(subnet.rules):
                    raise AzureReadError("DUPLICATE_NSG_PRIORITY")
            subnet.status = "complete"
        except (AzureReadError, ValidationError) as exc:
            result.status = "partial"
            result.subnets_status = "partial"
            warning(
                warnings,
                instance.resource_id,
                str(exc) if isinstance(exc, AzureReadError) else "INVALID_NETWORK_RESPONSE",
            )
    endpoint_ids = {
        connection.properties.privateEndpoint.id
        for connection in topology.privateEndpointConnections or []
        if connection.properties.privateEndpoint
    }
    if any(
        not item.properties.privateEndpoint for item in topology.privateEndpointConnections or []
    ):
        result.status = "partial"
        warning(warnings, instance.resource_id, "INCOMPLETE_PRIVATE_ENDPOINT_LINKAGE")
    for identifier in sorted(endpoint_ids):
        endpoint = EndpointEvidence(
            reference=reference_id(identifier.casefold()), status="unavailable"
        )
        result.private_endpoints.append(endpoint)
        try:
            props_ep = _Endpoint.model_validate(
                await network_get(
                    reader,
                    identifier,
                    rf"privateEndpoints/{NAME}",
                )
            ).properties
            linked_resource(
                props_ep.subnet.id, rf"Microsoft\.Network/virtualNetworks/{NAME}/subnets/{NAME}"
            )
            connections = [
                item.properties
                for item in (
                    props_ep.privateLinkServiceConnections
                    + props_ep.manualPrivateLinkServiceConnections
                )
                if item.properties.privateLinkServiceId.casefold()
                == instance.resource_id.casefold()
            ]
            if not connections:
                raise AzureReadError("PRIVATE_ENDPOINT_TARGET_MISMATCH")
            endpoint.approved = any(
                item.privateLinkServiceConnectionState.status == "Approved" for item in connections
            )
            endpoint.subnet_linked = True
            endpoint.status = "complete"
        except (AzureReadError, ValidationError) as exc:
            result.status = "partial"
            warning(
                warnings,
                instance.resource_id,
                str(exc) if isinstance(exc, AzureReadError) else "INVALID_NETWORK_RESPONSE",
            )
    for identifier in sorted(
        {item.publicIpAddressId for item in locations if item.publicIpAddressId}
    ):
        public_ip = PublicIpEvidence(
            reference=reference_id(identifier.casefold()), status="unavailable"
        )
        result.public_ips.append(public_ip)
        try:
            props_ip = _PublicIp.model_validate(
                await network_get(
                    reader,
                    identifier,
                    rf"publicIPAddresses/{NAME}",
                )
            ).properties
            public_ip.ddos_mode = (
                props_ip.ddosSettings.protectionMode if props_ip.ddosSettings else None
            )
            if public_ip.ddos_mode == "VirtualNetworkInherited":
                vnet_ids = {
                    location.virtualNetworkConfiguration.subnetResourceId.rsplit("/", 2)[0]
                    for location in locations
                    if location.publicIpAddressId
                    and location.publicIpAddressId.casefold() == identifier.casefold()
                    and location.virtualNetworkConfiguration
                }
                for vnet_id in sorted(vnet_ids):
                    if vnet_id not in vnet_ddos:
                        props_vnet = _Vnet.model_validate(
                            await network_get(
                                reader,
                                vnet_id,
                                rf"virtualNetworks/{NAME}",
                            )
                        ).properties
                        vnet_ddos[vnet_id] = props_vnet.enableDdosProtection
                values = [vnet_ddos[value] for value in sorted(vnet_ids)]
                public_ip.vnet_ddos_enabled = (
                    all(value is True for value in values)
                    if values and all(value is not None for value in values)
                    else None
                )
            public_ip.status = "complete"
            if public_ip.ddos_mode is None or (
                public_ip.ddos_mode == "VirtualNetworkInherited"
                and public_ip.vnet_ddos_enabled is None
            ):
                result.status = "partial"
                warning(warnings, instance.resource_id, "DDOS_METADATA_UNAVAILABLE")
        except (AzureReadError, ValidationError) as exc:
            result.status = "partial"
            warning(
                warnings,
                instance.resource_id,
                str(exc) if isinstance(exc, AzureReadError) else "INVALID_NETWORK_RESPONSE",
            )
    return result
