from __future__ import annotations

from typing import Literal

from pydantic import (
    AwareDatetime,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from apim_assess.models.policy import PolicyModel

CoverageStatus = Literal[
    "complete", "partial", "unavailable", "disabled", "not_applicable", "unsupported"
]
NetworkSource = Literal["any", "internet", "apim", "load_balancer", "virtual_network", "specific"]


class NsgRule(PolicyModel):
    priority: int = Field(ge=100, le=65535)
    access: Literal["Allow", "Deny"]
    protocol: Literal["Tcp", "Udp", "Icmp", "Esp", "Ah", "*"]
    sources: list[NetworkSource]
    ip_versions: list[Literal[4, 6]] = Field(default=[4, 6], min_length=1)
    source_ports_any: bool
    destination: Literal["subnet", "specific"]
    ports: list[tuple[int, int]]

    @model_validator(mode="after")
    def valid_ports(self) -> NsgRule:
        if not self.sources or not self.ports:
            raise ValueError("NSG rules require source and destination port coverage")
        if any(not 0 <= low <= high <= 65535 for low, high in self.ports):
            raise ValueError("Invalid NSG destination port range")
        return self


class SubnetEvidence(PolicyModel):
    reference: str
    status: CoverageStatus
    nsg_attached: bool | None = None
    rules: list[NsgRule] = Field(default_factory=list)
    ip_versions: list[Literal[4, 6]] = Field(default=[4, 6], min_length=1)


class EndpointEvidence(PolicyModel):
    reference: str
    status: CoverageStatus
    approved: bool | None = None
    subnet_linked: bool | None = None


class PublicIpEvidence(PolicyModel):
    reference: str
    status: CoverageStatus
    ddos_mode: Literal["Enabled", "Disabled", "VirtualNetworkInherited"] | None = None
    vnet_ddos_enabled: bool | None = None


class Networking(PolicyModel):
    status: CoverageStatus = "unavailable"
    subnets_status: CoverageStatus = "unavailable"
    subnets: list[SubnetEvidence] = Field(default_factory=list)
    private_endpoints: list[EndpointEvidence] = Field(default_factory=list)
    public_ips: list[PublicIpEvidence] = Field(default_factory=list)


class DiagnosticSetting(PolicyModel):
    reference: str
    gateway_logs: bool | None = None
    destination_configured: bool
    workspace: str | None = None


class ScaleProfile(PolicyModel):
    minimum: int = Field(ge=0)
    maximum: int = Field(ge=0)
    default: int = Field(ge=0)
    increase_rules: int = Field(ge=0)
    decrease_rules: int = Field(ge=0)

    @model_validator(mode="after")
    def valid_capacity(self) -> ScaleProfile:
        if not self.minimum <= self.default <= self.maximum:
            raise ValueError("Invalid autoscale capacity bounds")
        return self


class AutoscaleSetting(PolicyModel):
    reference: str
    enabled: bool
    profiles: list[ScaleProfile]


class PolicyState(PolicyModel):
    assignment: str
    definition: str
    definition_reference: str | None = None
    state: Literal["Compliant", "NonCompliant", "Exempt", "Conflict", "Error", "Unknown"]
    timestamp: AwareDatetime


class Governance(PolicyModel):
    diagnostics_status: CoverageStatus = "unavailable"
    diagnostics: list[DiagnosticSetting] = Field(default_factory=list)
    autoscale_status: CoverageStatus = "unavailable"
    autoscale: list[AutoscaleSetting] = Field(default_factory=list)
    defender_status: CoverageStatus = "unavailable"
    defender_plan: Literal["Free", "Standard"] | None = None
    defender_api_paths: list[str] = Field(default_factory=list)
    policy_status: CoverageStatus = "unavailable"
    policy_states: list[PolicyState] = Field(default_factory=list)


class LogAggregate(PolicyModel):
    requests: int = Field(ge=0)
    tls_known: int = Field(ge=0)
    weak_tls: int = Field(ge=0)
    response_known: int = Field(ge=0)
    gateway_5xx: int = Field(ge=0)
    backend_known: int = Field(ge=0)
    backend_5xx: int = Field(ge=0)
    latency_samples: int = Field(ge=0)
    backend_p95_ms: float | None = Field(default=None, ge=0)
    cache_hits: int = Field(ge=0)
    cache_misses: int = Field(ge=0)

    @model_validator(mode="after")
    def consistent_counts(self) -> LogAggregate:
        if (
            not self.weak_tls <= self.tls_known <= self.requests
            or not self.gateway_5xx <= self.response_known <= self.requests
            or not self.backend_5xx <= self.backend_known <= self.requests
            or self.latency_samples > self.requests
            or self.cache_hits + self.cache_misses > self.requests
            or (self.latency_samples > 0) != (self.backend_p95_ms is not None)
        ):
            raise ValueError("Inconsistent aggregate log coverage")
        return self


class LogHotspot(PolicyModel):
    api_reference: str
    api_path: str | None = None
    gateway_5xx: int = Field(ge=0)
    backend_5xx: int = Field(ge=0)


class LogLatency(PolicyModel):
    api_reference: str
    api_path: str | None = None
    samples: int = Field(gt=0)
    average_ms: float = Field(ge=0)
    maximum_ms: float = Field(ge=0)
    p95_ms: float = Field(ge=0)

    @model_validator(mode="after")
    def consistent_latency(self) -> LogLatency:
        if self.average_ms > self.maximum_ms or self.p95_ms > self.maximum_ms:
            raise ValueError("Inconsistent per-API latency aggregate")
        return self


class WorkspaceLogs(PolicyModel):
    workspace: str
    table: Literal["ApiManagementGatewayLogs", "AzureDiagnostics"]
    status: CoverageStatus = "unavailable"
    aggregate: LogAggregate | None = None
    hotspots: list[LogHotspot] = Field(default_factory=list)
    api_latency: list[LogLatency] | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        if self.api_latency is None:
            data.pop("api_latency", None)
        return data

    @model_validator(mode="after")
    def consistent_status(self) -> WorkspaceLogs:
        if (self.status == "complete") != (self.aggregate is not None):
            raise ValueError("Only complete log queries may contain aggregates")
        if self.aggregate is None and (self.hotspots or self.api_latency is not None):
            raise ValueError("Unavailable logs cannot contain per-API aggregates")
        return self


class LogAnalytics(PolicyModel):
    status: CoverageStatus = "unavailable"
    workspaces: list[WorkspaceLogs] = Field(default_factory=list)
