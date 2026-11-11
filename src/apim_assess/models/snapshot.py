from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from apim_assess.models.adjacent import Governance, LogAnalytics, Networking
from apim_assess.models.policy import CATALOG_METADATA_FIELDS, MODERN_METADATA_FIELDS, Inventory
from apim_assess.models.upstream import Upstream

Environment = Literal["prod", "non-prod"]
Profile = Literal["auto", "prod", "non-prod"]
SignalStatus = Literal["available", "unavailable", "unsupported"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


def subscription_id(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", value):
        raise ValueError("Expected a subscription UUID")
    return str(UUID(value))


def resource_group(value: str) -> str:
    if not re.fullmatch(r"[\w.() -]{1,90}", value) or value.endswith("."):
        raise ValueError("Expected a valid Azure resource group name")
    return value


def resource_id(value: str) -> str:
    match = re.fullmatch(
        r"/subscriptions/([^/]+)/resourceGroups/([\w.() -]+)/providers/"
        r"Microsoft\.ApiManagement/service/([a-zA-Z0-9-]+)",
        value,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError("Expected a full Microsoft.ApiManagement/service resource ID")
    sub, group, name = match.groups()
    resource_group(group)
    return (
        f"/subscriptions/{subscription_id(sub)}/resourceGroups/{group}"
        f"/providers/Microsoft.ApiManagement/service/{name}"
    )


ResourceId = Annotated[str, AfterValidator(resource_id)]
SubscriptionId = Annotated[str, AfterValidator(subscription_id)]
ResourceGroup = Annotated[str, AfterValidator(resource_group)]
Percent = Annotated[float, Field(ge=0)]


class CollectionWarning(Model):
    module: Literal[
        "discovery",
        "core",
        "metrics",
        "subresources",
        "policies",
        "networking",
        "governance",
        "log_analytics",
        "upstream",
    ]
    resource_id: str
    code: str
    message: str


class Sku(Model):
    name: str
    capacity: int | None = Field(default=None, ge=0)


class Region(Model):
    location: str | None = None
    zones: list[str] | None = None
    capacity: int | None = Field(default=None, ge=0)


class MetricPoint(Model):
    timestamp: AwareDatetime = Field(validation_alias=AliasChoices("timestamp", "timeStamp"))
    average: Percent | None = None
    maximum: Percent | None = None
    total: Percent | None = None


class MetricSeries(Model):
    name: Literal[
        "Capacity",
        "CpuPercent_Gateway",
        "MemoryPercent_Gateway",
        "Requests",
        "Duration",
        "BackendDuration",
    ]
    location: str | None = None
    dimensions: dict[Literal["Location", "GatewayResponseCodeCategory", "ApiId"], str] = Field(
        default_factory=dict
    )
    status: SignalStatus
    unit: str | None = None
    points: list[MetricPoint] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        data: dict[str, object] = handler(self)
        # Omit absent additions so historical snapshot digests remain replayable.
        if not self.dimensions:
            data.pop("dimensions", None)
        return data

    @model_validator(mode="after")
    def consistent_status(self) -> MetricSeries:
        if self.status != "available" and self.points:
            raise ValueError("Unavailable or unsupported metrics cannot contain samples")
        return self


class HostCertificate(Model):
    endpoint: Literal["Proxy", "Portal", "Management", "Scm", "DeveloperPortal"]
    source: Literal["KeyVault", "Custom", "Managed", "BuiltIn"] | None = None
    expires_at: AwareDatetime | None = None


class ServiceSettings(Model):
    minimum_api_version: date | None = None
    certificates: list[HostCertificate] | None = None
    portal_enabled: bool | None = None
    portal_signin_required: bool | None = None
    portal_signup_enabled: bool | None = None
    portal_entra_enabled: bool | None = None
    management_api_enabled: bool | None = None


class Instance(Model):
    resource_id: ResourceId
    name: str
    environment: Environment
    environment_source: str
    core_status: Literal["available", "unavailable"] = "unavailable"
    location: str | None = None
    sku: Sku | None = None
    zones: list[str] | None = None
    additional_locations: list[Region] | None = None
    virtual_network_type: Literal["None", "Internal", "External"] | None = None
    public_network_access: Literal["Enabled", "Disabled"] | None = None
    private_endpoint_statuses: list[str] | None = None
    identity_type: str | None = None
    custom_properties: dict[str, bool] = Field(default_factory=dict)
    metrics: list[MetricSeries] = Field(default_factory=list)
    inventory: Inventory | None = None
    service_settings: ServiceSettings | None = None
    networking: Networking | None = None
    governance: Governance | None = None
    log_analytics: LogAnalytics | None = None
    upstream: Upstream | None = None


class Snapshot(Model):
    schema_version: Literal["1.0", "1.1", "1.2", "1.3", "1.4"] = "1.4"
    collected_at: AwareDatetime
    telemetry_start: AwareDatetime
    telemetry_end: AwareDatetime
    instances: list[Instance]
    collection_warnings: list[CollectionWarning] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_scope(self) -> Snapshot:
        if self.telemetry_start >= self.telemetry_end or self.telemetry_end > self.collected_at:
            raise ValueError("Invalid collection time window")
        ids = [instance.resource_id.casefold() for instance in self.instances]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate APIM resource IDs")
        for instance in self.instances:
            if self.schema_version != "1.4" and (
                instance.upstream is not None
                or instance.inventory is not None
                and any(
                    getattr(item.metadata, field) is not None
                    for item in instance.inventory.resources
                    for field in MODERN_METADATA_FIELDS
                )
            ):
                raise ValueError(
                    "Upstream and modern workload metadata require snapshot schema 1.4"
                )
            if self.schema_version not in {"1.3", "1.4"} and any(
                value is not None
                for value in (instance.networking, instance.governance, instance.log_analytics)
            ):
                raise ValueError("Adjacent signals require snapshot schema 1.3")
            if self.schema_version in {"1.0", "1.1"} and (
                instance.service_settings is not None
                or instance.inventory is not None
                and any(
                    item.kind == "logger"
                    or any(
                        getattr(item.metadata, field) is not None
                        for field in CATALOG_METADATA_FIELDS
                    )
                    for item in instance.inventory.resources
                )
            ):
                raise ValueError("Catalog metadata requires snapshot schema 1.2")
            if self.schema_version == "1.0" and instance.inventory is not None:
                raise ValueError("Sub-resource inventory requires snapshot schema 1.1")
            if instance.inventory is not None:
                identifiers = [item.resource_id.casefold() for item in instance.inventory.resources]
                if len(identifiers) != len(set(identifiers)):
                    raise ValueError("Duplicate sub-resource IDs")
                prefix = instance.resource_id.casefold() + "/"
                if any(not identifier.startswith(prefix) for identifier in identifiers):
                    raise ValueError("Sub-resource is outside the APIM instance")
            for series in instance.metrics:
                timestamps = [point.timestamp for point in series.points]
                if len(timestamps) != len(set(timestamps)):
                    raise ValueError("Duplicate metric timestamps")
                if any(
                    not self.telemetry_start <= timestamp < self.telemetry_end
                    for timestamp in timestamps
                ):
                    raise ValueError("Metric timestamps must be inside the collection window")
        return self
