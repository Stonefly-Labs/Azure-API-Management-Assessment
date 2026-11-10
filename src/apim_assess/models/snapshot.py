from __future__ import annotations

import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

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
    module: Literal["discovery", "core", "metrics"]
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
    name: Literal["Capacity", "CpuPercent_Gateway", "MemoryPercent_Gateway", "Requests", "Duration"]
    location: str | None = None
    status: SignalStatus
    unit: str | None = None
    points: list[MetricPoint] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_status(self) -> MetricSeries:
        if self.status != "available" and self.points:
            raise ValueError("Unavailable or unsupported metrics cannot contain samples")
        return self


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


class Snapshot(Model):
    schema_version: Literal["1.0"] = "1.0"
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
