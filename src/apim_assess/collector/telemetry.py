from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.models.snapshot import (
    CollectionWarning,
    Instance,
    MetricPoint,
    MetricSeries,
    SignalStatus,
)

METRICS_API_VERSION = "2018-01-01"
CLASSIC = {"Developer", "Basic", "Standard", "Premium"}
V2 = {"BasicV2", "StandardV2", "PremiumV2"}
METRIC_NAMES = ("Capacity", "CpuPercent_Gateway", "MemoryPercent_Gateway", "Requests", "Duration")


class _Name(BaseModel):
    value: str


class _Dimension(BaseModel):
    name: _Name
    value: str


class _RawPoint(MetricPoint):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)


class _Series(BaseModel):
    metadatavalues: list[_Dimension] = Field(default_factory=list)
    data: list[_RawPoint]


class _Metric(BaseModel):
    name: _Name
    unit: str
    timeseries: list[_Series]
    errorCode: str | None = None


class _Response(BaseModel):
    value: list[_Metric]


def metric_status(name: str, sku: str | None) -> SignalStatus:
    if sku is None or sku not in CLASSIC | V2 | {"Consumption"}:
        return "unavailable"
    if name == "Capacity":
        return "available" if sku in CLASSIC else "unsupported"
    if name in {"CpuPercent_Gateway", "MemoryPercent_Gateway"}:
        return "available" if sku in V2 else "unsupported"
    return "available"


async def collect_metrics(
    reader: ArmReader,
    instance: Instance,
    start: datetime,
    end: datetime,
    warnings: list[CollectionWarning],
    *,
    enabled: bool,
) -> list[MetricSeries]:
    results: list[MetricSeries] = []
    for name in METRIC_NAMES:
        empty = MetricSeries.model_validate({"name": name, "status": "unavailable"})
        status = metric_status(name, instance.sku.name if instance.sku else None)
        if status == "unsupported":
            results.append(empty.model_copy(update={"status": "unsupported"}))
            continue
        if not enabled or status == "unavailable" or instance.core_status != "available":
            results.append(empty)
            continue
        aggregation = "Total" if name == "Requests" else "Average"
        if name in {"CpuPercent_Gateway", "MemoryPercent_Gateway", "Duration"}:
            aggregation += ",Maximum"
        # Classic Capacity maximum is not supported outside Premium and is not a scaling signal.
        params = {
            "api-version": METRICS_API_VERSION,
            "metricnames": name,
            "timespan": f"{start.isoformat()}/{end.isoformat()}",
            "interval": "PT1H",
            "aggregation": aggregation,
        }
        if name in {"Capacity", "Requests", "Duration"}:
            params["$filter"] = "Location eq '*'"
        path = quote(instance.resource_id, safe="/") + "/providers/Microsoft.Insights/metrics"
        try:
            response = _Response.model_validate(await reader.get(path, params))
            series_results: list[MetricSeries] = []
            for metric in response.value:
                if metric.name.value != name or metric.errorCode not in {None, "Success", ""}:
                    raise AzureReadError("METRIC_QUERY_FAILED")
                for series in metric.timeseries:
                    points = [
                        MetricPoint.model_validate(point.model_dump())
                        for point in series.data
                        if start <= point.timestamp < end
                        and any(
                            value is not None
                            for value in (point.average, point.maximum, point.total)
                        )
                    ]
                    if not points:
                        continue
                    if len({point.timestamp for point in points}) != len(points):
                        raise AzureReadError("DUPLICATE_METRIC_TIMESTAMPS")
                    location = next(
                        (
                            dim.value
                            for dim in series.metadatavalues
                            if dim.name.value.casefold() == "location"
                        ),
                        None,
                    )
                    series_results.append(
                        empty.model_copy(
                            update={
                                "status": "available",
                                "location": location,
                                "unit": metric.unit,
                                "points": points,
                            }
                        )
                    )
            if not series_results:
                raise AzureReadError("NO_METRIC_DATA")
            results.extend(series_results)
            expected = int((end - start).total_seconds() // 3600)
            if any(len(series.points) != expected for series in series_results):
                warnings.append(
                    CollectionWarning(
                        module="metrics",
                        resource_id=instance.resource_id,
                        code="PARTIAL_METRIC_DATA",
                        message=(
                            f"{name} has incomplete hourly coverage; missing samples are not zero."
                        ),
                    )
                )
        except (AzureReadError, ValidationError) as exc:
            results.append(empty)
            warnings.append(
                CollectionWarning(
                    module="metrics",
                    resource_id=instance.resource_id,
                    code=str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE",
                    message=f"{name} could not be collected; it is not a healthy zero.",
                )
            )
    if not enabled:
        warnings.append(
            CollectionWarning(
                module="metrics",
                resource_id=instance.resource_id,
                code="DISABLED",
                message="Metric collection was explicitly disabled.",
            )
        )
    elif instance.core_status == "available" and (
        instance.sku is None or instance.sku.name not in CLASSIC | V2 | {"Consumption"}
    ):
        warnings.append(
            CollectionWarning(
                module="metrics",
                resource_id=instance.resource_id,
                code="CAPABILITY_UNKNOWN",
                message="Metric capability could not be established from the collected SKU.",
            )
        )
    return results
