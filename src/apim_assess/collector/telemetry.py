from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError, linked_resource
from apim_assess.collector.governance import WORKSPACE_TYPE, LogLink
from apim_assess.collector.sanitizer import reference_id
from apim_assess.config import Telemetry
from apim_assess.models.adjacent import (
    LogAggregate,
    LogAnalytics,
    LogHotspot,
    LogLatency,
    WorkspaceLogs,
)
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
TOP_APIS = 5
Dimension = Literal["Location", "GatewayResponseCodeCategory", "ApiId"]


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


def dimensions_for(series: _Series, dimension: Dimension | None) -> dict[Dimension, str]:
    if dimension is None:
        if series.metadatavalues:
            raise AzureReadError("UNEXPECTED_METRIC_DIMENSIONS")
        return {}
    if (
        len(series.metadatavalues) != 1
        or series.metadatavalues[0].name.value.casefold() != dimension.casefold()
    ):
        raise AzureReadError("MISSING_METRIC_DIMENSION")
    value = series.metadatavalues[0].value
    if dimension == "ApiId":
        value = reference_id(value.casefold())
    elif dimension == "Location":
        if not re.fullmatch(r"[a-zA-Z0-9 -]{1,80}", value):
            raise AzureReadError("INVALID_METRIC_LOCATION")
    else:
        value = value.casefold()
        if value not in {"1xx", "2xx", "3xx", "4xx", "5xx", "other", "unknown"}:
            raise AzureReadError("INVALID_METRIC_CATEGORY")
    return {dimension: value}


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
    queries: list[tuple[str, Dimension | None]] = [
        (name, "Location" if name in {"Capacity", "Requests", "Duration"} else None)
        for name in METRIC_NAMES
    ] + [
        ("Requests", "GatewayResponseCodeCategory"),
        ("Requests", "ApiId"),
        ("BackendDuration", "ApiId"),
    ]
    sku = instance.sku.name if instance.sku else None
    for name, dimension in queries:
        empty = MetricSeries.model_validate(
            {
                "name": name,
                "status": "unavailable",
                "dimensions": {dimension: "*"} if dimension else {},
            }
        )
        status = metric_status(name, sku)
        if status == "unsupported":
            results.append(empty.model_copy(update={"status": "unsupported"}))
            continue
        if not enabled or status == "unavailable" or instance.core_status != "available":
            results.append(empty)
            continue
        aggregation = "Total" if name == "Requests" else "Average"
        if name in {
            "CpuPercent_Gateway",
            "MemoryPercent_Gateway",
            "Duration",
            "BackendDuration",
        } or (name == "Capacity" and sku == "Premium"):
            aggregation += ",Maximum"
        # Monitor's query decoding can turn numeric UTC offsets into invalid intervals.
        timespan = "/".join(
            instant.astimezone(UTC).isoformat().replace("+00:00", "Z") for instant in (start, end)
        )
        params = {
            "api-version": METRICS_API_VERSION,
            "metricnames": name,
            "timespan": timespan,
            "interval": "PT1H",
            "aggregation": aggregation,
        }
        if dimension:
            params["$filter"] = f"{dimension} eq '*'"
            params["top"] = str(TOP_APIS if dimension == "ApiId" else 100)
        if dimension == "ApiId":
            params["orderby"] = "Total desc" if name == "Requests" else "Maximum desc"
        query_label = f"{name} / {dimension or 'service'}"
        path = quote(instance.resource_id, safe="/") + "/providers/Microsoft.Insights/metrics"
        try:
            response = _Response.model_validate(await reader.get(path, params))
            series_results: list[MetricSeries] = []
            seen: set[tuple[tuple[Dimension, str], ...]] = set()
            for metric in response.value:
                if metric.name.value != name or metric.errorCode not in {None, "Success", ""}:
                    raise AzureReadError("METRIC_QUERY_FAILED")
                expected_unit = (
                    "Count"
                    if name == "Requests"
                    else "MilliSeconds"
                    if name in {"Duration", "BackendDuration"}
                    else "Percent"
                )
                if metric.unit != expected_unit:
                    raise AzureReadError("INVALID_METRIC_UNIT")
                if len(metric.timeseries) > int(params.get("top", "100")):
                    raise AzureReadError("METRIC_SERIES_LIMIT_EXCEEDED")
                for series in metric.timeseries:
                    dimensions = dimensions_for(series, dimension)
                    key = tuple(sorted(dimensions.items()))
                    if key in seen:
                        raise AzureReadError("DUPLICATE_METRIC_SERIES")
                    seen.add(key)
                    points = [
                        MetricPoint.model_validate(point.model_dump())
                        for point in series.data
                        if start <= point.timestamp < end
                        and any(
                            getattr(point, field.lower()) is not None
                            for field in aggregation.split(",")
                        )
                    ]
                    if not points:
                        continue
                    if len({point.timestamp for point in points}) != len(points):
                        raise AzureReadError("DUPLICATE_METRIC_TIMESTAMPS")
                    series_results.append(
                        empty.model_copy(
                            update={
                                "status": "available",
                                "location": dimensions.get("Location"),
                                "dimensions": dimensions,
                                "unit": metric.unit,
                                "points": sorted(points, key=lambda point: point.timestamp),
                            }
                        )
                    )
            if not series_results:
                raise AzureReadError("NO_METRIC_DATA")
            results.extend(series_results)
            expected = int((end - start).total_seconds() // 3600)
            if any(
                sum(getattr(point, field.lower()) is not None for point in series.points)
                != expected
                for series in series_results
                for field in aggregation.split(",")
            ):
                warnings.append(
                    CollectionWarning(
                        module="metrics",
                        resource_id=instance.resource_id,
                        code="PARTIAL_METRIC_DATA",
                        message=(
                            f"{query_label} has incomplete hourly coverage; "
                            "missing samples are not zero."
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
                    message=f"{query_label} could not be collected; it is not a healthy zero.",
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


class _WorkspaceProperties(BaseModel):
    customerId: str


class _Workspace(BaseModel):
    properties: _WorkspaceProperties


class _Column(BaseModel):
    name: str
    type: str


class _Table(BaseModel):
    columns: list[_Column]
    rows: list[list[object]]


class _LogResponse(BaseModel):
    tables: list[_Table]


def log_query(
    identifier: str,
    table: str,
    start: datetime,
    end: datetime,
    max_rows: int,
) -> str:
    if table not in {"ApiManagementGatewayLogs", "AzureDiagnostics"}:
        raise ValueError("Unsupported gateway log table")
    # Identifiers have already passed ResourceId validation; no user-supplied KQL is accepted.
    fields = {
        "tls": ("ClientTlsVersion", "clientTlsVersion_s"),
        "response": ("ResponseCode", "responseCode_d"),
        "backend": ("BackendResponseCode", "backendResponseCode_d"),
        "latency": ("BackendTime", "backendTime_d"),
        "cache": ("Cache", "cache_s"),
        "api": ("ApiId", "apiId_s"),
    }
    expressions = {}
    for alias, names in fields.items():
        name = names[0] if table == "ApiManagementGatewayLogs" else names[1]
        expressions[alias] = (
            f'coalesce(tostring(column_ifexists("{name}", "")), '
            f'tostring(column_ifexists("AdditionalFields", dynamic({{}})).{name}))'
        )
    category = '| where Category == "GatewayLogs"' if table == "AzureDiagnostics" else ""
    instants = [value.astimezone(UTC).isoformat().replace("+00:00", "Z") for value in (start, end)]
    return f"""
let data = materialize({table}
| where _ResourceId =~ "{identifier}"
| where TimeGenerated >= datetime({instants[0]}) and TimeGenerated < datetime({instants[1]})
{category}
| project tls=tolower({expressions["tls"]}), response=toint({expressions["response"]}),
    backend=toint({expressions["backend"]}), latency=toreal({expressions["latency"]}),
    cache=tolower({expressions["cache"]}), api={expressions["api"]});
data | summarize requests=count(),
    tls_known=countif(tls in ("1.0","1.1","1.2","1.3","tls1.0","tls1.1","tls1.2","tls1.3",
        "tlsv1.0","tlsv1.1","tlsv1.2","tlsv1.3","tls 1.0","tls 1.1","tls 1.2","tls 1.3")),
    weak_tls=countif(tls in ("1.0","1.1","tls1.0","tls1.1",
        "tlsv1.0","tlsv1.1","tls 1.0","tls 1.1")),
    response_known=countif(response between (100 .. 599)),
    gateway_5xx=countif(response between (500 .. 599)),
    backend_known=countif(backend between (100 .. 599)),
    backend_5xx=countif(backend between (500 .. 599)),
    latency_samples=countif(latency >= 0 and backend between (100 .. 599)),
    backend_p95_ms=percentile(
        iff(latency >= 0 and backend between (100 .. 599), latency, real(null)), 95),
    cache_hits=countif(cache == "hit"), cache_misses=countif(cache == "miss");
data | summarize gateway_5xx=countif(response between (500 .. 599)),
    backend_5xx=countif(backend between (500 .. 599)) by api
| where gateway_5xx > 0 or backend_5xx > 0
| order by backend_5xx desc, gateway_5xx desc
| take {max_rows}
| project api, gateway_5xx, backend_5xx;
data | where latency >= 0 and backend between (100 .. 599)
| summarize samples=count(), average_ms=avg(latency), maximum_ms=max(latency),
    p95_ms=percentile(latency, 95) by api
| order by samples desc, api asc
| take {max_rows}
| project api, samples, average_ms, maximum_ms, p95_ms
""".strip()


def table_rows(table: _Table, expected: set[str]) -> list[dict[str, object]]:
    names = [column.name for column in table.columns]
    if len(set(names)) != len(names) or set(names) != expected:
        raise AzureReadError("INVALID_LOG_COLUMNS")
    if any(len(row) != len(names) for row in table.rows):
        raise AzureReadError("INVALID_LOG_ROWS")
    return [dict(zip(names, row, strict=True)) for row in table.rows]


def log_api_path(instance: Instance, api: str) -> str | None:
    matches = (
        [
            item.path
            for item in instance.inventory.resources
            if item.kind == "api"
            and item.workspace is None
            and item.name.casefold() == api.casefold()
        ]
        if instance.inventory
        else []
    )
    return matches[0] if len(matches) == 1 else None


async def collect_logs(
    reader: ArmReader,
    instance: Instance,
    links: list[LogLink],
    start: datetime,
    end: datetime,
    warnings: list[CollectionWarning],
    settings: Telemetry,
    *,
    enabled: bool,
) -> LogAnalytics:
    if not enabled:
        warnings.append(
            CollectionWarning(
                module="log_analytics",
                resource_id=instance.resource_id,
                code="DISABLED",
                message=(
                    "Optional Log Analytics queries were disabled; "
                    "runtime evidence is not assessed."
                ),
            )
        )
        return LogAnalytics(status="disabled")
    if instance.sku and instance.sku.name == "Consumption":
        return LogAnalytics(status="unsupported")
    result = LogAnalytics(status="complete")
    timespan = "/".join(
        value.astimezone(UTC).isoformat().replace("+00:00", "Z") for value in (start, end)
    )
    for identifier, table in sorted(
        {(identifier.casefold(), table) for identifier, table in links}
    ):
        workspace = WorkspaceLogs(workspace=reference_id(identifier.casefold()), table=table)
        try:
            linked_resource(identifier, WORKSPACE_TYPE)
            raw = _Workspace.model_validate(
                await reader.get(
                    quote(identifier, safe="/"),
                    {"api-version": "2023-09-01"},
                )
            )
            response = _LogResponse.model_validate(
                await reader.query_logs(
                    raw.properties.customerId,
                    log_query(instance.resource_id, table, start, end, settings.kql_max_rows),
                    timespan,
                    settings.kql_timeout_seconds,
                )
            )
            if len(response.tables) != 3:
                raise AzureReadError("INVALID_LOG_TABLES")
            rows = table_rows(response.tables[0], set(LogAggregate.model_fields))
            if len(rows) != 1:
                raise AzureReadError("INVALID_LOG_AGGREGATE")
            aggregate = LogAggregate.model_validate(rows[0])
            hotspot_rows = table_rows(response.tables[1], {"api", "gateway_5xx", "backend_5xx"})
            if len(hotspot_rows) > settings.kql_max_rows:
                raise AzureReadError("LOG_ROW_LIMIT_EXCEEDED")
            hotspots = []
            for row in hotspot_rows:
                api = row["api"]
                if not isinstance(api, str):
                    raise AzureReadError("INVALID_LOG_API")
                hotspots.append(
                    LogHotspot.model_validate(
                        {
                            "api_reference": reference_id(api.casefold()),
                            "api_path": log_api_path(instance, api),
                            "gateway_5xx": row["gateway_5xx"],
                            "backend_5xx": row["backend_5xx"],
                        }
                    )
                )
            latency_rows = table_rows(
                response.tables[2], {"api", "samples", "average_ms", "maximum_ms", "p95_ms"}
            )
            if len(latency_rows) > settings.kql_max_rows:
                raise AzureReadError("LOG_ROW_LIMIT_EXCEEDED")
            api_latency = []
            for row in latency_rows:
                api = row.pop("api")
                if not isinstance(api, str):
                    raise AzureReadError("INVALID_LOG_API")
                api_latency.append(
                    LogLatency.model_validate(
                        {
                            **row,
                            "api_reference": reference_id(api.casefold()),
                            "api_path": log_api_path(instance, api),
                        }
                    )
                )
            workspace = WorkspaceLogs(
                workspace=workspace.workspace,
                table=table,
                status="complete",
                aggregate=aggregate,
                hotspots=hotspots,
                api_latency=api_latency,
            )
        except (AzureReadError, ValidationError) as exc:
            result.status = "partial"
            warnings.append(
                CollectionWarning(
                    module="log_analytics",
                    resource_id=instance.resource_id,
                    code=str(exc) if isinstance(exc, AzureReadError) else "INVALID_LOG_RESPONSE",
                    message=(
                        "A linked workspace query failed or was partial; "
                        "no raw log rows were saved."
                    ),
                )
            )
        result.workspaces.append(workspace)
    if not links:
        result.status = "unavailable"
        warnings.append(
            CollectionWarning(
                module="log_analytics",
                resource_id=instance.resource_id,
                code="NO_LINKED_WORKSPACE",
                message="No enabled GatewayLogs diagnostic setting linked a readable workspace.",
            )
        )
    elif instance.governance is None or instance.governance.diagnostics_status != "complete":
        result.status = "partial"
    return result
