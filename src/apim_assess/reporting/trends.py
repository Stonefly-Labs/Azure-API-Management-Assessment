from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Literal, TypedDict

from apim_assess.collector.sanitizer import reference_id
from apim_assess.models.findings import Thresholds
from apim_assess.models.snapshot import Instance, MetricSeries, Snapshot

Aggregation = Literal["average", "maximum", "total"]


class TrendPoint(TypedDict):
    day: str
    value: float | None
    hours: int
    expected: int
    x: float
    y: float


class TrendLine(TypedDict):
    label: str
    points: list[TrendPoint]
    segments: list[str]
    color: int
    dash: str


class Reference(TypedDict):
    value: float
    y: float
    label: str


class TrendChart(TypedDict):
    key: str
    title: str
    unit: str
    description: str
    lines: list[TrendLine]
    references: list[Reference]
    ceiling: float
    notes: list[str]


def api_label(instance: Instance, value: str) -> str:
    if instance.inventory:
        matches = [
            item.path
            for item in instance.inventory.resources
            if item.kind == "api"
            and item.workspace is None
            and reference_id(item.name.casefold()) == value
        ]
        if len(matches) == 1:
            return matches[0]
    return value


def daily_points(
    series: MetricSeries, aggregation: Aggregation, snapshot: Snapshot
) -> list[TrendPoint]:
    expected: dict[date, int] = defaultdict(int)
    instant = snapshot.telemetry_start.astimezone(UTC)
    while instant < snapshot.telemetry_end:
        expected[instant.date()] += 1
        instant += timedelta(hours=1)
    samples: dict[date, dict[datetime, float]] = defaultdict(dict)
    for point in series.points:
        value = getattr(point, aggregation)
        if value is not None:
            samples[point.timestamp.astimezone(UTC).date()][point.timestamp] = value
    result: list[TrendPoint] = []
    for day, hours in sorted(expected.items()):
        values = list(samples[day].values())
        value = None
        if values:
            value = (
                max(values)
                if aggregation == "maximum"
                else sum(values)
                if aggregation == "total"
                else sum(values) / len(values)
            )
        result.append(
            {
                "day": day.isoformat(),
                "value": value,
                "hours": len(values),
                "expected": hours,
                "x": 0,
                "y": 0,
            }
        )
    return result


def build_chart(
    key: str,
    title: str,
    unit: str,
    description: str,
    sources: list[tuple[str, MetricSeries, Aggregation]],
    references: list[tuple[float, str]],
    snapshot: Snapshot,
    notes: list[str],
) -> TrendChart:
    lines: list[TrendLine] = []
    for label, series, aggregation in sources:
        points = daily_points(series, aggregation, snapshot)
        if any(point["value"] is not None for point in points):
            index = len(lines)
            lines.append(
                {
                    "label": label,
                    "points": points,
                    "segments": [],
                    "color": index % 6,
                    "dash": ("none", "8 3", "2 3")[index // 6 % 3],
                }
            )
        else:
            notes.append(f"{label}: no {aggregation} samples collected.")
    ceiling = (
        max(
            [1.0]
            + [value for value, _ in references]
            + [
                point["value"]
                for line in lines
                for point in line["points"]
                if point["value"] is not None
            ]
        )
        * 1.1
    )
    for line in lines:
        segment: list[str] = []
        for index, point in enumerate(line["points"]):
            point["x"] = round(48 + 504 * index / max(1, len(line["points"]) - 1), 2)
            value = point["value"]
            if value is None:
                if segment:
                    line["segments"].append(" ".join(segment))
                segment = []
                continue
            point["y"] = round(190 - 160 * value / ceiling, 2)
            segment.append(f"{point['x']},{point['y']}")
        if segment:
            line["segments"].append(" ".join(segment))
    return {
        "key": key,
        "title": title,
        "unit": unit,
        "description": description,
        "lines": lines,
        "references": [
            {"value": value, "y": round(190 - 160 * value / ceiling, 2), "label": label}
            for value, label in references
        ],
        "ceiling": ceiling,
        "notes": notes,
    }


def telemetry_charts(
    instances: list[Instance], snapshot: Snapshot, thresholds: Thresholds
) -> list[TrendChart]:
    utilization: list[tuple[str, MetricSeries, Aggregation]] = []
    categories: list[tuple[str, MetricSeries, Aggregation]] = []
    requests: list[tuple[str, MetricSeries, Aggregation]] = []
    latency: list[tuple[str, MetricSeries, Aggregation]] = []
    notes: dict[str, list[str]] = {key: [] for key in ("utilization", "status", "apis", "latency")}
    for instance in instances:
        parts = instance.resource_id.split("/")
        prefix = f"{instance.name} ({parts[4]}, {parts[2]})"
        utilization_names = (
            {"CpuPercent_Gateway", "MemoryPercent_Gateway"}
            if instance.sku and instance.sku.name.endswith("V2")
            else {"Capacity"}
        )
        found: set[str] = set()
        for series in instance.metrics:
            dimension_keys = set(series.dimensions) - {"Location"}
            panel = None
            target = utilization
            label = f"{prefix} / {series.name} / {series.location or 'service'}"
            fields: tuple[Aggregation, ...] = ("average", "maximum")
            expected_unit = "Percent"
            if series.name in utilization_names and not dimension_keys:
                panel = "utilization"
                if series.name == "Capacity" and (
                    not instance.sku or instance.sku.name != "Premium"
                ):
                    fields = ("average",)
            elif series.name == "Requests" and dimension_keys == {"GatewayResponseCodeCategory"}:
                panel, target, fields, expected_unit = "status", categories, ("total",), "Count"
                label = f"{prefix} / {series.dimensions['GatewayResponseCodeCategory']}"
            elif series.name == "Requests" and dimension_keys == {"ApiId"}:
                panel, target, fields, expected_unit = "apis", requests, ("total",), "Count"
                label = f"{prefix} / {api_label(instance, series.dimensions['ApiId'])}"
            elif series.name == "BackendDuration" and dimension_keys == {"ApiId"}:
                panel, target, expected_unit = "latency", latency, "MilliSeconds"
                label = f"{prefix} / {api_label(instance, series.dimensions['ApiId'])}"
            if panel is None:
                continue
            found.add(panel)
            if series.status != "available" or series.unit != expected_unit:
                status = series.status if series.status != "available" else "unexpected unit"
                notes[panel].append(f"{label}: {status}; not a healthy zero.")
                continue
            target.extend((f"{label} / {field}", series, field) for field in fields)
        for key in notes:
            if key not in found:
                notes[key].append(f"{prefix}: not collected in this snapshot.")
        if utilization_names == {"Capacity"}:
            regions = {instance.location} | {
                region.location for region in instance.additional_locations or []
            }
            observed = {
                (series.location or instance.location or "").replace(" ", "").casefold()
                for series in instance.metrics
                if series.name == "Capacity" and series.status == "available" and series.points
            }
            for region in sorted(value for value in regions if value):
                if region.replace(" ", "").casefold() not in observed:
                    notes["utilization"].append(
                        f"{prefix} / {region}: Capacity samples not collected."
                    )
    return [
        build_chart(
            "utilization",
            "Gateway Capacity (Classic) / CPU & Memory (v2)",
            "%",
            "Daily mean of hourly averages and daily peak of hourly maxima, per instance/region. "
            "Classic Maximum is shown only for Premium. Reference lines are review thresholds, "
            "not a new rule evaluation.",
            utilization,
            [
                (thresholds.capacity_warning_pct, f"{thresholds.capacity_warning_pct:g}% warning"),
                (thresholds.capacity_max_pct, f"{thresholds.capacity_max_pct:g}% saturation"),
            ],
            snapshot,
            notes["utilization"],
        ),
        build_chart(
            "status",
            "Request volume by HTTP status code category",
            "requests",
            "Daily sums of observed hourly Totals, split by GatewayResponseCodeCategory "
            "(2xx / 3xx / 4xx / 5xx and any other returned categories). "
            "Each instance remains separate.",
            categories,
            [],
            snapshot,
            notes["status"],
        ),
        build_chart(
            "apis",
            "Request volume by top APIs",
            "requests",
            "Daily sums of observed hourly Totals. Collection selects up to five APIs per instance "
            "by Total descending across the saved window; this is not all traffic or a portfolio "
            "total. Unknown API identifiers remain hashed.",
            requests,
            [],
            snapshot,
            notes["apis"],
        ),
        build_chart(
            "latency",
            "Backend latency by API (BackendDuration Avg / Max)",
            "ms",
            "Daily mean of hourly averages (not request-weighted or p95) and peak hourly Maximum. "
            "Collection selects up to five APIs per instance by Maximum descending. "
            "Optional KQL window aggregates below are separate samples, not trend points.",
            latency,
            [(thresholds.backend_latency_ms, f"{thresholds.backend_latency_ms:g} ms review")],
            snapshot,
            notes["latency"],
        ),
    ]
