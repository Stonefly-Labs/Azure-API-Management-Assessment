import math
from datetime import timedelta

from apim_assess.models.findings import Evidence
from apim_assess.models.snapshot import Instance, MetricSeries, Snapshot


def region_key(value: str) -> str:
    return value.replace(" ", "").casefold()


def capacity_series(instance: Instance) -> list[MetricSeries]:
    names = (
        {"CpuPercent_Gateway", "MemoryPercent_Gateway"}
        if instance.sku and instance.sku.name.endswith("V2")
        else {"Capacity"}
    )
    return [series for series in instance.metrics if series.name in names]


def complete_coverage(
    instance: Instance, snapshot: Snapshot, *, require_maximum: bool = False
) -> bool:
    if not instance.location or instance.additional_locations is None:
        return False
    regions = [instance.location] + [region.location for region in instance.additional_locations]
    if any(region is None for region in regions):
        return False
    expected_regions = {region_key(region) for region in regions if region}
    expected_names = (
        {"CpuPercent_Gateway", "MemoryPercent_Gateway"}
        if instance.sku and instance.sku.name.endswith("V2")
        else {"Capacity"}
    )
    expected_times = set()
    timestamp = snapshot.telemetry_start
    while timestamp < snapshot.telemetry_end:
        expected_times.add(timestamp)
        timestamp += timedelta(hours=1)
    seen: set[tuple[str, str]] = set()
    for series in capacity_series(instance):
        location = series.location or (instance.location if len(expected_regions) == 1 else "")
        key = (series.name, region_key(location))
        if key in seen or series.status != "available" or series.unit != "Percent":
            return False
        seen.add(key)
        times = {point.timestamp for point in series.points if point.average is not None}
        if times != expected_times:
            return False
        if require_maximum:
            maximum_times = {
                point.timestamp for point in series.points if point.maximum is not None
            }
            if maximum_times != expected_times:
                return False
    return seen == {(name, region) for name in expected_names for region in expected_regions}


def averages(series: MetricSeries) -> list[float]:
    if series.status != "available" or series.unit != "Percent":
        return []
    return [point.average for point in series.points if point.average is not None]


def p95(values: list[float]) -> float:
    return sorted(values)[math.ceil(len(values) * 0.95) - 1]


def metric_evidence(instance: Instance, snapshot: Snapshot) -> list[Evidence]:
    evidence = [
        Evidence(
            source="Azure Monitor / metrics (2018-01-01)",
            detail=(
                f"Window {snapshot.telemetry_start.isoformat()} to "
                f"{snapshot.telemetry_end.isoformat()}; PT1H buckets; "
                "p95 is nearest-rank over hourly averages, not request-level percentiles."
            ),
        )
    ]
    for series in capacity_series(instance):
        values = averages(series)
        maxima = [
            point.maximum
            for point in series.points
            if point.maximum is not None and series.unit == "Percent"
        ]
        detail = f"{series.name} / {series.location or 'service'}: {series.status}"
        if values:
            detail += (
                f"; {len(values)} hourly averages; p95={p95(values):.2f}%; "
                f"peak hourly average={max(values):.2f}%"
            )
        if maxima and series.name != "Capacity":
            detail += f"; peak maximum={max(maxima):.2f}%"
        evidence.append(Evidence(source="snapshot.instances[].metrics", detail=detail))
    return evidence
