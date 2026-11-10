from apim_assess.analyzer.evaluators.metrics import (
    averages,
    capacity_series,
    complete_coverage,
    metric_evidence,
    p95,
)
from apim_assess.collector.telemetry import CLASSIC, V2
from apim_assess.models.findings import Evaluation
from apim_assess.models.snapshot import Instance, Snapshot


def saturation(
    instance: Instance, snapshot: Snapshot, *, warning_pct: float = 70, maximum_pct: float = 85
) -> Evaluation:
    if not instance.sku:
        return Evaluation(outcome="unknown", summary="SKU was not collected.")
    if instance.sku.name == "Consumption":
        return Evaluation(outcome="unsupported", summary="Capacity metrics are not supported.")
    if instance.sku.name not in CLASSIC | V2:
        return Evaluation(outcome="unknown", summary="Capacity capability is not established.")
    evidence = metric_evidence(instance, snapshot)
    for series in capacity_series(instance):
        values = averages(series)
        maxima = [
            point.maximum
            for point in series.points
            if point.maximum is not None
            and series.name != "Capacity"
            and series.unit == "Percent"
            and series.status == "available"
        ]
        if (values and p95(values) > warning_pct) or (maxima and max(maxima) > maximum_pct):
            return Evaluation(
                outcome="fail",
                summary=(
                    f"p95 hourly average exceeds {warning_pct:g}% or a v2 CPU/memory maximum "
                    f"exceeds {maximum_pct:g}%. "
                    "Investigate duration and workload; "
                    "an isolated spike is not a scaling decision."
                ),
                evidence=evidence,
            )
    if not complete_coverage(instance, snapshot, require_maximum=instance.sku.name in V2):
        return Evaluation(
            outcome="unknown",
            summary="No saturation established; incomplete telemetry cannot establish a pass.",
            evidence=evidence,
        )
    return Evaluation(
        outcome="pass",
        summary="Collected capacity signals do not exceed thresholds.",
        evidence=evidence,
    )
