from datetime import timedelta

from apim_assess.analyzer.evaluators.metrics import (
    averages,
    capacity_series,
    complete_coverage,
    metric_evidence,
)
from apim_assess.collector.telemetry import V2
from apim_assess.models.findings import Evaluation
from apim_assess.models.snapshot import Instance, Snapshot


def low_capacity(instance: Instance, snapshot: Snapshot) -> Evaluation:
    if not instance.sku:
        return Evaluation(outcome="unknown", summary="SKU was not collected.")
    if instance.sku.name in {"Developer", "Consumption"}:
        return Evaluation(
            outcome="not_applicable", summary="Paid dedicated production capacity is not assessed."
        )
    if instance.sku.name in V2:
        return Evaluation(
            outcome="unsupported", summary="Classic Capacity is unsupported on v2 tiers."
        )
    if instance.sku.name not in {"Basic", "Standard", "Premium"}:
        return Evaluation(outcome="unknown", summary="Capacity capability is not established.")
    evidence = metric_evidence(instance, snapshot)
    if snapshot.telemetry_end - snapshot.telemetry_start < timedelta(days=14):
        return Evaluation(
            outcome="unknown", summary="A full 14-day window is required.", evidence=evidence
        )
    if not complete_coverage(instance, snapshot):
        return Evaluation(
            outcome="unknown",
            summary="Complete hourly Capacity evidence for every region is required.",
            evidence=evidence,
        )
    peak = max(value for series in capacity_series(instance) for value in averages(series))
    return Evaluation(
        outcome="fail" if peak < 25 else "pass",
        summary=(
            "Peak hourly average Capacity is below 25%; review right-sizing with workload tests."
            if peak < 25
            else "Peak hourly average Capacity is at least 25%; low-utilization trigger not met."
        ),
        evidence=evidence,
    )
