from datetime import timedelta

import pytest

from apim_assess.analyzer.engine import ITERATION_2_IDS, SEED_IDS, analyze, load_rules, scores
from apim_assess.models.findings import Finding
from apim_assess.models.snapshot import MetricPoint, MetricSeries, Region, Sku, Snapshot


def finding(snapshot: Snapshot, rule_id: str) -> Finding:
    return next(item for item in analyze(snapshot).findings if item.rule.id == rule_id)


def test_seed_catalog_and_multi_instance_dispatch(snapshot: Snapshot) -> None:
    assessment = analyze(snapshot)
    ids = {rule.id for rule in load_rules()}
    assert ITERATION_2_IDS <= ids
    assert len(ids) == 40
    assert not ids & {
        "APIM-REL-004",
        "APIM-REL-005",
        "APIM-SEC-002",
        "APIM-SEC-003",
        "APIM-SEC-004",
        "APIM-SEC-005",
        "APIM-SEC-025",
        "APIM-COST-003",
        "APIM-OPS-001",
        "APIM-OPS-005",
        "APIM-OPS-006",
        "APIM-PERF-005",
    }
    assert len(assessment.findings) == 120
    assert {item.resource_id for item in assessment.findings} == {
        instance.resource_id for instance in snapshot.instances
    }
    assert next(score for score in assessment.pillar_scores if score.pillar == "OPS").score is None


@pytest.mark.parametrize(
    ("sku", "environment", "outcome", "severity"),
    [
        ("Developer", "prod", "fail", "Critical"),
        ("Developer", "non-prod", "fail", "Advisory"),
        ("Premium", "prod", "pass", "Critical"),
        ("Consumption", "prod", "pass", "Critical"),
        ("FutureSku", "prod", "unknown", "Critical"),
    ],
)
def test_developer_sku(full_snapshot, sku, environment, outcome, severity) -> None:
    instance = full_snapshot.instances[0]
    instance.sku = Sku(name=sku, capacity=1)
    instance.environment = environment
    result = finding(full_snapshot, "APIM-REL-001")
    assert result.result.outcome == outcome
    assert result.severity == severity


@pytest.mark.parametrize(
    ("sku", "zones", "outcome"),
    [
        ("Premium", ["1", "2"], "pass"),
        ("Premium", ["1"], "fail"),
        ("Premium", [], "unknown"),
        ("Premium", None, "unknown"),
        ("Developer", [], "unsupported"),
        ("BasicV2", [], "unsupported"),
        ("StandardV2", [], "unknown"),
        ("PremiumV2", ["1", "2"], "unknown"),
    ],
)
def test_zone_capabilities(full_snapshot, sku, zones, outcome) -> None:
    instance = full_snapshot.instances[0]
    instance.sku = Sku(name=sku, capacity=2)
    instance.zones = zones
    assert finding(full_snapshot, "APIM-REL-002").result.outcome == outcome


def test_zones_include_secondary_and_uncollected_regions(full_snapshot) -> None:
    instance = full_snapshot.instances[0]
    instance.additional_locations = [Region(location="westus2", zones=["3"])]
    assert finding(full_snapshot, "APIM-REL-002").result.outcome == "fail"
    instance.additional_locations = None
    assert finding(full_snapshot, "APIM-REL-002").result.outcome == "unknown"


def test_zones_require_units_consistent_with_manual_distribution(full_snapshot):
    full_snapshot.instances[0].sku.capacity = 1
    assert finding(full_snapshot, "APIM-REL-002").result.outcome == "unknown"


@pytest.mark.parametrize(
    ("sku", "mode", "connections", "outcome"),
    [
        ("Premium", "Internal", [], "pass"),
        ("Premium", "External", [], "pass"),
        ("Standard", "None", ["Approved"], "pass"),
        ("Standard", "None", ["Pending"], "fail"),
        ("Standard", "None", [], "fail"),
        ("Standard", "None", None, "unknown"),
        ("Standard", None, [], "unknown"),
        ("StandardV2", "External", [], "fail"),
        ("PremiumV2", "Internal", [], "pass"),
        ("BasicV2", "None", [], "unsupported"),
        ("Consumption", "None", [], "unsupported"),
    ],
)
def test_network_capabilities(full_snapshot, sku, mode, connections, outcome) -> None:
    instance = full_snapshot.instances[0]
    instance.sku = Sku(name=sku, capacity=1)
    instance.virtual_network_type = mode
    instance.private_endpoint_statuses = connections
    assert finding(full_snapshot, "APIM-SEC-001").result.outcome == outcome


@pytest.mark.parametrize(("value", "outcome"), [(0, "fail"), (24.99, "fail"), (25, "pass")])
def test_cost_threshold_requires_full_regional_history(full_snapshot, value, outcome) -> None:
    for point in full_snapshot.instances[0].metrics[0].points:
        point.average = value
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == outcome
    full_snapshot.instances[0].metrics[0].points.pop()
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == "unknown"


def test_cost_missing_region_short_history_and_v2(full_snapshot) -> None:
    instance = full_snapshot.instances[0]
    instance.additional_locations = [Region(location="westus2", zones=["1", "2"])]
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == "unknown"
    instance.additional_locations = []
    full_snapshot.telemetry_start += timedelta(days=1)
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == "unknown"
    instance.sku = Sku(name="StandardV2", capacity=1)
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == "unsupported"
    instance.sku = Sku(name="Developer", capacity=1)
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == "not_applicable"
    instance.sku = Sku(name="UnrecognizedV2", capacity=1)
    assert finding(full_snapshot, "APIM-COST-001").result.outcome == "unknown"


@pytest.mark.parametrize(("value", "outcome"), [(70, "pass"), (70.01, "fail")])
def test_performance_thresholds(full_snapshot, value, outcome) -> None:
    for point in full_snapshot.instances[0].metrics[0].points:
        point.average = value
        point.maximum = 99
    result = finding(full_snapshot, "APIM-PERF-001")
    assert result.result.outcome == outcome  # Classic Capacity max must not drive a failure.


@pytest.mark.parametrize(("maximum", "outcome"), [(85, "pass"), (85.01, "fail")])
def test_v2_cpu_memory_names_and_maximum(full_snapshot, maximum, outcome) -> None:
    instance = full_snapshot.instances[0]
    instance.sku = Sku(name="PremiumV2", capacity=2)
    points = [
        point.model_copy(update={"average": 30, "maximum": maximum})
        for point in instance.metrics[0].points
    ]
    instance.metrics = [
        MetricSeries(name=name, status="available", unit="Percent", points=points)
        for name in ("CpuPercent_Gateway", "MemoryPercent_Gateway")
    ]
    assert finding(full_snapshot, "APIM-PERF-001").result.outcome == outcome


def test_v2_missing_maximum_is_unknown(full_snapshot):
    instance = full_snapshot.instances[0]
    instance.sku = Sku(name="PremiumV2", capacity=2)
    instance.metrics = [
        MetricSeries(
            name=name,
            status="available",
            unit="Percent",
            points=[point.model_copy() for point in instance.metrics[0].points],
        )
        for name in ("CpuPercent_Gateway", "MemoryPercent_Gateway")
    ]
    assert finding(full_snapshot, "APIM-PERF-001").result.outcome == "unknown"


def test_partial_history_can_fail_but_not_pass(full_snapshot) -> None:
    series = full_snapshot.instances[0].metrics[0]
    series.points = [MetricPoint(timestamp=full_snapshot.telemetry_start, average=71)]
    assert finding(full_snapshot, "APIM-PERF-001").result.outcome == "fail"
    series.points[0].average = 50
    assert finding(full_snapshot, "APIM-PERF-001").result.outcome == "unknown"


def test_scores_exclude_unknown_and_do_not_average_instance_scores(full_snapshot) -> None:
    second = full_snapshot.instances[0].model_copy(deep=True)
    second.resource_id = second.resource_id + "-second"
    second.name += "-second"
    second.sku = Sku(name="Developer", capacity=1)
    second.zones = []
    second.metrics = []
    full_snapshot.instances.append(second)
    assessment = analyze(full_snapshot)
    reliability = next(
        score
        for score in scores([item for item in assessment.findings if item.rule.id in SEED_IDS])
        if score.pillar == "REL"
    )
    assert reliability.passed == 2
    assert reliability.failed == 1
    assert reliability.unsupported == 1
    assert reliability.score == round(100 * (5 + 4) / (5 + 4 + 5), 1)


def test_unavailable_core_never_passes(full_snapshot) -> None:
    full_snapshot.instances[0].core_status = "unavailable"
    assessment = analyze(full_snapshot)
    assert all(item.result.outcome == "unknown" for item in assessment.findings)
    assert all(score.score is None for score in assessment.pillar_scores)
