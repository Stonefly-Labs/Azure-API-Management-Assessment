from datetime import timedelta
from pathlib import Path

import pytest

from apim_assess.collector.sanitizer import reference_id
from apim_assess.models.snapshot import MetricPoint, MetricSeries, Sku, Snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "sample_multi_apim_snapshot.json"


@pytest.fixture
def snapshot() -> Snapshot:
    return Snapshot.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def full_snapshot(snapshot: Snapshot) -> Snapshot:
    instance = snapshot.instances[0].model_copy(deep=True)
    instance.additional_locations = []
    instance.metrics = [
        MetricSeries(
            name="Capacity",
            location="eastus",
            status="available",
            unit="Percent",
            points=[
                MetricPoint(timestamp=snapshot.telemetry_start + timedelta(hours=index), average=30)
                for index in range(14 * 24)
            ],
        )
    ]
    snapshot.instances = [instance]
    snapshot.collection_warnings = []
    return snapshot


@pytest.fixture
def dimensional_snapshot(snapshot: Snapshot) -> Snapshot:
    snapshot.schema_version = "1.4"
    snapshot.telemetry_start = snapshot.telemetry_end - timedelta(days=30)
    snapshot.instances = snapshot.instances[:2]
    for index, instance in enumerate(snapshot.instances):
        instance.sku = Sku(name="Premium" if index == 0 else "StandardV2", capacity=2)
        instance.additional_locations = []
        instance.metrics = []
        for name, dimensions, unit in [
            *(
                [("Capacity", {"Location": "eastus"}, "Percent")]
                if index == 0
                else [
                    ("CpuPercent_Gateway", {}, "Percent"),
                    ("MemoryPercent_Gateway", {}, "Percent"),
                ]
            ),
            ("Requests", {"Location": "eastus"}, "Count"),
            ("Requests", {"GatewayResponseCodeCategory": "2xx"}, "Count"),
            ("Requests", {"GatewayResponseCodeCategory": "5xx"}, "Count"),
            ("Requests", {"ApiId": reference_id("orders")}, "Count"),
            ("BackendDuration", {"ApiId": reference_id("orders")}, "MilliSeconds"),
        ]:
            instance.metrics.append(
                MetricSeries.model_validate(
                    {
                        "name": name,
                        "dimensions": dimensions,
                        "status": "available",
                        "unit": unit,
                        "location": dimensions.get("Location"),
                        "points": [
                            MetricPoint(
                                timestamp=snapshot.telemetry_start + timedelta(hours=hour),
                                average=average if name != "Requests" else None,
                                maximum=maximum if name != "Requests" else None,
                                total=average if name == "Requests" else None,
                            )
                            for hour, average, maximum in [(0, 10, 40), (1, 30, 80), (48, 0, 0)]
                        ],
                    }
                )
            )
    snapshot.collection_warnings = []
    return Snapshot.model_validate(snapshot.model_dump())
