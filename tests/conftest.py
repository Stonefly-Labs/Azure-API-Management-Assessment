from datetime import timedelta
from pathlib import Path

import pytest

from apim_assess.models.snapshot import MetricPoint, MetricSeries, Snapshot

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
