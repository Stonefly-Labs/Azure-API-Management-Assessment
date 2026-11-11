from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from azure.core.credentials import AccessToken
from typer.testing import CliRunner

from apim_assess.cli import app
from apim_assess.collector.apim_core import collect
from apim_assess.collector.client import ArmReader
from apim_assess.collector.sanitizer import reference_id
from apim_assess.models.findings import PortfolioAssessment
from apim_assess.models.snapshot import Snapshot

RUNNER = CliRunner()
FIXTURE = Path(__file__).parent / "fixtures" / "sample_multi_apim_snapshot.json"


def test_offline_stages_do_not_instantiate_azure_credentials(tmp_path, monkeypatch):
    def forbidden():
        raise AssertionError("Offline commands must not instantiate Azure credentials")

    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    findings = tmp_path / "findings.json"
    report = tmp_path / "report.html"
    result = RUNNER.invoke(app, ["analyze", "--snapshot", str(FIXTURE), "--output", str(findings)])
    assert result.exit_code == 0, result.output
    result = RUNNER.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(FIXTURE),
            "--findings",
            str(findings),
            "--output",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert len(PortfolioAssessment.model_validate_json(findings.read_text()).findings) == 162
    assert "Portfolio readout" in report.read_text()


def test_assess_runs_real_mocked_collection_and_same_offline_stages(
    snapshot, tmp_path, monkeypatch
):
    identifiers = [instance.resource_id for instance in snapshot.instances[:2]]
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("/policyStates/latest/queryResults"):
            assert request.method == "POST"
            return httpx.Response(200, json={"value": []})
        assert request.method == "GET"
        if request.url.path.endswith("/metrics"):
            return httpx.Response(403, json={"error": {"message": "SECRET_RESPONSE_SENTINEL"}})
        identifier = str(request.url.path)
        return httpx.Response(
            200,
            json={
                "id": identifier,
                "location": "eastus",
                "sku": {
                    "name": "Developer" if identifier.endswith("-dev") else "Premium",
                    "capacity": 2,
                },
                "zones": ["1", "2"],
                "properties": {
                    "additionalLocations": [],
                    "virtualNetworkType": "None",
                    "privateEndpointConnections": [],
                    "publicNetworkAccess": "Enabled",
                },
            },
        )

    async def mocked_collection(config):
        credential = AsyncMock()
        credential.get_token.return_value = AccessToken("synthetic-token", 9999999999)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, ArmReader(credential, client))

    monkeypatch.setattr("apim_assess.cli.collect", mocked_collection)
    directory = tmp_path / "assessment"
    result = RUNNER.invoke(
        app,
        [
            "assess",
            "--resource-id",
            identifiers[0],
            "--resource-id",
            identifiers[1],
            "--env",
            "prod",
            "--output-dir",
            str(directory),
        ],
    )
    assert result.exit_code == 0, result.output
    saved = Snapshot.model_validate_json((directory / "snapshot.json").read_text())
    assert len(saved.instances) == 2
    assert "SECRET_RESPONSE_SENTINEL" not in result.output
    assert "SECRET_RESPONSE_SENTINEL" not in (directory / "snapshot.json").read_text()
    staged_findings = tmp_path / "staged.json"
    result = RUNNER.invoke(
        app,
        [
            "analyze",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--output",
            str(staged_findings),
        ],
    )
    assert result.exit_code == 0, result.output
    assert staged_findings.read_text() == (directory / "findings.json").read_text()
    assert requests
    assert (directory / "apim-assessment-report.html").exists()


def test_dimensional_classic_v2_assess_and_offline_replay(tmp_path, monkeypatch, snapshot):
    identifiers = [instance.resource_id for instance in snapshot.instances[:2]]
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        if request.url.path.endswith("/metrics"):
            name = request.url.params["metricnames"]
            if name == "MemoryPercent_Gateway":
                return httpx.Response(403, json={"error": {"message": "PRIVATE_METRIC_SENTINEL"}})
            dimension = request.url.params.get("$filter", "").split(" ")[0]
            start = request.url.params["timespan"].split("/")[0]
            value = {
                "Location": "eastus",
                "ApiId": "orders",
                "GatewayResponseCodeCategory": "2xx",
            }.get(dimension)
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "name": {"value": name},
                            "unit": "Count"
                            if name == "Requests"
                            else (
                                "MilliSeconds"
                                if name in {"Duration", "BackendDuration"}
                                else "Percent"
                            ),
                            "timeseries": [
                                {
                                    "metadatavalues": [
                                        {"name": {"value": dimension}, "value": value}
                                    ]
                                    if dimension
                                    else [],
                                    "data": [
                                        {"timeStamp": start, "total": 12}
                                        if name == "Requests"
                                        else {"timeStamp": start, "average": 25, "maximum": 50}
                                    ],
                                }
                            ],
                        }
                    ]
                },
            )
        if request.url.path in identifiers:
            return httpx.Response(
                200,
                json={
                    "id": request.url.path,
                    "location": "eastus",
                    "sku": {
                        "name": "Premium" if request.url.path == identifiers[0] else "StandardV2",
                        "capacity": 2,
                    },
                    "properties": {
                        "additionalLocations": [],
                        "virtualNetworkType": "None",
                        "privateEndpointConnections": [],
                    },
                },
            )
        if request.url.path.endswith("/policies/policy"):
            return httpx.Response(404)
        if request.url.path.endswith(("/tenant/access", "/portalsettings/signup")):
            return httpx.Response(200, json={"properties": {"enabled": False}})
        if request.url.path.endswith("/portalconfigs/default"):
            return httpx.Response(200, json={"properties": {"signin": {"require": True}}})
        return httpx.Response(200, json={"value": []})

    async def mocked_collection(config):
        credential = AsyncMock()
        credential.get_token.return_value = AccessToken("synthetic-token", 9999999999)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, ArmReader(credential, client))

    def forbidden():
        raise AssertionError("Offline replay must not create Azure credentials")

    monkeypatch.setattr("apim_assess.cli.collect", mocked_collection)
    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    config = tmp_path / "settings.yaml"
    config.write_text("modules:\n  networking: false\n  defender_policy: false\n")
    directory = tmp_path / "composed"
    result = RUNNER.invoke(
        app,
        [
            "assess",
            "--resource-id",
            identifiers[0],
            "--resource-id",
            identifiers[1],
            "--config",
            str(config),
            "--output-dir",
            str(directory),
        ],
    )
    assert result.exit_code == 0, result.output
    saved = Snapshot.model_validate_json((directory / "snapshot.json").read_text())
    assert (saved.telemetry_end - saved.telemetry_start).days == 30
    assert {instance.resource_id: instance.sku.name for instance in saved.instances} == {
        identifiers[0]: "Premium",
        identifiers[1]: "StandardV2",
    }
    assert all(
        any(series.dimensions.get("ApiId") == reference_id("orders") for series in instance.metrics)
        for instance in saved.instances
    )
    assert any(warning.code == "HTTP_403" for warning in saved.collection_warnings)
    assert any(warning.code == "PARTIAL_METRIC_DATA" for warning in saved.collection_warnings)
    assert "PRIVATE_METRIC_SENTINEL" not in (directory / "snapshot.json").read_text()
    request_count = len(requests)
    replay = tmp_path / "findings.json"
    result = RUNNER.invoke(
        app,
        [
            "analyze",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--output",
            str(replay),
        ],
    )
    assert result.exit_code == 0, result.output
    assert replay.read_bytes() == (directory / "findings.json").read_bytes()
    report = tmp_path / "report.html"
    result = RUNNER.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--findings",
            str(replay),
            "--output",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert report.read_bytes() == (directory / "apim-assessment-report.html").read_bytes()
    assert "30-Day Telemetry &amp; Trends" in report.read_text()
    assert report.read_text().count('data-trend="latency"') == 3
    assert len(requests) == request_count


def test_no_readable_instance_saves_warning_snapshot_and_stops(snapshot, tmp_path, monkeypatch):
    snapshot.instances[0].core_status = "unavailable"
    snapshot.instances = snapshot.instances[:1]

    async def unavailable(config):
        return snapshot

    monkeypatch.setattr("apim_assess.cli.collect", unavailable)
    result = RUNNER.invoke(
        app,
        [
            "assess",
            "--resource-id",
            snapshot.instances[0].resource_id,
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert (tmp_path / "snapshot.json").exists()
    assert not (tmp_path / "findings.json").exists()
    assert not (tmp_path / "apim-assessment-report.html").exists()


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--resource-id", "invalid"],
        ["--subscriptions", "bad-uuid"],
        ["--resource-groups", "missing-subscription"],
    ],
)
def test_collection_requires_valid_explicit_scope(args):
    result = RUNNER.invoke(app, ["collect", *args])
    assert result.exit_code == 2, result.output


def test_input_path_cannot_be_overwritten(tmp_path):
    config = tmp_path / "assessment.yaml"
    config.write_text("env: auto\n")
    result = RUNNER.invoke(app, ["collect", "--config", str(config), "--output", str(config)])
    assert result.exit_code == 2
    assert "must be different" in result.output
    assert config.read_text() == "env: auto\n"


def test_schema_error_does_not_echo_secret_input(tmp_path):
    config = tmp_path / "assessment.yaml"
    config.write_text("env: PRIVATE_SENTINEL\n")
    result = RUNNER.invoke(app, ["collect", "--config", str(config)])
    assert result.exit_code == 2
    assert "PRIVATE_SENTINEL" not in result.output


def test_rule_configuration_composes_and_replays_offline(snapshot, tmp_path, monkeypatch):
    async def mocked(config):
        return snapshot

    monkeypatch.setattr("apim_assess.cli.collect", mocked)
    config = tmp_path / "settings.yaml"
    config.write_text(
        "rules:\n  waivers:\n"
        "    - rule_id: APIM-REL-006\n      justification: Approved recovery\n"
        "  severity_overrides: {APIM-REL-006: Low}\n"
        "  thresholds: {capacity_warning_pct: 65}\n"
    )
    composed = tmp_path / "composed"
    result = RUNNER.invoke(
        app,
        [
            "assess",
            "--resource-id",
            snapshot.instances[0].resource_id,
            "--config",
            str(config),
            "--output-dir",
            str(composed),
        ],
    )
    assert result.exit_code == 0, result.output
    replay = tmp_path / "replay.json"
    result = RUNNER.invoke(
        app,
        [
            "analyze",
            "--snapshot",
            str(composed / "snapshot.json"),
            "--config",
            str(config),
            "--output",
            str(replay),
        ],
    )
    assert result.exit_code == 0, result.output
    assert replay.read_bytes() == (composed / "findings.json").read_bytes()
    assessment = PortfolioAssessment.model_validate_json(replay.read_text())
    assert assessment.rule_settings.thresholds.capacity_warning_pct == 65
    assert all(
        item.waiver_justification == "Approved recovery" and item.severity == "Low"
        for item in assessment.findings
        if item.rule.id == "APIM-REL-006"
    )
    replay_html = tmp_path / "replay.html"
    result = RUNNER.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(composed / "snapshot.json"),
            "--findings",
            str(replay),
            "--output",
            str(replay_html),
        ],
    )
    assert result.exit_code == 0, result.output
    assert replay_html.read_bytes() == (composed / "apim-assessment-report.html").read_bytes()
