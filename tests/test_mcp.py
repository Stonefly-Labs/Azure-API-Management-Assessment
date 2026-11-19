import asyncio
import shutil
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from azure.identity.aio import AzureCliCredential
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from typer.testing import CliRunner

from apim_assess.analyzer.engine import analyze
from apim_assess.artifacts import write_model
from apim_assess.cli import app
from apim_assess.config import AssessmentConfig
from apim_assess.mcp.models import Filters, Job, Work
from apim_assess.mcp.server import create_server
from apim_assess.mcp.service import ServiceError, Workspace
from apim_assess.mcp.worker import execute
from apim_assess.models.findings import PortfolioAssessment, Waiver
from apim_assess.models.snapshot import Snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "sample_multi_apim_snapshot.json"


async def wait_job(client, identifier):
    for _ in range(200):
        result = await client.call_tool("get_job_status", {"job_id": identifier})
        assert not result.is_error, result
        job = Job.model_validate(result.structured_content)
        if job.state != "running":
            return job
        await asyncio.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("wire", [False, True])
@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_offline_mcp_pipeline_matches_cli_and_queries(tmp_path, wire, mode):
    shutil.copyfile(FIXTURE, tmp_path / "snapshot.json")

    async def run():
        target = (
            StdioServerParameters(
                command=sys.executable,
                args=[
                    "-c",
                    "from apim_assess.cli import app; app()",
                    "mcp",
                    "--workspace",
                    str(tmp_path),
                ],
            )
            if wire
            else create_server(tmp_path)
        )
        async with Client(target, mode=mode) as client:
            names = {item.name for item in (await client.list_tools()).tools}
            assert names == {
                "collect",
                "analyze",
                "report",
                "assess",
                "get_job_status",
                "get_job_result",
                "cancel_job",
                "query_findings",
                "explain_rule",
            }
            denied = await client.call_tool("collect", {})
            assert denied.is_error
            assert "TARGETS_REQUIRED" in str(denied)
            unknown = await client.call_tool("explain_rule", {"rule_id": "missing"})
            assert unknown.is_error
            rule = await client.call_tool("explain_rule", {"rule_id": "APIM-SEC-001"})
            assert rule.structured_content["id"] == "APIM-SEC-001"
            start = await client.call_tool("analyze", {"snapshot": "snapshot.json"})
            identifier = start.structured_content["job_id"]
            job = await wait_job(client, identifier)
            assert job.state == "completed", job
            assert sum(job.summary.values()) == 165
            findings = job.artifacts["findings"]
            expected = analyze(Snapshot.model_validate_json(FIXTURE.read_text()))
            actual = PortfolioAssessment.model_validate_json((tmp_path / findings).read_text())
            assert actual == expected
            assert job.pillar_scores == expected.pillar_scores
            assert job.mcsb_assessed_score == expected.mcsb_assessed_score
            page = await client.call_tool("query_findings", {"findings": findings, "page_size": 10})
            assert page.structured_content["total"] == 165
            assert len(page.structured_content["findings"]) == 10
            assert page.structured_content["next_cursor"]
            report = await client.call_tool(
                "report", {"snapshot": "snapshot.json", "findings": findings}
            )
            rendered = await wait_job(client, report.structured_content["job_id"])
            assert rendered.state == "completed", rendered
            assert "Portfolio readout" in (tmp_path / rendered.artifacts["report"]).read_text()

    asyncio.run(run())


def test_cursor_waivers_and_oversized_response(tmp_path):
    workspace = Workspace(tmp_path)
    saved = Snapshot.model_validate_json(FIXTURE.read_text())
    config = AssessmentConfig()
    config.rules.waivers = [Waiver(rule_id="APIM-SEC-001", justification="Synthetic waiver")]
    assessment = analyze(saved, config.rules)
    write_model(tmp_path / "findings.json", assessment)
    page = workspace.query("findings.json", Filters(waived=True), 1, None)
    assert page.total == 3
    following = workspace.query("findings.json", Filters(waived=True), 1, page.next_cursor)
    assert following.findings[0].resource_id != page.findings[0].resource_id
    with pytest.raises(ServiceError, match="STALE_CURSOR"):
        workspace.query("findings.json", Filters(), 1, page.next_cursor)
    with pytest.raises(ServiceError, match="INVALID_CURSOR"):
        workspace.query("findings.json", Filters(), 1, "!")
    (tmp_path / "findings.json").write_text((tmp_path / "findings.json").read_text() + "\n")
    with pytest.raises(ServiceError, match="STALE_CURSOR"):
        workspace.query("findings.json", Filters(waived=True), 1, page.next_cursor)
    assessment.findings[0].result.summary = "x" * (256 * 1024 + 1)
    write_model(tmp_path / "findings.json", assessment)
    with pytest.raises(ServiceError, match="RESPONSE_TOO_LARGE"):
        workspace.query("findings.json", Filters(), 100, None)


@pytest.mark.parametrize("reference", ["../secret", "/etc/passwd", r"C:\Windows", ""])
def test_workspace_rejects_outside_paths(tmp_path, reference):
    with pytest.raises(ServiceError):
        Workspace(tmp_path).path(reference)


def test_workspace_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (outside / "secret.json").write_text("{}")
    try:
        (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation privilege unavailable")
    with pytest.raises(ServiceError, match="PATH_DENIED"):
        Workspace(tmp_path).path("link/secret.json")


def test_malformed_config_artifact_and_digest_errors(tmp_path):
    shutil.copyfile(FIXTURE, tmp_path / "snapshot.json")
    (tmp_path / "bad.yaml").write_text("bad: [")
    with pytest.raises(ServiceError, match="INVALID_CONFIG"):
        Workspace(tmp_path).config("bad.yaml", None)
    (tmp_path / "bad.json").write_text("SECRET_RESPONSE_SENTINEL")
    with pytest.raises(ServiceError, match="INVALID_FINDINGS") as error:
        Workspace(tmp_path).assessment("bad.json")
    assert "SENTINEL" not in str(error.value)
    assessment = analyze(Snapshot.model_validate_json(FIXTURE.read_text()))
    assessment.snapshot_digest = "0" * 64
    write_model(tmp_path / "findings.json", assessment)

    async def run():
        async with Client(create_server(tmp_path)) as client:
            result = await client.call_tool(
                "report", {"snapshot": "snapshot.json", "findings": "findings.json"}
            )
            assert result.is_error
            assert "DIGEST_MISMATCH" in str(result)

    asyncio.run(run())


def test_mocked_live_composition_and_partial_collection(tmp_path, monkeypatch):
    saved = Snapshot.model_validate_json(FIXTURE.read_text())
    collect = AsyncMock(return_value=saved)
    monkeypatch.setattr("apim_assess.mcp.worker.collect", collect)
    config = AssessmentConfig.model_validate(
        {"targets": {"instances": [{"resource_id": saved.instances[0].resource_id}]}}
    )
    events = []
    asyncio.run(
        execute(
            Work(operation="assess", workspace=str(tmp_path), output="run", config=config),
            events.append,
        )
    )
    assert collect.await_count == 1
    assert len(events[-1].artifacts) == 3
    findings = PortfolioAssessment.model_validate_json((tmp_path / "run/findings.json").read_text())
    assert findings == analyze(saved)
    for instance in saved.instances:
        instance.core_status = "unavailable"
    with pytest.raises(ServiceError, match="NO_READABLE_INSTANCES"):
        asyncio.run(
            execute(
                Work(operation="collect", workspace=str(tmp_path), output="partial", config=config),
                events.append,
            )
        )
    assert (tmp_path / "partial/snapshot.json").is_file()


def test_optional_import_failure_is_actionable(tmp_path, monkeypatch):
    import builtins

    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "apim_assess.mcp.server":
            raise ModuleNotFoundError("missing optional dependency", name="mcp")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    result = CliRunner().invoke(app, ["mcp", "--workspace", str(tmp_path)])
    assert result.exit_code == 2
    assert "extra" in result.output


def test_azure_cli_credential_uses_config_directory_without_network(tmp_path, monkeypatch):
    import json
    import os

    payload = json.dumps(
        {
            "accessToken": "synthetic-token",
            "expires_on": 9999999999,
            "expiresOn": "2286-11-20 17:46:39.000000",
            "tokenType": "Bearer",
        }
    )
    config_dir = tmp_path / "cache"
    config_dir.mkdir()
    if os.name == "nt":
        executable = tmp_path / "az.cmd"
        executable.write_text(
            f'@echo off\nif not exist "%AZURE_CONFIG_DIR%" exit /b 1\necho {payload}\n'
        )
    else:
        executable = tmp_path / "az"
        executable.write_text(
            f"#!/bin/sh\n[ -d \"$AZURE_CONFIG_DIR\" ] || exit 1\nprintf '%s\\n' '{payload}'\n"
        )
        executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("AZURE_CONFIG_DIR", str(config_dir))

    async def run():
        async with AzureCliCredential() as credential:
            token = await credential.get_token("https://management.azure.com/.default")
            assert token.token == "synthetic-token"

    asyncio.run(run())


def test_offline_worker_never_constructs_credentials(tmp_path, monkeypatch):
    shutil.copyfile(FIXTURE, tmp_path / "snapshot.json")

    def forbidden():
        raise AssertionError("Offline execution constructed Azure credentials")

    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    events = []
    asyncio.run(
        execute(
            Work(
                operation="analyze",
                workspace=str(tmp_path),
                output="offline",
                snapshot="snapshot.json",
            ),
            events.append,
        )
    )
    assert events[-1].summary
