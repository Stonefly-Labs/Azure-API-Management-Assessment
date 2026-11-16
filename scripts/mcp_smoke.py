"""Offline stdio acceptance for a native installation or an already-built image."""

import argparse
import asyncio
import shutil
import sys
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters


async def smoke(workspace: Path, image: str | None) -> None:
    if image:
        command = "docker"
        args = [
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "--mount",
            f"type=bind,source={workspace.resolve()},target=/workspace",
            image,
            "mcp",
            "--workspace",
            "/workspace",
        ]
    else:
        command = sys.executable
        args = [
            "-c",
            "from apim_assess.cli import app; app()",
            "mcp",
            "--workspace",
            str(workspace.resolve()),
        ]
    async with Client(StdioServerParameters(command=command, args=args)) as client:
        tools = await client.list_tools()
        assert any(tool.name == "assess" for tool in tools.tools)
        result = await client.call_tool("analyze", {"snapshot": "snapshot.json"})
        assert not result.is_error, result
        identifier = result.structured_content["job_id"]
        for _ in range(400):
            result = await client.call_tool("get_job_status", {"job_id": identifier})
            assert not result.is_error, result
            if result.structured_content["state"] != "running":
                break
            await asyncio.sleep(0.05)
        assert result.structured_content["state"] == "completed", result
        findings = result.structured_content["artifacts"]["findings"]
        query = await client.call_tool("query_findings", {"findings": findings})
        assert not query.is_error, query
        assert query.structured_content["total"] == 165
        report = await client.call_tool(
            "report", {"snapshot": "snapshot.json", "findings": findings}
        )
        assert not report.is_error, report
        identifier = report.structured_content["job_id"]
        for _ in range(400):
            report = await client.call_tool("get_job_status", {"job_id": identifier})
            if report.structured_content["state"] != "running":
                break
            await asyncio.sleep(0.05)
        assert report.structured_content["state"] == "completed", report
        print("MCP offline discovery/analyze/query/report passed:", client.protocol_version)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--image")
    options = parser.parse_args()
    options.workspace.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        Path(__file__).resolve().parents[1] / "tests/fixtures/sample_multi_apim_snapshot.json",
        options.workspace / "snapshot.json",
    )
    asyncio.run(smoke(options.workspace, options.image))
