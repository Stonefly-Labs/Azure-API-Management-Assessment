"""In-VNet Container Apps Job runner for validation lab gateway smoke probes.

Executes inside `caj-apv-smoke-wus3-001` (delegated to `snet-aca`), where
`apim-apv-dev-wus3-001.azure-api.net` resolves via Private DNS to the internal
Developer APIM IP and `apim-apv-bv2-wus3-001.azure-api.net` resolves via public
DNS. Uploads `smoke-results.json` to Azure Blob Storage
(`assessment-runs/<run_id>/smoke-results.json`) using `DefaultAzureCredential` over OAuth.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import UTC, datetime

import httpx
from azure.identity import DefaultAzureCredential

from samples.validation_lab.smoke import run_gateway_probes


async def _upload_blob_oauth(
    *,
    storage_account_name: str,
    container_name: str,
    blob_name: str,
    payload_bytes: bytes,
    content_type: str = "application/json",
) -> str:
    credential = DefaultAzureCredential()
    token = credential.get_token("https://storage.azure.com/.default").token
    url = f"https://{storage_account_name}.blob.core.windows.net/{container_name}/{blob_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-ms-version": "2023-11-03",
        "x-ms-date": datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "x-ms-blob-type": "BlockBlob",
        "Content-Type": content_type,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.put(url, headers=headers, content=payload_bytes)
        resp.raise_for_status()
    return url


async def _run() -> int:
    dev_gateway_url = os.environ.get(
        "LAB_DEV_GATEWAY_URL", "https://apim-apv-dev-wus3-001.azure-api.net"
    )
    bv2_gateway_url = os.environ.get(
        "LAB_BV2_GATEWAY_URL", "https://apim-apv-bv2-wus3-001.azure-api.net"
    )
    bv2_sub_key = os.environ.get("LAB_BV2_SUBSCRIPTION_KEY", "")
    dev_sub_key = os.environ.get("LAB_DEV_SUBSCRIPTION_KEY")
    mcp_audience = os.environ.get("LAB_ENTRA_MCP_AUDIENCE", "api://app-apv-mcp-api")
    a2a_audience = os.environ.get("LAB_ENTRA_A2A_AUDIENCE", "api://app-apv-a2a-api")
    storage_account_name = os.environ.get("LAB_STORAGE_ACCOUNT_NAME", "")
    run_id = os.environ.get("LAB_RUN_ID", datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))

    credential = DefaultAzureCredential()
    mcp_scope = mcp_audience if mcp_audience.endswith("/.default") else f"{mcp_audience}/.default"
    a2a_scope = a2a_audience if a2a_audience.endswith("/.default") else f"{a2a_audience}/.default"

    mcp_token = os.environ.get("LAB_MCP_BEARER_TOKEN") or credential.get_token(mcp_scope).token
    a2a_token = os.environ.get("LAB_A2A_BEARER_TOKEN") or credential.get_token(a2a_scope).token

    report = await run_gateway_probes(
        dev_gateway_url=dev_gateway_url,
        bv2_gateway_url=bv2_gateway_url,
        bv2_subscription_key=bv2_sub_key,
        dev_subscription_key=dev_sub_key,
        mcp_token=mcp_token,
        a2a_token=a2a_token,
    )
    payload = json.dumps(report.to_dict(), indent=2).encode("utf-8")
    print(payload.decode("utf-8"))

    if storage_account_name:
        blob_url = await _upload_blob_oauth(
            storage_account_name=storage_account_name,
            container_name="assessment-runs",
            blob_name=f"{run_id}/smoke-results.json",
            payload_bytes=payload,
        )
        print(f"[smoke-job] Uploaded smoke report to {blob_url}")

    return 0 if report.passed else 1


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
