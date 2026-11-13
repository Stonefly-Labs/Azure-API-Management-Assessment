"""In-VNet Container Apps Job runner for `apim-assess assess`.

Executes inside `caj-apv-assess-wus3-001` using the read-only assessment
managed identity (`id-apv-gh-assess-wus3-001`). Runs:
    apim-assess assess --subscription-id <sub_id> --resource-group <lab_rg> --env prod
and uploads the sanitized `snapshot.json`, `findings.json`, and `report.html`
artifacts to the `assessment-runs/<run_id>/` blob prefix over OAuth.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from scripts.lab.run_smoke_in_job import _upload_blob_oauth

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "samples" / "validation_lab" / "assessment.lab.yaml"


async def _run() -> int:
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    resource_group = os.environ.get("AZURE_LAB_RESOURCE_GROUP", "rg-apv-lab-wus3-001")
    storage_account_name = os.environ.get("LAB_STORAGE_ACCOUNT_NAME", "")
    run_id = os.environ.get("LAB_RUN_ID", datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    output_dir = Path(os.environ.get("LAB_OUTPUT_DIR", f"/tmp/apim-assess-{run_id}"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if not subscription_id:
        raise RuntimeError("AZURE_SUBSCRIPTION_ID is required inside caj-apv-assess-wus3-001.")

    cmd = [
        "apim-assess",
        "assess",
        "--subscriptions",
        subscription_id,
        "--resource-groups",
        resource_group,
        "--env",
        "prod",
        "--config",
        str(DEFAULT_CONFIG),
        "--output-dir",
        str(output_dir),
    ]
    print(f"[assess-job] Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, check=False)
    if proc.returncode not in {0, 1, 2}:
        return proc.returncode

    artifact_specs = [
        ("snapshot.json", "snapshot.json", "application/json"),
        ("findings.json", "findings.json", "application/json"),
        ("apim-assessment-report.html", "report.html", "text/html; charset=utf-8"),
    ]
    if storage_account_name:
        for local_name, blob_filename, content_type in artifact_specs:
            path = output_dir / local_name
            if path.exists():
                blob_url = await _upload_blob_oauth(
                    storage_account_name=storage_account_name,
                    container_name="assessment-runs",
                    blob_name=f"{run_id}/{blob_filename}",
                    payload_bytes=path.read_bytes(),
                    content_type=content_type,
                )
                print(f"[assess-job] Uploaded {local_name} -> {blob_url}")

    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
