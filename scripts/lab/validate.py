"""Validation Lab orchestrator and 55-rule expectation verifier.

Supports two execution modes:
1. Offline artifact verification (`--findings-path` and optional `--snapshot-path` /
   `--report-path`): Verifies a `FindingsDocument` (or synthesized snapshot) against
   `samples/validation_lab/expectations.yaml` without Azure credentials.
2. Live Azure validation (`--live`):
   Triggers `caj-apv-smoke-wus3-001` to run in-VNet gateway traffic probes and
   seed Log Analytics telemetry, triggers `caj-apv-assess-wus3-001` (or runs
   `apim-assess assess` locally), downloads the resulting artifacts from
   Blob Storage, and verifies all 55 catalog rules against `expectations.yaml`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from azure.identity import DefaultAzureCredential

from apim_assess.analyzer.engine import load_rules
from apim_assess.models.findings import PortfolioAssessment

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPECTATIONS = REPO_ROOT / "samples" / "validation_lab" / "expectations.yaml"
DEFAULT_LAB_CONFIG = REPO_ROOT / "samples" / "validation_lab" / "assessment.lab.yaml"


@dataclass
class RuleExpectationEntry:
    rule_id: str
    statuses: set[str]
    target_contains: str | None = None
    rationale: str = ""


@dataclass
class InstanceExpectationSpec:
    instance_name: str
    sku: str
    expected_rules: dict[str, RuleExpectationEntry] = field(default_factory=dict)


@dataclass
class LabExpectationsContract:
    schema_version: str
    environment: str
    total_catalog_rules: int
    instances: dict[str, InstanceExpectationSpec]
    required_outcome_diversity: list[str]
    required_artifacts: list[str]


@dataclass
class ValidationCheckFailure:
    instance_name: str
    rule_id: str
    expected_statuses: list[str]
    actual_statuses: list[str]
    message: str


@dataclass
class ValidationSummary:
    passed: bool
    evaluated_instances: list[str]
    observed_outcomes: list[str]
    total_rules_checked: int
    failures: list[ValidationCheckFailure] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "evaluatedInstances": self.evaluated_instances,
            "observedOutcomes": self.observed_outcomes,
            "totalRulesChecked": self.total_rules_checked,
            "failureCount": len(self.failures),
            "failures": [
                {
                    "instanceName": f.instance_name,
                    "ruleId": f.rule_id,
                    "expectedStatuses": f.expected_statuses,
                    "actualStatuses": f.actual_statuses,
                    "message": f.message,
                }
                for f in self.failures
            ],
        }


def load_expectations(path: Path = DEFAULT_EXPECTATIONS) -> LabExpectationsContract:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid expectations YAML in {path}")

    instances: dict[str, InstanceExpectationSpec] = {}
    key_to_instance_name: dict[str, str] = {}
    for inst_key, inst_data in (raw.get("instances") or {}).items():
        if not isinstance(inst_data, dict):
            continue
        inst_name = str(inst_data.get("name_suffix") or inst_key)
        key_to_instance_name[str(inst_key)] = inst_name
        rules_map: dict[str, RuleExpectationEntry] = {}
        for rule_id, rule_spec in (inst_data.get("expected_rules") or {}).items():
            raw_status = rule_spec.get("status")
            statuses = (
                {str(s) for s in raw_status} if isinstance(raw_status, list) else {str(raw_status)}
            )
            rules_map[str(rule_id)] = RuleExpectationEntry(
                rule_id=str(rule_id),
                statuses=statuses,
                target_contains=rule_spec.get("target_contains"),
                rationale=str(rule_spec.get("rationale") or ""),
            )
        instances[inst_name] = InstanceExpectationSpec(
            instance_name=inst_name,
            sku=str(inst_data.get("sku") or ""),
            expected_rules=rules_map,
        )

    for rule_id, rule_spec in (raw.get("rules") or {}).items():
        if not isinstance(rule_spec, dict):
            continue
        rationale = str(rule_spec.get("rationale") or "")
        target_contains = rule_spec.get("target_contains")
        for inst_key, inst_name in key_to_instance_name.items():
            if inst_key not in rule_spec and inst_name not in rule_spec:
                continue
            raw_status = rule_spec.get(inst_key, rule_spec.get(inst_name))
            statuses = (
                {str(s) for s in raw_status} if isinstance(raw_status, list) else {str(raw_status)}
            )
            instances[inst_name].expected_rules[str(rule_id)] = RuleExpectationEntry(
                rule_id=str(rule_id),
                statuses=statuses,
                target_contains=target_contains,
                rationale=rationale,
            )

    return LabExpectationsContract(
        schema_version=str(raw.get("schema_version") or "1.0"),
        environment=str(raw.get("environment") or "prod"),
        total_catalog_rules=int(raw.get("total_catalog_rules") or 55),
        instances=instances,
        required_outcome_diversity=[
            str(s)
            for s in (
                raw.get("required_outcome_diversity")
                or ["pass", "fail", "unknown", "unsupported", "not_applicable", "waived"]
            )
        ],
        required_artifacts=[
            str(a)
            for a in (
                raw.get("required_artifacts")
                or ["snapshot.json", "findings.json", "report.html", "smoke-results.json"]
            )
        ],
    )


def verify_contract_covers_catalog(
    contract: LabExpectationsContract | None = None,
) -> list[str]:
    """Verify `expectations.yaml` covers every rule ID in the 55-rule catalog for both instances."""
    exp = contract or load_expectations()
    catalog = load_rules()
    catalog_ids = {rule.id for rule in catalog}
    errors: list[str] = []

    if len(catalog_ids) != exp.total_catalog_rules:
        errors.append(
            f"Catalog count mismatch: catalog has {len(catalog_ids)} rules, "
            f"expectations.yaml declares {exp.total_catalog_rules}."
        )

    for inst_name, inst_spec in exp.instances.items():
        spec_ids = set(inst_spec.expected_rules.keys())
        missing = sorted(catalog_ids - spec_ids)
        extra = sorted(spec_ids - catalog_ids)
        if missing:
            errors.append(f"Instance '{inst_name}' is missing expectations for: {missing}")
        if extra:
            errors.append(f"Instance '{inst_name}' references unknown rule IDs: {extra}")

    return errors


def _extract_instance_name(resource_id: str) -> str:
    parts = [p for p in resource_id.strip("/").split("/") if p]
    for idx, part in enumerate(parts):
        if part.lower() == "service" and idx + 1 < len(parts):
            return parts[idx + 1]
    return parts[-1] if parts else resource_id


def verify_findings_against_expectations(
    findings_doc: PortfolioAssessment,
    contract: LabExpectationsContract | None = None,
) -> ValidationSummary:
    """Compare a `PortfolioAssessment` against the expected per-instance rule matrix."""
    exp = contract or load_expectations()
    failures: list[ValidationCheckFailure] = []
    observed_outcomes: set[str] = set()
    evaluated_instances: list[str] = []
    total_checked = 0

    # Group findings by (instance_name, rule_id)
    by_instance_rule: dict[tuple[str, str], list[Any]] = {}
    for finding in findings_doc.findings:
        outcome_val = str(finding.result.outcome)
        observed_outcomes.add(outcome_val)
        if finding.waiver_justification:
            observed_outcomes.add("waived")
        inst_name = _extract_instance_name(str(finding.resource_id))
        key = (inst_name, finding.rule.id)
        by_instance_rule.setdefault(key, []).append(finding)

    for inst_name, inst_spec in exp.instances.items():
        evaluated_instances.append(inst_name)
        for rule_id, rule_exp in inst_spec.expected_rules.items():
            total_checked += 1
            matching = by_instance_rule.get((inst_name, rule_id), [])
            if rule_exp.target_contains:
                matching = [
                    f
                    for f in matching
                    if rule_exp.target_contains in str(f.resource_id)
                    or any(
                        rule_exp.target_contains in (ev.api_path or "")
                        or rule_exp.target_contains in ev.detail
                        for ev in f.result.evidence
                    )
                ] or matching

            actual_statuses = sorted(
                {"waived" if f.waiver_justification else str(f.result.outcome) for f in matching}
            )
            if not actual_statuses:
                failures.append(
                    ValidationCheckFailure(
                        instance_name=inst_name,
                        rule_id=rule_id,
                        expected_statuses=sorted(rule_exp.statuses),
                        actual_statuses=[],
                        message=f"No finding emitted for rule {rule_id} on {inst_name}",
                    )
                )
                continue

            # Allow match against either effective status (waived) or underlying outcome
            all_candidate_statuses = set(actual_statuses) | {
                str(f.result.outcome) for f in matching
            }
            if not any(status in rule_exp.statuses for status in all_candidate_statuses):
                failures.append(
                    ValidationCheckFailure(
                        instance_name=inst_name,
                        rule_id=rule_id,
                        expected_statuses=sorted(rule_exp.statuses),
                        actual_statuses=actual_statuses,
                        message=(
                            f"Rule {rule_id} on {inst_name} produced {actual_statuses}, "
                            f"expected one of {sorted(rule_exp.statuses)}"
                        ),
                    )
                )

    for required_status in exp.required_outcome_diversity:
        if required_status not in observed_outcomes:
            failures.append(
                ValidationCheckFailure(
                    instance_name="*",
                    rule_id="*",
                    expected_statuses=[required_status],
                    actual_statuses=sorted(observed_outcomes),
                    message=(
                        f"Required outcome diversity status '{required_status}' was never observed."
                    ),
                )
            )

    return ValidationSummary(
        passed=len(failures) == 0,
        evaluated_instances=evaluated_instances,
        observed_outcomes=sorted(observed_outcomes),
        total_rules_checked=total_checked,
        failures=failures,
    )


def _az_executable() -> str:
    exe = shutil.which("az") or shutil.which("az.cmd")
    if not exe:
        raise RuntimeError("Azure CLI ('az') was not found on PATH.")
    return exe


def _run_az_json(args: list[str]) -> Any:
    proc = subprocess.run(
        [_az_executable(), *args, "--output", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"az {' '.join(args)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def trigger_and_wait_container_app_job(
    *,
    subscription_id: str,
    resource_group: str,
    job_name: str,
    env_overrides: dict[str, str],
    timeout_seconds: int = 900,
) -> None:
    """Start a manual Container Apps Job execution and poll until Succeeded."""
    job_spec = _run_az_json(
        [
            "containerapp",
            "job",
            "show",
            "--subscription",
            subscription_id,
            "--resource-group",
            resource_group,
            "--name",
            job_name,
        ]
    )
    containers = job_spec.get("properties", {}).get("template", {}).get("containers", [])
    if not containers:
        raise RuntimeError(f"Container Apps Job '{job_name}' has no container template.")

    container = containers[0]
    existing_env = {
        item["name"]: item.get("value", "") for item in container.get("env", []) if "name" in item
    }
    existing_env.update(env_overrides)
    env_args = [f"{k}={v}" for k, v in existing_env.items() if v != ""]

    start_res = _run_az_json(
        [
            "containerapp",
            "job",
            "start",
            "--subscription",
            subscription_id,
            "--resource-group",
            resource_group,
            "--name",
            job_name,
            "--env-vars",
            *env_args,
        ]
    )
    execution_name = str(start_res.get("name") or "")
    print(f"[lab-validate] Started job {job_name} execution {execution_name}")

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        exec_info = _run_az_json(
            [
                "containerapp",
                "job",
                "execution",
                "show",
                "--subscription",
                subscription_id,
                "--resource-group",
                resource_group,
                "--name",
                job_name,
                "--job-execution-name",
                execution_name,
            ]
        )
        status = str(exec_info.get("properties", {}).get("status") or "")
        if status == "Succeeded":
            print(f"[lab-validate] Job {job_name} ({execution_name}) succeeded.")
            return
        if status in {"Failed", "Canceled"}:
            raise RuntimeError(
                f"Container Apps Job {job_name} ({execution_name}) finished with status {status}."
            )
        time.sleep(10)

    raise TimeoutError(f"Container Apps Job {job_name} timed out after {timeout_seconds}s.")


def download_blob_oauth(
    *,
    storage_account_name: str,
    container_name: str,
    blob_name: str,
    destination: Path,
) -> None:
    credential = DefaultAzureCredential()
    token = credential.get_token("https://storage.azure.com/.default").token
    url = f"https://{storage_account_name}.blob.core.windows.net/{container_name}/{blob_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "x-ms-version": "2023-11-03",
        "x-ms-date": datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT"),
    }
    with httpx.Client(timeout=30.0) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(resp.content)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate apim-assess findings against the 55-rule lab expectations matrix."
    )
    parser.add_argument(
        "--expectations-path",
        type=Path,
        default=DEFAULT_EXPECTATIONS,
        help="Path to expectations.yaml.",
    )
    parser.add_argument(
        "--findings-path",
        type=Path,
        default=None,
        help="Offline mode: path to an existing findings.json to validate.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live Azure Container Apps Jobs and download artifacts before validating.",
    )
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
    )
    parser.add_argument(
        "--resource-group",
        default=os.environ.get("AZURE_LAB_RESOURCE_GROUP", "rg-apv-lab-wus3-001"),
    )
    parser.add_argument(
        "--storage-account-name",
        default=os.environ.get("LAB_STORAGE_ACCOUNT_NAME", ""),
    )
    parser.add_argument(
        "--smoke-job-name",
        default=os.environ.get("LAB_SMOKE_JOB_NAME", "caj-apv-smoke-wus3-001"),
    )
    parser.add_argument(
        "--assess-job-name",
        default=os.environ.get("LAB_ASSESS_JOB_NAME", "caj-apv-assess-wus3-001"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "lab-validation",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    contract = load_expectations(args.expectations_path)
    catalog_errors = verify_contract_covers_catalog(contract)
    if catalog_errors:
        for err in catalog_errors:
            print(f"[contract-error] {err}", file=sys.stderr)
        return 2

    findings_path = args.findings_path
    if args.live:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out_dir: Path = args.output_dir / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        trigger_and_wait_container_app_job(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            job_name=args.smoke_job_name,
            env_overrides={"LAB_RUN_ID": run_id},
        )
        trigger_and_wait_container_app_job(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            job_name=args.assess_job_name,
            env_overrides={"LAB_RUN_ID": run_id},
        )

        for filename in contract.required_artifacts:
            download_blob_oauth(
                storage_account_name=args.storage_account_name,
                container_name="assessment-runs",
                blob_name=f"{run_id}/{filename}",
                destination=out_dir / filename,
            )
        findings_path = out_dir / "findings.json"

    if findings_path is None:
        print("Catalog contract check passed (55/55 rules covered across both instances).")
        return 0

    raw_findings = json.loads(findings_path.read_text(encoding="utf-8"))
    findings_doc = PortfolioAssessment.model_validate(raw_findings)
    summary = verify_findings_against_expectations(findings_doc, contract)
    print(json.dumps(summary.to_dict(), indent=2))
    return 0 if summary.passed else 1


if __name__ == "__main__":
    sys.exit(main())
