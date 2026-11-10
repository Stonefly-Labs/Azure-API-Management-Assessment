from collections.abc import Callable
from importlib.resources import files

import yaml
from pydantic import TypeAdapter

from apim_assess.analyzer.evaluators.cost import low_capacity
from apim_assess.analyzer.evaluators.performance import saturation
from apim_assess.analyzer.evaluators.reliability import developer_sku, zone_redundancy
from apim_assess.analyzer.evaluators.security import network_posture
from apim_assess.artifacts import digest
from apim_assess.models.findings import (
    PILLARS,
    Evaluation,
    Finding,
    PillarScore,
    PortfolioAssessment,
    Rule,
)
from apim_assess.models.snapshot import Instance, Snapshot

EVALUATORS: dict[str, Callable[[Instance, Snapshot], Evaluation]] = {
    "developer_sku": developer_sku,
    "zone_redundancy": zone_redundancy,
    "network_posture": network_posture,
    "low_capacity": low_capacity,
    "saturation": saturation,
}
WEIGHTS = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Advisory": 1}


def load_rules() -> list[Rule]:
    path = files("apim_assess").joinpath("rules", "seed.yaml")
    rules = TypeAdapter(list[Rule]).validate_python(
        yaml.safe_load(path.read_text(encoding="utf-8"))
    )
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("Duplicate rule IDs in the catalog")
    if any(rule.evaluator not in EVALUATORS for rule in rules):
        raise ValueError("Unknown rule evaluator binding")
    return rules


def scores(findings: list[Finding]) -> list[PillarScore]:
    result: list[PillarScore] = []
    for pillar in PILLARS:
        selected = [finding for finding in findings if finding.rule.pillar == pillar]
        assessed = [finding for finding in selected if finding.result.outcome in {"pass", "fail"}]
        possible = sum(WEIGHTS[finding.severity] for finding in assessed)
        earned = sum(
            WEIGHTS[finding.severity] for finding in assessed if finding.result.outcome == "pass"
        )
        result.append(
            PillarScore(
                pillar=pillar,
                score=round(100 * earned / possible, 1) if possible else None,
                passed=sum(finding.result.outcome == "pass" for finding in selected),
                failed=sum(finding.result.outcome == "fail" for finding in selected),
                unknown=sum(finding.result.outcome == "unknown" for finding in selected),
                unsupported=sum(finding.result.outcome == "unsupported" for finding in selected),
                not_applicable=sum(
                    finding.result.outcome == "not_applicable" for finding in selected
                ),
            )
        )
    return result


def analyze(snapshot: Snapshot) -> PortfolioAssessment:
    findings: list[Finding] = []
    rules = load_rules()
    for instance in snapshot.instances:
        for rule in rules:
            result = (
                EVALUATORS[rule.evaluator](instance, snapshot)
                if instance.core_status == "available"
                else Evaluation(outcome="unknown", summary="Core collection is unavailable.")
            )
            findings.append(
                Finding(
                    resource_id=instance.resource_id,
                    environment=instance.environment,
                    rule=rule,
                    severity=(
                        rule.severity if instance.environment == "prod" else rule.non_prod_severity
                    ),
                    result=result,
                )
            )
    return PortfolioAssessment(
        snapshot_digest=digest(snapshot), findings=findings, pillar_scores=scores(findings)
    )
