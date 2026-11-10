from collections.abc import Callable
from importlib.resources import files

import yaml
from pydantic import TypeAdapter

from apim_assess.analyzer.evaluators.adjacent_checks import ADJACENT_CHECKS
from apim_assess.analyzer.evaluators.checks import Context
from apim_assess.analyzer.evaluators.cost import low_capacity
from apim_assess.analyzer.evaluators.performance import saturation
from apim_assess.analyzer.evaluators.policy import BINDINGS, coverage, evaluate
from apim_assess.analyzer.evaluators.policy_checks import POLICY_CHECKS
from apim_assess.analyzer.evaluators.reliability import developer_sku, zone_redundancy
from apim_assess.analyzer.evaluators.security import network_posture
from apim_assess.analyzer.evaluators.service_checks import SERVICE_CHECKS
from apim_assess.analyzer.policy_resolver import resolve
from apim_assess.artifacts import digest
from apim_assess.models.findings import (
    PILLARS,
    Evaluation,
    Finding,
    McsbCoverage,
    PillarScore,
    PortfolioAssessment,
    Rule,
    RuleSettings,
)
from apim_assess.models.policy import PolicyCoverage
from apim_assess.models.snapshot import Instance, Snapshot

EVALUATORS: dict[str, Callable[[Instance, Snapshot], Evaluation]] = {
    "developer_sku": developer_sku,
    "zone_redundancy": zone_redundancy,
    "network_posture": network_posture,
    "low_capacity": low_capacity,
    "saturation": saturation,
}
WEIGHTS = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Advisory": 1}
SEED_IDS = {"APIM-REL-001", "APIM-REL-002", "APIM-SEC-001", "APIM-COST-001", "APIM-PERF-001"}
ITERATION_2_IDS = SEED_IDS | {
    "APIM-SEC-017",
    "APIM-SEC-018",
    "APIM-SEC-019",
    "APIM-SEC-020",
    "APIM-COST-004",
    "APIM-OPS-002",
}
ITERATION_4_IDS = {
    "APIM-SEC-003",
    "APIM-SEC-025",
    "APIM-REL-004",
    "APIM-COST-003",
    "APIM-OPS-001",
    "APIM-OPS-005",
    "APIM-PERF-005",
}
CATALOG_CHECKS = SERVICE_CHECKS | POLICY_CHECKS | ADJACENT_CHECKS


def load_rules() -> list[Rule]:
    rules = []
    directory = files("apim_assess").joinpath("rules")
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.name.endswith(".yaml"):
            rules.extend(
                TypeAdapter(list[Rule]).validate_python(
                    yaml.safe_load(path.read_text(encoding="utf-8"))
                )
            )
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("Duplicate rule IDs in the catalog")
    if any(
        rule.evaluator not in EVALUATORS
        and rule.evaluator not in BINDINGS
        and rule.evaluator not in CATALOG_CHECKS
        for rule in rules
    ):
        raise ValueError("Unknown rule evaluator binding")
    return rules


def validate_settings(settings: RuleSettings, snapshot: Snapshot) -> None:
    ids = {rule.id for rule in load_rules()}
    if set(settings.severity_overrides) - ids or any(
        waiver.rule_id not in ids for waiver in settings.waivers
    ):
        raise ValueError("Rule settings reference an unknown or deferred rule ID.")
    resources = {instance.resource_id.casefold() for instance in snapshot.instances}
    if any(
        waiver.resource_id and waiver.resource_id.casefold() not in resources
        for waiver in settings.waivers
    ):
        raise ValueError("A resource-scoped waiver does not match the snapshot.")


def scores(findings: list[Finding]) -> list[PillarScore]:
    result: list[PillarScore] = []
    for pillar in PILLARS:
        all_selected = [finding for finding in findings if finding.rule.pillar == pillar]
        selected = [finding for finding in all_selected if finding.waiver_justification is None]
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
                waived=len(all_selected) - len(selected),
            )
        )
    return result


def mcsb_coverage(findings: list[Finding]) -> list[McsbCoverage]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        for control in set(finding.rule.mcsb_controls):
            groups.setdefault((finding.resource_id, control), []).append(finding)
    rows = []
    for (identifier, control), selected in sorted(groups.items()):
        evaluated = [finding for finding in selected if finding.waiver_justification is None]
        outcomes = [finding.result.outcome for finding in evaluated]
        waived = len(selected) - len(evaluated)
        rows.append(
            McsbCoverage(
                resource_id=identifier,
                control=control,
                status=(
                    "fail"
                    if "fail" in outcomes
                    else "warning"
                    if waived or any(outcome in {"unknown", "unsupported"} for outcome in outcomes)
                    else "pass"
                    if "pass" in outcomes
                    else "not_applicable"
                ),
                rule_ids=sorted(finding.rule.id for finding in selected),
                passed=outcomes.count("pass"),
                failed=outcomes.count("fail"),
                unknown=outcomes.count("unknown"),
                unsupported=outcomes.count("unsupported"),
                not_applicable=outcomes.count("not_applicable"),
                waived=waived,
            )
        )
    return rows


def mcsb_score(rows: list[McsbCoverage]) -> float | None:
    known = [row for row in rows if row.status in {"pass", "fail"}]
    return (
        round(100 * sum(row.status == "pass" for row in known) / len(known), 1) if known else None
    )


def evaluate_rule(rule: Rule, context: Context, rows: list[PolicyCoverage]) -> Evaluation:
    instance, snapshot = context.instance, context.snapshot
    if instance.core_status != "available":
        return Evaluation(outcome="unknown", summary="Core collection is unavailable.")
    if rule.evaluator in BINDINGS:
        return evaluate(rule.evaluator, instance, context.views, rows)
    if rule.evaluator in CATALOG_CHECKS:
        return CATALOG_CHECKS[rule.evaluator](context)
    if rule.evaluator == "low_capacity":
        return low_capacity(instance, snapshot, low_pct=context.thresholds.capacity_low_pct)
    if rule.evaluator == "saturation":
        return saturation(
            instance,
            snapshot,
            warning_pct=context.thresholds.capacity_warning_pct,
            maximum_pct=context.thresholds.capacity_max_pct,
        )
    return EVALUATORS[rule.evaluator](instance, snapshot)


def analyze(snapshot: Snapshot, settings: RuleSettings | None = None) -> PortfolioAssessment:
    settings = settings or RuleSettings()
    validate_settings(settings, snapshot)
    findings: list[Finding] = []
    policy_coverage: list[PolicyCoverage] = []
    rules = load_rules()
    for instance in snapshot.instances:
        views = resolve(instance)
        rows = [coverage(instance, view) for view in views]
        policy_coverage.extend(rows)
        context = Context(instance, snapshot, views, settings.thresholds)
        for rule in rules:
            result = evaluate_rule(rule, context, rows)
            matching = [
                waiver
                for waiver in settings.waivers
                if waiver.rule_id == rule.id
                and (
                    waiver.resource_id is None
                    or waiver.resource_id.casefold() == instance.resource_id.casefold()
                )
            ]
            matching.sort(key=lambda waiver: waiver.resource_id is not None, reverse=True)
            findings.append(
                Finding(
                    resource_id=instance.resource_id,
                    environment=instance.environment,
                    rule=rule,
                    severity=settings.severity_overrides.get(
                        rule.id,
                        (
                            rule.severity
                            if instance.environment == "prod"
                            else rule.non_prod_severity
                        ),
                    ),
                    result=result,
                    waiver_justification=matching[0].justification if matching else None,
                )
            )
    controls = mcsb_coverage(findings)
    return PortfolioAssessment(
        snapshot_digest=digest(snapshot),
        findings=findings,
        pillar_scores=scores(findings),
        policy_coverage=policy_coverage,
        rule_settings=settings,
        mcsb_coverage=controls,
        mcsb_assessed_score=mcsb_score(controls),
    )
