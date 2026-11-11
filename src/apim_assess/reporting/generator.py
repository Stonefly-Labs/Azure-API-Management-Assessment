from collections import Counter, defaultdict
from importlib.resources import files
from typing import TypedDict
from urllib.parse import urlsplit

from jinja2 import Environment, StrictUndefined

from apim_assess.analyzer.engine import (
    ITERATION_2_IDS,
    ITERATION_4_IDS,
    ITERATION_5_IDS,
    SEED_IDS,
    load_rules,
    mcsb_coverage,
    mcsb_score,
    scores,
    validate_settings,
)
from apim_assess.analyzer.evaluators.policy import coverage
from apim_assess.analyzer.policy_resolver import resolve
from apim_assess.artifacts import digest
from apim_assess.models.findings import (
    Evidence,
    Finding,
    McsbCoverage,
    PillarScore,
    PortfolioAssessment,
    Rule,
    Severity,
)
from apim_assess.models.policy import PolicyCoverage
from apim_assess.models.snapshot import Instance, Snapshot
from apim_assess.reporting.trends import telemetry_charts

OUTCOMES = ("fail", "unknown", "unsupported", "pass", "waived", "not_applicable")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Advisory")
POLICY_CONTROLS = {
    "authentication": "Caller authentication",
    "jwt": "JWT / Entra",
    "rate_limit": "Rate / concurrency",
    "inheritance": "Base inheritance",
    "cors": "CORS wildcard check",
    "backend": "Backend entity",
}


class FindingGroup(TypedDict):
    rule: Rule
    findings: list[Finding]
    outcome: str
    severity: Severity


class EvidencePattern(TypedDict):
    detail: str
    items: list[Evidence]


class PolicySummary(TypedDict):
    resource_id: str
    api_path: str
    operations: int
    rows: list[PolicyCoverage]
    counts: dict[str, dict[str, int]]


def display_outcome(finding: Finding) -> str:
    return "waived" if finding.waiver_justification is not None else finding.result.outcome


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.rule.id].append(finding)
    result: list[FindingGroup] = []
    for rows in grouped.values():
        rows = sorted(
            rows,
            key=lambda finding: (
                OUTCOMES.index(display_outcome(finding)),
                SEVERITIES.index(finding.severity),
                finding.resource_id.casefold(),
            ),
        )
        result.append(
            {
                "rule": rows[0].rule,
                "findings": rows,
                "outcome": display_outcome(rows[0]),
                "severity": rows[0].severity,
            }
        )
    return sorted(
        result,
        key=lambda group: (
            OUTCOMES.index(group["outcome"]),
            SEVERITIES.index(group["severity"]),
            SEVERITIES.index(group["rule"].severity),
            group["rule"].id,
        ),
    )


def evidence_patterns(evidence: list[Evidence]) -> list[EvidencePattern]:
    grouped: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        grouped[item.detail].append(item)
    return [{"detail": detail, "items": items} for detail, items in grouped.items()]


def policy_summary(rows: list[PolicyCoverage]) -> list[PolicySummary]:
    grouped: dict[tuple[str, str], list[PolicyCoverage]] = defaultdict(list)
    for row in rows:
        grouped[row.resource_id, row.api_path].append(row)
    return [
        {
            "resource_id": resource_id,
            "api_path": api_path,
            "operations": len({row.operation_path for row in contexts if row.operation_path}),
            "rows": contexts,
            "counts": {
                control: dict(Counter(getattr(row, control) for row in contexts))
                for control in POLICY_CONTROLS
            },
        }
        for (resource_id, api_path), contexts in sorted(grouped.items())
    ]


def outcome_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(display_outcome(finding) for finding in findings)
    return {outcome: counts[outcome] for outcome in OUTCOMES}


def confidence(findings: list[Finding]) -> float | None:
    counts = outcome_counts(findings)
    applicable = sum(counts[key] for key in ("fail", "pass", "unknown", "unsupported"))
    return round(100 * (counts["fail"] + counts["pass"]) / applicable, 1) if applicable else None


class ReportScope(TypedDict):
    title: str
    portfolio: bool
    instances: list[Instance]
    findings: list[Finding]
    scores: list[PillarScore]
    policy_coverage: list[PolicyCoverage]
    mcsb_coverage: list[McsbCoverage]
    mcsb_score: float | None
    controls: list[str]
    apis: list[str]


def roadmap(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    phases = [
        ("Quick wins / 0-30 days", {"Critical", "High"}),
        ("Short-term / 30-60 days", {"Medium"}),
        ("Strategic / 60-90+ days", {"Low", "Advisory"}),
    ]
    return [
        (
            title,
            sorted(
                (
                    finding
                    for finding in findings
                    if finding.result.outcome == "fail"
                    and finding.waiver_justification is None
                    and finding.severity in severities
                ),
                key=lambda finding: (
                    {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Advisory": 4}[
                        finding.severity
                    ],
                    finding.rule.id,
                    finding.resource_id.casefold(),
                ),
            ),
        )
        for title, severities in phases
    ]


def finding_apis(finding: Finding) -> list[str]:
    return sorted({evidence.api_path for evidence in finding.result.evidence if evidence.api_path})


def metric_summary(instance: Instance) -> list[dict[str, str]]:
    rows = []
    for series in instance.metrics:
        averages = [point.average for point in series.points if point.average is not None]
        maxima = [point.maximum for point in series.points if point.maximum is not None]
        totals = [point.total for point in series.points if point.total is not None]
        rows.append(
            {
                "name": series.name,
                "location": series.location or "service",
                "dimensions": ", ".join(
                    f"{name}={value}" for name, value in series.dimensions.items()
                ),
                "status": series.status,
                "samples": str(len(series.points)),
                "average": f"{sum(averages) / len(averages):.2f}" if averages else "Not collected",
                "maximum": f"{max(maxima):.2f}" if maxima else "Not collected",
                "total": f"{sum(totals):.0f}" if totals else "Not collected",
                "unit": series.unit or "",
            }
        )
    return rows


def render(snapshot: Snapshot, assessment: PortfolioAssessment) -> str:
    if assessment.snapshot_digest != digest(snapshot):
        raise ValueError("Findings do not belong to this exact snapshot; rerun analyze.")
    identities = {instance.resource_id: instance for instance in snapshot.instances}
    pairs = [(finding.resource_id, finding.rule.id) for finding in assessment.findings]
    if len(set(pairs)) != len(pairs) or any(
        identifier not in identities for identifier, _ in pairs
    ):
        raise ValueError("Findings contain duplicate or out-of-scope resources.")
    rules = [
        rule
        for rule in load_rules()
        if assessment.schema_version == "1.4"
        or (
            rule.id not in ITERATION_5_IDS
            and (assessment.schema_version == "1.3" or rule.id not in ITERATION_4_IDS)
            if assessment.schema_version in {"1.2", "1.3"}
            else rule.id in (SEED_IDS if assessment.schema_version == "1.0" else ITERATION_2_IDS)
        )
    ]
    expected = {(identifier, rule.id) for identifier in identities for rule in rules}
    if set(pairs) != expected:
        raise ValueError("Findings must contain every catalog rule for every snapshot instance.")
    if assessment.schema_version != "1.0":
        # Preserve historical interpretations, but still verify every context's provenance.
        historical_controls = (
            {"authentication", "jwt", "rate_limit", "cors", "backend"}
            if assessment.schema_version == "1.1"
            else set()
        )
        actual_policy = [
            row.model_dump(exclude=historical_controls) for row in assessment.policy_coverage
        ]
        expected_policy = [
            coverage(instance, view).model_dump(exclude=historical_controls)
            for instance in snapshot.instances
            for view in resolve(instance)
        ]
        if actual_policy != expected_policy:
            raise ValueError("Policy coverage does not match the snapshot.")
    if any(
        finding.environment != identities[finding.resource_id].environment
        for finding in assessment.findings
    ):
        raise ValueError("Finding environments do not match the snapshot.")
    if assessment.pillar_scores != scores(assessment.findings):
        raise ValueError("Stored pillar scores do not agree with the findings.")
    if assessment.schema_version in {"1.2", "1.3", "1.4"}:
        validate_settings(assessment.rule_settings, snapshot)
        if assessment.mcsb_coverage != mcsb_coverage(assessment.findings) or (
            assessment.mcsb_assessed_score != mcsb_score(assessment.mcsb_coverage)
        ):
            raise ValueError("Stored MCSB coverage does not agree with the findings.")
        for finding in assessment.findings:
            matching = [
                waiver
                for waiver in assessment.rule_settings.waivers
                if waiver.rule_id == finding.rule.id
                and (
                    waiver.resource_id is None
                    or waiver.resource_id.casefold() == finding.resource_id.casefold()
                )
            ]
            matching.sort(key=lambda waiver: waiver.resource_id is not None, reverse=True)
            expected_waiver = matching[0].justification if matching else None
            expected_severity = assessment.rule_settings.severity_overrides.get(
                finding.rule.id,
                finding.rule.severity
                if finding.environment == "prod"
                else finding.rule.non_prod_severity,
            )
            if (
                finding.waiver_justification != expected_waiver
                or finding.severity != expected_severity
            ):
                raise ValueError("Finding grading does not agree with saved rule settings.")
    for finding in assessment.findings:
        for reference in finding.rule.references:
            parsed = urlsplit(reference)
            if parsed.scheme != "https" or parsed.netloc != "learn.microsoft.com":
                raise ValueError("Report references must be HTTPS Microsoft Learn URLs.")
    scopes: list[ReportScope] = [
        {
            "title": "Portfolio",
            "portfolio": True,
            "instances": snapshot.instances,
            "findings": assessment.findings,
            "scores": assessment.pillar_scores,
            "policy_coverage": assessment.policy_coverage,
            "mcsb_coverage": assessment.mcsb_coverage,
            "mcsb_score": assessment.mcsb_assessed_score,
            "controls": sorted({row.control for row in assessment.mcsb_coverage}),
            "apis": sorted(
                {api for finding in assessment.findings for api in finding_apis(finding)}
            ),
        }
    ]
    for instance in snapshot.instances:
        selected = [
            finding
            for finding in assessment.findings
            if finding.resource_id == instance.resource_id
        ]
        scopes.append(
            {
                "title": instance.name,
                "portfolio": False,
                "instances": [instance],
                "findings": selected,
                "scores": scores(selected),
                "policy_coverage": [
                    row
                    for row in assessment.policy_coverage
                    if row.resource_id == instance.resource_id
                ],
                "mcsb_coverage": [
                    row
                    for row in assessment.mcsb_coverage
                    if row.resource_id == instance.resource_id
                ],
                "mcsb_score": mcsb_score(
                    [
                        row
                        for row in assessment.mcsb_coverage
                        if row.resource_id == instance.resource_id
                    ]
                ),
                "controls": sorted(
                    {control for finding in selected for control in finding.rule.mcsb_controls}
                ),
                "apis": sorted({api for finding in selected for api in finding_apis(finding)}),
            }
        )
    environment = Environment(autoescape=True, undefined=StrictUndefined)
    template = files("apim_assess").joinpath("reporting", "templates", "report_deck.html.j2")
    return environment.from_string(template.read_text(encoding="utf-8")).render(
        snapshot=snapshot,
        scopes=scopes,
        metric_summary=metric_summary,
        telemetry_charts=telemetry_charts,
        telemetry_days=(snapshot.telemetry_end - snapshot.telemetry_start).total_seconds() / 86400,
        legacy=assessment.schema_version == "1.0",
        iteration={"1.0": "1", "1.1": "2", "1.2": "3", "1.3": "4", "1.4": "5"}[
            assessment.schema_version
        ],
        finding_apis=finding_apis,
        rule_settings=assessment.rule_settings,
        roadmap=roadmap,
        narrative=assessment.narrative,
        identities=identities,
        outcomes=OUTCOMES,
        severities=SEVERITIES,
        policy_controls=POLICY_CONTROLS,
        group_findings=group_findings,
        evidence_patterns=evidence_patterns,
        policy_summary=policy_summary,
        outcome_counts=outcome_counts,
        confidence=confidence,
        display_outcome=display_outcome,
        schema_version=assessment.schema_version,
        snapshot_digest=assessment.snapshot_digest,
    )
