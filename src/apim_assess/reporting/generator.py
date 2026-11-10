from importlib.resources import files
from typing import TypedDict
from urllib.parse import urlsplit

from jinja2 import Environment, StrictUndefined

from apim_assess.analyzer.engine import EVALUATORS, load_rules, scores
from apim_assess.analyzer.evaluators.policy import coverage
from apim_assess.analyzer.policy_resolver import resolve
from apim_assess.artifacts import digest
from apim_assess.models.findings import Finding, PillarScore, PortfolioAssessment
from apim_assess.models.policy import PolicyCoverage
from apim_assess.models.snapshot import Instance, Snapshot


class ReportScope(TypedDict):
    title: str
    portfolio: bool
    instances: list[Instance]
    findings: list[Finding]
    scores: list[PillarScore]
    policy_coverage: list[PolicyCoverage]


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
        if assessment.schema_version != "1.0" or rule.evaluator in EVALUATORS
    ]
    expected = {(identifier, rule.id) for identifier in identities for rule in rules}
    if set(pairs) != expected:
        raise ValueError("Findings must contain every catalog rule for every snapshot instance.")
    if assessment.schema_version != "1.0" and assessment.policy_coverage != [
        coverage(instance, view) for instance in snapshot.instances for view in resolve(instance)
    ]:
        raise ValueError("Policy coverage does not match the snapshot.")
    if any(
        finding.environment != identities[finding.resource_id].environment
        for finding in assessment.findings
    ):
        raise ValueError("Finding environments do not match the snapshot.")
    if assessment.pillar_scores != scores(assessment.findings):
        raise ValueError("Stored pillar scores do not agree with the findings.")
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
            }
        )
    environment = Environment(autoescape=True, undefined=StrictUndefined)
    template = files("apim_assess").joinpath("reporting", "templates", "report_deck.html.j2")
    return environment.from_string(template.read_text(encoding="utf-8")).render(
        snapshot=snapshot,
        scopes=scopes,
        metric_summary=metric_summary,
        legacy=assessment.schema_version == "1.0",
    )
