from html.parser import HTMLParser

import pytest

from apim_assess.analyzer.engine import analyze
from apim_assess.models.findings import Evidence
from apim_assess.models.policy import PolicyCoverage
from apim_assess.reporting.generator import (
    confidence,
    evidence_patterns,
    group_findings,
    outcome_counts,
    policy_summary,
    render,
)


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external_runtime = []
        self.options = []
        self.svg_count = 0
        self.script_sources = []
        self.scope_select = False
        self.ids = []
        self.views = []
        self.rules = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if "data-view" in attributes:
            self.views.append(attributes["data-view"])
        if "data-rule" in attributes:
            self.rules.append(attributes["data-rule"])
        if tag in {"script", "link", "img", "iframe", "object"}:
            if attributes.get("src") or attributes.get("href") or attributes.get("data"):
                self.external_runtime.append((tag, attrs))
        if tag == "select":
            self.scope_select = attributes.get("id") == "scope-select"
        if tag == "option" and self.scope_select:
            self.options.append(attributes.get("value"))
        if tag == "svg":
            self.svg_count += 1
        if tag == "script":
            self.script_sources.append(attributes.get("src"))


def test_self_contained_multi_instance_deck(snapshot):
    assessment = analyze(snapshot)
    html = render(snapshot, assessment)
    parser = ReportParser()
    parser.feed(html)
    assert parser.external_runtime == []
    assert len(parser.options) == 4
    assert parser.svg_count == 6  # portfolio plus individual views
    for instance in snapshot.instances:
        assert instance.resource_id in html
    for result in assessment.findings:
        assert result.rule.id in html
    assert "Not assessed; not a healthy score." in html
    assert "SYNTHETIC_PARTIAL_DATA" in html


def test_untrusted_names_evidence_and_urls_are_safe(snapshot):
    snapshot.instances[0].name = '</script><img src=x onerror="alert(1)">'
    assessment = analyze(snapshot)
    assessment.findings[0].result.summary = "<svg onload=alert(1)>"
    html = render(snapshot, assessment)
    assert '<img src=x onerror="alert(1)">' not in html
    assert "&lt;svg onload=alert(1)&gt;" in html
    assert "&lt;/script&gt;" in html
    assessment.findings[0].rule.references = ["javascript:alert(1)"]
    with pytest.raises(ValueError, match="HTTPS Microsoft Learn"):
        render(snapshot, assessment)


def test_mismatched_artifacts_and_duplicate_findings_are_rejected(snapshot):
    assessment = analyze(snapshot)
    changed = snapshot.model_copy(deep=True)
    changed.instances[0].environment = "non-prod"
    with pytest.raises(ValueError, match="exact snapshot"):
        render(changed, assessment)
    assessment.findings.append(assessment.findings[0])
    with pytest.raises(ValueError, match="duplicate"):
        render(snapshot, assessment)


def test_inconsistent_scores_are_rejected(snapshot):
    assessment = analyze(snapshot)
    assessment.pillar_scores[0].score = -1
    with pytest.raises(ValueError, match="scores"):
        render(snapshot, assessment)


def test_missing_rule_results_are_not_reported_as_coverage(snapshot):
    assessment = analyze(snapshot)
    assessment.findings.pop()
    with pytest.raises(ValueError, match="every catalog rule"):
        render(snapshot, assessment)


def test_stored_control_rollups_are_checked(snapshot):
    assessment = analyze(snapshot)
    assessment.mcsb_coverage[0].status = "pass"
    assessment.mcsb_coverage[0].passed += 1
    with pytest.raises(ValueError, match="MCSB coverage"):
        render(snapshot, assessment)


def test_waiver_html_is_escaped_and_explorer_uses_text_not_markup(snapshot):
    from apim_assess.models.findings import RuleSettings, Waiver

    assessment = analyze(
        snapshot,
        RuleSettings(
            waivers=[
                Waiver(rule_id="APIM-REL-001", justification='<img src=x onerror="alert(1)">'),
            ]
        ),
    )
    html = render(snapshot, assessment)
    assert '<img src=x onerror="alert(1)">' not in html
    assert "&lt;img" in html
    assert "result.textContent.toLowerCase().includes(search)" in html
    assert ".innerHTML" not in html


def test_focused_report_groups_each_rule_and_preserves_artifacts(snapshot):
    assessment = analyze(snapshot)
    original = assessment.model_dump_json()
    html = render(snapshot, assessment)
    parser = ReportParser()
    parser.feed(html)
    assert parser.views == ["overview", "findings", "gaps", "roadmap", "mcsb", "policy", "method"]
    assert len(parser.ids) == len(set(parser.ids))
    for rule in {finding.rule.id for finding in assessment.findings}:
        assert parser.rules.count(rule) == len(snapshot.instances) + 1
    assert 'data-mode="focused"' in html
    assert assessment.model_dump_json() == original
    assert render(snapshot, assessment) == html


def test_grouping_keeps_mixed_outcomes_and_excludes_waivers_from_confidence(snapshot):
    base = analyze(snapshot).findings[0]
    rows = [base.model_copy(deep=True) for _ in range(3)]
    for row, instance in zip(rows, snapshot.instances, strict=True):
        row.resource_id = instance.resource_id
    rows[0].result.outcome = "fail"
    rows[0].severity = "Critical"
    rows[1].result.outcome = "unknown"
    rows[2].result.outcome = "fail"
    rows[2].waiver_justification = "Accepted for testing"
    groups = group_findings(rows)
    assert len(groups) == 1
    assert groups[0]["outcome"] == "fail"
    assert [row.result.outcome for row in groups[0]["findings"]] == ["fail", "unknown", "fail"]
    assert group_findings(list(reversed(rows))) == groups
    assert outcome_counts(rows) == {
        "fail": 1,
        "unknown": 1,
        "unsupported": 0,
        "pass": 0,
        "waived": 1,
        "not_applicable": 0,
    }
    assert confidence(rows) == 50
    rows[0].result.outcome = "not_applicable"
    rows[1].result.outcome = "unsupported"
    assert confidence(rows) == 0
    rows[1].result.outcome = "not_applicable"
    assert confidence(rows) is None


def test_evidence_patterns_preserve_all_sources_paths_and_escaping(snapshot):
    assessment = analyze(snapshot)
    evidence = [
        Evidence(
            source=f"source-{index}",
            detail='<script>alert("pattern")</script>',
            api_path=f"apis/orders/operations/{index}",
        )
        for index in range(405)
    ]
    assessment.findings[0].result.evidence = evidence
    patterns = evidence_patterns(evidence)
    assert len(patterns) == 1 and patterns[0]["items"] == evidence
    html = render(snapshot, assessment)
    assert "405 items" in html
    assert "source-404" in html and "apis/orders/operations/404" in html
    assert '<script>alert("pattern")</script>' not in html
    assert "&lt;script&gt;" in html


def test_policy_api_rollups_preserve_distinct_product_and_operation_contexts():
    base = PolicyCoverage(
        resource_id="instance",
        api_path="apis/orders",
        operation_path="apis/orders/operations/get",
        product_path=None,
        subscription_required=True,
        authentication="present",
        jwt="present",
        rate_limit="absent",
        inheritance="present",
        cors="not_applicable",
        backend="unknown",
    )
    product = base.model_copy(update={"product_path": "products/public", "jwt": "unknown"})
    other_operation = base.model_copy(update={"operation_path": "apis/orders/operations/post"})
    rows = [base, product, other_operation]
    summary = policy_summary(rows)
    assert len(summary) == 1
    assert summary[0]["operations"] == 2
    assert summary[0]["rows"] == rows
    assert summary[0]["counts"]["jwt"] == {"present": 2, "unknown": 1}
    assert summary[0]["counts"]["rate_limit"] == {"absent": 3}
