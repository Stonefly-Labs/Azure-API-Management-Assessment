from html.parser import HTMLParser

import pytest

from apim_assess.analyzer.engine import analyze
from apim_assess.reporting.generator import render


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.external_runtime = []
        self.options = []
        self.svg_count = 0
        self.script_sources = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in {"script", "link", "img", "iframe", "object"}:
            if attributes.get("src") or attributes.get("href") or attributes.get("data"):
                self.external_runtime.append((tag, attrs))
        if tag == "option":
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
    with pytest.raises(ValueError, match="every seed rule"):
        render(snapshot, assessment)
