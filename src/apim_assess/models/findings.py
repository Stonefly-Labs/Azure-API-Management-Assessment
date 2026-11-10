from typing import Literal

from pydantic import Field, model_validator

from apim_assess.models.policy import PolicyCoverage
from apim_assess.models.snapshot import Environment, Model, ResourceId

Pillar = Literal["REL", "SEC", "COST", "OPS", "PERF"]
Severity = Literal["Critical", "High", "Medium", "Low", "Advisory"]
Outcome = Literal["pass", "fail", "unknown", "unsupported", "not_applicable"]
PILLARS: tuple[Pillar, ...] = ("REL", "SEC", "COST", "OPS", "PERF")


class Rule(Model):
    id: str
    title: str
    pillar: Pillar
    mcsb_controls: list[str] = Field(default_factory=list)
    severity: Severity
    non_prod_severity: Severity
    applicability: str
    required_signals: list[str]
    description: str
    business_impact: str
    remediation: str
    references: list[str]
    evaluator: str


class Evidence(Model):
    source: str
    detail: str


class Evaluation(Model):
    outcome: Outcome
    summary: str
    evidence: list[Evidence] = Field(default_factory=list)


class Finding(Model):
    resource_id: ResourceId
    environment: Environment
    rule: Rule
    severity: Severity
    result: Evaluation


class PillarScore(Model):
    pillar: Pillar
    score: float | None
    passed: int
    failed: int
    unknown: int
    unsupported: int
    not_applicable: int


class PortfolioAssessment(Model):
    schema_version: Literal["1.0", "1.1"] = "1.1"
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    findings: list[Finding]
    pillar_scores: list[PillarScore]
    policy_coverage: list[PolicyCoverage] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_version(self) -> "PortfolioAssessment":
        if self.schema_version == "1.0" and self.policy_coverage:
            raise ValueError("Policy coverage requires findings schema 1.1")
        return self
