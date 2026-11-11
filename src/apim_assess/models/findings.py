from typing import Literal

from pydantic import Field, field_validator, model_validator

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
    api_path: str | None = None


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
    waiver_justification: str | None = None


class PillarScore(Model):
    pillar: Pillar
    score: float | None
    passed: int
    failed: int
    unknown: int
    unsupported: int
    not_applicable: int
    waived: int = 0


class Thresholds(Model):
    capacity_low_pct: float = Field(default=25.0, ge=0, le=100)
    capacity_warning_pct: float = Field(default=70.0, ge=0, le=100)
    capacity_max_pct: float = Field(default=85.0, ge=0, le=100)
    cert_expiry_days: int = Field(default=30, ge=1, le=365)
    app_insights_max_sampling_pct: float = Field(default=50.0, ge=0, le=100)
    diagnostic_body_bytes: int = Field(default=1024, ge=0, le=8192)
    payload_max_bytes: int = Field(default=102400, ge=1, le=4194304)
    backend_latency_ms: float = Field(default=2000.0, gt=0, le=300000)
    gateway_error_pct: float = Field(default=1.0, ge=0, le=100)
    policy_max_age_days: int = Field(default=2, ge=1, le=30)


class Waiver(Model):
    rule_id: str = Field(pattern=r"^APIM-(REL|SEC|COST|OPS|PERF|AIGW)-[0-9]{3}$")
    justification: str = Field(min_length=1, max_length=2000)
    resource_id: ResourceId | None = None

    @field_validator("justification")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("A waiver requires a nonblank justification")
        return value.strip()


class RuleSettings(Model):
    waivers: list[Waiver] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    thresholds: Thresholds = Field(default_factory=Thresholds)

    @model_validator(mode="after")
    def unique_waivers(self) -> "RuleSettings":
        keys = [
            (waiver.rule_id, waiver.resource_id.casefold() if waiver.resource_id else None)
            for waiver in self.waivers
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate rule/resource waiver")
        return self


class McsbCoverage(Model):
    resource_id: ResourceId
    control: str
    status: Literal["pass", "fail", "warning", "not_applicable"]
    rule_ids: list[str]
    passed: int
    failed: int
    unknown: int
    unsupported: int
    not_applicable: int
    waived: int


class Narrative(Model):
    status: Literal["complete", "unavailable"]
    text: str | None = Field(default=None, min_length=1, max_length=4000)
    error_code: str | None = None

    @model_validator(mode="after")
    def consistent_status(self) -> "Narrative":
        if self.status == "complete":
            if self.text is None or self.error_code is not None:
                raise ValueError("Complete narratives require text and no error")
        elif self.text is not None or self.error_code is None:
            raise ValueError("Unavailable narratives require an explicit error and no text")
        return self


class PortfolioAssessment(Model):
    schema_version: Literal["1.0", "1.1", "1.2", "1.3", "1.4"] = "1.4"
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    findings: list[Finding]
    pillar_scores: list[PillarScore]
    policy_coverage: list[PolicyCoverage] = Field(default_factory=list)
    rule_settings: RuleSettings = Field(default_factory=RuleSettings)
    mcsb_coverage: list[McsbCoverage] = Field(default_factory=list)
    mcsb_assessed_score: float | None = Field(default=None, ge=0, le=100)
    narrative: Narrative | None = None

    @model_validator(mode="after")
    def consistent_version(self) -> "PortfolioAssessment":
        if self.schema_version != "1.4" and self.narrative is not None:
            raise ValueError("Narrative enrichment requires findings schema 1.4")
        if self.schema_version == "1.0" and self.policy_coverage:
            raise ValueError("Policy coverage requires findings schema 1.1")
        if self.schema_version in {"1.0", "1.1"} and (
            self.rule_settings != RuleSettings()
            or self.mcsb_coverage
            or self.mcsb_assessed_score is not None
            or any(finding.waiver_justification is not None for finding in self.findings)
        ):
            raise ValueError("Rule settings, waivers and MCSB coverage require findings schema 1.2")
        return self
