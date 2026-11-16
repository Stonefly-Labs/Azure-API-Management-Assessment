from typing import Literal

from pydantic import Field

from apim_assess.config import AssessmentConfig
from apim_assess.models.findings import Finding, Pillar, PillarScore, Severity
from apim_assess.models.snapshot import CollectionWarning, Model

Operation = Literal["collect", "analyze", "report", "assess"]


class Work(Model):
    operation: Operation
    workspace: str
    output: str
    config: AssessmentConfig = Field(default_factory=AssessmentConfig)
    snapshot: str | None = None
    findings: str | None = None


class Job(Model):
    contract_version: Literal["1.0"] = "1.0"
    job_id: str
    state: Literal["running", "completed", "failed", "cancelled"] = "running"
    stage: str
    artifacts: dict[str, str] = Field(default_factory=dict)
    error_code: str | None = None
    summary: dict[str, int] = Field(default_factory=dict)
    pillar_scores: list[PillarScore] = Field(default_factory=list)
    mcsb_assessed_score: float | None = None
    warnings: list[CollectionWarning] = Field(default_factory=list)


class Event(Model):
    stage: Operation | Literal["done"]
    artifacts: dict[str, str] = Field(default_factory=dict)
    error_code: str | None = None
    summary: dict[str, int] = Field(default_factory=dict)
    pillar_scores: list[PillarScore] = Field(default_factory=list)
    mcsb_assessed_score: float | None = None
    warnings: list[CollectionWarning] = Field(default_factory=list)


class Filters(Model):
    resource_id: str | None = None
    pillar: Pillar | None = None
    severity: Severity | None = None
    outcome: Literal["pass", "fail", "unknown", "unsupported", "not_applicable"] | None = None
    waived: bool | None = None
    rule_id: str | None = None


class FindingsPage(Model):
    contract_version: Literal["1.0"] = "1.0"
    total: int
    findings: list[Finding]
    next_cursor: str | None = None


class Cursor(Model):
    digest: str
    filters: Filters
    offset: int = Field(ge=0)
