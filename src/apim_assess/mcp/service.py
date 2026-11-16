from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import yaml
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from apim_assess.analyzer.engine import load_rules
from apim_assess.config import AssessmentConfig
from apim_assess.mcp.models import Cursor, Filters, FindingsPage
from apim_assess.models.findings import PortfolioAssessment, Rule
from apim_assess.models.snapshot import Snapshot

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_PAGE_BYTES = 256 * 1024


class ServiceError(ToolError):
    """Public error codes only, never exception bodies from input or Azure."""


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ServiceError("INVALID_WORKSPACE")

    def path(self, reference: str, *, directory: bool = False) -> Path:
        if not reference or "\x00" in reference:
            raise ServiceError("PATH_DENIED")
        candidate = Path(reference)
        if candidate.is_absolute() or candidate.drive or ".." in candidate.parts:
            raise ServiceError("PATH_DENIED")
        resolved = (self.root / candidate).resolve()
        if not resolved.is_relative_to(self.root) or resolved == self.root:
            raise ServiceError("PATH_DENIED")
        if directory:
            if resolved.exists():
                raise ServiceError("OUTPUT_EXISTS")
        elif not resolved.is_file():
            raise ServiceError("FILE_UNAVAILABLE")
        return resolved

    def read(self, reference: str) -> str:
        path = self.path(reference)
        try:
            with path.open("rb") as stream:
                content = stream.read(MAX_ARTIFACT_BYTES + 1)
            if len(content) > MAX_ARTIFACT_BYTES:
                raise ServiceError("ARTIFACT_TOO_LARGE")
            return content.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ServiceError("FILE_UNAVAILABLE") from exc

    def config(self, reference: str | None, settings: AssessmentConfig | None) -> AssessmentConfig:
        if reference and settings is not None:
            raise ServiceError("CONFIG_CONFLICT")
        try:
            config = (
                AssessmentConfig.model_validate(yaml.safe_load(self.read(reference)))
                if reference
                else (settings or AssessmentConfig())
            )
        except (ValueError, OSError, yaml.YAMLError) as exc:
            raise ServiceError("INVALID_CONFIG") from exc
        if config.ai_enrichment is not None:
            raise ServiceError("AI_ENRICHMENT_NOT_SUPPORTED")
        return config

    def snapshot(self, reference: str) -> Snapshot:
        try:
            return Snapshot.model_validate_json(self.read(reference))
        except ValidationError as exc:
            raise ServiceError("INVALID_SNAPSHOT") from exc

    def assessment(self, reference: str) -> PortfolioAssessment:
        try:
            return PortfolioAssessment.model_validate_json(self.read(reference))
        except ValidationError as exc:
            raise ServiceError("INVALID_FINDINGS") from exc

    def query(
        self, reference: str, filters: Filters, page_size: int, cursor: str | None
    ) -> FindingsPage:
        if not 1 <= page_size <= 100:
            raise ServiceError("INVALID_PAGE_SIZE")
        content = self.read(reference)
        content_digest = hashlib.sha256(content.encode()).hexdigest()
        offset = 0
        if cursor:
            try:
                if len(cursor) > 4096:
                    raise ValueError
                saved = Cursor.model_validate_json(base64.urlsafe_b64decode(cursor).decode())
            except (ValueError, UnicodeError) as exc:
                raise ServiceError("INVALID_CURSOR") from exc
            if saved.digest != content_digest or saved.filters != filters:
                raise ServiceError("STALE_CURSOR")
            offset = saved.offset
        try:
            assessment = PortfolioAssessment.model_validate_json(content)
        except ValidationError as exc:
            raise ServiceError("INVALID_FINDINGS") from exc
        selected = [
            finding
            for finding in assessment.findings
            if (
                filters.resource_id is None
                or finding.resource_id.casefold() == filters.resource_id.casefold()
            )
            and (filters.pillar is None or finding.rule.pillar == filters.pillar)
            and (filters.severity is None or finding.severity == filters.severity)
            and (filters.outcome is None or finding.result.outcome == filters.outcome)
            and (
                filters.waived is None
                or (finding.waiver_justification is not None) == filters.waived
            )
            and (filters.rule_id is None or finding.rule.id == filters.rule_id)
        ]
        selected.sort(key=lambda item: (item.resource_id.casefold(), item.rule.id))
        if offset > len(selected):
            raise ServiceError("INVALID_CURSOR")
        page = selected[offset : offset + page_size]
        if sum(len(item.model_dump_json().encode()) for item in page) > MAX_PAGE_BYTES:
            raise ServiceError("RESPONSE_TOO_LARGE: reduce page_size or narrow filters")
        following = offset + len(page)
        return FindingsPage(
            total=len(selected),
            findings=page,
            next_cursor=base64.urlsafe_b64encode(
                Cursor(digest=content_digest, filters=filters, offset=following)
                .model_dump_json()
                .encode()
            ).decode()
            if following < len(selected)
            else None,
        )


def explain(rule_id: str) -> Rule:
    for rule in load_rules():
        if rule.id == rule_id:
            return rule
    raise ServiceError("UNKNOWN_RULE")


def safe_counts(assessment: PortfolioAssessment) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in assessment.findings:
        outcome = "waived" if finding.waiver_justification is not None else finding.result.outcome
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts
