from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from apim_assess.analyzer.engine import analyze
from apim_assess.artifacts import digest, write_model, write_text
from apim_assess.collector.apim_core import collect
from apim_assess.mcp.models import Event, Work
from apim_assess.mcp.service import ServiceError, Workspace, safe_counts
from apim_assess.reporting.generator import render


async def execute(work: Work, emit: Callable[[Event], None]) -> None:
    workspace = Workspace(Path(work.workspace))
    output = workspace.path(work.output, directory=True)
    output.mkdir(parents=True, exist_ok=False)
    artifacts: dict[str, str] = {}

    def saved(name: str) -> str:
        return str(workspace.path(work.output + "/" + name).relative_to(workspace.root))

    def destination(name: str) -> Path:
        return workspace.path(work.output + "/" + name, directory=True)

    snapshot = workspace.snapshot(work.snapshot) if work.snapshot else None
    assessment = workspace.assessment(work.findings) if work.findings else None
    if work.operation in {"collect", "assess"}:
        if not work.config.targets.instances and not work.config.targets.subscriptions:
            raise ServiceError("TARGETS_REQUIRED")
        emit(Event(stage="collect"))
        snapshot = await collect(work.config)
        write_model(destination("snapshot.json"), snapshot)
        artifacts["snapshot"] = saved("snapshot.json")
        emit(Event(stage="collect", artifacts=artifacts, warnings=snapshot.collection_warnings))
        if not any(item.core_status == "available" for item in snapshot.instances):
            code = (
                "AUTHENTICATION_FAILED"
                if any(
                    item.code == "AUTHENTICATION_FAILED" for item in snapshot.collection_warnings
                )
                else "NO_READABLE_INSTANCES"
            )
            raise ServiceError(code)
    if work.operation in {"analyze", "assess"}:
        if snapshot is None:
            raise ServiceError("SNAPSHOT_REQUIRED")
        emit(Event(stage="analyze", artifacts=artifacts))
        assessment = analyze(snapshot, work.config.rules)
        write_model(destination("findings.json"), assessment)
        artifacts["findings"] = saved("findings.json")
    if work.operation in {"report", "assess"}:
        if snapshot is None or assessment is None:
            raise ServiceError("ARTIFACTS_REQUIRED")
        if digest(snapshot) != assessment.snapshot_digest:
            raise ServiceError("DIGEST_MISMATCH")
        emit(Event(stage="report", artifacts=artifacts))
        write_text(destination("apim-assessment-report.html"), render(snapshot, assessment))
        artifacts["report"] = saved("apim-assessment-report.html")
    emit(
        Event(
            stage="done",
            artifacts=artifacts,
            summary=safe_counts(assessment) if assessment is not None else {},
            pillar_scores=assessment.pillar_scores if assessment is not None else [],
            mcsb_assessed_score=assessment.mcsb_assessed_score if assessment is not None else None,
            warnings=snapshot.collection_warnings if snapshot is not None else [],
        )
    )


def main() -> None:
    logging.disable(logging.CRITICAL)

    def emit(event: Event) -> None:
        print(event.model_dump_json(), flush=True)

    try:
        work = Work.model_validate_json(sys.stdin.buffer.read())
        asyncio.run(execute(work, emit))
    except ServiceError as exc:
        emit(Event(stage="done", error_code=str(exc)))
    except (ValidationError, ValueError):
        emit(Event(stage="done", error_code="INVALID_ARTIFACT_OR_CONFIG"))
    except OSError:
        emit(Event(stage="done", error_code="FILE_UNAVAILABLE"))
    except Exception:
        # Worker exceptions are observable, but must never disclose input/Azure bodies.
        emit(Event(stage="done", error_code="WORKER_FAILED"))


if __name__ == "__main__":
    main()
