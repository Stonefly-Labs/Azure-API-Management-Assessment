from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console

from apim_assess.analyzer.engine import analyze
from apim_assess.artifacts import write_model, write_text
from apim_assess.collector.apim_core import collect
from apim_assess.config import AssessmentConfig, load_config
from apim_assess.models.findings import PortfolioAssessment
from apim_assess.models.snapshot import Profile, Snapshot
from apim_assess.reporting.generator import render

app = typer.Typer(
    no_args_is_help=True, help="Read-only APIM assessment. Iteration 1: five seed rules."
)
console = Console(highlight=False, markup=False)


@contextmanager
def input_errors() -> Iterator[None]:
    try:
        yield
    except ValidationError as exc:
        console.print(
            f"Invalid configuration or artifact schema ({exc.error_count()} issue(s)). "
            "Use the example configuration and matching schema-version artifacts."
        )
        raise typer.Exit(2) from exc
    except yaml.YAMLError as exc:
        console.print("Invalid YAML configuration. Check YAML syntax.")
        raise typer.Exit(2) from exc
    except OSError as exc:
        console.print("Cannot read or write the requested path. Check paths and permissions.")
        raise typer.Exit(2) from exc
    except ValueError as exc:
        console.print(str(exc))
        raise typer.Exit(2) from exc


def distinct_paths(*paths: Path | None) -> None:
    resolved = [str(path.resolve()).casefold() for path in paths if path is not None]
    if len(set(resolved)) != len(resolved):
        raise ValueError("Input and output paths must be different.")


def run_collect(config: AssessmentConfig, output: Path) -> Snapshot:
    snapshot = asyncio.run(collect(config))
    write_model(output, snapshot)
    console.print(
        f"Saved {output}: {len(snapshot.instances)} instance(s), "
        f"{len(snapshot.collection_warnings)} collection warning(s)."
    )
    for warning in snapshot.collection_warnings:
        console.print(f"Warning {warning.module}/{warning.code}: {warning.message}")
    if not any(instance.core_status == "available" for instance in snapshot.instances):
        console.print(
            "No readable APIM instances; partial snapshot saved. Check targets and access."
        )
        raise typer.Exit(2)
    return snapshot


def run_analyze(snapshot: Snapshot, output: Path) -> PortfolioAssessment:
    assessment = analyze(snapshot)
    write_model(output, assessment)
    console.print(f"Saved {output}: {len(assessment.findings)} rule result(s).")
    return assessment


def run_report(snapshot: Snapshot, assessment: PortfolioAssessment, output: Path) -> None:
    write_text(output, render(snapshot, assessment))
    console.print(f"Saved {output}.")


@app.command("collect")
def collect_command(
    resource_id: Annotated[list[str] | None, typer.Option("--resource-id")] = None,
    subscriptions: Annotated[list[str] | None, typer.Option("--subscriptions")] = None,
    resource_groups: Annotated[list[str] | None, typer.Option("--resource-groups")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    env: Annotated[Profile | None, typer.Option("--env")] = None,
    metrics: Annotated[bool | None, typer.Option("--metrics/--no-metrics")] = None,
    lookback_days: Annotated[int | None, typer.Option("--lookback-days", min=1, max=30)] = None,
    output: Annotated[Path, typer.Option("--output")] = Path("output/snapshot.json"),
) -> None:
    """Collect core service metadata and metrics from explicit Azure targets."""
    with input_errors():
        distinct_paths(config, output)
        settings = load_config(
            config,
            resource_id or [],
            subscriptions or [],
            resource_groups or [],
            env,
            metrics,
            lookback_days,
        )
        run_collect(settings, output)


@app.command("analyze")
def analyze_command(
    snapshot: Annotated[Path, typer.Option("--snapshot")],
    output: Annotated[Path, typer.Option("--output")] = Path("output/findings.json"),
) -> None:
    """Analyze a saved snapshot offline, without Azure credentials."""
    with input_errors():
        distinct_paths(snapshot, output)
        run_analyze(Snapshot.model_validate_json(snapshot.read_text(encoding="utf-8")), output)


@app.command("report")
def report_command(
    snapshot: Annotated[Path, typer.Option("--snapshot")],
    findings: Annotated[Path, typer.Option("--findings")],
    output: Annotated[Path, typer.Option("--output")] = Path("output/apim-assessment-report.html"),
) -> None:
    """Render matching saved artifacts to self-contained HTML offline."""
    with input_errors():
        distinct_paths(snapshot, findings, output)
        run_report(
            Snapshot.model_validate_json(snapshot.read_text(encoding="utf-8")),
            PortfolioAssessment.model_validate_json(findings.read_text(encoding="utf-8")),
            output,
        )


@app.command("assess")
def assess_command(
    resource_id: Annotated[list[str] | None, typer.Option("--resource-id")] = None,
    subscriptions: Annotated[list[str] | None, typer.Option("--subscriptions")] = None,
    resource_groups: Annotated[list[str] | None, typer.Option("--resource-groups")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    env: Annotated[Profile | None, typer.Option("--env")] = None,
    metrics: Annotated[bool | None, typer.Option("--metrics/--no-metrics")] = None,
    lookback_days: Annotated[int | None, typer.Option("--lookback-days", min=1, max=30)] = None,
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("output"),
) -> None:
    """Compose the same collect -> analyze -> report stages."""
    with input_errors():
        snapshot_path = output_dir / "snapshot.json"
        findings_path = output_dir / "findings.json"
        report_path = output_dir / "apim-assessment-report.html"
        distinct_paths(config, snapshot_path, findings_path, report_path)
        settings = load_config(
            config,
            resource_id or [],
            subscriptions or [],
            resource_groups or [],
            env,
            metrics,
            lookback_days,
        )
        snapshot = run_collect(settings, snapshot_path)
        assessment = run_analyze(snapshot, findings_path)
        run_report(snapshot, assessment, report_path)
