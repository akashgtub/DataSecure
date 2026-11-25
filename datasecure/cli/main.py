"""Typer CLI interface for DataSecure."""

from pathlib import Path
from typing import Optional
import sys
import typer

from datasecure import __version__
from datasecure.cli.formatters import format_finding, print_banner, print_summary
from datasecure.configuration.loader import load_config
from datasecure.core.engine import ScanEngine
from datasecure.core.models import Finding, ScanResult, ScanSummary, Severity

app = typer.Typer(
    name="datasecure",
    help="DataSecure: AI Security Scanning Tool for code, datasets, models, and LLM configs.",
    add_completion=False,
)


@app.command()
def version() -> None:
    """Show the DataSecure version."""
    typer.echo(f"DataSecure version: {__version__}")


@app.command()
def scan(
    target: str = typer.Argument(".", help="Target directory or file to scan"),
    dataset: Optional[str] = typer.Option(None, "--dataset", "-d", help="Scan a specific dataset file"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Scan a specific model file or directory"),
    llm: bool = typer.Option(False, "--llm", help="Run active LLM security checks"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to custom config YAML"),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Minimum severity level to trigger non-zero exit code: critical, high, medium, low, info",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner and non-essential output"),
) -> None:
    """Scan an AI/ML project, dataset, model, or LLM endpoint for security risks."""
    if not quiet:
        print_banner()

    target_path = Path(dataset or model or target).resolve()
    if not target_path.exists():
        typer.secho(f"Error: Target path does not exist: {target_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    # Load configuration
    try:
        cfg = load_config(
            config_path=Path(config) if config else None,
            base_dir=target_path if target_path.is_dir() else target_path.parent,
        )
    except Exception as e:
        typer.secho(f"Configuration error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    # Determine failure threshold
    threshold_str = fail_on or (cfg.fail_on_severity.value if cfg.fail_on_severity else "HIGH")
    try:
        threshold = Severity.from_string(threshold_str)
    except ValueError:
        typer.secho(f"Invalid --fail-on value: {threshold_str}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    typer.echo(f"[*] Scanning target: {target_path}")
    category: Optional[str] = None
    if dataset:
        typer.echo(f"[*] Mode: Specific Dataset Scanner")
        category = "dataset"
    elif model:
        typer.echo(f"[*] Mode: Specific Model Scanner")
        category = "model"
    elif llm:
        typer.echo(f"[*] Mode: Active LLM Scanner")
        category = "llm"
    else:
        typer.echo(f"[*] Mode: Full Project Scanner")

    engine = ScanEngine()
    result = engine.scan_path(target_path, cfg, category=category)
    findings = result.findings

    if not quiet:
        for f in findings:
            typer.echo(format_finding(f))
            typer.echo("-" * 40)
        print_summary(result)

    # Check exit code based on threshold
    has_exceeding_findings = any(f.severity.meets_or_exceeds(threshold) for f in findings)
    if has_exceeding_findings:
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@app.command()
def report(
    format: str = typer.Option("json", "--format", "-f", help="Report format: json or html"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate or export security reports from previous scan results."""
    format_lower = format.strip().lower()
    if format_lower not in ["json", "html"]:
        typer.secho(f"Unsupported format '{format}'. Supported formats: json, html", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    typer.echo(f"DataSecure report generator (format: {format_lower})")
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()

