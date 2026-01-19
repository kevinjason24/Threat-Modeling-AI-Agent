"""CLI entry point for Threat Model Copilot."""

import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn

from .pipeline import ThreatModelPipeline, run_pipeline
from .render_markdown import render_markdown_report

app = typer.Typer(
    name="threat-model",
    help="Threat Modeling Agent - AI-powered security threat analysis",
    add_completion=False,
)

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def read_input(input_path: Optional[Path]) -> tuple[str, str]:
    """Read input from file or stdin.

    Returns:
        Tuple of (content, source_name).
    """
    if input_path:
        if not input_path.exists():
            console.print(f"[red]Error:[/red] File not found: {input_path}")
            raise typer.Exit(1)
        content = input_path.read_text()
        return content, str(input_path)
    else:
        # Read from stdin
        if sys.stdin.isatty():
            console.print("[yellow]Reading from stdin (Ctrl+D to end)...[/yellow]")
        content = sys.stdin.read()
        if not content.strip():
            console.print("[red]Error:[/red] No input provided")
            raise typer.Exit(1)
        return content, "stdin"


@app.command()
def analyze(
    input_path: Optional[Path] = typer.Option(
        None,
        "--input", "-i",
        help="Path to design document (markdown/text). Reads from stdin if not provided.",
    ),
    output_md: Optional[Path] = typer.Option(
        None,
        "--out", "-o",
        help="Path for Markdown report output.",
    ),
    output_json: Optional[Path] = typer.Option(
        None,
        "--json", "-j",
        help="Path for structured JSON output.",
    ),
    redact: bool = typer.Option(
        False,
        "--redact", "-r",
        help="Redact secrets/sensitive patterns before sending to LLM.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose logging.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Suppress progress output (still shows errors).",
    ),
) -> None:
    """Analyze a design document and generate a threat model.

    Examples:

        threat-model --input design.md --out report.md --json report.json

        cat design.md | threat-model --out report.md

        threat-model -i feature.md -o out/report.md -r --verbose
    """
    setup_logging(verbose)

    # Read input
    try:
        input_text, source_name = read_input(input_path)
    except typer.Exit:
        raise

    # Set default outputs if none specified
    if not output_md and not output_json:
        output_md = Path("out/threat_model.md")
        output_json = Path("out/threat_model.json")
        if not quiet:
            console.print("[dim]No output paths specified, using defaults:[/dim]")
            console.print(f"[dim]  Markdown: {output_md}[/dim]")
            console.print(f"[dim]  JSON: {output_json}[/dim]")

    if not quiet:
        console.print("\n[bold]Threat Modeling Agent[/bold]")
        console.print(f"[dim]Input: {source_name}[/dim]")
        if redact:
            console.print("[dim]Secrets redaction: enabled[/dim]")
        console.print()

    # Create progress display
    stages = [
        "Planner",
        "Extractor",
        "DFD Builder",
        "STRIDE Analyst",
        "Abuse Writer",
        "Checklist Writer",
        "QA Checker",
        "Report Assembly",
    ]

    completed_stages: set[str] = set()

    def on_stage_complete(stage: str, status: str) -> None:
        if status == "complete":
            completed_stages.add(stage)

    try:
        if quiet:
            # Run without progress display
            report = run_pipeline(
                input_text=input_text,
                input_path=str(input_path) if input_path else None,
                output_md=str(output_md) if output_md else None,
                output_json=str(output_json) if output_json else None,
                redact=redact,
                verbose=verbose,
            )
        else:
            # Run with progress display
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Initializing pipeline...", total=len(stages))

                def update_progress(stage: str, status: str) -> None:
                    on_stage_complete(stage, status)
                    if status == "running":
                        progress.update(task, description=f"Running {stage}...")
                    elif status == "complete":
                        progress.advance(task)

                pipeline = ThreatModelPipeline(on_stage_complete=update_progress)
                report = pipeline.run(input_text, str(input_path) if input_path else None, redact)

                # Save outputs
                if output_md:
                    md_content = render_markdown_report(report)
                    output_md.parent.mkdir(parents=True, exist_ok=True)
                    output_md.write_text(md_content)

                if output_json:
                    json_content = report.model_dump_json(indent=2)
                    output_json.parent.mkdir(parents=True, exist_ok=True)
                    output_json.write_text(json_content)

        # Print summary
        if not quiet:
            console.print()
            console.print("[bold green]✓ Threat model generated successfully[/bold green]")
            console.print()

            # Summary stats
            threat_count = len(report.stride_analysis.threats)
            high_count = sum(1 for t in report.stride_analysis.threats if t.severity_label.value == "High")
            medium_count = sum(1 for t in report.stride_analysis.threats if t.severity_label.value == "Medium")

            console.print("[bold]Summary:[/bold]")
            console.print(f"  Components: {len(report.inventory.components)}")
            console.print(f"  Entry Points: {len(report.inventory.entry_points)}")
            console.print(f"  Threats: {threat_count} (🔴 {high_count} High, 🟡 {medium_count} Medium)")
            console.print(f"  Abuse Cases: {len(report.abuse_cases)}")
            console.print(f"  QA Status: {'✅ Passed' if report.qa_result.passed else '❌ Failed'}")

            console.print()
            if output_md:
                console.print(f"[dim]Markdown report: {output_md}[/dim]")
            if output_json:
                console.print(f"[dim]JSON output: {output_json}[/dim]")

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    console.print(f"Threat Modeling Agent v{__version__}")


@app.command()
def validate(
    json_path: Path = typer.Argument(
        ...,
        help="Path to threat model JSON file to validate.",
    ),
) -> None:
    """Validate a threat model JSON file."""
    from .schemas import ThreatModelReport

    if not json_path.exists():
        console.print(f"[red]Error:[/red] File not found: {json_path}")
        raise typer.Exit(1)

    try:
        content = json_path.read_text()
        import json
        data = json.loads(content)
        report = ThreatModelReport.model_validate(data)

        console.print("[green]✓ Valid threat model[/green]")
        console.print(f"  Generated: {report.generated_at}")
        console.print(f"  Threats: {len(report.stride_analysis.threats)}")
        console.print(f"  QA Status: {'Passed' if report.qa_result.passed else 'Failed'}")

    except Exception as e:
        console.print(f"[red]✗ Invalid threat model:[/red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()



