"""Typer CLI application for LogicGate vulnerability scanner."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from logicgate.parser import TreeSitterParser
from logicgate.graph import DependencyGraph
from logicgate.analyzer import Analyzer
from logicgate.models import Severity
from logicgate.reporter import SARIFReporter

app = typer.Typer(
    name="logicgate",
    help="AI-native Business Logic Vulnerability scanner for JS/TS",
    no_args_is_help=True,
)
console = Console()

# File extensions to scan
_SCAN_EXTENSIONS = frozenset({".js", ".ts", ".jsx", ".tsx"})

# Directories to skip during discovery
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "dist", "build", ".next", "coverage", "__pycache__",
})


def _discover_files(target: Path) -> list[Path]:
    """Recursively discover JS/TS source files under *target*.

    Skips ``node_modules`` and other common non-source directories.
    If *target* is a single file, returns it in a one-element list.
    """
    if target.is_file():
        if target.suffix.lower() in _SCAN_EXTENSIONS:
            return [target]
        return []

    files: list[Path] = []
    for child in sorted(target.rglob("*")):
        # Skip unwanted directories
        if any(part in _SKIP_DIRS for part in child.parts):
            continue
        if child.is_file() and child.suffix.lower() in _SCAN_EXTENSIONS:
            files.append(child)
    return files


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Directory or file to scan", exists=True),
    api_key: str = typer.Option(
        ...,
        "--api-key",
        envvar="ANTHROPIC_API_KEY",
        help="Anthropic API key",
    ),
    output: Path = typer.Option(
        "logicgate-report.sarif.json",
        "--output",
        "-o",
        help="Output SARIF file path",
    ),
    depth: int = typer.Option(5, "--depth", "-d", help="Call graph slice depth"),
    model: str = typer.Option("claude-opus-4-6", "--model", "-m", help="Claude model"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    remediate: bool = typer.Option(False, "--remediate", help="Generate code fixes for findings"),
) -> None:
    """Scan a JavaScript/TypeScript codebase for business-logic vulnerabilities."""

    # Resolve the target to an absolute path for consistency
    target_dir = target.resolve()

    # ------------------------------------------------------------------ #
    # Banner
    # ------------------------------------------------------------------ #
    console.print(
        Panel.fit(
            "[bold cyan]LogicGate[/bold cyan] v0.1.0",
            subtitle="AI-native Business Logic Vulnerability Scanner | v0.2.0",
            border_style="cyan",
        )
    )
    console.print()

    # ------------------------------------------------------------------ #
    # Phase 1 — Parse: discover files and extract routes
    # ------------------------------------------------------------------ #
    console.rule("[bold]Phase 1[/bold] — Parse")
    parser = TreeSitterParser()

    files = _discover_files(target_dir)
    if not files:
        console.print("[yellow]No JS/TS files found under target.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"  Found [bold]{len(files)}[/bold] source file(s)")

    all_routes = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing files...", total=len(files))
        for fpath in files:
            routes = parser.find_routes(fpath)
            all_routes.extend(routes)
            progress.update(task, advance=1)

    if not all_routes:
        console.print("[yellow]No Express routes discovered. Nothing to audit.[/yellow]")
        raise typer.Exit(code=0)

    # Route summary table
    route_table = Table(
        title=f"Discovered Routes ({len(all_routes)})",
        show_lines=False,
        header_style="bold magenta",
    )
    route_table.add_column("Method", style="green", width=8)
    route_table.add_column("Path", style="cyan")
    route_table.add_column("File", style="dim")
    route_table.add_column("Middleware", style="yellow")

    for r in all_routes:
        rel_file = str(r.file_path)
        try:
            rel_file = str(Path(r.file_path).relative_to(target_dir))
        except ValueError:
            pass
        mw = ", ".join(r.middleware) if r.middleware else "-"
        route_table.add_row(r.http_method, r.route_pattern, rel_file, mw)

    console.print(route_table)
    console.print()

    # ------------------------------------------------------------------ #
    # Phase 2 — Build dependency graph
    # ------------------------------------------------------------------ #
    console.rule("[bold]Phase 2[/bold] — Build Graph")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Building dependency graph...", total=None)
        graph = DependencyGraph(parser)
        graph.build_graph(target_dir)
        progress.update(task, completed=True)

    node_count = graph.node_count if hasattr(graph, "node_count") else "?"
    edge_count = graph.edge_count if hasattr(graph, "edge_count") else "?"
    console.print(f"  Graph: [bold]{node_count}[/bold] nodes, [bold]{edge_count}[/bold] edges")
    console.print()

    # ------------------------------------------------------------------ #
    # Phase 3 — Audit routes via Claude
    # ------------------------------------------------------------------ #
    console.rule("[bold]Phase 3[/bold] — Audit Routes")
    analyzer = Analyzer(api_key=api_key, model=model)
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing routes...", total=len(all_routes))
        for route in all_routes:
            route_label = f"{route.http_method} {route.route_pattern}"
            progress.update(task, description=f"Auditing {route_label}")

            context = graph.get_route_context(route, depth)
            result = analyzer.audit_route(route, context)
            results.append(result)

            if verbose and result.findings:
                for finding in result.findings:
                    console.print(
                        f"  [red]{finding.severity.value.upper()}[/red] "
                        f"{finding.vuln_type.value} — {finding.title} "
                        f"({finding.file_path}:{finding.start_line})"
                    )

            progress.update(task, advance=1)

    console.print()

    # ------------------------------------------------------------------ #
    # Phase 3.5 — Remediate (optional)
    # ------------------------------------------------------------------ #
    remediations = []
    if remediate:
        from logicgate.remediator import Remediator

        all_findings_for_fix = []
        for result in results:
            for finding in result.findings:
                # Find a matching route for this finding's file
                matching_route = None
                for r in all_routes:
                    route_label = f"{r.http_method} {r.route_pattern}"
                    if r.file_path == finding.file_path and route_label == finding.affected_route:
                        matching_route = r
                        break
                if matching_route is None:
                    # Fall back to any route in the same file
                    for r in all_routes:
                        if r.file_path == finding.file_path:
                            matching_route = r
                            break
                if matching_route:
                    all_findings_for_fix.append((finding, matching_route))

        if all_findings_for_fix:
            console.rule("[bold]Phase 3.5[/bold] — Remediate")
            remediator = Remediator(api_key=api_key, model=model)
            fixes_dir = Path("logicgate-fixes")
            fixes_dir.mkdir(exist_ok=True)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                console=console,
            ) as progress:
                task = progress.add_task("Generating fixes...", total=len(all_findings_for_fix))
                for finding, route in all_findings_for_fix:
                    progress.update(task, description=f"Fixing {finding.title[:40]}")
                    try:
                        file_content = Path(finding.file_path).read_text()
                    except Exception:
                        progress.update(task, advance=1)
                        continue

                    context = graph.get_route_context(route, depth)
                    rem = remediator.remediate(finding, route, file_content, context)

                    if rem:
                        remediations.append(rem)
                        safe_name = (
                            finding.title.replace(" ", "_")
                            .replace("/", "_")
                            .replace(":", "_")[:60]
                        )
                        patch_path = fixes_dir / f"{safe_name}_{finding.start_line}.patch"
                        patch_path.write_text(rem.diff)
                        if verbose:
                            console.print(f"  [green]Fix:[/green] {patch_path.name}")

                    progress.update(task, advance=1)

            console.print(
                f"\n  Generated [bold]{len(remediations)}[/bold] fix(es) "
                f"in [cyan]{fixes_dir}[/cyan]"
            )
            console.print()

    # ------------------------------------------------------------------ #
    # Phase 4 — Generate SARIF report
    # ------------------------------------------------------------------ #
    console.rule("[bold]Phase 4[/bold] — Report")
    reporter = SARIFReporter()
    sarif = reporter.generate(results, str(target_dir), remediations=remediations)
    reporter.write(sarif, output)

    # Tally findings by severity
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity.value] += 1

    total_findings = sum(severity_counts.values())

    # Summary table
    summary_table = Table(
        title=f"Scan Summary — {total_findings} finding(s)",
        header_style="bold",
    )
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    for sev in Severity:
        count = severity_counts[sev.value]
        style = severity_styles.get(sev.value, "")
        count_str = str(count)
        if count > 0:
            count_str = f"[{style}]{count}[/{style}]"
        summary_table.add_row(f"[{style}]{sev.value.upper()}[/{style}]", count_str)

    console.print(summary_table)
    console.print()
    console.print(f"  SARIF report written to [bold]{output}[/bold]")
    console.print()

    # ------------------------------------------------------------------ #
    # Exit code: 1 if critical or high findings exist
    # ------------------------------------------------------------------ #
    critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    if critical_high > 0:
        console.print(
            f"[bold red]FAIL[/bold red] — {critical_high} critical/high finding(s) detected."
        )
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]PASS[/bold green] — No critical/high findings.")
        raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
