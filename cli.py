"""CodeSentinel command-line interface.

Usage::

    python -m codesentinel scan <path|https://github.com/owner/repo|file.zip> \\
        --fail-on p0 --sarif results.sarif --sbom sbom.cdx.json --cbom cbom.cdx.json --pdf report.pdf

Exit codes: 0 = gate passed, 1 = gate failed, 2 = the scan could not run.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.config import APP_NAME, APP_VERSION, configure_logging
from app.db import init_db
from app.engine import STAGES, ScanOptions, ScanReport, run_scan
from app.exporters import write
from app.ingest import IngestError, resolve_target
from app.scoring import normalise_gate

app = typer.Typer(add_completion=False, no_args_is_help=True, help=f"{APP_NAME}: software supply-chain security gate.")
console = Console(stderr=False, highlight=False, width=max(Console().width, 110))
log = logging.getLogger("codesentinel.cli")
PRIO_STYLE = {"P0": "bold red", "P1": "dark_orange", "P2": "yellow", "P3": "grey62"}


@app.callback()
def _root() -> None:
    """Scan repositories for leaked secrets, exploitable dependencies, insecure code and CI misconfigurations."""


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"{APP_NAME} {APP_VERSION}")


def _print_report(r: ScanReport, show: int) -> None:
    g = r.gate
    verdict = "[bold white on red] FAIL [/]" if not g.passed else "[bold black on green] PASS [/]"
    st = r.stats
    head = (f"{verdict}  grade [bold]{g.grade}[/] ({g.score:.0f}/100)   fail-on {g.fail_on.upper()}\n"
            f"target {r.target}  commit {(r.commit_sha or 'n/a')[:12]}  {r.duration_seconds:.1f}s\n"
            f"P0 {g.counts['P0']}  P1 {g.counts['P1']}  P2 {g.counts['P2']}  P3 {g.counts['P3']}   "
            f"components {st.get('components', 0)}  CVEs {st.get('cves', 0)}  KEV {st.get('kev_hits', 0)}  "
            f"secrets HEAD/history {st.get('secrets_head', 0)}/{st.get('secrets_history', 0)}")
    console.print(Panel(head, title=f"{APP_NAME} {APP_VERSION}", expand=False))

    def table(title: str, rows: list) -> None:
        t = Table(title=title, title_justify="left", show_lines=False, header_style="bold")
        t.add_column("Tier", no_wrap=True)
        t.add_column("Rule", no_wrap=True)
        t.add_column("Finding", ratio=3, overflow="fold")
        t.add_column("Location", ratio=2, overflow="fold")
        t.add_column("Why", ratio=2, overflow="fold")
        for f in rows:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            title = f.title if f.module != "dependencies" else f"{f.extra.get('package')} {f.extra.get('version')}"
            t.add_row(f"[{PRIO_STYLE[f.priority]}]{f.priority}[/]", f.rule_id, title[:70], loc,
                      f.extra.get("priority_reason", ""))
        console.print(t)

    p0 = [f for f in r.active_findings if f.priority == "P0"]
    if p0:
        table(f"P0 findings ({len(p0)})", p0[:show])
    hist = [f for f in r.active_findings if f.module == "secrets" and f.extra.get("historical")]
    if hist:
        t = Table(title=f"History-only secrets ({len(hist)}): deleted from HEAD but still in git history",
                  title_justify="left", header_style="bold")
        for c in ("Tier", "Rule", "Preview", "File", "Commit", "Date"):
            t.add_column(c)
        for f in hist:
            t.add_row(f"[{PRIO_STYLE[f.priority]}]{f.priority}[/]", f.rule_id, f.extra.get("redacted", ""),
                      f"{f.file}:{f.line}", str(f.extra.get("commit", ""))[:10], f.extra.get("commit_date", ""))
        console.print(t)
    p1 = [f for f in r.active_findings if f.priority == "P1"]
    if p1 and show:
        table(f"P1 findings (top {min(show, len(p1))} of {len(p1)})", p1[:show])
    for reason in g.reasons[:1]:
        console.print(f"[bold]Gate:[/] {reason}")
    for e in r.policy_errors:
        console.print(f"[yellow]policy warning:[/] {e}")
    if r.intel_partial:
        console.print("[yellow]warning:[/] one or more intel feeds were unavailable; results are partial")


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Local path, .zip file or https://github.com/owner/repo URL")],
    fail_on: Annotated[str | None, typer.Option("--fail-on", help="Gate level: p0, p1 or p2 (also critical/high/medium)")] = None,
    sarif: Annotated[Path | None, typer.Option(help="Write SARIF 2.1.0 to this file")] = None,
    sbom: Annotated[Path | None, typer.Option(help="Write CycloneDX SBOM to this file")] = None,
    cbom: Annotated[Path | None, typer.Option(help="Write CycloneDX CBOM to this file")] = None,
    pdf: Annotated[Path | None, typer.Option(help="Write the PDF report to this file")] = None,
    csv: Annotated[Path | None, typer.Option(help="Write findings as CSV to this file")] = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write the full JSON report to this file")] = None,
    history: Annotated[bool, typer.Option("--history/--no-history", help="Scan git history for secrets")] = True,
    transitive: Annotated[bool, typer.Option("--transitive/--no-transitive", help="Include transitive dependencies")] = True,
    show: Annotated[int, typer.Option(help="Rows to print per table")] = 25,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Scan a target and enforce the CI gate (exit code 1 when it fails)."""
    configure_logging("INFO" if verbose else "WARNING")
    try:
        level = normalise_gate(fail_on) if fail_on else None
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    init_db()
    try:
        with console.status("Preparing target...") as status:
            tgt = resolve_target(target, include_history=history, allow_local=True)
            try:
                def progress(stage: str, state: str) -> None:
                    if state == "running":
                        status.update(f"[{STAGES.index(stage) + 1}/{len(STAGES)}] {stage}...")

                report = run_scan(tgt, ScanOptions(include_history=history, include_transitive=transitive, fail_on=level),
                                  progress=progress)
                status.update("Writing exports...")
                for fmt, path in (("sarif", sarif), ("sbom", sbom), ("cbom", cbom), ("pdf", pdf), ("csv", csv),
                                  ("json", json_out)):
                    if path:
                        write(report, fmt, path)
            finally:
                tgt.cleanup()
    except IngestError as exc:
        console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(2) from exc
    _print_report(report, show)
    for fmt, path in (("SARIF", sarif), ("SBOM", sbom), ("CBOM", cbom), ("PDF", pdf), ("CSV", csv), ("JSON", json_out)):
        if path:
            console.print(f"wrote {fmt}: {path}")
    raise typer.Exit(0 if report.gate.passed else 1)


def main() -> None:
    """Entry point for ``python -m codesentinel``."""
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(AttributeError, ValueError):
                stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    app()


if __name__ == "__main__":
    main()
