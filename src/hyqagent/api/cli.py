"""api/cli.py — HyqAgent CLI entry point (click).

Provides::

    hyqagent scan <PATH> [--lang LANG] [--output FILE] [--format FMT]
    hyqagent version
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from hyqagent.api.config import HyqAgentConfig
from hyqagent.report.generator import ReportGenerator
from hyqagent.scanner.deterministic import ScanResult


@click.group()
@click.version_option(package_name="hyqagent", message="hyqagent %(version)s")
@click.pass_context
def main(ctx: click.Context) -> None:
    """HyqAgent — CPG-based white-box code security audit CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = HyqAgentConfig()


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
)
@click.option(
    "--lang",
    "-l",
    default="",
    help="Programming language (python | javascript | java). "
    "Auto-detected from file extensions if empty.",
)
@click.option(
    "--framework",
    "-f",
    default="",
    help="Web framework (flask | django | fastapi | express | spring). Auto-detected if empty.",
)
@click.option(
    "--output",
    "-o",
    default="report.json",
    type=click.Path(writable=True),
    help="Output file path (default: report.json).",
)
@click.option(
    "--format",
    "-F",
    "report_format",
    default="json",
    type=click.Choice(["json", "markdown", "md", "sarif"]),
    help="Report format (default: json).",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress progress output.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    lang: str,
    framework: str,
    output: str,
    report_format: str,
    quiet: bool,
) -> None:
    """Run a zero-LLM deterministic scan against PATH.

    PATH may be a single source file or a directory.
    The scan runs entirely offline; no API keys are required.
    """
    config: HyqAgentConfig = ctx.obj["config"]
    target = Path(path).resolve()
    start_time = time.monotonic()

    # ── Language detection ──────────────────────────────────────────
    language = lang or _detect_language(target)

    try:
        language = config.resolve_language(language or None)
    except ValueError:
        if not quiet:
            click.secho(
                "⚠  Could not determine language.  Use --lang to specify.",
                fg="yellow",
            )
            click.echo("   Supported: python, javascript, java")
        sys.exit(1)

    if not quiet:
        click.echo(f"🔍 HyqAgent scanning {target}")
        click.echo(f"   Language:  {language}")
        if framework:
            click.echo(f"   Framework: {framework}")

    # ── Collect files ───────────────────────────────────────────────
    if target.is_file():
        file_paths = [str(target)]
    else:
        file_paths = sorted(
            str(p)
            for p in target.rglob("*")
            if p.suffix in _EXTENSIONS.get(language, set()) and p.is_file()
        )

    if not file_paths:
        if not quiet:
            click.secho(
                f"✖ No source files found for language '{language}' under {target}.",
                fg="red",
            )
        sys.exit(1)

    if not quiet:
        click.echo(f"   Files:     {len(file_paths)} source file(s)")

    # ── Run scan ────────────────────────────────────────────────────
    try:
        result = _run_scan(file_paths, language, config, quiet=quiet)
    except Exception as exc:
        if not quiet:
            click.secho(f"✖ Scan failed: {exc}", fg="red")
        sys.exit(1)

    elapsed_ms = int((time.monotonic() - start_time) * 1000)

    # ── Generate report ─────────────────────────────────────────────
    generator = ReportGenerator()

    # Normalize format name
    fmt = report_format
    if fmt == "md":
        fmt = "markdown"

    report_text = generator.generate(
        result=result,
        fmt=fmt,
        scan_duration_ms=elapsed_ms,
        files_scanned=len(file_paths),
        language=language,
    )

    Path(output).write_text(report_text, encoding="utf-8")

    # ── Summary ─────────────────────────────────────────────────────
    n_findings = len(getattr(result, "findings", []))

    if not quiet:
        severity_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }
        click.echo()
        click.secho(f"✓ Scan complete in {elapsed_ms}ms", fg="green")
        click.echo(f"   Findings:  {n_findings}")
        click.echo(f"   Report:    {output} ({fmt})")

        # Per-severity breakdown
        if n_findings > 0:
            from collections import Counter

            sev_counts = Counter(getattr(f, "severity", "unknown") for f in result.findings)
            for sev in ("critical", "high", "medium", "low"):
                count = sev_counts.get(sev, 0)
                if count:
                    color = severity_colors.get(sev, "white")
                    click.secho(f"     {sev}: {count}", fg=color)


@main.command()
def version_cmd() -> None:
    """Print version and exit."""
    import importlib.metadata

    try:
        ver = importlib.metadata.version("hyqagent")
    except importlib.metadata.PackageNotFoundError:
        ver = "0.1.0"
    click.echo(f"hyqagent {ver}")


# ── Internal helpers ─────────────────────────────────────────────────────


# Recognised source-file extensions per language.
_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py"},
    "javascript": {".js", ".mjs", ".cjs", ".jsx"},
    "java": {".java"},
}


def _detect_language(target: Path) -> str:
    """Infer the language from file extensions present under *target*."""
    exts: set[str] = set()
    if target.is_file():
        exts.add(target.suffix)
    else:
        for p in target.rglob("*"):
            if p.is_file() and p.suffix in {
                ".py",
                ".js",
                ".mjs",
                ".cjs",
                ".jsx",
                ".java",
            }:
                exts.add(p.suffix)

    if ".py" in exts:
        return "python"
    if exts & {".js", ".mjs", ".cjs", ".jsx"}:
        return "javascript"
    if ".java" in exts:
        return "java"

    return ""


def _try_load_extractor(language: str, base_dir: Path | None) -> list:
    """Attempt to load a framework extractor for *language*.

    Returns a list of extractor instances (empty if the import fails,
    which is expected for projects without a recognised framework).
    """
    result: list = []
    if base_dir is None:
        return result

    try:
        if language == "python":
            from hyqagent.cpg.extractor import (
                PythonExtractor,  # type: ignore[import-untyped]
            )

            result.append(PythonExtractor(project_dir=base_dir))
        elif language == "javascript":
            from hyqagent.cpg.extractor import (
                JavaScriptExtractor,  # type: ignore[import-untyped]
            )

            result.append(JavaScriptExtractor(project_dir=base_dir))
        elif language == "java":
            from hyqagent.cpg.extractor import (
                JavaExtractor,  # type: ignore[import-untyped]
            )

            result.append(JavaExtractor(project_dir=base_dir))
    except Exception:  # noqa: S110
        pass  # Extractor not available for this project — expected

    return result


def _run_scan(
    file_paths: list[str],
    language: str,
    config: HyqAgentConfig,
    quiet: bool = False,
) -> ScanResult:
    """Build the CPG pipeline and run :meth:`DeterministicScanner.scan_all`.

    This is the integration point that wires together the CPG build,
    config resolution, taint rule loading, and the five deterministic
    scanners.
    """
    # ── Build CPG graph ──────────────────────────────────────────────
    try:
        from hyqagent.cpg.build import CPGBuilder  # type: ignore[import-untyped]
    except ImportError as err:
        raise RuntimeError(
            "CPG build module not available. Ensure the 'hyqagent' package is installed correctly."
        ) from err

    builder = CPGBuilder()
    for fp in file_paths:
        builder.build_file(fp, language, parse_project=False)

    graph = builder.finalize()

    # ── Query layer ──────────────────────────────────────────────────
    from hyqagent.cpg.query import CPGQuery

    query = CPGQuery(graph)

    # ── Taint rules ──────────────────────────────────────────────────
    from hyqagent.cpg.taint_loader import TaintRuleLoader

    taint_loader = TaintRuleLoader()

    # ── Discovery / coverage ─────────────────────────────────────────
    from hyqagent.cpg.discovery import (
        SinkDiscoverer,
        SourceCompletenessChecker,
    )

    sink_discoverer = SinkDiscoverer(graph, taint_loader)
    source_checker = SourceCompletenessChecker(graph, taint_loader)

    # ── Framework extractors ─────────────────────────────────────────
    base_dir = Path(file_paths[0]).parent if file_paths else None
    frameworks: list = _try_load_extractor(language, base_dir)

    # ── Annotator ────────────────────────────────────────────────────
    from hyqagent.scanner.annotator import PathAnnotator

    annotator = PathAnnotator(query, taint_loader, sink_discoverer, source_checker)

    # ── Coverage tracker ─────────────────────────────────────────────
    from hyqagent.cpg.coverage import CoverageTracker

    tracker = CoverageTracker(graph)
    tracker.set_endpoints(frameworks)

    # ── Deterministic scanner ────────────────────────────────────────
    from hyqagent.scanner.deterministic import DeterministicScanner

    scanner = DeterministicScanner(
        graph=graph,
        query=query,
        taint_loader=taint_loader,
        annotator=annotator,
        frameworks=frameworks,
        tracker=tracker,
    )

    return scanner.scan_all(file_paths, language)
