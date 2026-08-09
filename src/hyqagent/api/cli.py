"""api/cli.py — HyqAgent CLI entry point (click).

Provides::

    hyqagent scan <PATH>              # Phase 1+2: deterministic-only (zero-LLM)
    hyqagent scan <PATH> --deep       # Phase 3: LLM-augmented deep audit
    hyqagent resume <SESSION_ID>      # Resume a previous deep audit session
    hyqagent sessions list            # List past audit sessions
    hyqagent version
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import time
from pathlib import Path
from typing import Any

import click

from hyqagent.api.config import HyqAgentConfig
from hyqagent.report.generator import ReportGenerator
from hyqagent.scanner.deterministic import ScanResult

# ── Session directory ──────────────────────────────────────────────────────

_SESSION_DIR = Path.home() / ".hyqagent" / "sessions"


def _ensure_session_dir() -> Path:
    _SESSION_DIR.mkdir(parents=True, exist_ok=True)
    return _SESSION_DIR


# ── CLI group ──────────────────────────────────────────────────────────────


@click.group()
@click.version_option(package_name="hyqagent", message="hyqagent %(version)s")
@click.pass_context
def main(ctx: click.Context) -> None:
    r"""HyqAgent — CPG-based white-box code security audit CLI.

    Supports three scan modes:
    \b
    1. Quick scan (default):  Phase 1+2 deterministic-only, zero-LLM, offline.
       hyqagent scan ./myapp
    \b
    2. Deep audit (--deep):   Phase 3 LLM-augmented.  Understands the project
       first, then hunts vulnerabilities iteratively.  Uses API keys.
       hyqagent scan ./myapp --deep
    \b
    3. Resume:                 Continue a previous deep audit from its last
       checkpoint.  Long audits may span hours or days.
       hyqagent resume <session-id>
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = HyqAgentConfig()


# ── scan command ───────────────────────────────────────────────────────────


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
@click.option(
    "--deep/--quick",
    default=False,
    help="Enable Phase 3 LLM-augmented deep audit (requires API keys). "
    "Default: --quick (deterministic-only, zero-LLM).",
)
@click.option(
    "--mode",
    "-m",
    "audit_mode",
    type=click.Choice(["precision", "recall"]),
    default="precision",
    help="Audit strategy: precision (reduce false positives, default) "
    "or recall (reduce false negatives — LLM gets full code access + tools). "
    "Recall mode implies --deep.",
)
@click.option(
    "--verify",
    "enable_dynamic_verification",
    is_flag=True,
    default=False,
    help="Enable dynamic PoC verification in Docker sandbox (L6). "
    "Requires Docker and hyqagent-sandbox image.",
)
@click.option(
    "--sandbox-image",
    default="hyqagent-sandbox:latest",
    help="Docker image for sandbox execution.",
    hidden=True,
)
@click.option(
    "--sandbox-timeout",
    type=int,
    default=30,
    help="Sandbox execution timeout in seconds.",
    hidden=True,
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
    deep: bool,
    audit_mode: str,
    enable_dynamic_verification: bool,
    sandbox_image: str,
    sandbox_timeout: int,
) -> None:
    r"""Audit PATH for security vulnerabilities.

    PATH may be a single source file or a directory.

    \b
    Without --deep:  Runs Phase 1+2 deterministic scanning only.
                     Zero LLM cost, offline, fast (<1 min for small projects).

    \b
    With --deep:     Runs the full pipeline:
                     1. Phase 2 deterministic scan (zero-LLM, fast)
                     2. Project understanding based on scan results
                     3. LLM hypothesis generation for heuristic findings
                     4. LLM validation of conditional/suspicious paths
                     5. Blind-spot coverage analysis
                     Creates a session that can be resumed later.
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
        if deep:
            click.echo(f"🔬 HyqAgent deep audit of {target}")
        else:
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
    # Recall mode implies deep audit (requires LLM)
    use_deep = deep or audit_mode == "recall"
    if use_deep:
        try:
            result = asyncio.run(
                _run_deep_audit(
                    file_paths,
                    language,
                    target,
                    config,
                    quiet=quiet,
                    audit_mode=audit_mode,
                    enable_dynamic_verification=enable_dynamic_verification,
                    sandbox_image=sandbox_image,
                    sandbox_timeout=sandbox_timeout,
                )
            )
        except Exception as exc:
            if not quiet:
                click.secho(f"✖ Deep audit failed: {exc}", fg="red")
            import traceback

            traceback.print_exc()
            sys.exit(1)
    else:
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

    # Extract deep audit data if present
    deep_kwargs: dict[str, Any] = {}
    deep_data = getattr(result, "_deep_audit", None)
    if deep_data is not None:
        deep_kwargs = {
            "mode": "deep",
            "hypotheses": deep_data.get("hypotheses", []),
            "convergence": deep_data.get("convergence"),
            "cost_summary": deep_data.get("cost_summary"),
            "completeness_review": deep_data.get("completeness_review"),
            "coverage_audit": deep_data.get("coverage_audit"),
            "phases_completed": deep_data.get("phases_completed", []),
            "validations": deep_data.get("validations", []),
            "dynamic_verification_results": deep_data.get(
                "dynamic_verification_results"
            ),
        }

    report_text = generator.generate(
        result=result,
        fmt=fmt,
        scan_duration_ms=elapsed_ms,
        files_scanned=len(file_paths),
        language=language,
        **deep_kwargs,
    )

    Path(output).write_text(report_text, encoding="utf-8")

    # ── Summary ─────────────────────────────────────────────────────
    n_findings = len(getattr(result, "findings", []))
    n_hypotheses = len(getattr(result, "hypotheses", []))

    if not quiet:
        severity_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }
        click.echo()
        click.secho(f"✓ Scan complete in {elapsed_ms}ms", fg="green")
        click.echo(f"   Findings:    {n_findings}")
        if n_hypotheses:
            click.echo(f"   Hypotheses:  {n_hypotheses} (LLM-generated, needs review)")
        click.echo(f"   Report:      {output} ({fmt})")

        # Per-severity breakdown
        if n_findings > 0:
            from collections import Counter

            sev_counts = Counter(getattr(f, "severity", "unknown") for f in result.findings)
            for sev in ("critical", "high", "medium", "low"):
                count = sev_counts.get(sev, 0)
                if count:
                    color = severity_colors.get(sev, "white")
                    click.secho(f"     {sev}: {count}", fg=color)


# ── resume command ─────────────────────────────────────────────────────────


@main.command()
@click.argument("session_id")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output.")
@click.option(
    "--format",
    "-F",
    "report_format",
    default="json",
    type=click.Choice(["json", "markdown", "md", "sarif"]),
    help="Report format (default: json).",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Output file path (auto-generated if not set).",
)
@click.pass_context
def resume(
    ctx: click.Context,
    session_id: str,
    quiet: bool,
    report_format: str,
    output: str | None,
) -> None:
    """Resume a previous deep audit session.

    Loads the session checkpoint and continues from where it left off.
    Use ``hyqagent sessions list`` to see past sessions.
    """
    # Use SQLite-backed session store
    from pathlib import Path as _Path

    db_path = _Path.home() / ".hyqagent" / "sessions.db"
    from hyqagent.session.checkpoint import CheckpointManager
    from hyqagent.session.manager import SessionManager

    session_mgr = SessionManager(db_path)
    checkpoint_mgr = CheckpointManager(db_path)

    session = asyncio.run(session_mgr.get_session(session_id))
    if session is None:
        click.secho(f"✖ Session '{session_id}' not found.", fg="red")
        click.echo(f"   Database: {db_path}")
        click.echo("   Use 'hyqagent sessions list' to see all sessions.")
        sys.exit(1)

    cp = asyncio.run(checkpoint_mgr.load_latest(session_id))
    if cp is None:
        click.secho(f"✖ No checkpoint found for session '{session_id}'.", fg="red")
        sys.exit(1)

    target = _Path(session["project_path"])
    language = session["language"]

    if not quiet:
        click.echo(f"📋 Resuming session {session_id}")
        click.echo(f"   Project:     {session['project_path']}")
        click.echo(f"   Language:    {language}")
        click.echo(f"   Last phase:  {cp.phase}")
        click.echo(f"   Findings so far: {cp.finding_count}")
        click.echo(f"   Cost so far: ${cp.cost_total:.4f}")

    # Discover files
    if target.is_file():
        file_paths = [str(target)]
    else:
        file_paths = sorted(
            str(p)
            for p in target.rglob("*")
            if p.suffix in _EXTENSIONS.get(language, set()) and p.is_file()
        )

    if not file_paths:
        click.secho(f"✖ No source files found for '{language}'.", fg="red")
        sys.exit(1)

    # Run via orchestrator
    from hyqagent.scanner.orchestrator import Orchestrator

    orch = Orchestrator(
        session_manager=session_mgr,
        checkpoint_manager=checkpoint_mgr,
        db_path=db_path,
        quiet=quiet,
    )

    start_time = time.monotonic()
    try:
        report = asyncio.run(orch.resume(session_id))
    except Exception as exc:
        if not quiet:
            click.secho(f"✖ Resume failed: {exc}", fg="red")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    elapsed_ms = int((time.monotonic() - start_time) * 1000)

    # ── Generate report ─────────────────────────────────────────────
    _output_report(
        report,
        target,
        language,
        file_paths,
        elapsed_ms,
        quiet,
        report_format=report_format,
        output_path=Path(output) if output else None,
    )


# ── sessions command ───────────────────────────────────────────────────────


@main.group()
def sessions() -> None:
    """Manage past audit sessions."""
    pass


@sessions.command("list")
def list_sessions() -> None:
    """List all past audit sessions."""
    db_path = Path.home() / ".hyqagent" / "sessions.db"
    from hyqagent.session.manager import SessionManager

    session_mgr = SessionManager(db_path)
    sessions_list = asyncio.run(session_mgr.list_sessions(limit=20))

    if not sessions_list:
        click.echo("No past sessions found.")
        return

    click.echo(f"{'SESSION ID':<38} {'DATE':<20} {'TARGET':<30} {'STATUS':<12}")
    click.echo("-" * 100)
    for sess in sessions_list:
        sid = sess.get("id", "?")[:36]
        started = sess.get("created_at", "unknown")[:19]
        target = str(sess.get("project_path", ""))[:28]
        status = sess.get("status", "unknown")
        click.echo(f"{sid:<38} {started:<20} {target:<30} {status:<12}")


@main.command()
def version_cmd() -> None:
    """Print version and exit."""
    import importlib.metadata

    try:
        ver = importlib.metadata.version("hyqagent")
    except importlib.metadata.PackageNotFoundError:
        ver = "0.1.0"
    click.echo(f"hyqagent {ver}")


# ── Deep audit pipeline ────────────────────────────────────────────────────


async def _run_deep_audit(
    file_paths: list[str],
    language: str,
    target: Path,
    config: HyqAgentConfig,
    quiet: bool = False,
    audit_mode: str = "precision",
    enable_dynamic_verification: bool = False,
    sandbox_image: str = "hyqagent-sandbox:latest",
    sandbox_timeout: int = 30,
) -> ScanResult:
    """Phase 3+ deep audit powered by :class:`Orchestrator`.

    Delegates the full pipeline (CPG build → deterministic scan → hypothesis
    generation → validation → coverage audit → completeness critic →
    convergence loop) to the Orchestrator, which handles checkpointing,
    signal handling, and resume support automatically.
    """
    from pathlib import Path as _Path

    from hyqagent.core.state import AuditMode
    from hyqagent.scanner.orchestrator import Orchestrator

    db_path = _Path.home() / ".hyqagent" / "sessions.db"
    mode = AuditMode(audit_mode)

    orch = Orchestrator(
        db_path=db_path,
        quiet=quiet,
        mode=mode,
        max_agent_turns=config.max_agent_turns,
        tool_result_max_chars=config.tool_result_max_chars,
        enable_dynamic_verification=enable_dynamic_verification,
        sandbox_image=sandbox_image,
        sandbox_timeout=sandbox_timeout,
    )

    report = await orch.run(
        project_path=target,
        language=language,
        file_paths=file_paths,
    )

    # ── Convert AuditReport → ScanResult for report generator ──────
    result = ScanResult(
        findings=list(report.findings) if report.findings else [],
        annotated_paths=list(report.annotated_paths) if report.annotated_paths else [],
    )
    # Pack deep audit data for the report generator
    result._deep_audit = {  # type: ignore[attr-defined]
        "hypotheses": report.hypotheses,
        "validations": report.validations,
        "convergence": report.convergence,
        "cost_summary": report.cost_summary,
        "completeness_review": report.completeness_review,
        "coverage_audit": report.coverage_audit,
        "phases_completed": report.phases_completed,
        "dynamic_verification_results": report.dynamic_verification_results,
    }
    result.hypotheses = report.hypotheses  # type: ignore[attr-defined]
    result.coverage_audit = report.coverage_audit  # type: ignore[attr-defined]

    if not quiet:
        if report.convergence:
            click.echo(f"   Convergence: {report.convergence.summary}")
        click.echo(f"   Total LLM cost: ${report.cost_summary.total_cost:.4f}")
        click.echo()
        click.secho(f"📋 Session saved: {report.session_id}", fg="green")
        click.echo(f"   Resume with: hyqagent resume {report.session_id}")

    return result


def _output_report(
    report: Any,  # AuditReport
    target: Path,
    language: str,
    file_paths: list[str],
    elapsed_ms: int,
    quiet: bool = False,
    report_format: str = "json",
    output_path: Path | None = None,
) -> None:
    """Generate and write the audit report file, and print a summary."""
    from hyqagent.report.generator import ReportGenerator

    # Build a ScanResult-compatible object from AuditReport
    result = ScanResult(
        findings=list(report.findings) if report.findings else [],
        annotated_paths=list(report.annotated_paths) if report.annotated_paths else [],
    )
    result.hypotheses = report.hypotheses  # type: ignore[attr-defined]
    result.coverage_audit = report.coverage_audit  # type: ignore[attr-defined]

    # Pack deep audit data
    result._deep_audit = {  # type: ignore[attr-defined]
        "hypotheses": report.hypotheses,
        "validations": report.validations,
        "convergence": report.convergence,
        "cost_summary": report.cost_summary,
        "completeness_review": report.completeness_review,
        "coverage_audit": report.coverage_audit,
        "phases_completed": report.phases_completed,
    }

    # Normalize format
    fmt = report_format
    if fmt == "md":
        fmt = "markdown"

    generator = ReportGenerator()
    report_text = generator.generate(
        result=result,
        fmt=fmt,
        scan_duration_ms=elapsed_ms,
        files_scanned=len(file_paths),
        language=language,
        mode="deep",
        hypotheses=report.hypotheses,
        convergence=report.convergence,
        cost_summary=report.cost_summary,
        completeness_review=report.completeness_review,
        coverage_audit=report.coverage_audit,
        phases_completed=report.phases_completed,
        validations=report.validations,
    )

    if output_path is None:
        ext = ".json" if fmt == "json" else ".md" if fmt == "markdown" else ".sarif"
        base_dir = target if target.is_dir() else target.parent
        output_path = base_dir / f"report{ext}"
    output_path.write_text(report_text, encoding="utf-8")

    n_findings = len(getattr(result, "findings", []))
    n_hypotheses = len(getattr(result, "hypotheses", []))

    if not quiet:
        click.echo()
        click.secho(f"✓ Scan complete in {elapsed_ms}ms", fg="green")
        click.echo(f"   Findings:    {n_findings}")
        if n_hypotheses:
            click.echo(f"   Hypotheses:  {n_hypotheses} (LLM-generated)")
        click.echo(f"   Report:      {output_path} ({fmt})")

        if n_findings > 0:
            from collections import Counter

            sev_counts = Counter(getattr(f, "severity", "unknown") for f in result.findings)
            for sev in ("critical", "high", "medium", "low"):
                count = sev_counts.get(sev, 0)
                if count:
                    sev_colors = {
                        "critical": "red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "blue",
                    }
                    color = sev_colors.get(sev, "white")
                    click.secho(f"     {sev}: {count}", fg=color)


# ── Additional helpers for Phase 3 mitigation strategies ──────────────────


def _build_cpg_query(file_paths: list[str], language: str) -> Any:
    """Build a minimal CPGQuery for coverage auditing and blind scanning."""
    from hyqagent.cpg.graph import CPGGraphBuilder
    from hyqagent.cpg.parser import Parser
    from hyqagent.cpg.query import CPGQuery
    from hyqagent.cpg.taint_loader import TaintRuleLoader

    taint_loader = TaintRuleLoader()
    parser = Parser()
    builder = CPGGraphBuilder(parser, taint_loader=taint_loader)
    for fp in file_paths:
        builder.add_file(fp)
    return CPGQuery(builder.graph)


def _format_findings_summary(result: ScanResult) -> str:
    """Format Phase 2 findings for the Completeness Critic prompt."""
    lines: list[str] = []
    for f in result.findings[:15]:
        sev = getattr(f, "severity", "?")
        loc = getattr(f, "location", "?")
        rule = getattr(f, "rule_id", getattr(f, "rule", "?"))
        lines.append(f"- [{sev}] {rule} at {loc}")
    if len(result.findings) > 15:
        lines.append(f"... and {len(result.findings) - 15} more")
    return "\n".join(lines)


# ── Helpers ────────────────────────────────────────────────────────────────


def _has_llm_keys(config: HyqAgentConfig) -> bool:
    """Check if at least one LLM provider is configured."""
    try:
        _ = config.deepseek_key
        return True
    except ValueError:
        pass
    try:
        _ = config.anthropic_key
        return True
    except ValueError:
        pass
    return False


def _find_meta_files(target: Path, language: str) -> dict[str, str]:
    """Find project metadata files for context building."""
    candidates = [
        "README.md",
        "README.rst",
        "README",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "package.json",
        "requirements.txt",
        "Pipfile",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Makefile",
        "docker-compose.yml",
        "Dockerfile",
        ".env.example",
        "config.yaml",
        "config.yml",
        "app.py",
        "main.py",
        "index.js",
        "server.js",
        "Application.java",
        "Main.java",
    ]
    result: dict[str, str] = {}
    for cand in candidates:
        fp = target / cand
        if fp.is_file():
            with contextlib.suppress(OSError):
                result[cand] = fp.read_text(encoding="utf-8", errors="replace")
    return result


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


def _try_load_extractor(language: str, base_dir: Path | None) -> list[Any]:
    """Attempt to load a framework extractor for *language*.

    Returns a list of extractor instances (empty if the import fails,
    which is expected for projects without a recognised framework).
    """
    result: list[Any] = []
    if base_dir is None:
        return result

    try:
        if language == "python":
            from hyqagent.cpg.extractor import PythonExtractor

            result.append(PythonExtractor(project_dir=base_dir))
        elif language == "javascript":
            from hyqagent.cpg.extractor import JavaScriptExtractor

            result.append(JavaScriptExtractor(project_dir=base_dir))
        elif language == "java":
            from hyqagent.cpg.extractor import JavaExtractor

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
    from hyqagent.cpg.graph import CPGGraphBuilder
    from hyqagent.cpg.parser import Parser
    from hyqagent.cpg.taint_loader import TaintRuleLoader

    taint_loader = TaintRuleLoader()
    parser = Parser()
    builder = CPGGraphBuilder(parser, taint_loader=taint_loader)

    for fp in file_paths:
        builder.add_file(fp)

    graph = builder.graph

    # ── Query layer ──────────────────────────────────────────────────
    from hyqagent.cpg.query import CPGQuery

    query = CPGQuery(graph)

    # ── Discovery / coverage ─────────────────────────────────────────
    from hyqagent.cpg.discovery import (
        SinkDiscoverer,
        SourceCompletenessChecker,
    )

    sink_discoverer = SinkDiscoverer(graph, taint_loader)
    source_checker = SourceCompletenessChecker(graph, taint_loader)

    # ── Framework extractors ─────────────────────────────────────────
    base_dir = Path(file_paths[0]).parent if file_paths else None
    frameworks: list[Any] = _try_load_extractor(language, base_dir)

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
