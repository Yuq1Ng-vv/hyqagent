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
import json
import sys
import time
import uuid
from datetime import UTC, datetime
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
    if deep:
        try:
            result = asyncio.run(
                _run_deep_audit(
                    file_paths,
                    language,
                    target,
                    config,
                    quiet=quiet,
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
@click.pass_context
def resume(ctx: click.Context, session_id: str, quiet: bool) -> None:
    """Resume a previous deep audit session.

    Loads the session checkpoint and continues from where it left off.
    Use ``hyqagent sessions list`` to see past sessions.
    """
    session_file = _ensure_session_dir() / f"{session_id}.json"
    if not session_file.exists():
        click.secho(f"✖ Session '{session_id}' not found.", fg="red")
        click.echo(f"   Looked in: {session_file}")
        sys.exit(1)

    session = json.loads(session_file.read_text())
    if not quiet:
        click.echo(f"📋 Resuming session {session_id}")
        click.echo(f"   Project:     {session.get('target', 'unknown')}")
        click.echo(f"   Language:    {session.get('language', 'unknown')}")
        click.echo(f"   Started:     {session.get('started_at', 'unknown')}")
        click.echo(f"   Status:      {session.get('status', 'unknown')}")
        click.echo(f"   Files:       {session.get('files_scanned', 0)}")
        click.echo(f"   Findings so far: {len(session.get('findings', []))}")

    click.secho(
        "⏳ Resume not yet fully implemented — re-running scan instead.",
        fg="yellow",
    )
    # TODO: Implement full checkpoint resume in a future session


# ── sessions command ───────────────────────────────────────────────────────


@main.group()
def sessions() -> None:
    """Manage past audit sessions."""
    pass


@sessions.command("list")
def list_sessions() -> None:
    """List all past audit sessions."""
    sd = _ensure_session_dir()
    files = sorted(sd.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not files:
        click.echo("No past sessions found.")
        return

    click.echo(f"{'SESSION ID':<38} {'DATE':<20} {'TARGET':<30} {'STATUS':<12}")
    click.echo("-" * 100)
    for f in files[:20]:  # show last 20
        try:
            sess = json.loads(f.read_text())
            sid = f.stem
            started = sess.get("started_at", "unknown")[:19]
            target = str(sess.get("target", ""))[:28]
            status = sess.get("status", "unknown")
            click.echo(f"{sid:<38} {started:<20} {target:<30} {status:<12}")
        except (json.JSONDecodeError, KeyError):
            click.echo(f"{f.stem:<38} (corrupt or empty)")


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
) -> ScanResult:
    """Phase 3 deep audit: scan → understand → hypothesise → validate.

    Order is deliberate:
    1. Phase 2 deterministic scan first (zero LLM, fast) → concrete evidence
    2. Project understanding based on scan results (evidence-based, not speculative)
    3. Phase 3 hypothesis generation guided by understanding + coverage gaps

    Creates a persistent session that can be resumed via ``hyqagent resume``.
    """
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    session_id = f"audit-{ts}-{uuid.uuid4().hex[:6]}"
    session: dict[str, Any] = {
        "session_id": session_id,
        "target": str(target),
        "language": language,
        "started_at": datetime.now(UTC).isoformat(),
        "status": "running",
        "phase": "phase2_scan",
    }

    # ══════════════════════════════════════════════════════════════════
    # Step 1: Phase 2 Deterministic scan (zero LLM, fast)
    # ══════════════════════════════════════════════════════════════════
    if not quiet:
        click.echo()
        click.secho("⚡ Phase 2: Deterministic scan...", fg="cyan")

    result = _run_scan(file_paths, language, config, quiet=quiet)
    session["phase2_findings"] = len(result.findings)
    session["phase2_annotated_paths"] = len(result.annotated_paths)

    if not quiet:
        click.echo(f"   Findings: {len(result.findings)}")
        click.echo(f"   Annotated paths: {len(result.annotated_paths)}")

    # Summarise by label for project understanding
    label_breakdown: dict[str, int] = {}
    for ap in result.annotated_paths:
        lbl = getattr(ap, "label", None)
        if lbl is not None:
            key = lbl.value if hasattr(lbl, "value") else str(lbl)
            label_breakdown[key] = label_breakdown.get(key, 0) + 1

    if not quiet and label_breakdown:
        for lbl, cnt in sorted(label_breakdown.items()):
            click.echo(f"     {lbl}: {cnt}")

    # ══════════════════════════════════════════════════════════════════
    # Step 2: Project understanding (evidence-based, cheap LLM)
    # ══════════════════════════════════════════════════════════════════
    session["phase"] = "understanding"

    if not quiet:
        click.echo()
        click.secho("🧠 Project understanding (based on scan results)...", fg="cyan")

    project_context = await _understand_project(
        target=target,
        language=language,
        file_paths=file_paths,
        config=config,
        scan_findings=result.findings,
        label_breakdown=label_breakdown,
        coverage_summary=getattr(result, "coverage_summary", {}),
        quiet=quiet,
    )
    session["project_context"] = project_context

    if not quiet and project_context:
        summary = project_context.get("summary", "")
        if summary:
            click.echo(f"   {summary[:300]}")
        audit_plan = project_context.get("audit_plan", [])
        if audit_plan:
            click.echo(f"   Audit priorities: {', '.join(audit_plan[:6])}")

    # ══════════════════════════════════════════════════════════════════
    # Step 3: Phase 3 LLM hypothesis generation
    # ══════════════════════════════════════════════════════════════════
    annotated = result.annotated_paths
    llm_targets = [
        ap
        for ap in annotated
        if getattr(ap, "label", None) is not None
        and getattr(ap.label, "value", str(ap.label))
        in (
            "heuristic_sink",
            "exposed_no_source",
            "uncovered_sink",
            "conditional_sanitized",
            "uncovered_but_reachable",
        )
    ]

    hypotheses: list[Any] = []
    if llm_targets and _has_llm_keys(config):
        if not quiet:
            click.echo()
            click.secho(
                f"🤖 Phase 3: LLM hypothesis generation ({len(llm_targets)} candidate paths)...",
                fg="cyan",
            )

        hypotheses = await _run_phase3_hypotheses(
            llm_targets,
            language,
            config,
            quiet=quiet,
        )
        session["hypotheses"] = [
            {
                "id": h.id,
                "vuln_type": h.vuln_type,
                "severity": h.severity,
                "confidence": h.confidence,
            }
            for h in hypotheses
        ]
    else:
        if not quiet:
            click.echo()
            click.secho(
                "⏭  Phase 3 skipped — no LLM-eligible paths or missing API keys.",
                fg="yellow",
            )

    # ══════════════════════════════════════════════════════════════════
    # Step 4: Coverage audit (zero-LLM, differential coverage analysis)
    # ══════════════════════════════════════════════════════════════════
    if not quiet:
        click.echo()
        click.secho("📊 Coverage audit: differential coverage analysis...", fg="cyan")

    from hyqagent.scanner.coverage_auditor import CoverageAuditor

    # Build CPG query for auditor (reuse or rebuild minimally)
    cq = _build_cpg_query(file_paths, language)
    auditor = CoverageAuditor(cq, annotated, language=language)
    coverage_audit = auditor.audit()
    session["coverage_audit"] = {
        "total_entries": coverage_audit.total_entries,
        "covered": coverage_audit.covered,
        "coverage_pct": round(coverage_audit.coverage_pct, 2),
        "high_risk_gaps": len(coverage_audit.high_risk_gaps),
        "medium_risk_gaps": len(coverage_audit.medium_risk_gaps),
        "total_gaps": len(coverage_audit.gaps),
    }

    if not quiet:
        click.echo(
            f"   Coverage: {coverage_audit.coverage_pct:.0%} "
            f"({coverage_audit.covered}/{coverage_audit.total_entries})"
        )
        if coverage_audit.high_risk_gaps:
            click.secho(
                f"   ⚠ {len(coverage_audit.high_risk_gaps)} high-risk coverage gaps",
                fg="yellow",
            )
            for gap in coverage_audit.high_risk_gaps[:5]:
                click.echo(f"     - {gap.location}: {gap.reason[:120]}")

    # ══════════════════════════════════════════════════════════════════
    # Step 5: Completeness Critic (MID-tier LLM, ~$0.02)
    # ══════════════════════════════════════════════════════════════════
    if _has_llm_keys(config) and hypotheses:
        if not quiet:
            click.echo()
            click.secho("🔍 Completeness review: what did we miss?...", fg="cyan")

        from hyqagent.models.providers.anthropic_provider import (
            AnthropicProvider,
            ProviderConfig,
        )
        from hyqagent.scanner.completeness import CompletenessCritic

        mid_provider = AnthropicProvider(
            ProviderConfig(api_key=config.anthropic_key, base_url=None),
            max_retries=config.llm_max_retries,
            timeout_seconds=config.llm_timeout_seconds,
        )

        critic = CompletenessCritic(mid_provider, config.mid_model)
        critic_report = await critic.review(
            project_summary=project_context.get("summary", ""),
            findings_summary=_format_findings_summary(result),
            label_breakdown=label_breakdown,
            coverage={"coverage_pct": coverage_audit.coverage_pct,
                      "high_risk_gaps": len(coverage_audit.high_risk_gaps)},
            hypotheses=session.get("hypotheses", []),
            language=language,
        )
        session["completeness_review"] = {
            "overall": critic_report.overall_assessment[:500],
            "missed_classes": critic_report.missed_vuln_classes,
            "assumptions": critic_report.questionable_assumptions,
            "recommendations": critic_report.recommendations,
        }

        if not quiet:
            missed = len(critic_report.missed_vuln_classes)
            recs = len(critic_report.recommendations)
            click.echo(f"   Missed classes: {missed}")
            click.echo(f"   Recommendations: {recs}")
            for rec in critic_report.recommendations[:3]:
                click.echo(f"     → {rec[:150]}")
    elif not quiet:
        click.echo()
        click.secho(
            "⏭  Completeness review skipped — no hypotheses or missing API keys.",
            fg="yellow",
        )

    # ── Update result ───────────────────────────────────────────────
    result.hypotheses = hypotheses  # type: ignore[attr-defined]
    result.coverage_audit = coverage_audit  # type: ignore[attr-defined]
    session["status"] = "completed"
    session["completed_at"] = datetime.now(UTC).isoformat()

    # ── Save session ────────────────────────────────────────────────
    _save_session(session_id, session)

    if not quiet:
        click.echo()
        click.secho(f"📋 Session saved: {session_id}", fg="green")
        click.echo(f"   Resume with: hyqagent resume {session_id}")

    return result


# ── Phase 0: Project understanding (evidence-based) ─────────────────────────


async def _understand_project(
    target: Path,
    language: str,
    file_paths: list[str],
    config: HyqAgentConfig,
    scan_findings: list[Any] | None = None,
    label_breakdown: dict[str, int] | None = None,
    coverage_summary: dict[str, Any] | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Build a high-level project understanding AFTER Phase 2 scan.

    Key design decision (see COVERAGE-GAP-ANALYSIS.md):
    Understanding comes AFTER the deterministic scan, not before it.
    This way the LLM works with concrete evidence — Phase 2 findings,
    annotated path labels, coverage gaps — rather than guessing from
    directory structure alone.

    The LLM receives:
    - Project structure + metadata files (what the project IS)
    - Phase 2 findings + label breakdown (what the scanner FOUND)
    - Coverage gaps (what the scanner MISSED)

    From this it produces:
    - Summary of what the project does
    - Risk assessment based on actual findings
    - Blind-spot analysis: which modules/vuln-types are under-covered
    - Prioritised audit plan for Phase 3
    """
    context: dict[str, Any] = {
        "summary": "",
        "modules": [],
        "tech_stack": [],
        "audit_plan": [],
        "risk_assessment": "",
    }

    scan_findings = scan_findings or []
    label_breakdown = label_breakdown or {}
    coverage_summary = coverage_summary or {}

    # 1. Collect project metadata
    meta_files = _find_meta_files(target, language)
    meta_text = ""
    for name, content in meta_files.items():
        meta_text += f"\n### {name}\n```\n{content[:3000]}\n```\n"

    # 2. Directory structure
    dirs: set[str] = set()
    for fp in file_paths:
        rel = Path(fp).relative_to(target)
        if rel.parts:
            dirs.add(rel.parts[0])
    top_dirs = sorted(dirs)[:15]

    if not meta_text and not top_dirs and not scan_findings:
        return context

    # 3. Build evidence-rich prompt
    structure = "\n".join(f"  {d}/" for d in top_dirs)

    # ── Scan findings summary ──────────────────────────────────────
    findings_text = ""
    if scan_findings:
        n = min(10, len(scan_findings))
        findings_text = f"\n## Phase 2 Scan Results ({len(scan_findings)} findings)\n"
        for f in scan_findings[:n]:
            sev = getattr(f, "severity", "?")
            loc = getattr(f, "location", "?")
            rule = getattr(f, "rule_id", getattr(f, "rule", "?"))
            findings_text += f"- [{sev}] {rule} at {loc}\n"
        if len(scan_findings) > n:
            findings_text += f"... and {len(scan_findings) - n} more\n"

    # ── Label breakdown ────────────────────────────────────────────
    labels_text = ""
    if label_breakdown:
        labels_text = "\n## Annotated Path Labels (Phase 2 classifications)\n"
        for lbl, cnt in sorted(label_breakdown.items()):
            labels_text += f"- {lbl}: {cnt} paths\n"

    # ── Coverage gaps ──────────────────────────────────────────────
    coverage_text = ""
    if coverage_summary:
        coverage_text = "\n## Coverage Summary\n"
        for k, v in coverage_summary.items():
            coverage_text += f"- {k}: {v}\n"

    # ── Assemble prompt ───────────────────────────────────────────
    prompt = (
        f"## Project: {target.name}\n"
        f"**Language**: {language}\n"
        f"**Top-level directories**:\n{structure}\n"
    )
    if meta_text:
        prompt += f"\n## Key Files\n{meta_text}"
    prompt += findings_text
    prompt += labels_text
    prompt += coverage_text

    prompt += (
        "\n\n## Your Task\n"
        "You have just received the results of a **deterministic static analysis scan** "
        "(Phase 2, zero-LLM, rule-based). Now you need to understand this project "
        "and plan the next phase of the audit.\n\n"
        "Provide:\n"
        "1. **Summary**: What does this project do? "
        "(Use the code structure and metadata, not guesswork.)\n"
        "2. **Risk Assessment**: Based on the ACTUAL scan findings above, "
        "what are the most concerning patterns? Be specific — cite the findings.\n"
        "3. **Coverage Blind Spots**: The deterministic scanner has known limitations. "
        "Looking at the label breakdown, what important vulnerability classes might "
        "have been missed? (e.g. many 'heuristic_sink' labels means the scanner "
        "couldn't classify dangerous operations; 'exposed_no_source' means endpoints "
        "accept user input but data flow tracing failed.)\n"
        "4. **Audit Plan**: Prioritised list of 3-6 areas to investigate in Phase 3 "
        "(LLM deep analysis). Order by risk: most dangerous first. "
        "For each, name the module/file and the specific concern.\n"
        "\nKeep the output concise and actionable — you are briefing a security "
        "engineer who will execute the deeper analysis."
    )

    # 4. Use cheap LLM
    if not _has_llm_keys(config):
        return context

    try:
        from hyqagent.models.providers.anthropic_provider import (
            AnthropicProvider,
            ProviderConfig,
        )

        provider = AnthropicProvider(
            ProviderConfig(
                api_key=config.deepseek_key,
                base_url=config.deepseek_base_url,
            ),
            max_retries=2,
            timeout_seconds=60,
        )

        result = await provider.generate(
            messages=[{"role": "user", "content": prompt}],
            model=config.cheap_model,
            system=(
                "You are a senior security engineer reviewing the results of an "
                "automated static analysis scan. Your job is to interpret the "
                "findings, identify what the scanner likely MISSED, and plan the "
                "next phase of the audit. "
                "Be evidence-based — ground every observation in the scan data. "
                "When the data is ambiguous, say so rather than guessing."
            ),
            max_tokens=1536,
            temperature=0.3,
        )

        text = ""
        for block in result.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        context["summary"] = text

        # Parse out audit plan items (lines starting with numbers or bullets)
        audit_plan: list[str] = []
        for line in text.split("\n"):
            stripped = line.strip()
            if (
                stripped.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "- ", "* "))
                and len(stripped) > 3
            ):
                audit_plan.append(stripped.lstrip("0123456789.*- ").strip()[:120])
        context["audit_plan"] = audit_plan[:8]
        context["modules"] = top_dirs

        # Track cost
        usage = result.get("usage", {})
        if not quiet:
            input_t = usage.get("input_tokens", 0)
            output_t = usage.get("output_tokens", 0)
            cost_est = input_t * 0.00014 / 1000 + output_t * 0.00028 / 1000
            click.echo(f"   (Project understanding: ~${cost_est:.4f})")

    except Exception:
        if not quiet:
            click.secho("   ⚠ Project understanding skipped (LLM unavailable)", fg="yellow")

    return context


# ── Phase 3: Hypothesis generation + validation ────────────────────────────


async def _run_phase3_hypotheses(
    annotated_paths: list[Any],
    language: str,
    config: HyqAgentConfig,
    quiet: bool = False,
) -> list[Any]:
    """Run LLM hypothesis generation on annotated paths from Phase 2."""
    from hyqagent.models.providers.anthropic_provider import (
        AnthropicProvider,
        ProviderConfig,
    )
    from hyqagent.models.router import ModelRouter
    from hyqagent.scanner.hypothesis import HypothesisGenerator

    cheap = AnthropicProvider(
        ProviderConfig(
            api_key=config.deepseek_key,
            base_url=config.deepseek_base_url,
        ),
        max_retries=config.llm_max_retries,
        timeout_seconds=config.llm_timeout_seconds,
    )
    mid = AnthropicProvider(
        ProviderConfig(api_key=config.anthropic_key, base_url=None),
        max_retries=config.llm_max_retries,
        timeout_seconds=config.llm_timeout_seconds,
    )
    strong = mid  # Same provider, different model (handled by router)

    router = ModelRouter(
        providers={"deepseek": cheap, "anthropic": mid},
        cheap_model=config.cheap_model,
        mid_model=config.mid_model,
        strong_model=config.strong_model,
    )

    # Need a CPGQuery for hypothesis generation
    from hyqagent.cpg.graph import CPGGraphBuilder
    from hyqagent.cpg.parser import Parser
    from hyqagent.cpg.query import CPGQuery
    from hyqagent.cpg.taint_loader import TaintRuleLoader

    taint_loader = TaintRuleLoader()
    parser = Parser()

    # Build minimal graph for query access (or reuse — for simplicity, rebuild)
    builder = CPGGraphBuilder(parser, taint_loader=taint_loader)
    for fp in annotated_paths[:1]:  # Just one file is enough for query
        with contextlib.suppress(Exception):
            builder.add_file(
                fp.path.nodes[0].location.split(":")[0]
                if hasattr(fp, "path") and fp.path.nodes
                else ""
            )
    query = CPGQuery(builder.graph)

    gen = HypothesisGenerator(
        query=query,
        router=router,
        cheap_provider=cheap,
        mid_provider=mid,
        strong_provider=strong,
        language=language,
    )

    hypotheses = await gen.generate(annotated_paths)

    if not quiet and hypotheses:
        click.echo(f"   Generated {len(hypotheses)} hypotheses")

        from collections import Counter

        sev_counts = Counter(h.severity for h in hypotheses)
        for sev, count in sev_counts.most_common():
            click.echo(f"     {sev}: {count}")

    return hypotheses


# ── Session persistence ────────────────────────────────────────────────────


def _save_session(session_id: str, session: dict[str, Any]) -> None:
    """Persist session state to disk for later resume."""
    sd = _ensure_session_dir()
    session_file = sd / f"{session_id}.json"
    session_file.write_text(json.dumps(session, indent=2, default=str, ensure_ascii=False))


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
