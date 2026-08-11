"""scanner/sandbox.py — Dynamic PoC verification in Docker sandbox.

Implements L6 (Dynamic Verification) from the severity-based vulnerability
mining framework.  Generates and executes PoC code for confirmed CRITICAL/HIGH
findings to validate exploitability at runtime.

Inspired by AutoCVE's Verification Agent pattern.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class SandboxResult:
    """Outcome of a single PoC execution in the Docker sandbox."""

    finding_id: str
    success: bool  # PoC confirmed the vulnerability?
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    execution_time_ms: float = 0.0
    error: str = ""


@dataclass
class PocCode:
    """LLM-generated PoC code ready for sandbox execution."""

    finding_id: str
    language: str  # python | javascript | java
    code: str  # the actual PoC script
    expected_behavior: str  # what the PoC should do if vulnerable
    risk_level: str = "safe"  # safe | read_only | may_modify
    reasoning: str = ""  # why this PoC should verify the finding


@dataclass
class DynamicVerificationResult:
    """Aggregate result: PoC generation + execution + interpretation."""

    finding_id: str
    vuln_type: str
    severity: str
    poc_code: str = ""
    execution: SandboxResult | None = None
    verdict: str = "inconclusive"  # confirmed | rejected | inconclusive
    updated_confidence: float = 0.0
    reasoning: str = ""
    model: str = ""


# ── PoC Generation Prompt ──────────────────────────────────────────────────────

POC_GENERATION_SYSTEM = """\
You are a penetration testing engineer. Given a confirmed vulnerability finding,
generate a SAFE, READ-ONLY Proof-of-Concept (PoC) script that verifies the
vulnerability WITHOUT causing any damage.

## Safety Rules (MUST follow)
1. **Read-only verification only**: the PoC should demonstrate exploitability
   without modifying data, deleting files, or changing system state.
2. **Use benign payloads**: for SQLi, use `SELECT 1` or `SELECT version()`.
   For Command Injection, use `id`, `whoami`, or `echo VULNERABLE`.
   For SSTI, use `{{7*7}}` or equivalent non-destructive template expression.
3. **No exfiltration**: do not send data to any external server.
4. **Self-contained**: the script should work with only standard library.
5. **Exit code 0**: if vulnerable, exit 0 and print confirmation.
   Exit 1 if not vulnerable or if the check is inconclusive.

## PoC Structure
- Print a clear banner: "PoC for &lt;VULN_TYPE&gt; at &lt;LOCATION&gt;"
- Demonstrate the vulnerability path
- Print "[VULNERABLE]" or "[NOT_VULNERABLE]" on the last line
- Only use standard library modules

## Output Format
Use the report_poc tool to return structured JSON.
"""

POC_GENERATION_SCHEMA: dict[str, Any] = {
    "name": "report_poc",
    "description": "Return the generated PoC code for sandbox execution.",
    "input_schema": {
        "type": "object",
        "properties": {
            "language": {
                "type": "string",
                "enum": ["python", "javascript", "java"],
                "description": "Programming language for the PoC script.",
            },
            "code": {
                "type": "string",
                "description": "The complete PoC script source code.",
            },
            "expected_behavior": {
                "type": "string",
                "description": "What the PoC should do if the vulnerability exists.",
            },
            "risk_level": {
                "type": "string",
                "enum": ["safe", "read_only", "may_modify"],
                "description": "Risk assessment of the generated PoC.",
            },
            "reasoning": {
                "type": "string",
                "description": "Why this PoC verifies the specific finding.",
            },
        },
        "required": ["language", "code", "expected_behavior", "risk_level"],
    },
}

# ── PoC Interpretation Prompt ──────────────────────────────────────────────────

POC_INTERPRETATION_SYSTEM = """\
You are a security engineer interpreting the results of a dynamic PoC execution.

The system executed a PoC script in an isolated Docker sandbox and captured
the output.  Your job is to determine whether the execution CONFIRMS or
REJECTS the vulnerability hypothesis.

## Interpretation Guidelines
1. **CONFIRMED**: The PoC output matches the expected behavior —
   the vulnerability is real and exploitable.
   - Example: a command injection PoC successfully ran `id` and printed
     user information.
   - Confidence: 0.85-1.0

2. **REJECTED**: The PoC clearly shows the vulnerability is NOT exploitable.
   - Example: SQLi payload was treated as a literal string, no injection occurred.
   - Confidence: 0.15-0.4

3. **INCONCLUSIVE**: The PoC didn't run properly, timed out, or the output
   is ambiguous.
   - Example: script crashed with ImportError, connection refused, timeout.
   - Confidence: keep at current level (no update)

## Rules
- Do NOT infer exploitability from error messages alone.
- If the sandbox timed out, mark INCONCLUSIVE.
- If stdout contains "[VULNERABLE]", lean toward CONFIRMED.
- If stdout contains "[NOT_VULNERABLE]", lean toward REJECTED.
- Account for the possibility that the PoC code itself was buggy.

Use the report_interpretation tool for your output.
"""

POC_INTERPRETATION_SCHEMA: dict[str, Any] = {
    "name": "report_interpretation",
    "description": "Interpret the results of dynamic PoC execution.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "rejected", "inconclusive"],
                "description": "Final verdict after dynamic verification.",
            },
            "updated_confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Updated confidence score after dynamic verification.",
            },
            "reasoning": {
                "type": "string",
                "description": (
                    "Step-by-step reasoning: what the PoC did, what the output shows, "
                    "and why this confirms or refutes the finding."
                ),
            },
        },
        "required": ["verdict", "updated_confidence", "reasoning"],
    },
}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _build_poc_generation_prompt(
    finding: dict[str, Any],
    code_context: str = "",
) -> str:
    """Build the user prompt for PoC generation."""
    vuln_type = finding.get("vuln_type", "unknown")
    severity = finding.get("severity", "unknown")
    source = finding.get("source_location", finding.get("source", ""))
    sink = finding.get("sink_location", finding.get("sink", ""))
    description = finding.get("description", "")
    language = finding.get("language", "python")

    parts = [
        "## Vulnerability Finding",
        f"**Type**: {vuln_type}",
        f"**Severity**: {severity}",
        f"**Language**: {language}",
        f"**Source**: {source}",
        f"**Sink**: {sink}",
        f"\n**Description**: {description}",
    ]
    if code_context:
        parts.append(f"\n## Code Context\n```{language}\n{code_context[:2000]}\n```")
    parts.append(
        "\nGenerate a SAFE PoC script that verifies this vulnerability. "
        "The PoC must be read-only — no destructive operations. "
        "Use the report_poc tool to return the generated code."
    )
    return "\n".join(parts)


def _build_interpretation_prompt(
    poc_code: str,
    result: SandboxResult,
    expected_behavior: str,
    vuln_type: str,
) -> str:
    """Build the user prompt for PoC result interpretation."""
    return "\n".join(
        [
            "## PoC Code Executed",
            f"```\n{poc_code[:1500]}\n```",
            "",
            "## Expected Behavior (if vulnerable)",
            expected_behavior,
            "",
            "## Execution Result",
            f"**Exit Code**: {result.exit_code}",
            f"**Timed Out**: {result.timed_out}",
            f"**Execution Time**: {result.execution_time_ms:.0f}ms",
            "",
            "## stdout",
            "```",
            result.stdout[:2000] or "(empty)",
            "```",
            "",
            "## stderr",
            "```",
            result.stderr[:1000] or "(empty)",
            "```",
            "",
            f"Interpret these results for the {vuln_type} finding. "
            "Use the report_interpretation tool for your output.",
        ]
    )


# ── SandboxExecutor ────────────────────────────────────────────────────────────


class SandboxExecutor:
    """Execute PoC code in an isolated Docker container.

    Safety constraints (enforced by Docker):
    - Network: none (no external connectivity)
    - Memory: 256MB hard limit
    - CPU: 50% of one core
    - Filesystem: read-only root with tmpfs /tmp
    - User: nobody (non-root)
    - Timeout: 30s wall-clock

    Usage::

        executor = SandboxExecutor(image="hyqagent-sandbox:latest")
        result = await executor.execute(poc_code, language="python")
    """

    def __init__(
        self,
        image: str = "hyqagent-sandbox:latest",
        timeout: int = 30,
        memory_limit: str = "256m",
        cpu_quota: int = 50000,
    ) -> None:
        self._image = image
        self._timeout = timeout
        self._memory_limit = memory_limit
        self._cpu_quota = cpu_quota

    async def execute(
        self,
        poc_code: str,
        language: str = "python",
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Execute poc_code in a Docker container and return the result.

        The Docker SDK is synchronous, so we run it in a thread pool via
        :func:`asyncio.to_thread`.
        """
        return await asyncio.to_thread(self._execute_sync, poc_code, language, env)

    def _execute_sync(
        self,
        poc_code: str,
        language: str,
        env: dict[str, str] | None,
    ) -> SandboxResult:
        """Execute PoC code in a Docker container synchronously (runs in thread pool)."""
        from docker.errors import DockerException, ImageNotFound

        import docker

        start = time.monotonic()

        # Determine file extension and command
        ext, cmd = _language_config(language)

        try:
            client = docker.from_env()
        except DockerException as exc:
            return SandboxResult(
                finding_id="",
                success=False,
                error=f"Docker unavailable: {exc}",
            )

        # Ensure image exists
        try:
            client.images.get(self._image)
        except ImageNotFound:
            logger.info("sandbox_image_not_found", image=self._image)
            return SandboxResult(
                finding_id="",
                success=False,
                error=f"Sandbox image not found: {self._image}. Build it with: "
                f"docker build -t {self._image} docker/sandbox/",
            )

        # Write PoC to temp file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=ext,
            prefix="poc_",
            delete=False,
        ) as tmp:
            tmp.write(poc_code)
            tmp_path = tmp.name

        try:
            container = client.containers.run(
                image=self._image,
                command=[*cmd, f"/tmp/{Path(tmp_path).name}"],  # noqa: S108
                volumes={tmp_path: {"bind": f"/tmp/{Path(tmp_path).name}", "mode": "ro"}},  # noqa: S108
                network_mode="none",
                mem_limit=self._memory_limit,
                cpu_quota=self._cpu_quota,
                read_only=True,
                tmpfs={"/tmp": "size=64m,mode=1777"},  # noqa: S108
                user="nobody",
                environment=env or {},
                detach=True,
                remove=False,
            )

            try:
                result = container.wait(timeout=self._timeout)
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                exit_code = result.get("StatusCode", -1)
                elapsed = (time.monotonic() - start) * 1000

                return SandboxResult(
                    finding_id="",
                    success=exit_code == 0,
                    exit_code=exit_code,
                    stdout=stdout[:5000],
                    stderr=stderr[:2000],
                    timed_out=False,
                    execution_time_ms=elapsed,
                )
            except Exception as exc:
                # Check for timeout from docker
                container.kill()
                elapsed = (time.monotonic() - start) * 1000
                return SandboxResult(
                    finding_id="",
                    success=False,
                    timed_out=True,
                    execution_time_ms=elapsed,
                    stderr=str(exc)[:500],
                    error=f"Execution error or timeout: {exc}",
                )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return SandboxResult(
                finding_id="",
                success=False,
                execution_time_ms=elapsed,
                error=f"Container creation failed: {exc}",
            )
        finally:
            with contextlib.suppress(OSError):
                Path(tmp_path).unlink(missing_ok=True)


def _language_config(language: str) -> tuple[str, list[str]]:
    """Return (file_extension, command) for the target language."""
    configs = {
        "python": (".py", ["python3"]),
        "javascript": (".js", ["node"]),
        "java": (".java", ["java"]),
    }
    return configs.get(language, (".py", ["python3"]))


# ── PocGenerator ───────────────────────────────────────────────────────────────


class PocGenerator:
    """LLM-based PoC code generation for vulnerability verification.

    Uses a strong LLM provider to generate safe, read-only PoC scripts
    based on confirmed vulnerability findings and surrounding code context.

    Usage::

        gen = PocGenerator(provider=strong_provider, model="claude-opus-5")
        poc = await gen.generate(finding, language="python", code_context="...")
    """

    def __init__(self, provider: Any, model: str) -> None:
        """Create a PoC generator backed by an LLM provider.

        Args:
            provider: LlmProvider (or compatible).
            model: Model ID string — should be a strong reasoning model.

        """
        self._provider = provider
        self._model = model

    async def generate(
        self,
        finding: dict[str, Any],
        language: str = "python",
        code_context: str = "",
    ) -> PocCode | None:
        """Generate PoC code for a confirmed vulnerability finding.

        Returns ``None`` if the LLM call fails or returns invalid data.
        """
        prompt = _build_poc_generation_prompt(finding, code_context)

        try:
            raw = await self._provider.generate_structured(
                messages=[{"role": "user", "content": prompt}],
                model=self._model,
                output_schema=POC_GENERATION_SCHEMA,
                system=POC_GENERATION_SYSTEM,
                max_tokens=4096,
                temperature=0.1,
            )
        except Exception:
            logger.exception(
                "poc_generation_failed",
                finding_id=finding.get("id", "unknown"),
            )
            return None

        return PocCode(
            finding_id=finding.get("id", "unknown"),
            language=str(raw.get("language", language)),
            code=str(raw.get("code", "")),
            expected_behavior=str(raw.get("expected_behavior", "")),
            risk_level=str(raw.get("risk_level", "safe")),
            reasoning=str(raw.get("reasoning", "")),
        )

    async def interpret(
        self,
        poc_code: str,
        result: SandboxResult,
        expected_behavior: str,
        vuln_type: str,
    ) -> dict[str, Any]:
        """Interpret sandbox execution results via LLM.

        Returns a dict with keys: verdict, updated_confidence, reasoning.
        """
        prompt = _build_interpretation_prompt(
            poc_code,
            result,
            expected_behavior,
            vuln_type,
        )

        try:
            raw = await self._provider.generate_structured(
                messages=[{"role": "user", "content": prompt}],
                model=self._model,
                output_schema=POC_INTERPRETATION_SCHEMA,
                system=POC_INTERPRETATION_SYSTEM,
                max_tokens=2048,
                temperature=0.0,
            )
            return {
                "verdict": str(raw.get("verdict", "inconclusive")),
                "updated_confidence": float(raw.get("updated_confidence", 0.5)),
                "reasoning": str(raw.get("reasoning", "")),
            }
        except Exception:
            logger.exception("poc_interpretation_failed")
            return {
                "verdict": "inconclusive",
                "updated_confidence": 0.5,
                "reasoning": "LLM interpretation failed — defaulting to inconclusive.",
            }


# ── Top-level verification orchestrator ────────────────────────────────────────


async def verify_finding(
    finding: dict[str, Any],
    executor: SandboxExecutor,
    generator: PocGenerator,
    language: str = "python",
    code_context: str = "",
) -> DynamicVerificationResult:
    """Run the full dynamic verification pipeline for a single finding.

    1. Generate PoC code via LLM
    2. Execute PoC in Docker sandbox
    3. Interpret results via LLM
    4. Return aggregated result
    """
    fid = finding.get("id", "unknown")
    vuln_type = finding.get("vuln_type", "unknown")
    severity = finding.get("severity", "medium")

    # Step 1: Generate PoC
    poc = await generator.generate(finding, language, code_context)
    if poc is None:
        return DynamicVerificationResult(
            finding_id=fid,
            vuln_type=vuln_type,
            severity=severity,
            verdict="inconclusive",
            reasoning="PoC generation failed (LLM error).",
        )

    # Step 2: Execute
    result = await executor.execute(poc.code, language=poc.language)

    # Step 3: Interpret
    interpretation = await generator.interpret(
        poc.code,
        result,
        poc.expected_behavior,
        vuln_type,
    )

    return DynamicVerificationResult(
        finding_id=fid,
        vuln_type=vuln_type,
        severity=severity,
        poc_code=poc.code,
        execution=result,
        verdict=interpretation["verdict"],
        updated_confidence=interpretation["updated_confidence"],
        reasoning=interpretation["reasoning"],
        model=generator._model,
    )


async def verify_findings(
    findings: list[dict[str, Any]],
    executor: SandboxExecutor,
    generator: PocGenerator,
    language: str = "python",
    code_contexts: dict[str, str] | None = None,
    concurrency: int = 3,
) -> list[DynamicVerificationResult]:
    """Verify multiple findings concurrently (bounded by ``concurrency``).

    Uses a semaphore to limit parallel Docker containers.
    """
    ctx = code_contexts or {}
    sem = asyncio.Semaphore(concurrency)

    async def _verify_one(finding: dict[str, Any]) -> DynamicVerificationResult:
        async with sem:
            fid = finding.get("id", "unknown")
            return await verify_finding(
                finding,
                executor,
                generator,
                language=language,
                code_context=ctx.get(fid, ""),
            )

    tasks = [_verify_one(f) for f in findings]
    return list(await asyncio.gather(*tasks))
