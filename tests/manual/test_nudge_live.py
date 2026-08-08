"""Minimal live-LLM test for the Nudge system.

Uses DeepSeek-V4-Flash-0731 (CHEAP tier, lowest cost).
Token budget: ~3K input, ~500 output per call, max ~6K total.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from hyqagent.api.config import HyqAgentConfig
from hyqagent.models.providers.anthropic_provider import AnthropicProvider, ProviderConfig
from hyqagent.scanner.nudge import (
    NudgeConfig,
    NudgeLoop,
    NudgeResult,
    stop_on_empty,
    stop_on_low_confidence,
)

HYPOTHESIS_SCHEMA = {
    "name": "report_hypotheses",
    "description": "Report vulnerability hypotheses",
    "input_schema": {
        "type": "object",
        "properties": {
            "hypotheses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "vuln_type": {"type": "string"},
                        "severity": {"type": "string"},
                        "confidence": {"type": "number"},
                        "description": {"type": "string"},
                    },
                    "required": ["vuln_type", "severity", "confidence", "description"],
                },
            },
        },
        "required": ["hypotheses"],
    },
}

SYSTEM_PROMPT = """You are a security auditor. Analyse code and report vulnerabilities
using the report_hypotheses tool. Be thorough — don't say "no vulnerabilities"
unless you have carefully examined every line."""


async def test_with_nudge(code: str, label: str) -> NudgeResult:
    """Run one nudge-protected analysis."""
    config = HyqAgentConfig()
    provider = AnthropicProvider(
        ProviderConfig(
            api_key=config.deepseek_key,
            base_url=config.deepseek_base_url,
        )
    )

    loop = NudgeLoop(NudgeConfig(max_turns=3, terminal_nudge_limit=1))
    result = await loop.run(
        provider=provider,
        model="deepseek-v4-flash",
        messages=[
            {
                "role": "user",
                "content": (
                    f"## Test Scenario: {label}\n\n"
                    f"Analyse this Python code for web application "
                    f"vulnerabilities:\n\n```python\n{code}\n```\n\n"
                    f"Report using the report_hypotheses tool."
                ),
            }
        ],
        output_schema=HYPOTHESIS_SCHEMA,
        system=SYSTEM_PROMPT,
        max_tokens=1024,
        temperature=0.0,
        stop_hooks=[stop_on_empty("hypotheses"), stop_on_low_confidence(0.3)],
    )
    return result


def print_result(label: str, result: NudgeResult) -> None:
    """Pretty-print a nudge result."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Success: {result.success}")
    print(f"  Turns: {result.turns}")
    print(f"  Reason: {result.termination_reason}")
    print(f"  Nudges: {len(result.nudges)}")
    for n in result.nudges:
        print(f"    - turn {n['turn']}: {n['type']} ({n['message'][:80]}...)")
    hyps = result.data.get("hypotheses", [])
    print(f"  Hypotheses found: {len(hyps)}")
    for h in hyps[:3]:
        print(f"    - [{h.get('severity','?')}] {h.get('vuln_type','?')} "
              f"(confidence: {h.get('confidence','?')})")


async def main() -> None:
    print("=" * 60)
    print("  HyqAgent Nudge System — Live LLM Smoke Test")
    print("  Model: deepseek-v4-flash-0731 (CHEAP)")
    print("=" * 60)

    # ── Test 1: Code with NO vulnerability ───────────────────────────
    # This should trigger stop_on_empty → QUALITY nudge
    safe_code = """
def add(a: int, b: int) -> int:
    \"\"\"Pure function, no user input, no side effects.\"\"\"
    return a + b

def multiply(x: int, y: int) -> int:
    \"\"\"Another pure function.\"\"\"
    return x * y
""".strip()

    result1 = await test_with_nudge(safe_code, "Safe code (should trigger quality nudge)")
    print_result("Test 1: Safe pure functions", result1)

    # ── Test 2: Code WITH a clear SQL injection ──────────────────────
    # This should succeed on first try — no nudge needed
    vuln_code = """
from flask import request
import sqlite3

@app.route('/user/<user_id>')
def get_user(user_id):
    \"\"\"Vulnerable: direct string formatting into SQL.\"\"\"
    conn = sqlite3.connect('db.sqlite3')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query)
    return result.fetchone()
""".strip()

    result2 = await test_with_nudge(vuln_code, "SQL injection (should succeed directly)")
    print_result("Test 2: SQL Injection", result2)

    # ── Summary ────────────────────────────────────────────────────
    total_turns = result1.turns + result2.turns
    total_nudges = len(result1.nudges) + len(result2.nudges)
    print(f"\n{'='*60}")
    print(f"  Summary: {total_turns} total turns, {total_nudges} nudges issued")
    print(f"  Token estimate: ~{total_turns * 3}K input + ~{total_turns * 500} output")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
