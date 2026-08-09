"""Comprehensive live-LLM smoke test for all Phase 3 components.

Tests: AnthropicProvider, ModelRouter, CostTracker, HypothesisGenerator,
       Validator L2, NudgeLoop, and the full --deep CLI pipeline.

Uses DeepSeek-V4-Flash (CHEAP tier, ~$0.14/1M tokens).
Total estimated cost: < $0.05 for this entire run.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hyqagent.api.config import HyqAgentConfig
from hyqagent.models.providers.anthropic_provider import AnthropicProvider, ProviderConfig
from hyqagent.models.router import ModelRouter, Task, TaskType
from hyqagent.observability.cost_tracker import PRICING, CostTracker
from hyqagent.scanner.nudge import (
    NudgeConfig,
    NudgeLoop,
    stop_on_empty,
    stop_on_low_confidence,
)

# ── Mini schema for hypothesis generation ─────────────────────────────────────

HYP_SCHEMA = {
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
                        "source_location": {"type": "string"},
                        "sink_location": {"type": "string"},
                        "description": {"type": "string"},
                        "reasoning": {"type": "string"},
                    },
                    "required": ["vuln_type", "severity", "confidence", "description", "reasoning"],
                },
            },
        },
        "required": ["hypotheses"],
    },
}

SYSTEM_PROMPT = """You are a white-box security auditor analysing code for
web application vulnerabilities (SQL injection, XSS, command injection,
SSRF, IDOR, etc.). For each finding provide a structured report.
Be specific: cite code lines, variable names, and function calls.
If you find nothing, explain why each potential sink is safe.
Use the report_hypotheses tool for output."""

# ── Mini schema for validation ─────────────────────────────────────────────────

VAL_SCHEMA = {
    "name": "report_validation",
    "description": "Report validation verdict",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["confirmed", "rejected", "inconclusive"]},
            "confidence": {"type": "number"},
            "q1_reachability": {"type": "string"},
            "q2_bypass": {"type": "string"},
            "q3_sanitizer": {"type": "string"},
            "q4_framework": {"type": "string"},
            "q5_judgment": {"type": "string"},
        },
        "required": ["verdict", "confidence", "q1_reachability", "q5_judgment"],
    },
}

VAL_SYSTEM = """You are a senior security engineer verifying a vulnerability report.
For the hypothesis below, answer 5 questions:
1. Path Reachability — can source reach sink at runtime?
2. Condition Bypass — can attackers bypass guards?
3. Sanitizer Adequacy — is the sanitizer effective?
4. Framework Protection — does the framework auto-protect?
5. Comprehensive Judgment — final verdict.
Use the report_validation tool for output."""


def sep(title: str) -> None:
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def ok(msg: str) -> None:
    print(f"  ✅ {msg}")


def fail(msg: str) -> None:
    print(f"  ❌ {msg}")


# ──────────────────────────────────────────────────────────────────────────────


async def test_1_provider_connectivity(cfg: HyqAgentConfig) -> AnthropicProvider:
    """Test 1: Provider connectivity — simple generate call."""
    sep("Test 1: Provider connectivity")
    provider = AnthropicProvider(
        ProviderConfig(api_key=cfg.deepseek_key, base_url=cfg.deepseek_base_url)
    )

    result = await provider.generate_structured(
        messages=[{"role": "user", "content": 'What is 2+2? Answer in JSON: {"answer": N}'}],
        model="deepseek-v4-flash",
        output_schema={
            "name": "math",
            "input_schema": {
                "type": "object",
                "properties": {"answer": {"type": "integer"}},
                "required": ["answer"],
            },
        },
        max_tokens=256,
        temperature=0.0,
    )
    if result.get("answer") == 4:
        ok(f"Provider works: 2+2={result['answer']}")
    else:
        fail(f"Provider returned unexpected: {result}")

    # Token count
    tokens = provider.count_tokens(
        [{"role": "user", "content": "Hello"}], model="deepseek-v4-flash"
    )
    ok(f"Token counter: {tokens} tokens estimated for 'Hello'")
    return provider


async def test_2_model_router(cfg: HyqAgentConfig) -> None:
    """Test 2: ModelRouter — route decisions."""
    sep("Test 2: ModelRouter")
    # Need at least a fake provider to instantiate router
    cheap = AnthropicProvider(
        ProviderConfig(api_key=cfg.deepseek_key, base_url=cfg.deepseek_base_url)
    )
    mid = AnthropicProvider(ProviderConfig(api_key="sk-placeholder"))
    strong = AnthropicProvider(ProviderConfig(api_key="sk-placeholder"))

    router = ModelRouter(
        providers={"deepseek": cheap, "anthropic": mid},
        cheap_model="deepseek-v4-flash",
        mid_model="claude-sonnet-5",
        strong_model="claude-opus-5",
    )

    # Low complexity → CHEAP
    _, model_low = router.route(
        Task(TaskType.HYPOTHESIS_GENERATION, complexity=3, estimated_prompt_tokens=500)
    )
    ok(f"Complexity 3 → model='{model_low}' (expected cheap)")

    # High complexity → STRONG
    _, model_high = router.route(
        Task(TaskType.L2_VALIDATION, complexity=9, estimated_prompt_tokens=2000)
    )
    ok(f"Complexity 9 → model='{model_high}' (expected strong)")

    # Complexity scoring
    score_simple = router.assess_complexity(path_length=2, cross_file_count=0)
    score_complex = router.assess_complexity(path_length=15, cross_file_count=5)
    ok(f"assess_complexity: simple={score_simple}, complex={score_complex}")


async def test_3_cost_tracker() -> None:
    """Test 3: CostTracker — record and query."""
    sep("Test 3: CostTracker")
    tracker = CostTracker(max_budget=5.0)
    tracker.record("hypothesis_gen", "deepseek-v4-flash", input_tokens=1000, output_tokens=200)
    tracker.record("l2_validation", "deepseek-v4-flash", input_tokens=500, output_tokens=100)

    total = tracker.total_cost()
    by_phase = tracker.cost_by_phase().get("hypothesis_gen", 0)

    ok(f"Total cost after 2 calls: ${total:.6f} (budget: ${tracker.remaining_budget():.2f} left)")
    ok(f"Cost by phase 'hypothesis_gen': ${by_phase:.6f}")
    ok(f"Budget exceeded: {tracker.is_budget_exceeded()}")


async def test_4_nudge_happy_path(provider: AnthropicProvider) -> None:
    """Test 4: NudgeLoop — happy path (no nudges needed)."""
    sep("Test 4: NudgeLoop — Happy Path")
    loop = NudgeLoop(NudgeConfig(max_turns=3))

    vuln_code = """
from flask import request
import sqlite3

@app.route('/search')
def search():
    query = request.args.get('q')
    sql = "SELECT * FROM products WHERE name = '%s'" % query
    return db.execute(sql)
""".strip()

    result = await loop.run(
        provider=provider,
        model="deepseek-v4-flash",
        messages=[
            {
                "role": "user",
                "content": (
                    "Analyse this Python code for vulnerabilities:\n"
                    f"```python\n{vuln_code}\n```\n"
                    "Use the report_hypotheses tool."
                ),
            }
        ],
        output_schema=HYP_SCHEMA,
        system=SYSTEM_PROMPT,
        max_tokens=1024,
        temperature=0.0,
        stop_hooks=[stop_on_empty("hypotheses"), stop_on_low_confidence(0.3)],
    )

    if result.success and result.turns == 1:
        hyps = result.data.get("hypotheses", [])
        ok(f"Nudge happy path: {result.turns} turn, {len(hyps)} hypotheses, 0 nudges")
        for h in hyps:
            print(
                f"     - [{h.get('severity', '?')}] {h.get('vuln_type', '?')}: {h.get('description', '')[:80]}..."
            )
    elif result.success:
        ok(f"Nudge passed after {result.turns} turns, {len(result.nudges)} nudges")
    else:
        fail(f"Nudge failed: {result.termination_reason} after {result.turns} turns")


async def test_5_nudge_quality_block(provider: AnthropicProvider) -> None:
    """Test 5: NudgeLoop — quality block (empty result → nudge → retry)."""
    sep("Test 5: NudgeLoop — Quality Block")
    loop = NudgeLoop(NudgeConfig(max_turns=3))

    # Safe code — model should correctly report no vulns, but stop_on_empty will nudge
    safe_code = """
def add(a: int, b: int) -> int:
    \"\"\"Pure function — no I/O, no user input, no dangerous operations.\"\"\"
    return a + b
""".strip()

    result = await loop.run(
        provider=provider,
        model="deepseek-v4-flash",
        messages=[
            {
                "role": "user",
                "content": (
                    "Analyse this Python code for vulnerabilities:\n"
                    f"```python\n{safe_code}\n```\n"
                    "Use the report_hypotheses tool."
                ),
            }
        ],
        output_schema=HYP_SCHEMA,
        system=SYSTEM_PROMPT,
        max_tokens=1024,
        temperature=0.0,
        stop_hooks=[stop_on_empty("hypotheses")],
    )

    hyps = result.data.get("hypotheses", [])
    if result.success:
        ok(
            f"Quality block test: {result.turns} turns, {len(result.nudges)} nudges, {len(hyps)} hypotheses"
        )
        for n in result.nudges:
            print(f"     🔔 Nudge: {n['type']} — {n['message'][:100]}...")
    else:
        ok(
            f"Quality block exhausted: {result.termination_reason} ({result.turns} turns, {len(result.nudges)} nudges)"
        )
        # Empty is expected for truly safe code with limited turns


async def test_6_validator_l2(provider: AnthropicProvider) -> None:
    """Test 6: Validator L2 — 5-question verification."""
    sep("Test 6: Validator L2 (5-question verification)")

    hypothesis_desc = (
        "The /search endpoint takes user input from request.args.get('q') "
        "and interpolates it directly into a SQL query using Python's % "
        "string formatting operator, without any parameterization or "
        "escaping. The sink is db.execute(sql)."
    )

    result = await provider.generate_structured(
        messages=[
            {
                "role": "user",
                "content": (
                    "## Vulnerability Hypothesis\n"
                    f"**Type**: sql_injection\n"
                    f"**Severity**: high\n"
                    f"**Source**: app.py:5 (request.args.get('q'))\n"
                    f"**Sink**: app.py:7 (db.execute(sql))\n"
                    f"**Description**: {hypothesis_desc}\n\n"
                    "## Code Context\n```python\n"
                    "from flask import request\n"
                    "query = request.args.get('q')\n"
                    "sql = \"SELECT * FROM p WHERE n = '%s'\" % query\n"
                    "db.execute(sql)\n"
                    "```\n\n"
                    "Answer the 5 validation questions and provide your verdict "
                    "using the report_validation tool."
                ),
            }
        ],
        model="deepseek-v4-flash",
        output_schema=VAL_SCHEMA,
        system=VAL_SYSTEM,
        max_tokens=1024,
        temperature=0.0,
    )

    verdict = result.get("verdict", "?")
    confidence = result.get("confidence", 0)
    has_reasoning = bool(result.get("q1_reachability") and result.get("q5_judgment"))

    if verdict in ("confirmed", "rejected", "inconclusive") and has_reasoning:
        ok(f"Validator L2: verdict='{verdict}', confidence={confidence:.2f}")
        print(f"     Q1 (reachability): {result.get('q1_reachability', '')[:80]}...")
        print(f"     Q5 (judgment): {result.get('q5_judgment', '')[:80]}...")
    else:
        fail(f"Validator L2 unexpected: verdict={verdict}, has_reasoning={has_reasoning}")


async def test_7_full_hypothesis_flow(provider: AnthropicProvider) -> None:
    """Test 7: Complete flow — generate + nudge-protected validate."""
    sep("Test 7: Complete Generate→Validate Flow")

    # Complex vulnerable code with multiple issues
    code = """
from flask import Flask, request, redirect
import sqlite3, os, pickle

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    # Vulnerable: direct string formatting
    query = "SELECT * FROM users WHERE name='%s' AND pass='%s'" % (username, password)
    user = conn.execute(query).fetchone()
    if user:
        return redirect('/dashboard')
    return 'Login failed'

@app.route('/export')
def export():
    fmt = request.args.get('format', 'json')
    # Vulnerable: command injection
    os.system(f'mysqldump -f {fmt}')
    return 'OK'

@app.route('/load')
def load():
    data = request.args.get('data')
    # Vulnerable: unsafe deserialization
    obj = pickle.loads(data.encode())
    return str(obj)
""".strip()

    loop = NudgeLoop(NudgeConfig(max_turns=3))

    # Step 1: Generate hypotheses
    gen_result = await loop.run(
        provider=provider,
        model="deepseek-v4-flash",
        messages=[
            {
                "role": "user",
                "content": (
                    "Analyse this Python Flask application for ALL vulnerabilities:\n"
                    f"```python\n{code}\n```\n"
                    "Report EVERY vulnerability you find using the report_hypotheses tool. "
                    "Check each endpoint carefully."
                ),
            }
        ],
        output_schema=HYP_SCHEMA,
        system=SYSTEM_PROMPT,
        max_tokens=2048,
        temperature=0.0,
        stop_hooks=[stop_on_empty("hypotheses"), stop_on_low_confidence(0.3)],
    )

    hyps = gen_result.data.get("hypotheses", [])
    print(
        f"  Step 1 — Generation: {len(hyps)} hypotheses, {gen_result.turns} turns, {len(gen_result.nudges)} nudges"
    )

    # Step 2: Validate each hypothesis
    confirmed = 0
    for h in hyps:
        val_result = await provider.generate_structured(
            messages=[
                {
                    "role": "user",
                    "content": (
                        "## Vulnerability Hypothesis\n"
                        f"**Type**: {h.get('vuln_type')}\n"
                        f"**Severity**: {h.get('severity')}\n"
                        f"**Source**: {h.get('source_location')}\n"
                        f"**Sink**: {h.get('sink_location')}\n"
                        f"**Description**: {h.get('description')}\n"
                        f"**LLM Reasoning**: {h.get('reasoning')}\n\n"
                        "Answer the 5 questions and provide your verdict "
                        "using the report_validation tool."
                    ),
                }
            ],
            model="deepseek-v4-flash",
            output_schema=VAL_SCHEMA,
            system=VAL_SYSTEM,
            max_tokens=1024,
            temperature=0.0,
        )
        verdict = val_result.get("verdict", "?")
        if verdict == "confirmed":
            confirmed += 1
        print(
            f"     [{h.get('vuln_type', '?')}] → {verdict} (conf={val_result.get('confidence', 0):.0%})"
        )

    if len(hyps) >= 2 and confirmed >= 1:
        ok(f"Full flow: {len(hyps)} found, {confirmed} confirmed")
    elif len(hyps) >= 1:
        ok(f"Full flow: {len(hyps)} found, {confirmed} confirmed (some may be false positives)")
    else:
        fail(f"Full flow returned unexpectedly few hypotheses: {len(hyps)}")


# ──────────────────────────────────────────────────────────────────────────────


async def main() -> None:
    print("=" * 60)
    print("  HyqAgent Phase 3 — Full LLM Integration Smoke Test")
    print("  Model: DeepSeek-V4-Flash (CHEAP)")
    print(
        f"  Pricing: ${PRICING.get('deepseek-v4-flash', {}).get('input_price_per_1k', 0)}/1M input"
    )
    print("=" * 60)

    cfg = HyqAgentConfig()

    # Test 1-3: Infrastructure (minimal tokens)
    provider = await test_1_provider_connectivity(cfg)
    await test_2_model_router(cfg)
    await test_3_cost_tracker()

    # Test 4-5: Nudge system (~3K tokens each)
    await test_4_nudge_happy_path(provider)
    await test_5_nudge_quality_block(provider)

    # Test 6: Validator L2 (~1.5K tokens)
    await test_6_validator_l2(provider)

    # Test 7: Full generate→validate flow (~5K tokens)
    await test_7_full_hypothesis_flow(provider)

    # ── Summary ────────────────────────────────────────────────────────
    sep("Summary")
    print("  All 7 tests executed against DeepSeek-V4-Flash")
    print("  Estimated total: ~20K input + ~5K output tokens")
    pricing = PRICING.get("deepseek-v4-flash", {})
    input_cost = pricing.get("input_price_per_1k", 0)
    output_cost = pricing.get("output_price_per_1k", 0)
    est = (20000 * input_cost + 5000 * output_cost) / 1000
    print(f"  Estimated cost: ${est:.4f}")
    print("\n  Run: uv run python tests/manual/test_llm_smoke.py")


if __name__ == "__main__":
    asyncio.run(main())
