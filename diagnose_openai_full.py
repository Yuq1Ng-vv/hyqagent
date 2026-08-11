#!/usr/bin/env python3
"""OpenAI Provider 全链路诊断脚本
Usage:
  uv run python diagnose_openai_full.py

层层检查 OpenAI 模式下 LLM 调用链路的每个环节，明确显示哪一步失败及原因。
"""

import asyncio
import sys
import time

SEP = "=" * 65


def section(title: str) -> None:
    print(f"\n{SEP}\n  {title}\n{SEP}")


def ok(msg: str) -> None:
    print(f"  ✅ {msg}")


def warn(msg: str) -> None:
    print(f"  ⚠️  {msg}")


def fail(msg: str) -> None:
    print(f"  ❌ {msg}")


# ──────────────────────────────────────────────────────────────────────
# Step 1: 环境变量检查
# ──────────────────────────────────────────────────────────────────────
section("Step 1: 环境变量检查")

from hyqagent.api.config import HyqAgentConfig

cfg = HyqAgentConfig()

checks = [
    ("HYQAGENT_CHEAP_PROVIDER", cfg.cheap_provider, ["openai", "anthropic"]),
    ("HYQAGENT_MID_PROVIDER", cfg.mid_provider, ["openai", "anthropic"]),
    ("HYQAGENT_STRONG_PROVIDER", cfg.strong_provider, ["openai", "anthropic"]),
    ("HYQAGENT_CHEAP_MODEL", cfg.cheap_model, None),
    ("HYQAGENT_MID_MODEL", cfg.mid_model, None),
    ("HYQAGENT_STRONG_MODEL", cfg.strong_model, None),
    ("HYQAGENT_OPENAI_BASE_URL", cfg.openai_base_url or "(default/empty)", None),
    ("HYQAGENT_LLM_MAX_RETRIES", cfg.llm_max_retries, None),
    ("HYQAGENT_LLM_TIMEOUT_SECONDS", cfg.llm_timeout_seconds, None),
]

all_ok = True
for name, value, valid in checks:
    if valid and value not in valid:
        fail(f"{name} = {value} (不在合法值 {valid} 中)")
        all_ok = False
    elif name.endswith("_PROVIDER") and value == "openai":
        ok(f"{name} = {value} (OpenAI 模式)")
    elif name.endswith("_PROVIDER"):
        ok(f"{name} = {value}")
    else:
        ok(f"{name} = {value}")

# Check API key
try:
    key = cfg.openai_key
    ok(f"OpenAI API key: {key[:12]}...{key[-6:]} (len={len(key)})")
except ValueError as e:
    fail(f"OpenAI API key 未配置: {e}")
    fail("  请设置 HYQAGENT_OPENAI_API_KEY 或 OPENAI_API_KEY")
    all_ok = False

print()

# ──────────────────────────────────────────────────────────────────────
# Step 2: openai 包导入检查
# ──────────────────────────────────────────────────────────────────────
section("Step 2: openai 包导入检查")

try:
    import openai

    ok(f"openai 版本: {openai.__version__}")
except ImportError as e:
    fail(f"openai 包未安装: {e}")
    fail("  请运行: uv sync --dev  或  pip install openai>=1.0")
    sys.exit(1)

try:
    from openai import AsyncOpenAI, RateLimitError

    ok("AsyncOpenAI, RateLimitError 导入成功")
except ImportError as e:
    fail(f"导入失败: {e}")
    sys.exit(1)

print()

# ──────────────────────────────────────────────────────────────────────
# Step 3: Provider 创建
# ──────────────────────────────────────────────────────────────────────
section("Step 3: Provider 创建")

from hyqagent.models.providers.openai_provider import OpenAIProvider, ProviderConfig

base_url = cfg.openai_base_url or None
model = cfg.cheap_model

try:
    provider = OpenAIProvider(
        ProviderConfig(api_key=cfg.openai_key, base_url=base_url),
        max_retries=1,
        timeout_seconds=30,
    )
    ok(f"OpenAIProvider 创建成功 (base_url={base_url}, timeout=30s)")
except Exception as e:
    fail(f"Provider 创建失败: {type(e).__name__}: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

print()

# ──────────────────────────────────────────────────────────────────────
# Step 4: 网络连通性 — 简单 generate 调用
# ──────────────────────────────────────────────────────────────────────
section("Step 4: 简单 generate() 调用")


async def test_generate():
    try:
        start = time.monotonic()
        result = await provider.generate(
            messages=[{"role": "user", "content": 'Say "hello" in one lowercase word.'}],
            model=model,
            system="Respond with exactly one word, lowercase.",
            max_tokens=50,
            temperature=0.0,
        )
        elapsed = (time.monotonic() - start) * 1000
        content = result.get("content", [])
        text = content[0].get("text", "").strip() if content else "(empty)"
        usage = result.get("usage", {})

        ok(f"调用成功! 耗时 {elapsed:.0f}ms")
        ok(f"  响应内容: '{text}'")
        ok(f"  实际模型: {result.get('model')}")
        ok(
            f"  Token: in={usage.get('input_tokens')} "
            f"out={usage.get('output_tokens')}"
        )
        return True
    except Exception as e:
        fail(f"generate() 调用失败: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        return False


gen_ok = asyncio.run(test_generate())
if not gen_ok:
    print("\n  可能原因:")
    print("    - API key 无效 (AuthenticationError)")
    print("    - 网络不通，无法访问 base_url")
    print("    - base_url 格式错误 (应如 https://api.deepseek.com/v1)")
    print("    - 模型名不存在 (NotFoundError)")

print()

# ──────────────────────────────────────────────────────────────────────
# Step 5: 结构化输出 — generate_structured() 调用
# ──────────────────────────────────────────────────────────────────────
section("Step 5: generate_structured() 调用 (Function Calling)")


async def test_structured():
    schema = {
        "name": "classify",
        "description": "Classify the input",
        "input_schema": {
            "type": "object",
            "properties": {
                "sentiment": {
                    "type": "string",
                    "enum": ["positive", "negative", "neutral"],
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "required": ["sentiment", "confidence"],
        },
    }

    try:
        start = time.monotonic()
        result = await provider.generate_structured(
            messages=[{"role": "user", "content": "I love this product!"}],
            output_schema=schema,
            model=model,
            system="Classify the sentiment.",
            max_tokens=256,
            temperature=0.0,
        )
        elapsed = (time.monotonic() - start) * 1000

        sentiment = result.get("sentiment", "?")
        confidence = result.get("confidence", 0)

        ok(f"结构化调用成功! 耗时 {elapsed:.0f}ms")
        ok(f"  情感: {sentiment}")
        ok(f"  置信度: {confidence}")
        return True
    except Exception as e:
        fail(f"generate_structured() 调用失败: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()

        print("\n  可能原因:")
        print("    - 该 API 不支持 function calling / tool use")
        print("    - 该模型不支持 structured output")
        print("    - tool_choice 参数不被该 API 接受")
        return False


struct_ok = asyncio.run(test_structured())

print()

# ──────────────────────────────────────────────────────────────────────
# Step 6: 模拟 Orchestrator 流程
# ──────────────────────────────────────────────────────────────────────
section("Step 6: 模拟 Orchestrator 的 provider 创建流程")

# 模拟 orchestrator._ensure_scanner_modules 里的逻辑
from hyqagent.models.router import ModelRouter


def _create_provider(provider_type, api_key, base_url):
    if provider_type == "openai":
        return OpenAIProvider(
            ProviderConfig(api_key=api_key, base_url=base_url),
            max_retries=cfg.llm_max_retries,
            timeout_seconds=cfg.llm_timeout_seconds,
        )
    else:
        ok(f"  {provider_type} provider 不是 openai，跳过 (使用 Anthropic 协议)")
        return None


try:
    cheap = _create_provider(
        cfg.cheap_provider,
        cfg.openai_key,
        cfg.openai_base_url if cfg.cheap_provider == "openai" else None,
    )
    if cheap:
        ok(f"CHEAP provider ({cfg.cheap_provider}) 创建成功")
    else:
        warn("CHEAP provider 为 None")
except Exception as e:
    fail(f"CHEAP provider 创建失败: {type(e).__name__}: {e}")
    cheap = None

try:
    mid = _create_provider(
        cfg.mid_provider,
        cfg.openai_key,
        cfg.openai_base_url if cfg.mid_provider == "openai" else None,
    )
    if mid:
        ok(f"MID provider ({cfg.mid_provider}) 创建成功")
    else:
        warn("MID provider 为 None (将回退到 CHEAP)")
        mid = cheap
except Exception as e:
    fail(f"MID provider 创建失败: {type(e).__name__}: {e}")
    mid = cheap

strong = mid
ok(f"STRONG provider = MID (同 provider)")

# Router
if cheap is not None:
    router = ModelRouter(
        providers={
            "deepseek": cheap,
            "anthropic": mid,
            "openai": mid,
        },
        cheap_model=cfg.cheap_model,
        mid_model=cfg.mid_model,
        strong_model=cfg.strong_model,
    )
    ok(f"ModelRouter 创建成功")
else:
    fail("ModelRouter 无法创建: cheap provider 为 None")
    fail("  → 所有 LLM 阶段将被静默跳过！")
    router = None

print()

# ──────────────────────────────────────────────────────────────────────
# Step 7: Router 路由测试
# ──────────────────────────────────────────────────────────────────────
section("Step 7: Router 路由测试")

if router is not None:
    from hyqagent.models.router import Task, TaskType

    tiers = [
        ("CHEAP (复杂1-4)", 3, TaskType.HYPOTHESIS_GENERATION),
        ("MID (复杂5-7)", 6, TaskType.L2_VALIDATION),
        ("STRONG (复杂8-10)", 9, TaskType.BLIND_SCAN),
    ]

    for label, complexity, task_type in tiers:
        task = Task(task_type=task_type, complexity=complexity)
        routed_provider, routed_model = router.route(task)
        provider_type = type(routed_provider).__name__
        ok(f"{label}: → {provider_type} / model={routed_model}")
else:
    fail("Router 为 None，跳过路由测试")

print()

# ──────────────────────────────────────────────────────────────────────
# 总结
# ──────────────────────────────────────────────────────────────────────
section("诊断总结")

if gen_ok and struct_ok and router is not None:
    ok("全部检查通过！OpenAI Provider 应该可以正常工作。")
    ok("如果 hyqagent scan --deep 仍然不工作，请检查:")
    print("    1. 被扫描的项目路径是否正确")
    print("    2. 语言参数是否正确 (--lang python)")
    print("    3. 是否使用了 --deep 模式")
    print("    4. 查看日志中是否有 'llm_call_completed' 事件")
else:
    print("  发现以上 ❌ 问题。请根据每步的提示修复后重试。")

print(f"\n{SEP}")
