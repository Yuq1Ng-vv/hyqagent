---
name: session-1-40-openai-provider
description: Session 1.40 — 新增 OpenAIProvider，支持 OpenAI 格式 API，实现多 Provider 架构
metadata:
  type: project
---

# Session 1.40 — 多 Provider 架构：支持 OpenAI 格式 API

## 目标

让 HyqAgent 同时支持 Anthropic 和 OpenAI 两种 API 格式，用户可自由选择每层（CHEAP/MID/STRONG）走哪个 Provider。

## 产出清单

| 文件 | 变更 |
|---|---|
| `src/hyqagent/core/protocols.py` | 重写 `LlmProvider` 协议，匹配实际调用签名（model/system/max_tokens 等），新增 `generate_with_tools`/`count_tokens`/`call_history` |
| `src/hyqagent/models/providers/anthropic_provider.py` | 正式 `implements LlmProvider`；DeepSeek hack 改为 `ProviderConfig` 的 `disable_thinking`/`force_auto_tool_choice` 配置字段 |
| `src/hyqagent/models/providers/openai_provider.py` | **新增** — 用 `openai` SDK 实现 `LlmProvider`，含内容块/工具调用归一化层 |
| `src/hyqagent/models/providers/__init__.py` | 导出 `OpenAIProvider`, `OpenAIConfig` |
| `src/hyqagent/models/__init__.py` | 同上 |
| `src/hyqagent/models/router.py` | `AnthropicProvider` → `LlmProvider` 类型泛化 |
| `src/hyqagent/api/config.py` | 新增 `cheap/mid/strong_provider`、`openai_api_key`、`openai_base_url`、`openai_key` property |
| `src/hyqagent/api/cli.py` | `_has_llm_keys()` 加入 OpenAI key 检测 |
| `src/hyqagent/scanner/orchestrator.py` | 按 `cfg.*_provider` 字符串选择 `AnthropicProvider` 或 `OpenAIProvider` 实例化 |
| `src/hyqagent/scanner/nudge.py` | `AnthropicProvider` → `LlmProvider` 类型标注 |
| `src/hyqagent/scanner/hypothesis.py` | 同上 |
| `src/hyqagent/scanner/validator.py` | 同上 |
| `src/hyqagent/scanner/completeness.py` | 同上 |
| `src/hyqagent/scanner/sandbox.py` | 同上（docstring） |
| `src/hyqagent/scanner/adversarial.py` | 同上（docstring） |
| `src/hyqagent/scanner/blind_scan.py` | 同上（docstring） |
| `pyproject.toml` | 添加 `openai>=1.0` 依赖 |

## 实现过程

### 核心设计

**抽象协议** (`LlmProvider`) 本身不需要改架构 — 它在 `protocols.py` 里早就定义好了：
```python
# 设计之初就写了 — 只是没被用过
class LlmProvider(ABC):
    """LLM Provider抽象 — Anthropic/OpenAI/Kimi实现此接口"""
```

问题是：
1. 协议签名与实际调用不匹配（`generate_structured` 参数不一致）
2. `AnthropicProvider` 没有 `implements LlmProvider`
3. 所有地方的类型标注都是具体类 `AnthropicProvider` 而非抽象 `LlmProvider`
4. 只有一种 Provider 实现

### 内容块归一化

两种 SDK 返回格式完全不同，OpenAIProvider 内部做了转换：

```
Anthropic:                    OpenAI:                       → 规范化（内部格式）
─────────────                 ────────                        ──────────────────
tool_use block               tool_calls[].function           {"type":"tool_use", ...}
tool_result block            tool role message               {"type":"tool_result", ...}
text block                   message.content                {"type":"text", ...}
response.usage.input_tokens  response.usage.prompt_tokens    usage.input_tokens
stop_reason                  finish_reason                   stop_reason
```

### DeepSeek hack 清理

旧代码：`_is_deepseek = "deepseek" in self._config.base_url` 散落各处
新代码：`ProviderConfig` 的两个 quirk flag：
```python
@dataclass
class ProviderConfig:
    disable_thinking: bool = False       # DeepSeek 需要关闭 thinking
    force_auto_tool_choice: bool = False # DeepSeek 不支持强制 tool
```

Orchestrator 根据 base_url 自动判断是否设这两个 flag。

### 工具格式兼容

工具定义统一用 OpenAI function-calling 格式 `{"type":"function","function":{...}}`。Anthropic SDK 也接受此格式，无需转换。`OpenAIProvider._normalize_tools()` 负责把 Anthropic 原生格式（如果有的话）转成 OpenAI 格式。

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|---|---|---|
| `SyntaxError` — metadata 字符串内嵌 JSON `{"type":"disabled"}` | 双引号字符串内包含双引号 | 外层换单引号 |
| `tiktoken` import-not-found | `tiktoken` 是可选依赖，未安装 | 已在 `try/except ImportError` 内，加 `# type: ignore[import-not-found]` |
| OpenAI SDK 严格类型（TypedDict）不接受泛型 `dict` | SDK v1 用了 TypedDict 校验参数字段 | 加 `# type: ignore[arg-type]` — 运行时完全兼容 |

## 质量门禁

- **pytest**: 480 passed (test_models + test_scanner)
- **ruff**: 无新增警告（原有中文标点警告与本次改动无关）
- **mypy**: OpenAIProvider 3 errors, AnthropicProvider 5 errors（均为预存：circuitbreaker 无 stubs、untyped decorator、return Any）
- **import**: `issubclass(AnthropicProvider, LlmProvider)` ✅ `issubclass(OpenAIProvider, LlmProvider)` ✅

## 设计反思

**做得好的：**
- `LlmProvider` 抽象从一开始就预留了，这次补齐而不是推倒重建
- 内容块归一化放在 Provider 内部，Scanner 零改动
- DeepSeek hack 改成显式配置字段，可读性提升

**可改进的：**
- `ToolRegistry.to_anthropic_tools()` 名字有误导性（实际是通用格式），后续可改名
- `LlmProvider` 协议的方法签名有大量参数，后续可考虑 `TypedDict` 形式的 request config

## 下步衔接

所有改动向后兼容。默认配置不变（CHEAP 仍走 DeepSeek Anthropic 兼容端点）。要切到 OpenAI：
```bash
export HYQAGENT_CHEAP_PROVIDER=openai
export HYQAGENT_OPENAI_API_KEY=sk-...
export HYQAGENT_CHEAP_MODEL=gpt-4o-mini
```

可选后续：[[phase2-required-fixes]] 中提到的 Prompt 模板独立化可以顺手做了，现在两个 Provider 共用同一套 prompt。
