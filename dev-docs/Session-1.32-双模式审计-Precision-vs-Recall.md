# Session 1.32 — 双模式 LLM 审计策略：Precision vs Recall

## 目标

解决当前 LLM 管道的系统性代码盲区问题——Validator、AdversarialReviewer、BlindScanReviewer 三个 LLM 通道收到空 `code_context`，导致漏报率偏高。在不破坏现有 behavior 的前提下，增加 `--mode recall` 选项让 LLM 能通过工具（ReAct Agent Loop）实际读取代码寻找漏洞。

## 产出清单

| 类型 | 文件 | 行数 | 说明 |
|------|------|------|------|
| **新增** | `scanner/tools/__init__.py` | 42 | 工具包导出 + `create_default_tools()` 工厂 |
| **新增** | `scanner/tools/read_file.py` | 112 | `ReadFileTool` — 读文件，支持行范围，上限 200 行/8000 字符 |
| **新增** | `scanner/tools/grep_code.py` | 105 | `GrepCodeTool` — 正则搜索，上限 20 命中/4000 字符 |
| **新增** | `scanner/tools/get_function.py` | 110 | `GetFunctionTool` — AST 查函数，上限 200 行/6000 字符 |
| **新增** | `scanner/tools/list_functions.py` | 94 | `ListFunctionsTool` — 列出文件内函数 |
| **新增** | `scanner/tools/get_related.py` | 111 | `GetRelatedTool` — 同文件相关函数查询 |
| **新增** | `scanner/tools/tool_registry.py` | 106 | `ToolRegistry` — 注册/执行/Anthropic 格式输出 |
| **新增** | `scanner/agent_loop.py` | 250 | `AgentLoop` — ReAct 多轮对话循环 + 预算截断 |
| **修改** | `core/state.py` | +8 | `AuditMode` StrEnum（PRECISION / RECALL） |
| **修改** | `api/config.py` | +5 | 3 个新字段：`audit_mode`、`max_agent_turns`、`tool_result_max_chars` |
| **修改** | `api/cli.py` | +30 | `--mode/-m` 选项，recall 自动启用 `--deep` |
| **修改** | `models/providers/anthropic_provider.py` | +77 | `generate_with_tools()` — 合并 audit_tools + output_tool |
| **修改** | `scanner/hypothesis.py` | +112 | Recall 模式分叉：AgentLoop 替代 generate_structured |
| **修改** | `scanner/validator.py` | +50 | Recall 模式自动读取 source/sink 代码上下文 |
| **修改** | `scanner/orchestrator.py` | +145 | Recall 模式构建 CodeRetriever→ToolRegistry→AgentLoop 并注入各模块 |
| **新增** | `tests/test_scanner/test_tools.py` | 154 | ToolRegistry + tool formatting 单元测试（10 个） |
| **新增** | `tests/test_scanner/test_agent_loop.py` | 150 | AgentLoopConfig/Result/truncation 单元测试（7 个） |

**净增**: ~1650 行，17 个文件

## 实现过程

### 决策 1：双模式设计 vs 统一重构

**选择双模式**。不改写现有架构，两种模式共享同一个 `Orchestrator`，差异通过 `if mode == RECALL` 守卫驱动。所有 recall 代码路径都是追加，precision mode 行为零变化。理由：
- 避免回归风险 — precision mode 已有 1469 个通过的测试
- 边际成本低 — 每个 scanner 模块 ~50 行新代码
- 用户可选择 — `--mode precision`（默认）专注降误报，`--mode recall` 专注降漏报

### 决策 2：AgentLoop vs 直接 tool_use

最初考虑直接在 `generate_structured()` 中传 tools，但 Anthropic API 的 `tool_choice` 机制有问题：force output tool 则审计工具被忽略，`auto` 则可能不调 output tool。故新增 `generate_with_tools()`（`tool_choice: auto`，同时传 audit_tools + output_tool），在 AgentLoop 里自己处理回合循环和结构提取。

### 决策 3：工具结果预算管理

参考 AutoCVE 的 budget-aware 截断：
- 每个工具结果有字符上限（200~6000）
- 累积超过 `tool_result_max_chars`(8000) 时截断旧结果
- 保留最近 3 个完整结果，其余标记 `[content truncated]`
- 防止上下文窗口爆炸

### 核心代码片段

**AgentLoop 核心循环** (`agent_loop.py:101-197`):
```python
for turn in range(1, self._cfg.max_turns + 1):
    response = await self._provider.generate_with_tools(...)
    for block in content:
        if block["type"] == "tool_use":
            if block["name"] == output_tool_name:
                return AgentLoopResult(output=tool_input, ...)  # done!
            result = await self._tool_registry.execute(tool_name, **tool_input)
            messages.append(assistant_block)
            messages.append(user_tool_result)
            continue  # keep looping
```

**HypothesisGenerator 分叉** (`hypothesis.py`):
```python
if self._agent_loop is not None and self._code_retriever is not None:
    # Recall: LLM 探索代码，自由调用工具
    loop_result = await self._agent_loop.run(provider, model, enriched_prompt, ...)
    if loop_result is not None and loop_result.output:
        return self._parse_response(loop_result.output)
else:
    # Precision: 当前行为完全不变
    result = await provider.generate_structured(...)
```

**Orchestrator 接入** (`orchestrator.py`, `_ensure_scanner_modules`):
```python
if self._audit_mode == AuditMode.RECALL:
    self._code_retriever = CodeRetriever(...)
    tool_registry = ToolRegistry()
    for tool_cls in create_default_tools():
        tool_registry.register(tool_cls(self._code_retriever))
    agent_loop = AgentLoop(self._mid, tool_registry, AgentLoopConfig(...))
    self._hypothesis_gen.set_recall_deps(self._code_retriever, agent_loop)
    self._validator.set_recall_deps(self._code_retriever)
```

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| ruff: 58 errors（D102 居多） | 工具 property 方法（name/description/parameters/execute）缺少 docstring | 为所有 BaseTool 接口方法添加 `"""..."""`
| ruff: RUF002 non-breaking hyphen | `tool_registry.py` 注释中误用了 Unicode `‑`(U+2011) | 替换为标准 `-`(U+002D) |
| ruff: E501 line too long | truncation 消息写在一行超过 100 字符 | 拆成多行，suffix 变量 |
| ruff: D417/D401/RUF005 | `anthropic_provider.py` 和 `__init__.py` 中的 pre-existing 问题 | docstring 补 `**kwargs` 说明，list concat 改 unpack，import contextlib，改 docstring 语气 |
| `test_execute_success` 失败 | 断言了不存在的 `result.name`（实际是 `result.tool_name`）| 改为 `result.tool_name` |
| `test_truncates_old_results` 误判 | 5 个 tool results 中 keep last 3 只截断前 2 个，测试却期望截断前 3 个 | 增加一个 old result（共 6 个），正确验证截断前 3 个 |
| `import pytest` 未使用 | ruff F401 | 移除了 `import pytest` |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff (新增/修改文件) | ✅ All checks passed |
| mypy | ✅ 未新增类型错误（全项目状态由 pre-existing 错误决定） |
| pytest (全量) | ✅ 1486 passed, 2 skipped |
| 新增测试 | ✅ 17 passed（test_tools: 10, test_agent_loop: 7） |
| ruff (orchestrator.py pre-existing) | ❌ 17 个历史遗留（S101/S110/SIM105/RUF006/N806/N818），非本次引入 |

## 设计反思

**做得好的**：
- **向后兼容零回归** — precision mode 和修改前完全一致，1486 测试全绿
- **守卫模式清晰** — 所有新代码都在 `if mode == RECALL` 下，未来移除/重构也容易
- **基础设施复用** — CodeRetriever 和 BaseTool 协议都是 Phase 4 就写好的，这次只是连上线
- **预算管理到位** — AgentLoop 有累积截断和 max_turns 双重保护，不会无限消耗 tokens

**可改进的**：
- 缺少 recall mode 的集成测试（需要真实 LLM 调用来验证工具调用流程）— 受限于当时没有可用 API key 做集成测试
- orchestrator.py 的 recall 接入代码散布在各 phase handler 中，后续可以提取成一个 `RecallModeAdapter` 类来降低 orchestrator 复杂度
- `AgentLoop` 和 `NudgeLoop` 有功能重叠（都是多轮 LLM 循环），但 NudgeLoop 目前用 `generate_structured`，AgentLoop 用 `generate_with_tools`，未来可以统一

## 下步衔接

- 需要在有 API key 的环境下做 recall mode 的端到端测试（在有已知漏洞的 vulpy/dvna 项目上对比 precision vs recall 的发现数量和 tokens 成本）
- `Validator._read_code_for_hypothesis()` 目前只读 source/sink 所在 chunk，未来可扩展为读完整数据流路径上的所有函数
- 动态验证沙箱（Docker PoC 执行）是 AutoCVE 对比中 HyqAgent 唯一缺失的能力，约 8 个检测项需要运行时确认（反序列化 RCE、JNDI 注入等）
- 考虑做一个 `RecallModeAdapter` 类集中管理 recall 依赖的构建和注入，减轻 orchestrator 负担
- CompletenessCritic 的 `project_summary` 可以通过 CodeRetriever 提供更丰富的项目统计（依赖包列表、框架版本等）

> **修正 (2026-08-09)**: "下步衔接"原版错误声称 AdversarialReviewer 和 BlindScanReviewer 的 code_contexts wiring "待补完"，实际代码已在 Session 1.32 中全部完成（`orchestrator.py:746-778` 和 `:928-952`）。5 个 LLM 通道的 recall-mode 接线全部到位。
