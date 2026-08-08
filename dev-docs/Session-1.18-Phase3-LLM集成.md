# Session 1.18 — Phase 3 LLM 集成

## 目标

完成 Phase 3 LLM 集成：Provider → Router → HypothesisGenerator → Validator → CLI 全链路。
实现 `hyqagent scan --deep` 深度审计模式，支持 session 持久化恢复。

## 产出清单

| 文件 | 操作 | 行数 | 说明 |
|------|------|------|------|
| `src/hyqagent/models/providers/anthropic_provider.py` | **新建** | 294 | Anthropic SDK 封装，支持 DeepSeek Anthropic 格式 API，tenacity 重试，tool_use 结构化输出 |
| `src/hyqagent/models/router.py` | **新建** | 238 | CHEAP/MID/STRONG 三档路由，复杂度评估 1-10，预算感知降级 |
| `src/hyqagent/observability/cost_tracker.py` | **新建** | 180 | 按 phase/hypothesis 归因成本，DeepSeek+Claude 定价表 |
| `src/hyqagent/scanner/hypothesis.py` | **新建** | 449 | CPG 切片 → LLM 结构化假设生成，覆盖 HEURISTIC_SINK / EXPOSED_NO_SOURCE / UNCOVERED_SINK / 盲区扫描 |
| `src/hyqagent/scanner/validator.py` | **新建** | 378 | L1 确定性验证 + L2 LLM 五问验证（路径可达性/条件绕过/消毒器/框架保护/综合判断） |
| `src/hyqagent/models/__init__.py` | **新建** | 15 | 重新导出 AnthropicProvider、ModelRouter、ProviderConfig |
| `src/hyqagent/models/providers/__init__.py` | **新建** | 13 | 重新导出 |
| `src/hyqagent/api/config.py` | **修改** | +47 | 新增 anthropic_api_key、deepseek_api_key、deepseek_base_url、max_llm_budget、cheap_model 默认改为 deepseek-v4-flash-0731 |
| `src/hyqagent/api/cli.py` | **修改** | +689 | --deep 模式、resume/sessions 命令、Phase 2→理解→Phase 3 流水线、session 持久化 |
| `tests/test_api/test_config.py` | **修改** | ±2 | cheap_model 默认值更新 |

**总计: 7 新建 + 4 修改，+2274 行**

## 实现过程

### 1. 关键技术发现: DeepSeek 支持 Anthropic 格式

DeepSeek V4 Flash 支持 Anthropic Messages API 格式 (`https://api.deepseek.com/anthropic`)。这意味着：
- **不需要引入 `openai` 包** — 单一 `AnthropicProvider` 同时服务 DeepSeek 和 Claude
- `base_url` 参数区分提供商：`None` = Anthropic 默认，`"https://api.deepseek.com/anthropic"` = DeepSeek
- 架构从 2 个 Provider 类简化为 1 个

```python
@dataclass
class ProviderConfig:
    api_key: str
    base_url: str | None  # None=Anthropic, "https://api.deepseek.com/anthropic"=DeepSeek
```

### 2. Anthropic tool_use 实现结构化输出

用 Anthropic 原生 tool_use 约束 LLM 输出为结构化 JSON：
```python
# 将 JSON Schema 转为 tool 定义
tool = {"name": "report_hypotheses", "input_schema": HYPOTHESIS_SCHEMA}
# 强制 tool_choice
response = await client.messages.create(
    ...,
    tools=[tool],
    tool_choice={"type": "tool", "name": "report_hypotheses"},
)
# 解析 tool_use block
result = response.content[0].input  # 已验证的 JSON 对象
```

相比 OpenAI function calling，Anthropic tool_use 的 schema 嵌套结构不同（多一层 `input_schema`），但格式更接近标准 JSON Schema。

### 3. 设计决策: 先扫后理解 vs 先理解后扫

这是本次 Session 最重要的架构决策。用户提出两种方案后，我研读了 `COVERAGE-GAP-ANALYSIS.md` 和 `LONG-RUNNING-AGENT-ARCHITECTURE.md` 得出结论：

**最终选择: 先 Phase 2 扫描 → 再 Phase 0 项目理解**

核心理由:
- COVERAGE-GAP-ANALYSIS.md 第 2.1 节揭示：Phase 2 是 FILTER，不匹配规则的数据流路径会被丢弃。无论先理解还是后理解，这个过滤效应都存在
- 但先扫后理解时，LLM 可以同时看到「Phase 2 发现了什么」和「Phase 2 遗漏了什么」— 基于证据做决策
- 先理解后扫时，LLM 只能从项目结构推测风险，缺乏具体数据

新的 `--deep` 流程:
```
Phase 2 确定性扫描 (零成本, 秒级)
    → Phase 0 项目理解 (便宜 LLM, 基于 Phase 2 结果)
    → Phase 3 假设生成 (LLM 深挖)
    → Session 持久化 (可 resume)
```

`_understand_project()` 现在接收 Phase 2 的 findings + label_breakdown + coverage_summary，构建证据驱动的 prompt。

### 4. Three-tier model routing

| Tier | 模型 | Provider | 复杂度 | 1K tokens (in/out) |
|------|------|----------|--------|---------------------|
| CHEAP | deepseek-v4-flash-0731 | DeepSeek | 1-4 | $0.00014/$0.00028 |
| MID | claude-sonnet-5 | Anthropic | 5-7 | $0.003/$0.015 |
| STRONG | claude-opus-5 | Anthropic | 8-10 | $0.015/$0.075 |

复杂度评估: 数据流跳数(1pt/3hop) + 跨文件边界(1pt/boundary) + 异步/反射(2pt each) + 嵌套深度(1pt/2level)

### 5. Session 持久化

- 存储: `~/.hyqagent/sessions/{session_id}.json`
- 包含: 目标路径、语言、Phase 2 结果摘要、项目理解、Phase 3 hypotheses、时间戳
- `hyqagent resume <id>` — 加载 session 继续审计（当前回退到重新扫描，完整恢复待后续实现）
- `hyqagent sessions list` — 列出最近 20 个会话

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| BlindSpot 导入路径错误 | BlindSpot 在 `hyqagent.cpg.types` 而非 `.cover` | 修正导入路径 |
| Task/TaskType 内联导入 | 写在函数体内部 | 移至 TYPE_CHECKING 块 |
| `__init__.py` 写入被拒 | Write 工具要求先 Read 空文件 | 先 Read 再 Write |
| ANTHROPIC_API_KEY 在 uv run 中不可用 | `uv run python` 运行在干净环境中 | 非错误，shell 环境变量可用 |
| StrEnum vs `str, Enum` | ruff UP042 要求 3.12+ 用 StrEnum | 从 `from enum import Enum` 改为 `from enum import StrEnum` |
| cheap_model 默认值测试失败 | 测试断言旧默认值 `claude-haiku` | 更新为 `deepseek-v4-flash-0731` |
| 多个 mypy type-arg 错误 | `dict`/`list` 缺少类型参数 | 添加 `dict[str, Any]`/`list[Any]` |

## 质量门禁

- **ruff check**: All checks passed ✓
- **ruff format**: 7 files reformatted, now clean ✓
- **mypy**: 仅预存的 `import-untyped` 警告 (cpg.extractor)，新增代码零错误 ✓
- **pytest**: 883 passed, 2 skipped, 0 failures ✓

## 设计反思

### 做得好
- **DeepSeek Anthropic 格式** — 这个发现从根本上简化了 provider 层，从 2 类降为 1 类
- **tool_use 结构化输出** — 比解析 free-text JSON 可靠得多，且 Anthropic SDK 原生支持
- **先扫后理解** — 基于架构文档的审慎决策，而非默认直觉
- **Session 持久化** — 为长任务能力打下基础，关联到 LONG-RUNNING-AGENT-ARCHITECTURE.md 的检查点恢复方案
- **成本控制** — CostTracker 从第一天就内置，避免 LLM 费用失控

### 可改进
- **`_run_phase3_hypotheses` 的 CPG 重建** — 当前在 CLI 中重建 CPG graph builder，与 `_run_scan` 重复。理想情况应该从 Phase 2 的 `ScanResult` 中复用 query/cpg 对象
- **Resume 尚未实现** — `hyqagent resume` 当前只展示 session 信息然后重跑，真正的检查点恢复需要 LangGraph SqliteSaver 或类似机制
- **Phase 3 的 validator 未集成到 CLI** — 当前 CLI 只跑 hypothesis generation，validation 步骤留在后续实现

## 下步衔接

1. **Task 44**: Phase 3 单元测试 (mock LLM)
2. **Task 45**: mypy 全局 type-check、ruff 格式最终确认
3. **Resume 实现**: LangGraph SqliteSaver 或 Prefect 检查点，对齐 LONG-RUNNING-AGENT-ARCHITECTURE.md 第五章
4. **Validator L2 集成**: 在 CLI 中加入 validation pipeline (L1→L2)
5. **PHP/Go 污点规则扩展** — 计划中的语言支持
