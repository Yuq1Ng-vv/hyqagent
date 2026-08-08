# Session 1.21 — AutoCVE 横向对比研究 + Nudge 系统实现

## 目标

1. **AutoCVE 深度研究** — 用户指定的开源项目横向对比，产出可操作的借鉴结论
2. **Nudge 系统移植** — 借鉴 AutoCVE 的三个核心 Nudge 类型，实现到 HyqAgent 的 Phase 3 LLM 流水线中

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `docs/AUTOCVE-RESEARCH.md` | ~380 | AutoCVE 架构深度解析 + 横向对比 |
| 新建 | `src/hyqagent/scanner/nudge.py` | ~405 | Nudge 系统核心（3 类型 + 3 StopHook + 继续意图检测） |
| 修改 | `src/hyqagent/scanner/hypothesis.py` | +30 | 集成 NudgeLoop（可选参数，空结果/低置信度钩子） |
| 修改 | `src/hyqagent/scanner/validator.py` | +30 | 集成 NudgeLoop（inconclusive 无推理阻断） |
| 新建 | `src/hyqagent/scanner/__init__.py` | +18 | Package 重导出 nudge 公共 API |
| 新建 | `tests/test_scanner/test_nudge.py` | ~320 | 46 个 nudge 测试（无真实 LLM 调用） |
| 新建 | `.env` | +2 | DeepSeek API Key（gitignored） |
| 修改 | `progress.md` | — | 指标更新 + 新功能记录 |

## 实现过程

### 1. AutoCVE 研究

用户指定了开源项目 [larlarua/AutoCVE](https://github.com/larlarua/AutoCVE)，要求横向对比。

**研究方法**：
- `WebFetch` 获取 GitHub README + ARCHITECTURE_DESIGN_EN.md（完整技术文档）
- `WebFetch` 获取 query_loop.py 源码（核心 ReAct Loop 实现）
- 交叉对比 HyqAgent 的 38 个源码模块

**核心发现**：

AutoCVE 是"重 LLM"路线，6 Agent 编排 + ReAct Loop + 7 Nudge 系统。HyqAgent 是"重静态分析"路线，CPG 图 + 确定性规则 + 贝叶斯信念。

最值得借鉴的三项：
1. Nudge 系统（防止 LLM 提前终止）
2. 上下文管理管线（8 步处理）
3. 动态验证沙箱（PoC 执行）

HyqAgent 独特优势：
- CPG 图基础（AutoCVE 无图抽象）
- 贝叶斯信念系统（AutoCVE 无数学框架）
- CoverageTracker 盲区分析（AutoCVE 无此概念）
- 3350 条零成本确定规则（AutoCVE 每项目烧 token）

**许可证说明**：AutoCVE 为 AGPL v3。HyqAgent 借鉴的是架构思路（非代码拷贝），在源码文档中明确标注来源。

详见 `docs/AUTOCVE-RESEARCH.md`。

### 2. Nudge 系统设计

从 AutoCVE 的 7 种 Nudge 中选取 3 种最适配 HyqAgent 单 Agent + 结构化输出管线的类型：

| Nudge | 触发条件 | 上限 | 来源 |
|-------|---------|------|------|
| TERMINAL | 模型返回文本而非调用 tool_use | 2 | AutoCVE terminal_action_nudge |
| CONTINUE | 模型表达继续意图但未调用工具 | 2 | AutoCVE continue_intent_nudge |
| QUALITY | StopHook 拒绝输出（空/低置信/缺推理） | 2 | **HyqAgent 原创扩展** |

第三种 QUALITY 是 HyqAgent 的自有创新——AutoCVE 的 Stop Hook 系统用于会话级别，而我们将它用于结构化输出的质量检查。

**架构**：

```
NudgeLoop.run()
  → provider.generate_structured()
  → 检测空结果 → TERMINAL nudge
  → 检测 continue-intent → CONTINUE nudge
  → 运行 stop_hooks → QUALITY nudge
  → 全部通过 → 返回 NudgeResult
```

**3 个内置 StopHook**：
- `stop_on_empty(key)` — 阻止空列表（如 `{"hypotheses": []}`）
- `stop_on_low_confidence(threshold)` — 所有发现置信度低于阈值时阻断
- `stop_on_missing_verdict` — inconclusive 判决无详细推理时阻断

**继续意图检测**：~20 个中英文正则（`"let me continue"`, `"继续审查"` 等），改编自 AutoCVE 的 `_CONTINUE_INTENT_PATTERNS`。

### 3. 集成方式

**向后兼容**：`HypothesisGenerator` 和 `Validator` 均新增可选参数 `nudge_loop: NudgeLoop | None = None`。不传则行为不变（保持现有单次 LLM 调用）。

**hypothesis.py 集成**：
```python
if self._nudge_loop is not None:
    nudge_result = await self._nudge_loop.run(
        provider=provider, model=model_id,
        messages=[{"role": "user", "content": user_prompt}],
        output_schema=HYPOTHESIS_SCHEMA, system=SYSTEM_PROMPT,
        stop_hooks=[stop_on_empty("hypotheses"), stop_on_low_confidence(0.3)],
    )
```

**validator.py 集成**：
```python
if self._nudge_loop is not None:
    nudge_result = await self._nudge_loop.run(
        ..., stop_hooks=[stop_on_missing_verdict]
    )
```

### 4. API Key 配置

`.env` 文件已创建并加入 `.gitignore`。DeepSeek API Key 通过 `HYQAGENT_DEEPSEEK_API_KEY` 环境变量自动加载（`pydantic-settings` 的 `env_file=".env"` 机制）。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| `TYPE_CHECKING` not defined | nudge.py 开头漏了 import | 加上 `from typing import TYPE_CHECKING` |
| 16 个 ruff 报错（I001/UP035/E501/D413 等） | 新代码初次未调格式 | `ruff --fix` 自修 12 项，剩余 5 项手动改（行太长→拆行、docstring→规范格式） |
| RUF100 未使用的 noqa | 加了 docstring 后 D102 已不再触发 | `ruff --fix` 自动移除 |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| `uv run pytest` | **1062 passed, 2 skipped, 0 failures** (+46 nudge tests) |
| `uv run ruff check` (新文件) | All checks passed |
| `uv run mypy` (新文件) | Success: no issues found |

## 设计反思

### 做得好的
- **最小借鉴 + 自创扩展** — 3 种 Nudge 适配 HyqAgent 的单 Agent 架构，QUALITY 类型是原生的结构化输出质量门
- **向后兼容** — 不传 nudge_loop 时行为完全不变，渐进式采用
- **测试无外网依赖** — 46 个测试全部用 `AsyncMock` fake provider，快速+可靠
- **来源标注** — 模块文档、代码注释、研究文档三处标明 AutoCVE 来源和 AGPL 协议

### 可改进的
- NudgeLoop 目前只适配 `generate_structured`（tool_use 模式）。若要支持 Phase 4 的 ReAct 式多工具会话，需要扩展到裸 `generate()`。
- 继续意图正则偏少（~20 个），AutoCVE 有 ~25 个且持续调优。后续可从真实 LLM 输出中收集更多模式。
- StopHook 目前只读结果——若需要更深入的检查（如"必须引用具体行号"），需要能访问原始 code context。

## 下步衔接

Phase 3 基础设施已全面完成（8/8 任务 + 1 Nudge 增强）。**Phase 4 就绪**。

Phase 4 前置条件：
- ✅ session/ — 会话持久化 + 检查点
- ✅ belief/ — 贝叶斯更新（收敛检测框架）
- ✅ mapper.py — 端点过滤（优先级调度）
- ✅ nudge.py — 多轮 LLM 调用质量保证

Phase 4 核心任务：
1. 三区段上下文模型 + 上下文结晶
2. 代码检索（向量化 + 混合检索）
3. 收敛检测（VDR/EC/RWC/VCC/C_hat 多指标）
4. Observability 完整集成
5. 对抗性审查 + 饱和扫描
