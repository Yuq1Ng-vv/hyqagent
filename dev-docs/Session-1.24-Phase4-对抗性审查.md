# Session 1.24 — Phase 4 对抗性审查（Adversarial Review）

## 目标
实现 Phase 4 Task 7：对抗性审查（Adversarial Review）。核心理念来自 **"提出者 ≠ 裁决者"**——验证器判定为"安全/已拒绝"的假设，必须由独立模型从攻击者视角重新审查。完善 `--deep` 模式收敛管道。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `src/hyqagent/scanner/adversarial.py` | ~365 | AdversarialReviewer 核心模块（prompt + schema + 类） |
| 修改 | `src/hyqagent/scanner/orchestrator.py` | +111 | 新增 ADVERSARIAL_REVIEW Phase + DI 注入 + 双视角收敛 |
| 新建 | `tests/test_scanner/test_adversarial.py` | ~650 | 41 tests — 数据模型、schema、prompt、mock LLM、orchestrator 集成 |

## 实现过程

### 1. `scanner/adversarial.py` — 独立对抗审查器

参考 `CompletenessCritic` (completeness.py) 的依赖注入模式，不引入 `channels/` 子目录，保持 scanner 模块平铺结构。

**核心类**：

```python
class AdversarialReviewer:
    def __init__(self, provider, model, nudge_loop=None)
    async def review(rejected, code_contexts=None) -> list[AdversarialReviewResult]
    async def _review_one(hypothesis, validation, code_context) -> AdversarialReviewResult
    async def _call_llm(prompt) -> dict
    async def _call_with_nudge(prompt) -> dict
```

**结构化输出 schema**：
- Tool name: `report_adversarial_review`
- 字段：verdict (upheld/overturned), confidence, bypass_found, attack_vector, reasoning

**SYSTEM prompt** — 六个攻击向量：
1. Sanitizer Bypass（编码绕过：URL encoding, double encoding, Unicode normalization 等）
2. Second-Order Attacks（数据库存储后无重新净化）
3. Type-System Manipulation（类型系统颠覆）
4. Alternative Input Vectors（HTTP headers, cookies, WebSocket 等间接输入）
5. Timing Side Channels（时序侧信道）
6. Error Message Leaks（错误消息泄露）

**关键设计决策**：
- `_build_adversarial_prompt()` 同时接受 dataclass 和 dict（提升可测试性）
- LLM 失败默认 `upheld`（安全优先——漏报优于误报推翻）
- `bypass_found=False` 时自动清空 `attack_vector`（防止 LLM 幻觉污染）
- 置信度自动 clamp 到 [0, 1] 范围

### 2. `scanner/orchestrator.py` — 管道集成

**PhaseName 扩展**：
- 新增 `ADVERSARIAL_REVIEW = "adversarial_review"`，插入 VALIDATION 和 COVERAGE_AUDIT 之间
- `DEEP_PHASES` 和 `_CONVERGE_BODY` 同步更新

**`_phase_adversarial_review()` 新方法** (~80 行)：
- 模式感知过滤：quick=跳过, standard=仅 HIGH+, deep=全部
- standard 模式下额外过滤 severity 和 confidence>0.4
- 对 overturned 的结果自动创建 `ValidationResult(verdict="confirmed", validation_type="adversarial_review")`
- 异常安全：整体 try/except 包裹，失败时 logger.warning + 跳过

**收敛双视角填充**：
`_phase_convergence_check()` 现在填充：
- `perspective_a_findings` ← 所有 hypothesis gen IDs
- `perspective_b_findings` ← adversarial review overturned IDs
- 启用 Chao2 完整性估计器的双视角交叉验证

**DI 自动构建** (`_ensure_scanner_modules()`)：
```python
if self._adversarial_reviewer is None and self._strong is not None:
    cfg = HyqAgentConfig()
    nudge = NudgeLoop(NudgeConfig(max_turns=3))
    self._adversarial_reviewer = AdversarialReviewer(
        provider=self._strong,
        model=cfg.strong_model,
        nudge_loop=nudge,
    )
```

### 3. `tests/test_scanner/test_adversarial.py` — 41 tests

| 测试类 | 数量 | 覆盖 |
|--------|------|------|
| TestAdversarialReviewResult | 2 | 默认值、字段可设 |
| TestAdversarialSchema | 3 | schema 名、属性、required |
| TestAdversarialSystemPrompt | 8 | 攻击者角色、6 攻击向量、tool 指令 |
| TestBuildAdversarialPrompt | 7 | 假设详情、拒绝推理、攻击指令、code/sanitizer 上下文、dict 输入、缺失字段容错 |
| TestAdversarialReviewerConstruction | 2 | 构造、nudge 注入 |
| TestAdversarialReviewerMockLLM | 9 | 空输入、upheld/overturned、批量、LLM 失败默认 upheld、code contexts、nudge loop、置信度 clamp、bypass_false 清理 attack_vector |
| TestSafeId | 4 | dataclass/object/dict id、缺失 id |
| TestPhaseAdversarialReview | 6 | 无 reviewer 跳过、无 rejected 跳过、处理存储结果、overturned 添加 confirmed validation、standard 模式过滤低严重度、无真实 API 调用验证 |

Mock 策略：`MagicMock + AsyncMock` 模拟 `provider.generate_structured()`，零真实 LLM 调用。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `assert "HTTP headers" in ADVERSARIAL_SYSTEM.lower()` 失败 | 大写 "HTTP headers" 搜索已 lower() 的全小写文本 | 改为 `"http headers"` |
| `assert 'upheld' == 'uphold'` | mock 响应中拼写错误 `"uphold"` | 改为 `"upheld"` |
| `PipelineState.__init__() got unexpected keyword argument 'phase'` | PipelineState 是 dataclass，字段名是 `current_phase`，且 `session_id` 必填 | 改为 `PipelineState(session_id="test-...", current_phase=...)` |
| ruff: E101 mixed spaces/tabs | Edit 工具引入了 tab 缩进 | 重写为纯空格缩进 |
| ruff: E501 line too long (103 > 100) | f-string 内联太长 | 拆分为多行 msg 变量 |
| ruff: F401 unused import (`field`, `pytest`) | 代码不需要 | `--fix` 自动移除 |
| mypy: `no-any-return` (3 处) | provider 声明为 Any 类型，返回值丢失类型 | `cast(dict[str, Any], ...)` + assert nudge_loop not None |

## 质量门禁

### ruff
```
$ uv run ruff check --select E,F src/hyqagent/scanner/adversarial.py tests/test_scanner/test_adversarial.py
All checks passed!
```

### mypy
```
$ uv run mypy src/hyqagent/scanner/adversarial.py
Success: no issues found in 1 source file
```

### pytest
```
1224 passed, 2 skipped, 5 warnings — 全量回归
新测试: 41 passed (tests/test_scanner/test_adversarial.py)
```

## 设计反思

### 做得好
1. **模式一致性** — AdversarialReviewer 完全遵循 CompletenessCritic 的 DI + nudge_loop 模式，降低学习成本
2. **安全优先默认** — LLM 调用失败默认 `upheld`（不推翻拒绝），错误消息泄露不暴露敏感信息
3. **可测试性** — `_build_adversarial_prompt()` 同时接受 dataclass/dict，测试无需构造完整对象
4. **收敛管道完整** — 双视角字段 `perspective_a_findings` / `perspective_b_findings` 现在被真实填充，Chao2 估计器首次发挥作用

### 可改进
1. **模型独立性约束** — 当前代码注释了独立性要求但未在运行时强制执行。理想情况下应在 `review()` 前检查 reviewer_model ≠ validator_model
2. **代码上下文获取** — `_phase_adversarial_review()` 调用 `review(rejected)` 时始终传空 `code_contexts={}`，未从文件中提取实际代码片段。后续应在 orchestrator 中集成 `memory/` 包的代码检索
3. **端到端验证** — 对抗性审查效果需要 eval 回归测试验证（需要真实 LLM 调用对比 overturn rate）

## 下步衔接

Phase 4 剩余任务：
- **Task 6: 饱和扫描**（参数化变异）— SSRF/XSS/SQLi 子类型矩阵，同一漏洞模式用不同参数组合重新测试
- **Task 8: NudgeLoop 实际跑通** — 当前 NudgeLoop 已注入 adversarial reviewer，但尚未在真实 LLM 调用流中端到端验证
