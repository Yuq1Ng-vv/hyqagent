# Session 1.28 — P1 收敛循环补全

## 目标
将四个在初始扫描中只运行一次但收敛循环中本应每轮重跑的 Phase，加入到 `_execute_phases()` 的收敛循环体中。

**问题根因**：Session 1.24–1.26 新增的四个 Phase（ADVERSARIAL_REVIEW、SATURATION_SCAN、REVERSE_SINK、BLIND_SCAN）在 `DEEP_PHASES` 中注册（初始扫描一次）且在 `_CONVERGE_BODY` 中注册（flag 清除），但 `_execute_phases()` 的收敛循环体（for 循环）只显式调用了 HYPOTHESIS_GEN、VALIDATION、COVERAGE_AUDIT、CONVERGENCE_CHECK——这四个新 Phase 虽然 completed flag 被每轮清除，却没有被重新执行。

**影响**：收敛循环的每一轮本应以"更多发现 → 更多假设 → 更准确的收敛判断"的飞轮效应运行，但缺少这四个 Phase 意味着：
- 对抗性审查只在第一轮运行，后续轮次的 rejected 假设无人重新审查
- 饱和扫描不会在后续轮次中从新确认的 sink 扩展
- 反向 sink 分析不会利用更新后的 sink 覆盖信息
- 盲扫不会在发现新假设后重新审视未覆盖端点

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 修改 | `src/hyqagent/scanner/orchestrator.py` | +16 | 收敛循环体新增 4 个 Phase 调用 |

## 实现过程

### 修改点：`_execute_phases()` 收敛循环体

**原代码**（~10 行循环体）：
```python
for round_num in range(1, max_rounds + 1):
    # HYPOTHESIS_GEN
    if PhaseName.HYPOTHESIS_GEN.value not in completed:
        await self._run_phase(PhaseName.HYPOTHESIS_GEN)
    # VALIDATION
    if PhaseName.VALIDATION.value not in completed:
        await self._run_phase(PhaseName.VALIDATION)
    # COVERAGE_AUDIT
    if PhaseName.COVERAGE_AUDIT.value not in completed:
        await self._run_phase(PhaseName.COVERAGE_AUDIT)
    # CONVERGENCE_CHECK
    await self._run_phase(PhaseName.CONVERGENCE_CHECK)
    # ... flag clearing via _CONVERGE_BODY
```

**新代码**（+16 行，四个新 Phase 插入 VALIDATION 和 COVERAGE_AUDIT 之间）：
```python
    # ADVERSARIAL_REVIEW — attacker-lens review of rejected hypotheses
    if PhaseName.ADVERSARIAL_REVIEW.value not in completed:
        await self._run_phase(PhaseName.ADVERSARIAL_REVIEW)

    # SATURATION_SCAN — expand CPG call graph from confirmed sinks
    if PhaseName.SATURATION_SCAN.value not in completed:
        await self._run_phase(PhaseName.SATURATION_SCAN)

    # REVERSE_SINK — reverse BFS from sinks to unrecognised sources
    if PhaseName.REVERSE_SINK.value not in completed:
        await self._run_phase(PhaseName.REVERSE_SINK)

    # BLIND_SCAN — LLM reviews endpoints for pattern-blind issues
    if PhaseName.BLIND_SCAN.value not in completed:
        await self._run_phase(PhaseName.BLIND_SCAN)
```

### 每轮执行顺序与依赖关系

```
Round N:
  HYPOTHESIS_GEN      ← 消耗 annotated_paths + seeds（含上轮 saturation/reverse 的产出）
  VALIDATION          ← L1 确定性 + L2 LLM 验证
  ADVERSARIAL_REVIEW  ← 攻击者视角重新审查被拒绝的假设
  SATURATION_SCAN     ← 从确认的 sink 沿 CPG 调用图扩展邻域
  REVERSE_SINK        ← 逆向 BFS：sink → 未识别 source（零 LLM）
  BLIND_SCAN          ← LLM 审视无 taint 覆盖的端点
  COVERAGE_AUDIT      ← 更新覆盖指标
  CONVERGENCE_CHECK   ← 判定是否收敛（含双视角 Chao2）
```

**关键设计**：
- 四个新 Phase 都已有完整的 skip guard（module is None → return、empty input → return、quick mode → skip），无需在循环体中重复条件判断
- 每轮结束后 `_CONVERGE_BODY` 清除 completed flags → 下轮 `_run_phase` 重新执行
- `_run_phase` 在 Phase 完成后重新标记 completed → 防止同轮重复执行

### 不变量保护

| 不变量 | 状态 |
|--------|------|
| `DEEP_PHASES` 初始执行顺序不变 | ✅ 首次扫描仍按注册顺序执行 |
| `_CONVERGE_BODY` flag 清除不变 | ✅ 四个 Phase 已在列表中 |
| 各 Phase 的 skip guard 不变 | ✅ 模块缺失/空输入/quick 模式均处理 |
| 收敛终止条件不变 | ✅ converged/escalate 仍需 break |

## 遇到的问题与修复

无。这是一个纯粹的机械性补全——四个 Phase 的 handler 和 `_CONVERGE_BODY` 注册早已就绪，只是循环体遗漏了调用。

## 质量门禁

### ruff
```
All 11 issues pre-existing — zero new (orchestrator.py)
```

### mypy
```
Success: no issues found in 1 source file
```

### pytest
```
1356 passed, 2 skipped, 5 warnings — 全量回归
```

## 设计反思

### 做得好
1. **最小改动** — 仅 16 行新增，零重构，零新文件
2. **依赖关系正确** — 四个 Phase 插入位置在 VALIDATION 之后、COVERAGE_AUDIT 之前，确保它们消费最新验证结果、产出被覆盖审计消费
3. **已有 guard 复用** — 不重复 skip 逻辑

### 可改进
1. **收敛循环第一阶段跳过** — Round 1 时这四个 Phase 已被 `DEEP_PHASES` 执行过（初始扫描），收敛循环 Round 1 会因为 `completed` flag 仍然存在而跳过它们。这是正确的行为（不重复执行），但逻辑分散在两处（`DEEP_PHASES` + 循环体），将来可能造成困惑
2. **无针对性测试** — 现有测试验证了各 Phase 独立行为和 orchestrator 集成，但没有端到端收敛多轮测试（需要 mock 多轮 LLM + CPG 交互，成本高）

## 下步衔接
- **P1 收敛循环补全 ✅** — 四个 Phase 已加入收敛循环
- **Task 8 — Observability 集成**：OTel + LangFuse + Prometheus（cost_tracker 已有基础）
- **Phase 5 — 动态验证沙箱**：用户表示"暂时不是很需要"
- **其他优化**：种子去重、源启发式词边界匹配、NudgeLoop 接入 BlindScanReviewer
