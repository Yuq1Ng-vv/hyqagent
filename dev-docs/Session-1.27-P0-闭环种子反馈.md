# Session 1.27 — P0 闭环种子反馈（Seed Feedback Loop）

## 目标
实现扫描管道闭环种子反馈机制：将 SaturationScanner 和 ReverseSinkAnalyzer 发现的新函数/新 sink 反馈到假设生成阶段，使扫描器能从已确认漏洞的邻域自动发现更多漏洞。

核心理念来自三通道覆盖生态系统：
- **通道1** (PathAnnotator) — 前向 taint → 生成 annotated_paths
- **通道2** (BlindScanReviewer) — LLM 盲区扫描
- **通道3** (ReverseSinkAnalyzer) — 逆向 BFS 发现未标注 sink

通道1 直接产生 hypothesis，但通道3 和 SaturationScanner 的发现（saturation_seeds、reverse_sink_result.discoveries）**从未被假设生成消费**——这是闭环的断裂点。本次 Session 补全这个闭环。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 修改 | `src/hyqagent/scanner/hypothesis.py` | +110 | 新增 `generate_from_seeds()` + `_read_function_source()` |
| 修改 | `src/hyqagent/scanner/orchestrator.py` | +45 | `_phase_hypothesis_gen()` 双源假设生成（annotated + seeds） |
| 新建 | `tests/test_scanner/test_hypothesis.py` | ~420 | 16 tests — 读函数源码 + 种子生成 + orchestrator 集成 |

## 实现过程

### 1. `HypothesisGenerator.generate_from_seeds()` — 种子到假设

**入口参数**：
- `seed_functions: list[str]` — SaturationScanner 发现的函数名（已确认 sink 的调用者/被调用者）
- `sink_discoveries: list[dict] | None` — ReverseSinkAnalyzer 发现的未标注 sink→source 对

**处理流程**：
```
seed_functions → CPG graph._read_function_source() → markdown code blocks
sink_discoveries → 格式化 bullet list (最多 15 条，防 prompt 溢出)
                → 组合 prompt → CHEAP tier LLM → Structured Output → Hypothesis[]
```

**设计决策**：
- 使用 **CHEAP tier**（deepseek）——与 `blind_scan()` 一致，种子扫描是探索性的，低成本优先
- 复用已有的 `HYPOTHESIS_SCHEMA` 和 `SYSTEM_PROMPT`——不引入新的结构化输出 schema
- 异常时返回空列表，不中断整个假设生成阶段

### 2. `HypothesisGenerator._read_function_source()` — CPG 源码提取

```python
def _read_function_source(self, func_name: str, graph: Any) -> str | None:
```

遍历 CPG graph 节点，匹配 `node_type="function"` 且 `name == func_name` 的节点：
- 提取 `source` 属性（截断至 1500 字符）
- 返回 markdown 代码块：`` ```python\n...\n``` ``
- 无 source 或无匹配节点 → `None`

### 3. Orchestrator `_phase_hypothesis_gen()` 双源合并

**原逻辑**（~8 行）：
```python
annotated = self._hypothesis_gen.generate(paths)
state.phase_states["hypotheses"] = annotated
```

**新逻辑**（~50 行）：
```python
# 1. 主路径：annotated paths → generate()
hypotheses = await self._hypothesis_gen.generate(annotated_paths)

# 2. 种子反馈：saturation_seeds + reverse_sink_result → generate_from_seeds()
seed_functions = state.phase_states.get("saturation_seeds", [])
reverse_sink_result = state.phase_states.get("reverse_sink_result")
discoveries = [attr-to-dict conversion]  # ReverseSinkDiscovery → dict

if seed_functions or discoveries:
    seed_hyps = await self._hypothesis_gen.generate_from_seeds(
        seed_functions=seed_functions,
        sink_discoveries=discoveries,
    )
    hypotheses.extend(seed_hyps)

# 3. 合并存储
state.phase_states["hypotheses"] = hypotheses
```

**关键约束**：
- 种子反馈异常被单独 try/except 包裹——不影响主路径假设生成
- `ReverseSinkDiscovery` dataclass → dict 转换使用 `getattr()` 安全读取
- 无种子/发现时跳过，不调用 LLM

### 4. 测试 — 16 tests

| 测试类 | 数量 | 覆盖 |
|--------|------|------|
| TestReadFunctionSource | 4 | 正常查找返回 markdown、未知函数返回 None、空 source 跳过、长源码截断 |
| TestGenerateFromSeeds | 7 | 空输入返回空、seed_functions 生成、sink_discoveries 生成、两者合并、LLM 失败降级、多条假设、>15 条发现截断 |
| TestPhaseHypothesisGenSeedFeedback | 5 | seeds 存在→调用 generate_from_seeds、discoveries 存在→调用、合并 annotated+seed 假设、无种子跳过反馈、种子失败不崩溃 |

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `test_merges_seed_and_annotated_hypotheses` — `TypeError: unexpected keyword argument 'sanitizer_exists'` | `Hypothesis` dataclass 无 `sanitizer_exists` 字段（那是 `_parse_response` 忽略的 LLM dict key），测试直接构造 Hypothesis 时错误使用了该字段 | 改为正确的构造字段：`id`, `evidence`, `reasoning`（`id` 必须提供） |
| ruff E501 | 测试中 graph.add_node 的 source 参数行太长（107 字符） | 拆分为多行字符串拼接 |
| ruff I001 | import 顺序不符合 isort 规则 | `--fix` 自动排序 |

## 质量门禁

### ruff
```
All checks passed! (0 errors on new/modified files)
```

### mypy
```
Success: no issues found in 2 source files
(hypothesis.py, orchestrator.py)
```

### pytest
```
1356 passed, 2 skipped, 5 warnings — 全量回归
新测试: 16 passed (test_hypothesis.py)
(基线: 1340 → 1356)
```

## 设计反思

### 做得好
1. **最小侵入** — `generate_from_seeds()` 作为独立方法添加到 `HypothesisGenerator`，不修改 `generate()` 或 `blind_scan()` 的签名
2. **双源不互害** — 种子反馈异常不影响主路径假设生成，try/except 隔离
3. **复用现有基础设施** — CHEAP tier + HYPOTHESIS_SCHEMA + SYSTEM_PROMPT 全部复用，零重复代码
4. **三通道真正闭环** — 通道1+2+3 的发现现在全部反馈到假设生成

### 可改进
1. **种子去重** — 当前不检查种子产生的假设是否与 annotated 产生的假设重复（同一 sink 可能被两个路径发现）。可在合并时按 `(vuln_type, sink_location)` 去重
2. **种子质量过滤** — 所有种子平等对待，未区分置信度高低。低置信度种子可能产生噪音假设
3. **批量优化** — 每个种子函数独立调用 `_read_function_source` 遍历全图，种子数量大时应一次遍历收集所有匹配节点

## 下步衔接
- **P0 完成** ✅ — 闭环种子反馈已实现并测试
- **P1 — 收敛循环补全**：ADVERSARIAL_REVIEW/SATURATION_SCAN/REVERSE_SINK/BLIND_SCAN 在 `_CONVERGE_BODY` flag 清除中存在，但 `_execute_phases()` 收敛循环体未显式调用它们
- **Task 8 — Observability 集成**：OTel + LangFuse + Prometheus
- **Phase 5 — 动态验证**：用户表示"暂时不是很需要"
