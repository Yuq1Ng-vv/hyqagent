# Session 1.25 — Phase 4 饱和扫描（Saturation Scanner）

## 目标
实现 Phase 4 Task 7 后半：饱和扫描（Saturation Scanning）——从已确认漏洞出发，沿 CPG 调用图迭代扩张攻击面。零 LLM 成本，纯图论操作。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `src/hyqagent/scanner/saturation.py` | ~285 | SaturationScanner 核心模块（SeedPoint + 图遍历 + 迭代扩张） |
| 修改 | `src/hyqagent/scanner/orchestrator.py` | +85 | PhaseName.SATURATION_SCAN + Phase 方法 + DI + 端点计数联动 |
| 新建 | `tests/test_scanner/test_saturation.py` | ~480 | 33 tests — 数据模型、图遍历、Scanner、确认提取、orchestrator 集成 |

## 实现过程

### 1. `scanner/saturation.py` — 迭代攻击面扩张

**核心原理**（来自 COVERAGE-MINIMIZATION-ARCHITECTURE.md §3.8）：

```
已确认漏洞 (execute_sql 存在 SQLi)
  ├── 谁调用了 execute_sql?   → do_query          (caller)
  ├── execute_sql 调用了什么?  → (none)            (callee)
  └── do_query 谁还调用?      → sanitize, upload  (round 2)
       └── sanitize 谁调用?    → main              (round 3)
```

每轮候选自然递减，循环自收敛（max 4 轮）。

**数据模型**：

```python
@dataclass(frozen=True)
class SeedPoint:
    function_name: str  # 发现的相邻函数名
    file_path: str  # 所在文件
    reason: str  # "caller_of_sink" | "callee_of_sink"
    source_finding_id: str  # 追踪链：哪个确认发现触发的
    source_sink: str  # 追踪链：原始 sink 函数


@dataclass
class SaturationResult:
    rounds_completed: int
    total_seeds_generated: int
    seeds_per_round: list[int]
    seed_functions: list[str]  # 去重后的函数名
```

**SaturationScanner 类**：
- `__init__(cpg_query, max_rounds=4)` — 与 AdversarialReviewer 相同的 DI 模式
- `async scan(confirmed)` — 主入口，接收 `[(Hypothesis, ValidationResult)]` 元组
- `_extract_seeds(confirmed, graph)` — Round 0：从确认 sink 提取 caller/callee
- `_expand_one(seed, graph)` — Round N：单种子扩张
- `_func_from_location(location, graph)` — `"file.py:line"` → CPG 函数名解析

**图遍历 helpers**（模块级函数）：
- `_resolve_function_at(graph, file, line)` — 扫描 NODE_FUNCTION 的 start_line/end_line 范围
- `_find_callers(graph, func_name)` — caller → call_site → func 反向遍历
- `_find_callees(graph, func_name)` — func → call_site → callee 正向遍历

**关键设计决策**：
- `SeedPoint` 使用 `frozen=True` — 放入 set 去重
- `self._seen: set[str]` — `"file::func"` 格式的全局去重键
- 完全零 LLM — 仅操作 CPG NetworkX 图
- `confirmed_from_state(state)` 公共 helper — 从 PipelineState 提取确认对

### 2. Orchestrator 集成

**PhaseName 扩展**：
- 新增 `SATURATION_SCAN = "saturation_scan"`，位于 ADVERSARIAL_REVIEW 之后
- `DEEP_PHASES` 和 `_CONVERGE_BODY` 同步更新

**`_phase_saturation_scan()`** (~45 行)：
- 模式过滤：quick 跳过
- 无确认发现 → 跳过
- 调用 `SaturationScanner.scan(confirmed)` → 存储 `saturation_result` + `saturation_seeds`
- **端点计数联动**：`state.endpoint_count += result.total_seeds_generated`
  — 新发现的函数增加端点计数 → 影响 EC 收敛指标 → 需要更多轮次覆盖

**DI 自动构建**：
```python
if self._saturation_scanner is None and self._query is not None:
    self._saturation_scanner = SaturationScanner(
        cpg_query=self._query,
        max_rounds=4,
    )
```

构造简单 — 不需要 LLM provider，只需要 CPGQuery。

### 3. 测试 — 33 tests

| 测试类 | 数量 | 覆盖 |
|--------|------|------|
| TestSeedPoint | 2 | 默认值、全字段 |
| TestSaturationResult | 2 | 默认值、含数据 |
| TestGraphTraversal | 9 | 函数解析（精确/边界/无匹配）、caller（单/多/无）、callee（单/无） |
| TestSaturationScannerConstruction | 2 | 构造参数、默认 max_rounds |
| TestSaturationScannerScan | 6 | 空输入、无 graph、种子提取、多轮扩张、去重、seeds_per_round |
| TestSaturationScannerEdgeCases | 3 | 不可解析位置、无效格式、混入 rejected |
| TestConfirmedFromState | 4 | 提取 confirmed、空状态、去重、adversarial overturned |
| TestPhaseSaturationScan | 5 | 无 scanner 跳过、quick 跳过、无 confirmed 跳过、存储结果、端点计数更新 |

测试图拓扑：
```
main → sanitize → do_query → execute_sql
       upload_file → do_query (共享 callee)
```

使用 `nx.MultiDiGraph` 构建最小 CPG-like 图，完全自包含。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `SeedPoint` unhashable → can't add to `set` | 非 frozen dataclass 默认不可哈希 | 加 `frozen=True` |
| `SeedPoint.__init__() missing 1 required positional argument: 'reason'` | `reason: str` 无默认值，且 test 未传 | 改为 `reason: str = ""` |
| ruff F841 unused variables (`main_id` 等) | `add_func()` 返回值赋给变量但未使用 | 直接丢弃返回值（不赋值给变量） |
| mypy `no-any-return` | `data.get("name")` 返回 `Any` 类型 | `isinstance(name, str)` 类型收窄 |
| Orchestrator 测试 `endpoint_count` 未递增 | 上游 `SeedPoint` unhashable 导致 scanner 抛异常被 try/except 吞掉 | 修复 hashable 后级联修复 |

## 质量门禁

### ruff
```
All checks passed! (E/F zero)
```

### mypy
```
Success: no issues found in 1 source file
```

### pytest
```
1257 passed, 2 skipped, 5 warnings — 全量回归
新测试: 33 passed (tests/test_scanner/test_saturation.py)
```

## 设计反思

### 做得好
1. **零 LLM 成本** — 纯图遍历，每次饱和扫描不消耗 token，适合 deep 模式多轮迭代
2. **收敛联动** — `endpoint_count` 递增直接推高 EC 指标阈值，管道自然发现有更多工作要做
3. **SeedPoint 冻结** — `frozen=True` 天然支持 set 去重，且不可变语义防止意外的状态污染
4. **追踪链完整** — `source_finding_id` + `source_sink` 字段保留完整的种子→发现溯源

### 可改进
1. **种子反馈循环未闭环** — 当前种子存储在 `saturation_seeds` 但 hypothesis_gen 未读取它们来生成新假设。下步应让 `_phase_hypothesis_gen` 读取种子，将其作为额外的分析目标注入管道
2. **Route neighbor 未实现** — 架构文档提到"同路由模块的其他端点"，但代码库没有 route module 概念，当前只做了 caller/callee 扩张
3. **轻量扫描未集成** — 架构文档中的轻量通道（CPG 数据流 + 确定性规则）未实现；当前种子只是记录，未自动分析其安全性

## 下步衔接

- **闭环种子反馈**：在 `_phase_hypothesis_gen` 中读取 `saturation_seeds`，为每个种子函数创建 AnnotatedPath 或直接注入为 Hypothesis 生成目标
- **Phase 5**: 动态验证沙箱 — Docker 执行 PoC，验证结果接入贝叶斯信念系统
- **Phase 4 Observability** — OTel + LangFuse 集成（cost_tracker 已有基础）
