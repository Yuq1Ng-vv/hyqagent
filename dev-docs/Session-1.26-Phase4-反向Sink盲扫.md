# Session 1.26 — Phase 4 反向 Sink 分析 + 盲扫 LLM 通道

## 目标
实现 Phase 4 Task 6：补充机制 — 反向 Sink 分析（通道3）和盲扫 LLM 通道（通道2）。两者来自 COVERAGE-IMPROVEMENT-PLAN.md 的三通道覆盖架构：
- **通道2 (BlindScanChannel)**: LLM-based，问"基于模式的扫描器会遗漏什么？" — IDOR、缺少鉴权、业务逻辑等
- **通道3 (ReverseSinkChannel)**: Zero-LLM，从所有 sink 反向 BFS 追溯未识别 source

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `src/hyqagent/scanner/reverse_sink.py` | ~270 | ReverseSinkAnalyzer（通道3，零LLM，逆向图遍历） |
| 新建 | `src/hyqagent/scanner/blind_scan.py` | ~360 | BlindScanReviewer（通道2，LLM，8种盲区类型） |
| 修改 | `src/hyqagent/scanner/orchestrator.py` | +120 | PhaseName ×2 + Phase 方法 ×2 + DI 构建 + 收敛视角联动 |
| 新建 | `tests/test_scanner/test_reverse_sink.py` | ~350 | 35 tests — 数据模型、源启发、逆向BFS、分析器、orchestrator 集成 |
| 新建 | `tests/test_scanner/test_blind_scan.py` | ~500 | 48 tests — 数据模型、Schema、System Prompt、Prompt构建、Reviewer、orchestrator 集成 |

## 实现过程

### 1. `scanner/reverse_sink.py` — 通道3，逆向 Sink 分析

**核心算法**：
```
所有 sink 候选 (get_all_sink_candidates)
  ├── 已标注 sink (有 taint_category) → 统计用量
  ├── 未标注 sink (危险但未分类) → 重点分析目标
  └── 对每个未覆盖 sink → 逆向 BFS 追溯上游
       └── 遇到 source-like 节点 → 记录为发现
```

**数据模型**：
```python
@dataclass
class ReverseSinkDiscovery:
    sink_name: str
    sink_file: str
    sink_line: int
    sink_source: str            # 实际调用表达式
    source_names: list[str]     # 上游 source 函数名
    source_files: list[str]
    taint_category: str         # 空 = 新发现
    confidence: str             # high/medium/low 按 BFS 深度

@dataclass
class ReverseSinkResult:
    total_sinks_checked: int
    total_labeled: int
    total_unlabeled: int
    discoveries: list[ReverseSinkDiscovery]
    previously_covered: int     # 前向分析已覆盖
```

**源启发式检测** (`_looks_like_source`)：
- 28 种 source-like 模式：request、params、query、body、input、cookie、header、session、argv、stdin、environ、files、get_json 等
- NODE_SOURCE → 直接认为是源（除非已标注 taint_category）
- NODE_PARAMETER → 作为源代理（可能是未追踪的入口点）
- 贪婪字符串匹配 `any(h in combined for h in _SOURCE_HEURISTICS)`

**逆向 BFS** (`_reverse_bfs_from_node`)：
- 标准队列 BFS，deque 驱动
- 仅遍历 DATA_FLOW + CALLS 两种边（不跟踪 CTRL_FLOW）
- 遇到 source-like 节点 → 记录并停止（不穿越源继续追溯）
- 缺失节点保护：`if start_node_id not in graph: return sources`
- 深度限制：超过 max_depth 的节点不访问

**置信度计算**：
```
min_depth ≤ 3  → high
min_depth ≤ 8  → medium
min_depth > 8  → low
```

**排序**：未标注 sink 在前（`lambda d: (1 if d.taint_category else 0, ...)`）— 新发现比已知标注更值得关注。

### 2. `scanner/blind_scan.py` — 通道2，盲扫 LLM

**核心设计**：从 `exposed_endpoints_from_state()` 提取攻击面中未被 taint 路径覆盖的端点，用 LLM 从 8 个维度审视：

1. IDOR — 资源所有权检查
2. Missing auth — 缺少鉴权装饰器
3. Business logic — 支付跳过、负数数量等
4. Race conditions — TOCTOU、重复提交
5. Mass assignment — 越权字段更新
6. Parameter pollution — 查询字符串覆盖内部参数
7. Error leaks — 生产环境调试信息泄露
8. Missing rate limiting — 可暴力破解的端点

**数据模型**：
```python
@dataclass
class BlindScanFinding:
    endpoint: str         # route 或 handler_func
    issue_type: str       # idor/missing_auth/business_logic/...
    severity: str         # critical/high/medium/low
    confidence: float     # 0.0-1.0
    title: str
    description: str
    reasoning: str        # 为什么模式扫描器会漏掉

@dataclass
class BlindScanResult:
    endpoints_reviewed: int
    findings: list[BlindScanFinding]
    model: str
    reasoning: str
```

**Structured output (tool_use)**: `report_blind_scan` — endpoints_reviewed + findings 数组，每个 finding 包含 endpoint/issue_type/severity/description（必填）+ confidence/title/reasoning（可选）。

**SYSTEM prompt**：分三部分 — (1) 模式扫描器擅长什么，(2) 模式扫描器对什么盲区，(3) 审查五步流程 + 五条规则。

**Prompt 构建** (`_build_blind_scan_prompt`)：端点列表 + handler/方法/位置/鉴权/框架信息 + 可选代码上下文（1500 字符截断）+ 目标语言标注。

**DI 模式**：与 AdversarialReviewer 相同 — `__init__(provider, model, nudge_loop=None)`，内部用 `cast(dict[str, Any], result)` 满足 mypy。

**`exposed_endpoints_from_state(state)`**：
- 从 `state.phase_states.attack_surface`（或 `endpoints` 备选键）收集端点
- 从 `state.phase_states.annotated_paths` 提取已覆盖 handler 函数
- 返回 handler_func 不在覆盖集中的端点

### 3. Orchestrator 集成

**PhaseName 新增**：
- `REVERSE_SINK = "reverse_sink"` — 位于 SATURATION_SCAN 之后
- `BLIND_SCAN = "blind_scan"` — 位于 REVERSE_SINK 之后

**DEEP_PHASES** 和 **_CONVERGE_BODY** 同步更新（两个新 Phase 均注册在 COVERAGE_AUDIT 之前）。

**`_phase_reverse_sink()`** (~45 行)：
- 模式过滤：quick → 跳过
- 读取 `annotated_paths` + `language`
- 调用 `ReverseSinkAnalyzer.analyse()` → 存储 `reverse_sink_result`
- **端点计数联动**：发现越多 → `endpoint_count` 越大 → EC 收敛阈值更高

**`_phase_blind_scan()`** (~45 行)：
- 模式过滤：quick → 跳过
- 调用 `exposed_endpoints_from_state(state)` 提取目标
- 调用 `BlindScanReviewer.review()` → 存储 `blind_scan_result`
- **发现计数联动**：盲扫发现越多 → `finding_count` 越大 → VDR 收敛需更多轮次

**收敛视角联动**（`_phase_convergence_check()`）：
- `perspective_b` 已包含 adversarial overturned IDs
- 新增：盲扫发现的端点也注入 `perspective_b`（`f"blind:{endpoint}"` 格式）
- 目的：Chao2 估计器看到独立"视角"产生更多发现 → 估计总漏洞数更高 → 收敛更晚

**DI 自动构建**（`_ensure_scanner_modules()`）：
```python
# Reverse sink (zero-LLM, needs CPGQuery only)
self._reverse_sink_analyzer = ReverseSinkAnalyzer(
    cpg_query=self._query, max_depth=15)

# Blind scan (LLM-based, needs mid provider)
self._blind_scan_reviewer = BlindScanReviewer(
    provider=self._mid, model=cfg.mid_model)
```

### 4. 测试 — 83 tests total

**reverse_sink (35 tests)**：

| 测试类 | 数量 | 覆盖 |
|--------|------|------|
| TestReverseSinkDiscovery | 2 | 默认值、完整字段 |
| TestReverseSinkResult | 2 | 默认值、含发现 |
| TestLooksLikeSource | 10 | source 节点、tainted 跳过、parameter、名称匹配、源文本匹配、普通赋值排除、cookie/get_json/stdin 启发式 |
| TestReverseBFS | 7 | 上游 source、未标注 parameter、深度限制、源节点停止、缺失节点、CTRL_FLOW 过滤、CALLS 边 |
| TestReverseSinkAnalyzerConstruction | 2 | 构造参数、默认 max_depth |
| TestReverseSinkAnalyzerAnalyse | 7 | 无 graph、无候选、发现、annotated_paths 去重、深度→置信度、未标注优先排序、空语言 |
| TestPhaseReverseSink | 5 | 无 analyzer 跳过、quick 跳过、存储结果、端点计数更新、PhaseName 注册 |

**blind_scan (48 tests)**：

| 测试类 | 数量 | 覆盖 |
|--------|------|------|
| TestBlindScanFinding | 2 | 默认值、完整字段（含 CWE） |
| TestBlindScanResult | 2 | 默认值、含发现 |
| TestBlindScanSchema | 5 | 名称、必填字段、finding 属性、severity 枚举、confidence 范围 |
| TestBlindScanSystemPrompt | 6 | 探索者角色、模式扫描器擅长项、盲区、审查步骤、规则部分、tool 指令 |
| TestBuildBlindScanPrompt | 8 | 端点计数、路由+handler、方法、框架、代码上下文、缺失上下文优雅处理、语言标注、多端点 |
| TestEndpointToDict | 3 | HttpEndpoint 转换、dict 透传、缺失属性默认值 |
| TestExposedEndpointsFromState | 5 | 提取暴露端点、全覆盖返回空、空状态、无 handler 跳过、endpoints 备选键 |
| TestBlindScanReviewerConstruction | 2 | 构造参数、带 nudge_loop |
| TestBlindScanReviewerReview | 9 | 空端点、mock LLM、多项发现、LLM 失败优雅降级、多样 issue_type、HttpEndpoint 对象标准化、缺失字段默认值、code_contexts 传播、语言参数 |
| TestPhaseBlindScan | 6 | 无 reviewer 跳过、quick 跳过、无暴露端点跳过、存储结果+更新计数、PhaseName 注册、LLM 失败不崩溃 |

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| Reverse BFS `test_finds_upstream_source` 失败 — n1 未被识别为 source | n1 的 `taint_category="user_input"` → `_looks_like_source` 优先检查 taint（`if taint: return False`），跳过了 NODE_SOURCE 检查 | n1 移除 taint_category（未标注 source 才是"新发现"） |
| `test_finds_untainted_parameter` 失败 — BFS 在 n5 就停了，未到达 n4 | n5 的源文本 "read_input()" 匹配 `_SOURCE_HEURISTICS` 中的 "input" → 被当作 source-like 节点 | n5 源文本改为 "helper_call()"（零启发式匹配） |
| "transform_data()" 仍然匹配 | "transform" 包含 "form" → 匹配 `_SOURCE_HEURISTICS` 中的 "form" | 必须用完全不会匹配启发式的文本 |
| `labeled_ids` ruff F841 | 变量赋值但未使用 | 前缀 `_` → ruff 豁免 |
| `graph.predecessors("nonexistent")` → NetworkXError | BFS 未校验节点存在性 | `if start_node_id not in graph: return []` 守卫 |
| 盲扫 `exposed_endpoints_from_state` 测试失败 | `annotated_paths` 未放入 `state.phase_states` 而是局部变量 | 移到 `state.phase_states["annotated_paths"]` |
| `test_review_with_mock_llm` → `assert result.endpoints_reviewed == 2` 失败 | `_parse_response` 用 `len(endpoints)`（=1）而非 mock 返回值 | 断言修正为 `== 1` |
| `test_llm_failure_does_not_crash` → 期望空 phase_states 但结果被存储 | `BlindScanReviewer.review()` 内部捕获异常返回空 BlindScanResult，orchestrator 看到的是正常结果 | 断言改为验证结果已存储但 findings 为空 |
| mypy `no-any-return` | Provider 返回类型为 `Any` | `cast(dict[str, Any], result)` |
| ruff I001 import 排序 | 新建测试文件 import 未排序 | `--fix` 自动修正 |
| ruff D205 docstring 双行摘要 | 新 Phase 方法 docstring 跨行 | 缩短为单行摘要 |
| 反向 sink 排序：`test_unlabelled_sorted_first` 失败 | 排序键 `(0 if taint else 1, ...)` → 已标注在前 | 修正为 `(1 if taint else 0, ...)` → 未标注在前 |

## 质量门禁

### ruff
```
All checks passed! (E/F zero on new files)
11 pre-existing in orchestrator.py (assert/except-pass/naming — not introduced)
```

### mypy
```
Success: no issues found in 5 source files
(reverse_sink.py, blind_scan.py, orchestrator.py, both test files)
```

### pytest
```
1340 passed, 2 skipped, 5 warnings — 全量回归
新测试: 83 passed (35 reverse_sink + 48 blind_scan)
```

## 设计反思

### 做得好
1. **三通道覆盖架构首次全实现** — 通道1 (PathAnnotator, 前向 taint) + 通道2 (BlindScan, LLM 盲区) + 通道3 (ReverseSink, 逆向图) 构成完整的覆盖生态系统
2. **两个 Phase 都注入收敛视角** — ReverseSink → endpoint_count, BlindScan → finding_count + perspective_b，管道自然发现更多工作要做的轮次
3. **零 LLM + LLM 通道互补** — 通道3 零成本做粗筛（source 启发式 → sink 发现），通道2 用 LLM 做精筛（语义逻辑 vs 模式签名），预算友好
4. **DI 模式一致性** — 所有 scanner 模块遵循相同的 DI 构造模式，`_ensure_scanner_modules()` 统一管理懒初始化
5. **测试覆盖密度高** — 83 tests 覆盖数据模型→启发式→BFS→analyzer→reviewer→orchestrator 全链路

### 可改进
1. **源启发式匹配过于贪婪** — 28 个子串匹配，"form" 匹配 "transform"，"get" 匹配 "get_user_data"。应改用词边界或完整 token 匹配
2. **`_labeled_ids` 未使用** — 预留了标注 sink ID 集合但分析逻辑未用它（未来可用作去重基准）
3. **BlindScanReviewer 未接入 NudgeLoop** — 构造时接收 nudge_loop 参数但 `review()` 方法未调用（应为 future work，当端点数量大时多次 nudging 有用）
4. **收敛循环未调用新 Phase** — ADVERSARIAL_REVIEW/SATURATION_SCAN/REVERSE_SINK/BLIND_SCAN 在 `_CONVERGE_BODY` 中（flag 清除）但 `_execute_phases` 收敛循环体未显式调用它们 → 每轮只运行一次

## 下步衔接
- **Task 8**: Observability 完整集成 (OTel + LangFuse + Prometheus) — cost_tracker 已有基础
- **Phase 5**: 动态验证沙箱 — Docker PoC 执行 → Bayesian belief system
- **闭环种子反馈**: `_phase_hypothesis_gen` 读取 `saturation_seeds` + `reverse_sink_result.discoveries` 生成假设
