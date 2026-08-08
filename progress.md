# HyqAgent 开发进度

> 上次更新: Session 1.21 完成后 (2026-08-09)
> 最新: Nudge 系统实现 — AutoCVE 借鉴 + 自有扩展

## Phase 1: CPG Foundation — ✅ 完成

- [x] **Session 1.1** — 项目骨架初始化 (commit: `4ba65f7`)
  - pyproject.toml, src-layout, .env, pre-commit
  - CLAUDE.md, AGENTS.md, README.md, progress.md
  - core/protocols.py (6个核心协议), core/state.py, core/events.py (12种事件类型)
  - docs/ 目录整理 (10份参考文档移入，docs/README.md 索引)
- [x] **Session 1.2** — tree-sitter 安装和单文件解析 (cpg/parser.py)
  - 安装 tree-sitter 0.26.0 + Python/JS/Java 语法包
  - 实现 `cpg/parser.py` — Parser 类支持 parse_file/parse_code
  - 支持 extract_functions/extract_classes/extract_imports（三种语言）
  - 44 个 pytest 测试全部通过
- [x] **Session 1.3** — AST 遍历器 (cpg/traversal.py + 59 tests)
  - Traverser 类: TreeCursor 实现的 DFS 前序/后序遍历
  - 节点类型过滤、named_only 模式、子树遍历
  - 导航工具: get_children/parent/ancestors/ancestor_of_type
  - 工具方法: find_first/find_all/count/node_type_path
  - 103 个 pytest 测试全部通过
- [x] **Session 1.4** — 单文件调用图 (cpg/callgraph.py + 69 tests)
  - SingleFileCallGraph 类: 支持 Python/JS/Java 三种语言
  - 调用边解析（简单调用/方法调用/递归自环/嵌套函数）
  - 已解析/未解析分类 + UnresolvedCall 供跨文件使用
  - 查询接口: get_callees/get_callers/has_edge
  - 172 个 pytest 测试全部通过
- [x] **Session 1.5** — 可扩展性重构 + 跨文件调用图 (193 tests)
  - ⭐ **LanguageProvider 策略模式**: parser.py (671→260行) + callgraph.py (382→260行)
  - 新增 `cpg/languages/` 包: base.py + python/js/java Adaptor
  - 新增 `cpg/types.py` — 共享数据类，打破循环依赖
  - 添加新语言 = 1个文件 + 1行注册，核心模块零改动
  - **CallGraphBuilder** 跨文件调用图: 支持 add_directory/resolve_imports/build_calls
  - 导入解析: 相对导入 + 绝对导入
  - 193 个 pytest 测试全部通过
- [x] **🔧 基础加固** — 边界测试 + 性能基线 + 契约验证 (240 tests)
  - 新增 39 个边界测试（语法错误/Unicode/空输入/深层嵌套/互递归/循环导入等）
  - 新增 8 个性能基准（4 benchmark + 4 回归断言，CI 默认跳过）
  - `__post_init__` 拒绝空 name/无效行号；`get_provider` 统一 ValueError
  - `_languages` 缓存泄漏检测；`_validate()` Provider 契约检查
  - 240 个 pytest 测试全部通过
- [x] **Session 1.6** — 数据流图构建 (cpg/dataflow.py + 29 tests)
  - LanguageProvider 扩展: 新增 `assignment_types`/`extract_assignment_target`/`is_variable_identifier` 3 个抽象成员
  - DataFlowBuilder 类: `build_def_use_chains()` 函数内 def-use、`trace_cross_function()` 跨函数追踪、`propagate_taint()` 基础污点传播
  - 新增 4 个 dataclass: DefUsePair/DataFlowStep/TaintPath/TaintConfig
  - 269 个 pytest 测试全部通过
- [x] **Session 1.7** — CPG 图构建 + 查询接口 + Taint 规则 (cpg/graph.py + query.py + 33 tests)
  - CPGGraphBuilder: NetworkX MultiDiGraph 统一索引 AST/CALLS/DATA_FLOW
  - CPGQuery: find_path/find_sources/find_sinks/get_call_chain/slice_path
  - taint_rules.yaml: Python/JS/Java 三种语言 × 9 种漏洞类别完整规则
  - 302 个 pytest 测试全部通过
- [x] **Session 1.8** — 框架提取器（五种框架一次到位，33 tests）
  - BaseFrameworkExtractor ABC + HttpEndpoint/RouteParam 统一数据结构
  - Flask/FastAPI/Django/Express/Spring 五种框架完整实现
  - TaintRuleLoader: YAML→结构化规则加载器（match_source/sink/rules_for）
  - 335 个 pytest 测试全部通过
- [x] **Session 1.9** — 端到端 CPG 集成验证（26 tests）
  - 微型漏洞 Flask 应用：CWE-89/78/79/639 四种真实漏洞
  - 5 层 26 个集成测试：Parser→CallGraph→DataFlow→Graph→Frameworks→Query→TaintLoader 全链路
  - 361 个 pytest 测试全部通过
- [x] **Session 1.10** — Bug 清零 + 代码去重 + 错误处理补强（12 bugs fixed）
  - trace_cross_function 类型修复, 跨文件边 is_resolved, YAML sanitizer 拼写
  - _source/_loc 去重到 traversal.py, detect() narrow except, 懒加载 URL config
- [x] **Session 1.11** — 性能优化（5 perf fixes）
  - def-use O(n*m)→O(n+m) 单 pass, callgraph_builder 单次解析
  - _fn_to_node 缓存索引, find_path 多源 BFS 共享 visited
  - get_sanitizers 支持 TaintRuleLoader, 消除硬编码列表
- [x] **Session 1.12** — 测试 + YAML + 文档收尾（+11 tests）
  - Django/FastAPI/Java def-use 测试补齐, cross-function/taint_loader 集成测试
  - JS/Java YAML sanitizer 补全, __init__.py re-exports
- [x] **Session 1.13** — ureport2 系统性根因诊断与修复
  - ureport2 (469 Java 文件) 端到端验证：SQL 注入检测 3/4 通过
  - propagate_taint BFS 逻辑修复，match_source/sink 改为最长匹配
  - 对抗性审查：7 bugs fixed
- [x] **Session 1.14** — 跨函数数据流 + CPG 缓存 + JS 导入
  - `_add_cross_function_edges()` caller arg→callee param taint 追踪
  - Java `.java` 文件导入解析修复
  - **CPG pickle 缓存**: 首次 800s → 后续 0.3s（~2700x 加速）
  - JS/TS 相对导入（`./foo`→`foo.js`）支持 index 文件入口
  - filename 消歧：多文件同名时按包路径匹配
  - XXE 最小测试通过（2 paths），全量验证受阻于同名函数冲突
- [x] **Session 1.15** — Spring DI + 同名函数冲突修复 (BUG 8)
  - `_extract_field_types()` — 字段声明→虚拟 import（Spring @Autowired 支持）
  - Java 同 package 默认可达（C 组合）
  - ⭐ **BUG 8**: `_all_functions` 改为 `dict[str, list[str]]`，遍历候选消歧
  - ureport2 36 个 `parse()` 定义全部正确消歧
  - 跨文件 edge 从 ~2137 → **4,581**
- [x] **Session 1.16** — Bug 清零 + Phase 2 准备 (BUG 9-26)
  - **BUG 9**: Java 重载方法消歧（`ClassName.methodName` 限定名索引 + callee 后缀匹配）
  - **BUG 10+11**: Spring `@RequestMapping(method=)` 属性解析 + class-level 路由前缀
  - **BUG 12+13**: Django `re_path` 平衡引号 + Express handler 函数体 source 扫描
  - **BUG 15**: graph.py 双重解析修复（复用已解析 tree）
  - **BUG 18**: `_find_enclosing_func` 代码去重（统一用 `Traverser.get_ancestors`）
  - **BUG 20-26**: 安全/null 检查、缓存 FIFO 淘汰、YAML 校验、Windows 路径兼容等
  - ureport2 完整 CPG 图验证: **76,481 节点 / 239,706 边** / 缓存 0.3s 加载
  - XXE 跨文件 sink 检测确认 (`saxReader.read` @ ReportParser → DesignerServletAction)
- [x] **Session 1.17** — 测试策略与语言战略 (commit: `a3573b6`)
  - 测试缺口分析文档：3 项严重缺口 + 4 项中缺口
  - 语言优先级确立：PHP > Go，但 Java 优先打磨
  - 基准数据集调研（OWASP Benchmark、SARD、SecuriBench Micro 等）
- [x] **Session 1.18** — 真实项目端到端验证 + JS 函数提取修复 (commit: `205c454`)
  - **rwtests/**: 新增 vulpy (Flask, 8 vulns) + dvna (Express, 9 vulns)
  - **JS 修复**: `function_query` 新增 assignment_expression 模式，`appHandler.js` 0→13 函数
  - **新增 310 tests**: 6 个新测试文件 + fixtures + frameworks 测试扩展
  - 测试从 372 → **714** tests, 0 failures
- [x] **Session 1.19** — propagate_taint 重构 + 精确参数匹配 (commit: `27956d2`)
  - **移除死代码**: dataflow.py -274 行（propagate_taint/_bfs_taint 等 7 个方法）
  - **污点标签**: CPGGraphBuilder 集成 TaintRuleLoader，自动标记 source/sink
  - **位置参数匹配**: call_args 提取 + arg→param 1-to-1 边（回退到全连接）
  - **查询增强**: CPGQuery 支持 taint_category 优先匹配
  - **测试**: 移除 4 个死测试，新增 8 个集成测试，718 tests total
  - 净代码 -64 行
- [x] **Session 1.20** — ureport2 回归测试 (commit: `cae539b`)
  - **27 个回归测试**: 6 个测试类覆盖图结构/SQL注入/XXE/Java特性/污点标签/大图压力
  - **快加载**: 直接加载 pickle 快照（~30MB），避免 800s 全量重建
  - 测试总计: **745 tests, 0 failures**
- [x] **Session 1.21** — AutoCVE 横向对比研究 + Nudge 系统实现
  - `docs/AUTOCVE-RESEARCH.md` — AutoCVE 架构深度解析（6 Agent/7 Nudge/ReAct Loop/状态机）
  - `scanner/nudge.py` — 3 种 Nudge + 3 个内置 StopHook（~380 行，借鉴 AutoCVE AGPL v3）
  - `scanner/hypothesis.py` — 集成 NudgeLoop（可选，空结果/低置信度阻断）
  - `scanner/validator.py` — 集成 NudgeLoop（inconclusive 无推理阻断）
  - `scanner/__init__.py` — 重新导出 nudge 公共 API
  - `tests/test_scanner/test_nudge.py` — 46 tests（配置/继续意图检测/StopHook/NudgeLoop fake provider）
  - `.env` — DeepSeek API key 配置（gitignored）
  - **测试总计: 1062 tests, 0 failures** (+46 nudge tests)
  - **ruff: clean · mypy: no issues**

## Phase 1 最终指标

| 维度 | 数据 |
|------|------|
| 测试 | **801** tests, 0 failures |
| 源码模块 | **24** 个 |
| 源码行数 | **~6,100** 行 |
| 支持语言 | **3** 种 (Python/JavaScript/Java) |
| CPG 边类型 | **4** 种 (AST/CALLS/DATA_FLOW/CTRL_FLOW) |
| CPG 节点类型 | **8** 种 (+ NODE_BASIC_BLOCK) |
| 支持框架 | **5** 种 (Flask/Django/FastAPI/Express/Spring) |
| Taint 规则 | **3** 语言 × 10 类别 (Java 含 XXE) |
| CPG 图规模 | ureport2: 76K 节点 / 240K 边 |
| CPG 缓存 | 首次 822s → 后续 **0.3s** (~2700x) |
| 真实项目测试集 | **3** 项目 (ureport2/Java + vulpy/Flask + dvna/Express) |
| 已知 Bug | **26/26** 全部修复 ✅ |
| ruff | 仅预存问题 |
| mypy | 24 pre-existing（类型标注 + stub 缺失） |

## Phase 2: Deterministic Scanner — ✅ 完成

- [x] **Session 1.14-1.17** — 扫描流水线底层组件
  - `scanner/deterministic.py` — DeterministicScanner 五阶段扫描
  - `scanner/annotator.py` — PathAnnotator 10 标签分类 (PathLabel)
  - `cpg/discovery.py` — SinkDiscoverer + SourceCompletenessChecker
  - `cpg/coverage.py` — CoverageTracker (~179 盲点检测)
  - `scanner/coverage_metrics.py` — CoverageMetrics 指标聚合
- [x] **测试**: 883 tests, 0 failures

## Phase 3: LLM Integration — 🔵 进行中

- [x] **Session 1.18** — LLM 深度审计管道 (commit: `1950c36`)
  - `models/providers/anthropic_provider.py` — Anthropic SDK 封装 (DeepSeek + Claude 双 base_url)
  - `models/router.py` — CHEAP/MID/STRONG 三档路由 + 复杂度评估
  - `scanner/hypothesis.py` — CPG 切片 → LLM 假设生成 (tool_use 结构化输出)
  - `scanner/validator.py` — L1 确定性 + L2 LLM 五问验证
  - `observability/cost_tracker.py` — 按 phase 成本归因 + 预算控制
  - `api/cli.py` — `--deep` 模式, `resume`/`sessions` 命令
  - **设计决策**: 先 Phase 2 扫描 → 再 Phase 0 项目理解 (证据驱动)
- [x] **Session 1.18-1.19** — 覆盖盲区缓解 + Phase 3 单元测试
  - `scanner/coverage_auditor.py` — 零 LLM 差异覆盖分析（方案 5）
  - `scanner/completeness.py` — CompletenessCritic（方案 3）
  - `tests/test_models/test_provider.py` — Provider 测试 (mock Anthropic)
  - `tests/test_models/test_router.py` — 路由决策 + 复杂度评估测试
  - `tests/test_observability/test_cost_tracker.py` — 成本追踪测试
  - `tests/test_scanner/test_validator.py` — L1 验证逻辑测试
  - `tests/test_scanner/test_coverage_auditor.py` — 覆盖审计测试
  - `tests/test_scanner/test_completeness.py` — 完整性审查测试
  - `src/hyqagent/models/router.py` — StrEnum 修复 + 实例级 ModelSpec 副本（测试隔离）
- [x] **Session 1.20** — Phase 3 收尾: mapper + session
  - `scanner/mapper.py` — 攻击面映射（Phase 3 Task 3）— 端点分类 + 风险评分 + Phase 3 过滤
  - `session/schema.sql` — SQLite 表结构（sessions/findings/checkpoints/belief_history）
  - `session/manager.py` — SessionManager（实现 AuditRepository 协议）
  - `session/belief.py` — 贝叶斯信念系统（bayes_update + EvidenceStrength 预设）
  - `session/checkpoint.py` — CheckpointManager（save/load/list，支持中断续扫）
  - `tests/test_scanner/test_mapper.py` — 19 mapper tests
  - `tests/test_session/test_belief.py` — 16 belief tests
  - `tests/test_session/test_manager.py` — 10 session manager tests
- [x] **质量**: ruff clean, mypy clean (新代码), **1016 tests, 0 failures**
- [x] **文档同步**: progress.md / 新手友好文档状态标记刷新

## 当前指标

| 维度 | 数据 |
|------|------|
| 测试 | **1119** tests, 2 skipped, 0 failures (+57 memory tests) |
| Phase 3 累计新增代码 | **24 文件, +~5,100 行** |
| Phase 4 memory 代码 | **3 文件, +~900 行** (context + crystallizer + retriever) |
| 源码总模块 | **43** 个 (+3: context.py + crystallizer.py + retriever.py) |
| 模型提供商 | **2** (DeepSeek + Anthropic, 同一 Provider 类) |
| 模型层级 | **3** (CHEAP/MID/STRONG) |
| CLI 命令 | **4** (scan/scan --deep/resume/sessions) |
| Nudge 类型 | **3** (TERMINAL/CONTINUE/QUALITY) + 3 内置 StopHook |
| 覆盖盲区缓解 | **3/7** 方案已实现 (CompletenessCritic + 差异覆盖分析 + 盲扫增强) |

## Phase 3 — ✅ 全部完成

Phase 3 全部 8 项任务已全部完成。

## Phase 4: 长任务能力 — 🔵 进行中

- [x] **memory/context.py** — 三区段上下文模型 (固定/长期/工作)
  - ZoneBudget token 预算 + TurnRecord 对话轮次
  - ContextManager: Prompt Cache breakpoints, sliding window, crystallization 触发
  - snapshot/restore 检查点序列化
- [x] **memory/crystallizer.py** — 上下文结晶协议
  - CrystalSummary 结构化摘要 (phase/findings/decisions/questions)
  - 双语正则提取 (中英文 verdict/confidence 匹配)
  - should_crystallize_on_phase_change() 阶段边界自动触发
- [x] **memory/retriever.py** — 混合代码检索
  - search_exact(): ripgrep → Python re fallback
  - search_structural(): tree-sitter AST + function name fast-path
  - search_similar(): difflib.SequenceMatcher dedup (>85%)
  - mark_analyzed / find_related — 分析进度追踪
- [x] **测试**: 1119 tests, 0 failures (+57 memory tests)

### Phase 4 剩余任务（按 DESIGN-IMPLEMENTATION.md §Phase 4）

| # | 任务 | 状态 |
|---|------|------|
| 1 | ~~三区段上下文模型 + Prompt Caching~~ | ✅ 完成 |
| 2 | ~~上下文结晶协议~~ | ✅ 完成 |
| 3 | ~~代码检索 (ripgrep + tree-sitter 混合)~~ | ✅ 完成 |
| 4 | 检查点管理集成 (checkpoint.py 已存在，待接入 scanner) | 🔵 待集成 |
| 5 | 收敛检测: VDR/EC/RWC/VCC/C_hat | 📋 计划 |
| 6 | 补充机制: 反向Sink分析 + 盲扫LLM通道 | 📋 计划 |
| 7 | 对抗性审查 + 饱和扫描 | 📋 计划 |
| 8 | Observability 完整集成 (OTel + LangFuse + Prometheus) | 🔵 cost_tracker 已有 |
| 9 | 信号处理 (SIGTERM/SIGUSR1) + Orchestrator | 📋 计划 |
| 10 | CLI resume 真正实现 (当前是 stub) | 📋 计划 |

| # | 任务 | 状态 | 预计文件 |
|---|------|------|---------|
| 3 | 攻击面映射 (mapper.py) — 端点分类 + 风险优先级 | ✅ 完成 | `scanner/mapper.py` |
| 6 | 会话管理 — SQLite schema + 信念系统 + 检查点 | ✅ 完成 | `session/` 包 (5 文件) |
| 7 | 报告生成集成 | 🔵 部分（ReportGenerator 已存在，未接入 CLI --deep） | `report/` |

## Phase 3: 最终状态 — ✅ 核心完成

Phase 3 全部 8 项任务中，7 项已完成，1 项部分完成（报告生成 CLI 集成）。
新增强化: **Nudge 系统**（借鉴 AutoCVE，3 种 Nudge + 3 个 StopHook）。
下一阶段: **Phase 4 — 长任务能力**（上下文结晶、代码检索、收敛检测、Observability）。

## Phase 4 前置研究: AutoCVE 横向对比 ✅

> 详见 [docs/AUTOCVE-RESEARCH.md](docs/AUTOCVE-RESEARCH.md)

### AutoCVE 是什么
基于多 Agent 编排的自动化代码审计平台（6 Agent: Orchestrator→Recon→Scan→Triage→Finding→Verification），已在 14 个项目中发现 30 个 CVE（最高 CVSS 9.9）。

### 核心发现

| 维度 | HyqAgent | AutoCVE |
|------|---------|---------|
| 技术路线 | 重静态分析（CPG 图），LLM 辅助 | 重 LLM（ReAct Loop），工程师防 LLM 出错 |
| Agent 架构 | 单 Agent + 丰富工具 | 6 Agent 编排 + Orchestrator 去重合并 |
| 分析基础 | CPG 图（AST+CallGraph+DataFlow+CFG） | LLM 直接读代码 + Grep + Semgrep |
| 信念系统 | 贝叶斯更新，7 种 EvidenceStrength | confidence 由 LLM 自行赋值 |
| 覆盖盲区 | CoverageTracker ~179 盲点 | 无此概念 |
| 动态验证 | **无** | Docker 沙箱 PoC 执行 |
| 工程鲁棒性 | 简单调度，一次性 LLM 调用 | 18 种状态转换 + 7 种 Nudge + 自动恢复 |

### AutoCVE 最值得学的三项

1. **Nudge 系统** — 防止 LLM 在证据不足时提前终止（terminal_action_nudge / continue_intent_nudge / stop_hook_blocking / legacy_tool_syntax_nudge / token_budget_continuation / finalizer_recovery）
2. **上下文管理管线** — 8 步精确管线（tool_result_budget → history_snip → microcompact → collapse → auto-compact → system_prompt → user_context → normalize）
3. **动态验证沙箱** — Docker 执行 PoC，验证结果可直接接入 HyqAgent 信念系统（ADVERSARIAL_PASS/FAIL）

### HyqAgent 对且 AutoCVE 没做的

- **CPG 图** — AutoCVE 的 LLM 要反复 Read/Grep 理解代码关系，HyqAgent 一次图查询解决
- **贝叶斯信念** — 多证据融合有数学保证，AutoCVE 的 confidence 是 LLM "感觉"的
- **CoverageTracker** — HyqAgent 知道自己漏了什么，AutoCVE 不知道
- **零成本常见模式** — 3350 条规则覆盖的漏洞不花 token

### Phase 4 行动建议
1. **移植 3 种核心 Nudge** 到现有流水线（不改变架构，最大性价比）
2. **上下文管线 3 步**（tool_result_budget / history_snip / auto_compact），融入 Phase 4 上下文管理
3. **动态验证沙箱** 作为 Phase 5 特性

## 当前阻塞
- 无

## 文档索引

### 项目说明（根目录）
| 文档 | 说明 |
|------|------|
| [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) | 项目白皮书，架构全景，**推荐首次阅读** |
| [DESIGN-IMPLEMENTATION.md](DESIGN-IMPLEMENTATION.md) | 12 章实现蓝图，接口/数据流/阶段划分，**开发时最常用** |
| [AGENTS.md](AGENTS.md) | AI Agent 项目文档标准 |
| [progress.md](progress.md) | 开发进度追踪，**每次 Session 开始必读** ← 你在这 |

### 新手入门
| 文档 | 说明 |
|------|------|
| [docs/新手友好-HyqAgent架构详解.md](docs/新手友好-HyqAgent架构详解.md) | 零基础可读的架构讲解，含术语速查表和五阶段流程图 |

### 开发过程文档（`dev-docs/`）
每次 Session 的详细实现记录，中文命名，含目标/产出/实现过程/问题修复/质量门禁/设计反思。

### 深度参考（docs/ 目录）
| 文档 | 说明 |
|------|------|
| [docs/README.md](docs/README.md) | 文档目录总索引 |
| [docs/RESEARCH.md](docs/RESEARCH.md) | 20+论文、15+系统对比的原始研究 |
| [docs/PLAN.md](docs/PLAN.md) | 原始设计方案（CPG/扫描流水线/Model Router） |
| [docs/COVERAGE-GAP-ANALYSIS.md](docs/COVERAGE-GAP-ANALYSIS.md) | 覆盖盲区分析 + 七种缓解方案 |
| [docs/severity_based_vulnerability_mining_framework.md](docs/severity_based_vulnerability_mining_framework.md) | 五级危害 × 七层挖掘阶梯 |
| [docs/detection_matrix.json](docs/detection_matrix.json) | 200 项 ASVS 对齐的结构化检测项 |
| [docs/WEB-VULN-FULL-MATRIX.md](docs/WEB-VULN-FULL-MATRIX.md) | 180+ 漏洞类型全量覆盖矩阵 |
| [docs/LONG-RUNNING-AGENT-ARCHITECTURE.md](docs/LONG-RUNNING-AGENT-ARCHITECTURE.md) | 长任务持续运行架构 |
| [docs/IMPLEMENTATION-GUIDE.md](docs/IMPLEMENTATION-GUIDE.md) | 实现前必读（关键风险 + 多 Agent 决策） |
| [docs/DEVELOPMENT-STANDARDS.md](docs/DEVELOPMENT-STANDARDS.md) | 生产级开发规范 |
| [docs/CLAUDE-CODE-DEVELOPMENT-GUIDE.md](docs/CLAUDE-CODE-DEVELOPMENT-GUIDE.md) | 用 Claude Code 开发的实操指南 |
| [docs/CODE-AUDIT-SKILL-ANALYSIS.md](docs/CODE-AUDIT-SKILL-ANALYSIS.md) | 业界 code-audit skill 方案的深度分析与改进建议 |
| [docs/AUTOCVE-RESEARCH.md](docs/AUTOCVE-RESEARCH.md) | AutoCVE 架构深度解析 + HyqAgent 横向对比 |
