# HyqAgent 开发进度

> 上次更新: Session 1.5 完成后

## Phase 1: CPG Foundation — 进行中
- [x] **Session 1.1** — 项目骨架初始化 (commit: 4ba65f7)
  - pyproject.toml, src-layout, .env, pre-commit
  - CLAUDE.md, AGENTS.md, README.md, progress.md
  - core/protocols.py (6个核心协议), core/state.py, core/events.py (12种事件类型)
  - docs/ 目录整理 (10份参考文档移入，docs/README.md 索引)
- [x] **Session 1.2** — tree-sitter 安装和单文件解析 (cpg/parser.py)
  - 安装 tree-sitter 0.26.0 + Python/JS/Java 语法包
  - 实现 `cpg/parser.py` — Parser 类支持 parse_file/parse_code
  - 支持 extract_functions/extract_classes/extract_imports（三种语言）
  - 44 个 pytest 测试全部通过
  - ruff/mypy 零错误
- [x] **Session 1.3** — AST 遍历器 (cpg/traversal.py + 59 tests)
  - Traverser 类: TreeCursor 实现的 DFS 前序/后序遍历
  - 节点类型过滤、named_only 模式、子树遍历
  - 导航工具: get_children/parent/ancestors/ancestor_of_type
  - 工具方法: find_first/find_all/count/node_type_path
  - 103 个 pytest 测试全部通过，ruff/mypy 零错误
- [x] **Session 1.4** — 单文件调用图 (cpg/callgraph.py + 69 tests)
  - SingleFileCallGraph 类: 支持 Python/JS/Java 三种语言
  - 调用边解析（简单调用/方法调用/递归自环/嵌套函数）
  - 已解析/未解析分类 + UnresolvedCall 供跨文件使用
  - 查询接口: get_callees/get_callers/has_edge
  - 172 个 pytest 测试全部通过，ruff/mypy 零错误
- [x] **Session 1.5** — 可扩展性重构 + 跨文件调用图 (193 tests)
  - ⭐ **LanguageProvider 策略模式**: parser.py (671→260行) + callgraph.py (382→260行)
  - 新增 `cpg/languages/` 包: base.py + python/js/java Adaptor
  - 新增 `cpg/types.py` — 共享数据类，打破循环依赖
  - 添加新语言 = 1个文件 + 1行注册，核心模块零改动
  - **CallGraphBuilder** 跨文件调用图: 支持 add_directory/resolve_imports/build_calls
  - 导入解析: 相对导入 + 绝对导入
  - 193 个 pytest 测试全部通过，ruff/mypy 零错误
- [x] **🔧 基础加固** — 边界测试 + 性能基线 + 契约验证 (240 tests)
  - 新增 39 个边界测试（语法错误/Unicode/空输入/深层嵌套/互递归/循环导入等）
  - 新增 8 个性能基准（4 benchmark + 4 回归断言，CI 默认跳过）
  - `__post_init__` 拒绝空 name/无效行号；`get_provider` 统一 ValueError
  - `_languages` 缓存泄漏检测；`_validate()` Provider 契约检查
  - 240 个 pytest 测试全部通过，ruff/mypy 零错误
- [ ] Session 1.6 — 数据流图构建
- [ ] Session 1.7 — CPG 查询接口 (cpg/query.py)
- [ ] Session 1.8 — Flask 框架提取器
- [ ] Session 1.9 — 端到端 CPG 测试（用已知 CVE 项目验证）
- [ ] Session 1.10-1.12 — 边界情况修复

## Phase 2-5: 待开始

## 跨 Session 改进追踪（来自 code-audit skill 分析）

> 来源：`docs/CODE-AUDIT-SKILL-ANALYSIS.md`（2026-08-05）
> 这些是分析文章中提炼的改进项，按优先级融入后续 Session。

### P0 — 立即落地（高影响、低复杂度）
- [ ] **CPG 查询缓存** — `cpg/query.py` 实现时加基于查询哈希的缓存层，防同一查询在不同假设中重复执行（~40行，Session 1.7 顺手做）
- [ ] **跨轮覆盖状态追踪** — `AuditState` 添加 `files_read`/`grep_done`/`coverage_gaps`/`hotspots` 字段（~60行，Session 1.5 后做）
- [ ] **扫描前能力声明** — Orchestrator 启动时读取 detection_matrix.json + taint_rules.yaml，计算并输出"可检测/部分检测/无法检测"清单（~50行，Session 2.1 CLI 初始化时做）

### P1 — 中期规划
- [ ] **覆盖率自检阶段** — 在 Phase 3/Phase 4 之间加入 Coverage Self-Check，用 detection_matrix.json 做结构化查漏，输出 GAPS + HOTSPOTS（Session 3.4 附近）
- [ ] **CPG 驱动的置信度自动分级** — `Validator.validate_deterministic()` 中加硬门禁：CPG 存在完整 source→sink 路径 → confidence≥0.7；不存在 → confidence≤0.3 自动降级（~30行，Session 2.3 Validator 实现时）
- [ ] **攻击链分析模块** — CPG 图中找"低权限入口→权限提升→高影响 sink"路径，用中等模型做组合分析（Session 3.4 附近）
- [ ] **结构化截断防御** — 所有 LLM 输出加 `---FINDING_START---` / `---FINDING_END---` 哨兵标记（Session 3.x LLM 集成时）
- [ ] **Completeness Critic 结构化提示词** — 将 code-audit skill 的 10 维度转化为 Critic 的提问模板（Session 3.4）

### P2 — 长期参考
- [ ] 多扫描模式（Quick/Quick-Diff/Standard/Deep）
- [ ] Agent 合约框架（在 protocols.py 中预留接口）
- [ ] 多轮增量扫描（R2 由 GAPS 驱动，不重复 R1 工作）

## 当前阻塞
- 无

> 上次更新: 基础加固完成后 (2026-08-05)

## 当前状态
- **240 个测试**，ruff/mypy 零错误
- **12 个源模块**，~2,500 行
- **下一个**: Session 1.6 — 数据流图构建

## 下次 Session 目标
- **Session 1.6**: 实现数据流图构建 `cpg/dataflow.py`
  - def-use chain 分析 + 跨函数数据流追踪 + 基础污点传播
  - 产出标准: `DataFlowBuilder` 支持 `build_def_use_chains()` + `trace_cross_function()` + `propagate_taint()`

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
