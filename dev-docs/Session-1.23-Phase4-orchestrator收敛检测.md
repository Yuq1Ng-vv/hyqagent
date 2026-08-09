# Session 1.23 — Phase 4 Orchestrator + 收敛检测 + 断点续扫

## 目标
将 Phase 4 零散任务（检查点集成、收敛检测、信号处理、CLI resume）构建为一个内聚的 **中央编排器（Orchestrator）**，替换 `cli.py` 中 ~250 行的内联管道，实现真正的断点续扫和收敛判断。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `src/hyqagent/scanner/convergence.py` | ~280 | 五指标收敛检测（VDR/EC/RWC/VCC/C_hat） |
| 新建 | `src/hyqagent/scanner/orchestrator.py` | ~1000 | 中央编排器——8 阶段管道 + 检查点 + 信号处理 + resume |
| 修改 | `src/hyqagent/session/checkpoint.py` | +25 | 新增 `delete_old()` 清理旧检查点 |
| 修改 | `src/hyqagent/api/cli.py` | ~350→~150 | `_run_deep_audit()` 委托给 Orchestrator；`resume` 命令真实实现 |
| 新建 | `tests/test_scanner/test_convergence.py` | ~430 | 34 tests — 五指标全维度覆盖 |
| 新建 | `tests/test_scanner/test_orchestrator.py` | ~440 | 30 tests — 状态序列化/Phase 执行/检查点/Resume/边界条件 |

## 实现过程

### 1. `scanner/convergence.py` — 多指标收敛检测

完整实现 LONG-RUNNING-AGENT-ARCHITECTURE.md §7 的五项收敛指标：

| 指标 | 含义 | 阈值 | 实现 |
|------|------|------|------|
| VDR | 漏洞发现率 | 最近 3 轮 0 个新高危 | 滚动窗口 |
| EC | 端点覆盖率 | ≥95% | `endpoints_analyzed / total_endpoints` |
| RWC | 风险加权覆盖 | ≥98% | `risk_score_analyzed / risk_score_total` |
| VCC | 漏洞类别覆盖 | ≥90% | `cwe_classes_covered / total_cwe_classes` |
| C_hat | Chao2 完整性估计 | ≥0.85 | `1 - f1²/(2*f2)`（f1=单视角, f2=双视角发现数）|

关键类：
- `ConvergenceThresholds` — 可配置阈值，硬上限 `max_rounds=5`
- `ConvergenceSnapshot` — 单轮快照，包含两视角重叠数据
- `ConvergenceMonitor` — 累加快照 → 汇聚评估，`update()` 返回 `ConvergenceReport`
- 推荐策略：全部通过 → `"converged"`；达上限未通过 → `"escalate_to_human"`；否则 → `"continue"`

**修复**：原来的 escalate 逻辑使用硬编码 `MAX_ROUNDS=5`（类常量），改为使用 `self._thresholds.max_rounds`，使自定义阈值真正生效。同时修复了 `orchestrator.py:433` 的相同问题。

### 2. `scanner/orchestrator.py` — 中央编排器

核心架构：
```
Orchestrator
├── owns: SessionManager, CheckpointManager, CostTracker, ConvergenceMonitor
├── receives via DI: CPGQuery, DeterministicScanner, HypothesisGenerator, Validator, ...
├── run(project_path, language) → AuditReport
├── resume(session_id) → AuditReport
└── signals: SIGTERM → _emergency_checkpoint(); SIGUSR1 → _manual_checkpoint()
```

**PhaseName(StrEnum)** — 固定 8 阶段枚举：
`CPG_BUILD → DETERMINISTIC_SCAN → ATTACK_SURFACE_MAP → HYPOTHESIS_GEN → VALIDATION → COVERAGE_AUDIT → COMPLETENESS_CRITIC → CONVERGENCE_CHECK`

收敛循环（`_CONVERGE_BODY`）在 `HYPOTHESIS_GEN → ... → CONVERGENCE_CHECK` 重复最多 5 轮。

**PipelineState** — 可序列化快照：
- `to_dict()` / `from_dict()` — JSON-safe 往返
- `_state_to_checkpoint()` / `_checkpoint_to_state()` — Checkpoint ↔ PipelineState 转换
- **检查点触发**：Phase 边界（事件驱动）+ SIGTERM/SIGUSR1（信号驱动）

**AuditReport** — 统一输出，聚合所有阶段结果（findings, hypotheses, validations, annotated_paths, coverage_audit, completeness_review, convergence, cost_summary）

**依赖注入模型**：
- 构造器接受所有依赖，如未注入则 `_ensure_scanner_modules()` 自动构建
- 支持真实运行（CLI 简洁调用）和测试（Mock 注入）两种模式
- Framework 提取器通过 `hyqagent.cpg.parser.Parser` 而非裸 Path 构建（修复 mypy 类型错误）
- DeterministicScanner 的 graph 参数使用 `nx.MultiDiGraph()` 作为默认值替代 None（修复 mypy 类型错误）

**信号处理**：
- `SIGTERM` → 设置 `_shutdown_requested`，紧急保存检查点，抛 `_ShutdownSignal` 中断管道
- `SIGUSR1` → 手动触发检查点保存，继续执行

### 3. `session/checkpoint.py` — delete_old()

新增 `CheckpointManager.delete_old(session_id, keep_latest=5)` 方法：
- 保留最近 N 个检查点，删除更早的
- 在 Orchestrator 中每次保存检查点后自动调用

### 4. `api/cli.py` — 重构

- `_run_deep_audit()`: ~250 行内联管道 → ~30 行委托给 `Orchestrator.run()`
- `resume` 命令: 从 SQLite 加载 session + checkpoint → `Orchestrator.resume()` → `ReportGenerator`
- `sessions list`: JSON 文件枚举 → `SessionManager.list_sessions()` SQLite 查询
- 删除函数: `_understand_project()`, `_run_phase3_hypotheses()`, `_save_session()`
- 新增: `_output_report()` 辅助函数
- 保留: `_run_scan()`, `_build_cpg_query()`, `_format_findings_summary()`, `_has_llm_keys()`, `_find_meta_files()`, `_detect_language()`, `_try_load_extractor()` — 仍用于 `--quick` 模式

### 5. 测试

**test_convergence.py** (34 tests):
- `TestConvergenceSnapshot`: 默认值、字段可设置
- `TestConvergenceThresholds`: 默认阈值、自定义阈值
- `TestVDR`: 零新发现收敛、新发现重置、不足窗口、自定义窗口
- `TestEC`: 超过/低于/等于阈值、零分母
- `TestRWC`: 超过/低于阈值、零总分
- `TestVCC`: 全覆盖/部分覆盖/空目标
- `TestCHat`: 完全重叠/完全不重叠/部分重叠/高重叠（C_hat≈0.833）/空视角
- `TestConvergenceReport`: 全收敛/未收敛/推荐继续/推荐escalate/推荐收敛/摘要字符串
- `TestMonitorLifecycle`: 轮次计数/最新快照/历史/重置/空监控器未收敛

**test_orchestrator.py** (30 tests):
- `TestPipelineState`: 默认值/序列化往返/from_dict（无phase/有phase str）
- `TestCheckpointConversion`: state→checkpoint/checkpoint→state/完整往返
- `TestOrchestratorInit`: 创建/db_path/注入依赖/默认路径
- `TestPhaseExecution`: PhaseName枚举/已完成的Phase跳过/run创建session/resume报错（无session/无checkpoint）
- `TestCheckpointIntegration`: 保存检查点/紧急检查点/清理旧检查点
- `TestAuditReport`: 默认值/带数据
- `TestEdgeCases`: 空文件列表/恢复相同状态/静默模式/session_id生成/文件发现（目录/单文件/错误语言）
- `TestOrchestratorConvergence`: 高危判断/发现摘要（有数据/空）

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `test_all_converged` 断言 `converged is False` 失败 | 测试写反了——5轮完美覆盖后确实应收敛 | 改为 `assert report.converged is True` |
| `test_to_dict_roundtrip` 报 `unexpected keyword argument 'find_count'` | PipelineState 字段名是 `finding_count` 不是 `find_count` | 测试中改用 `finding_count` |
| `test_recommendation_escalate` 返回 `"continue"` 而非 `"escalate_to_human"` | 代码用硬编码 `MAX_ROUNDS=5` 而非 `self._thresholds.max_rounds` | 改为 `self._thresholds.max_rounds`，同步修复 orchestrator 引用 |
| mypy: Framework extractors 接收 Path 但期望 Parser | `_ensure_scanner_modules()` 错误地将 `base_dir` (Path) 传给提取器 | 创建 `hyqagent.cpg.parser.Parser(languages=[language])` 传入 |
| mypy: DeterministicScanner graph 参数 Optional vs 非 Optional | `self._query._graph` 可能为 None | 用 `getattr(self._query, '_graph', None) or nx.MultiDiGraph()` 兜底，添加 `networkx` import |
| ruff: cli.py 残留未使用 import（json, uuid, UTC, datetime） | 删除内联管道后这些 import 不再使用 | 移除未使用的 import 和变量 `config` |
| ruff: 多行超 100 字符 | 长字典/函数调用 | 提取变量/换行格式化 |

## 质量门禁

### ruff
```
$ uv run ruff check --select E,F src/hyqagent/scanner/orchestrator.py src/hyqagent/scanner/convergence.py src/hyqagent/api/cli.py
All checks passed!
```
- 仅剩 D/S/RUF/N 风格建议（docstring、assert、命名约定等），无阻塞性错误

### mypy
```
$ uv run mypy src/hyqagent/scanner/orchestrator.py src/hyqagent/scanner/convergence.py src/hyqagent/session/checkpoint.py
Success: no issues found in 3 source files
```

### pytest
```
64 passed — tests/test_scanner/test_convergence.py + tests/test_scanner/test_orchestrator.py
1183 passed, 2 skipped, 5 warnings — 全量回归（排除 pre-existing manual smoke tests cfg fixture 缺失）
```

## 设计反思

### 做得好
1. **收敛检测独立可测** — `ConvergenceMonitor` 是纯函数式（no I/O, no async），30+ 测试秒级跑完
2. **DIP 贯彻** — Orchestrator 构造器接受全部依赖，自动构建仅作兜底；CLI 干净，测试可控
3. **Phase 边界恢复** — 明确决策不做 mid-phase resume，简化了序列化且避免了一致性问题
4. **类型安全** — `PhaseName(StrEnum)` 替代裸字符串，PipelineState 序列化往返有完整测试覆盖

### 可改进
1. Mid-phase resume 能力 — 当前检查点绑定 Phase 边界，如果大项目中 HYPOTHESIS_GEN 中途中断，会丢失部分进度
2. `_ensure_scanner_modules()` 仍偏长（~200行），可拆分为语言专属工厂函数
3. 信号处理集成测试需要在真实 async event loop 中验证（当前仅单元测试覆盖）

## 下步衔接

Phase 4 剩余任务（Task 6-8）：
- **Task 6: 对抗性审查流程** — 两角色交叉验证（generator vs skeptic），要求: 每个 hypothesis 至少有 1 个独立模型的确认
- **Task 7: 饱和扫描** — 参数化变异，同一漏洞模式用不同参数组合重新测试（覆盖 SSRF、XSS、SQLi 的子类型矩阵）
- **Task 8: NudgeLoop 实际跑通** — 目前 NudgeLoop 已创建并注入，但尚未在真实 LLM 调用流中验证（需要端到端集成测试）

建议下次 Session 优先 Task 6（对抗性审查），因为它直接强化"提出者≠裁决者"的核心设计哲学。
