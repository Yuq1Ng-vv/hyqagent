# Session 1.20 — Phase 3 收尾：攻击面映射 + 会话管理

## 目标

完成 Phase 3（DESIGN-IMPLEMENTATION.md §3.3）剩余两项核心任务：
- Task 3: `scanner/mapper.py` — 攻击面映射（端点分类 + 风险优先级）
- Task 6: `session/` — 会话管理（SQLite + 信念系统 + 检查点）

以及三份文档的状态同步更新。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `src/hyqagent/scanner/mapper.py` | ~340 | 攻击面映射器 — 确定性端点风险评分 |
| 新建 | `src/hyqagent/session/schema.sql` | ~70 | SQLite DDL — 4 表 5 索引 |
| 新建 | `src/hyqagent/session/manager.py` | ~370 | SessionManager — 实现 AuditRepository 协议 |
| 新建 | `src/hyqagent/session/belief.py` | ~115 | 贝叶斯信念系统 + EvidenceStrength 预设 |
| 新建 | `src/hyqagent/session/checkpoint.py` | ~145 | CheckpointManager — 中断续扫 |
| 更新 | `src/hyqagent/session/__init__.py` | +14 | 重新导出 session/ 公共 API |
| 新建 | `tests/test_scanner/test_mapper.py` | ~170 | 19 mapper tests |
| 新建 | `tests/test_session/test_belief.py` | ~100 | 16 belief tests |
| 新建 | `tests/test_session/test_manager.py` | ~120 | 10 session manager tests |
| 修改 | `progress.md` | — | Phase 3 最终状态、指标、测试数更新 |
| 修改 | `docs/新手友好-HyqAgent架构详解.md` | — | session/ + mapper 标记 🟢 |

## 实现过程

### 1. 攻击面映射 (mapper.py)

这是扫描流水线 Phase 2 的核心组件，之前被跳过。实现方式：

**评分模型**（纯确定性，零 LLM 成本）：
- HTTP 方法权重：DELETE=3, PUT/PATCH/POST=2, GET/HEAD=0
- 参数来源权重：file=4, body=2, form/query=1, path/header=0
- Auth 惩罚：无认证 + 状态变更方法 → +3；无认证 + GET → +1；有认证 → -1
- 路由启发式：admin/config 模式 +2，file/upload 模式 +3

**7 种端点分类**：
```
AUTH_BYPASS    — 认证端点无 guard / 状态变更无认证
DATA_MUTATION  — POST/PUT/PATCH/DELETE（有认证）
FILE_UPLOAD    — 文件参数 / upload 路由模式
ADMIN_EXPOSED  — admin/dashboard/config/actuator 路由
SENSITIVE_READ — GET 返回敏感数据
PUBLIC_READ    — GET 无认证，低敏感
CONFIG_LEAK    — debug/trace/health/metrics/env 端点
```

**过滤机制**：`filter_for_phase3()` 按高→中→低三级桶优先级返回 top-N，确保 Phase 3 LLM 预算集中到高风险端点。

### 2. 会话管理 (session/)

SQLite 方案选择理由：项目哲学为"async for I/O, sync for CPU"——SQLite 是本地文件 I/O，用 `asyncio.to_thread()` 包装同步调用。

**schema.sql 四表设计**：
- `sessions` — 审计会话元数据（project_path/language/status）
- `findings` — 漏洞发现（vuln_type/cwe_id/severity/confidence/status/source/sink/evidence）
- `checkpoints` — 阶段快照（phase/state_json/file_count/cost_total）
- `belief_history` — 贝叶斯更新链（prior/likelihood/posterior/evidence_summary）

**SessionManager** 实现 `core.protocols.AuditRepository`，方法：
- `save_session`/`get_session`/`list_sessions`/`update_session_status`
- `save_finding`/`get_findings`（支持 severity 过滤）/`update_hypothesis_status`
- `record_belief_update` — 审计链不可变记录

**Belief 系统**：贝叶斯公式 `P(H|E) = P(E|H)P(H) / [P(E|H)P(H) + P(E|¬H)(1-P(H))]`，7 种 EvidenceStrength 预校准：
```
L1_CONFIRMED: P(E|H)=0.95, P(E|¬H)=0.10  → 强支持
L1_REJECTED:  P(E|H)=0.05, P(E|¬H)=0.90  → 强否定
L2_CONFIRMED: P(E|H)=0.90, P(E|¬H)=0.05  → 强支持
L2_REJECTED:  P(E|H)=0.10, P(E|¬H)=0.85  → 强否定
ADVERSARIAL_PASS: P(E|H)=0.85, P(E|¬H)=0.20
ADVERSARIAL_FAIL: P(E|H)=0.15, P(E|¬H)=0.80
```

置信度 0.5 + L1_CONFIRMED → 0.905，再 + L2_CONFIRMED → 0.997（三次确认即近乎确定）。

**CheckpointManager**：`save`/`load_latest`/`list_all`，每次 checkpoint 记录当前 phase + state blob + 计数快照。

### 3. 文档同步

发现三套 "Phase" 定义在混用（扫描流水线/项目开发/PLAN.md 原始设计），文档更新明确区分：
- 扫描 Phase 2（攻击面映射）→ 项目开发 Phase 3 Task 3
- 扫描 Phase 4（分层验证）→ 已实现为 validator.py
- 项目 Phase 4（长任务能力）→ 下一阶段

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| `_row_to_hypothesis` 使用 `row.get("remediation")` mypy 报错 | `sqlite3.Row` 不支持 `.get()` 方法 | 改为 `row["remediation"]`（列总是存在，有 DEFAULT ''） |
| RUF002: × (multiplication sign) 在 docstring 中 | 数学公式用 × 是 Unicode 歧义字符 | 全部替换为 `x` |
| `filter_for_phase3` 过滤低风险端点时忽略它们 | 原实现只返回 high + medium 桶 | 改为三桶依次填充，低风险在预算剩余时也纳入 |
| `datetime.now(timezone.utc)` UP017 | Python 3.12 可用 `datetime.UTC` | ruff --fix 自动转换 |
| `VulnerabilityHypothesis` 字段名不同于 `Hypothesis` | protocol 用 `source: CodeLocation` 而非 `source_location: str` | SessionManager 内部做 CodeLocation↔"file:line" 双向转换 |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| `uv run pytest` | **1016 passed, 2 skipped, 0 failures** |
| `uv run ruff check` (新文件) | All checks passed |
| `uv run mypy` (新文件) | Success: no issues found |

## 设计反思

### 做得好的
- **贝叶斯信念系统**是 Phase 4 长任务能力的前置依赖——多种证据源（L1/L2/Adversarial）需要统一的数学框架融合置信度。此实现简洁且可扩展。
- **mapper.py 纯确定性**——符合"能不花钱就不花钱"的核心哲学，Phase 3 LLM 预算集中到 mapper 筛选后的高风险端点。
- **session/ 模块化**——schema.sql 独立于代码，可被 SQLite CLI 直接执行；manager/belief/checkpoint 各自独立但共享同一数据库。

### 可改进的
- SessionManager 目前直接操作 sqlite3，未使用连接池。对于多会话并发场景，可考虑 aiosqlite。
- mapper 的权重表是硬编码常量——未来可从配置文件加载，允许不同项目类型（API 优先 vs 全栈）定制风险模型。
- EvidenceStrength 的似然比是经验值，需要在实际使用中根据误报/漏报数据校准。

## 下步衔接

Phase 3 全部 8 项任务中，7 项完成，1 项部分完成（报告生成 CLI 集成）。下阶段：**Phase 4 — 长任务能力**。

Phase 4 前置条件已就绪：
- ✅ session/ — 会话持久化 + 检查点（Phase 4 的存储基础）
- ✅ belief/ — 贝叶斯更新（收敛检测的置信度框架）
- ✅ mapper.py — 端点过滤（Phase 4 的上下文管理可基于端点优先级调度）

Phase 4 核心任务（DESIGN-IMPLEMENTATION.md §4）：
1. 三区段上下文模型 + 上下文结晶
2. 代码检索（向量化 + 混合检索）
3. 收敛检测（VDR/EC/RWC/VCC/C_hat 多指标）
4. Observability 完整集成
5. 对抗性审查 + 饱和扫描

另外用户提到的 [AutoCVE](https://github.com/larlarua/AutoCVE)（已初步研究）可在下个 Session 交叉对比——它在多 Agent 协作、ReAct Loop、动态验证等方面有可借鉴之处。
