# 使用 Claude Code 开发 HyqAgent — 实操指南

> 目标：从11份设计文档出发，用Claude Code逐步构建完整的白盒代码审计Agent系统

---

## 目录

1. [开始之前：理解Claude Code的工作方式](#一开始之前理解claude-code的工作方式)
2. [第一步：初始化项目骨架和 CLAUDE.md](#二第一步初始化项目骨架和-claudemd)
3. [第二步：按Phase拆解开发Session](#三第二步按phase拆解开发session)
4. [第三步：每个Session的标准工作流](#四第三步每个session的标准工作流)
5. [第四步：保持Session之间的连续性](#五第四步保持session之间的连续性)
6. [第五步：常见问题和应对策略](#六第五步常见问题和应对策略)
7. [完整开发路线图（12-15周）](#七完整开发路线图12-15周)
8. [附录：Session命令速查](#八附录session命令速查)

---

## 一、开始之前：理解Claude Code的工作方式

Claude Code是Anthropic的CLI开发工具，它有几个关键特性决定了我们怎么用它做大型项目开发：

### 能力
- **读写文件**：可以直接创建、编辑项目中的所有文件
- **执行命令**：可以运行 `pytest`、`uv sync`、`git` 等任何shell命令
- **Web搜索**：可以查找最新的库版本、API文档、常见问题的解决方案
- **多Agent并行**：可以用 `Workflow` 或 `Agent` 工具并行处理独立任务
- **规划模式** (`EnterPlanMode`)：对于复杂改动，会先出方案再执行

### 约束
- **无状态**：每次新会话不会自动记住上次做了什么（除非有 CLAUDE.md 和记忆文件）
- **上下文有限**：约200K tokens，长会话会触发摘要压缩
- **需要明确指令**：不会主动推进项目，需要你给出清晰的目标

### 核心策略

**把 Claude Code 当作一个"有记忆的高级开发者"**：
1. 每次会话聚焦一个可完成的目标
2. 用 CLAUDE.md 和进度文件保持跨会话的上下文
3. 由你（人类）负责项目方向和架构决策，Claude Code负责执行

---

## 二、第一步：初始化项目骨架和 CLAUDE.md

### 2.1 创建项目骨架（第一个Session，约30分钟）

进入项目目录后，告诉 Claude Code：

```
我正在开始实现 HyqAgent 白盒代码审计工具。请阅读 /root/hyqagent/DESIGN-IMPLEMENTATION.md
的第一章，然后执行以下操作：

1. 创建 pyproject.toml，配置 uv 构建系统
2. 创建 src/hyqagent/ 目录结构（按照文档中的 src-layout）
3. 创建 .env.example 和 .pre-commit-config.yaml
4. 创建 AGENTS.md（面向AI Agent的项目文档）

不要写任何业务代码，只搭建项目骨架。
```

**产出**：pyproject.toml、完整目录树、.env.example、.pre-commit-config.yaml、AGENTS.md

### 2.2 创建项目的 CLAUDE.md（同一个Session）

CLAUDE.md 是 Claude Code 的"长期记忆文件"——每次新会话启动时自动加载。它告诉 Claude Code 这个项目是什么、怎么构建、怎么测试、代码风格是什么。

在项目根目录创建 `CLAUDE.md`，内容应该包括：

```markdown
# CLAUDE.md — HyqAgent 项目开发指南

## 项目概述
HyqAgent 是一个基于CPG+多模型级联的白盒代码审计CLI工具。
优先支持Python/JavaScript/Java的Web应用漏洞检测（SQL注入、XSS、SSRF、IDOR等）。

## 构建与测试命令
- 安装依赖: `uv sync --dev`
- 运行所有测试: `uv run pytest`
- 仅单元测试(快速): `uv run pytest tests/unit/ -x`
- 仅Eval测试: `uv run pytest tests/eval/ -m eval`
- Lint检查: `uv run ruff check . && uv run ruff format --check .`
- 类型检查: `uv run mypy src/`

## 架构
- `src/hyqagent/core/protocols.py` — 核心抽象（ToolResult, BaseTool, CpgAnalyzer, AuditRepository）
- `src/hyqagent/tools/` — 可插拔分析工具（CPG、扫描、报告）
- `src/hyqagent/agents/` — LangGraph Agent定义
- `src/hyqagent/session/` — SQLite持久化+信念系统
- `src/hyqagent/observability/` — 日志+追踪+指标

## 代码风格
- Python 3.12+, 严格Type Hints (mypy --strict)
- 配置: pydantic-settings + .env
- 日志: structlog, 事件名用snake_case
- 异步: I/O操作用async (LLM调用、子进程), CPU密集型用sync+asyncio.to_thread()
- 测试: pytest, 确定性组件精确断言, 概率性组件统计阈值(多次重跑)

## 安全约束
- API Key从环境变量读取，永不硬编码
- 日志不输出完整源码
- 被审计代码不执行，只读取分析

## 关键设计原则
- 确定性先行，LLM后行
- 提出者≠裁决者（不同模型/上下文做假设和验证）
- 单一职责：每个模块只有一个变更理由
- 依赖倒置：高层模块依赖协议，不依赖具体实现
```

**为什么这一步至关重要**：CLAUDE.md 是每次新会话启动时 Claude Code 首先读取的文件。一份好的 CLAUDE.md = 省掉每次会话前 10 分钟的项目背景铺垫。

### 2.3 初始化 Git 仓库

```
请初始化 git 仓库，创建 .gitignore（排除 .env、__pycache__、*.pyc、审计缓存等），
并做初始提交。
```

---

## 三、第二步：按Phase拆解开发Session

整个开发按照 `DESIGN-IMPLEMENTATION.md` 第十章划分的5个Phase进行。每个Phase包含多个Session。

### 开发Session的分层策略

```
   Session粒度： 每个Session聚焦一个可独立验证的目标
   时长：        每次Session 30分钟-2小时（Claude Code单次会话的舒适区间）
   验证：        每个Session结束时必须通过编译/测试/手动验证
   提交：        每个Session结束时做一次 git commit
```

### Phase 1：CPG Foundation（目标3-4周 | 8-12个Session）

决定做什么之前，先看 `IMPLEMENTATION-GUIDE.md` 的 P0/P1 风险清单：**跨文件调用图是最大风险**。

```
Session 1.1  安装tree-sitter + Python/JS/Java语法 → 解析单个Python文件成功
Session 1.2  实现AST遍历器 → 能提取函数/类/变量/导入定义
Session 1.3  构建调用图（单文件内）→ 相同文件的函数调用能被追踪
Session 1.4  构建调用图（跨文件）→ 解析import，连接跨文件的calls边
Session 1.5  构架数据流图 → def-use chain，跨函数数据流
Session 1.6  实现CPGQuery接口 → find_path, find_sources, find_sinks可用
Session 1.7  实现Flask框架提取器 → 能从路由文件提取所有HTTP端点
Session 1.8  编写taint_rules.yaml + sanitizers.yaml → 配置化的source/sink管理
Session 1.9  端到端测试 → 对已知CVE项目（如VulnPy）做CPG分析
Session 1.10-1.12  修复跨文件调用图的边界情况（反射、动态import等P0风险）
```

**每个Session的标准开场**：

```
继续开发 Phase 1 的 Session X.X。上一个 Session 我们完成了 [具体产出]。
这次的目标是 [具体目标]。相关设计文档是 DESIGN-IMPLEMENTATION.md 第X章。
先读取上一次提交的变更（git diff HEAD~1），然后继续。
```

### Phase 2：确定性扫描器（目标1-2周 | 4-6个Session）

```
Session 2.1  实现正则规则引擎 → secrets.yaml/dangerous_calls.yaml规则加载和执行
Session 2.2  实现CPG污点追踪 → source→sink路径自动发现，检查消毒
Session 2.3  实现CLI v0 → hyqagent scan --quick 基本可用
Session 2.4  测试和调优 → 用WebGoat/DVWA验证检出率和误报率
Session 2.5-2.6  处理边界情况 → 跨模块路径、间接source识别
```

### Phase 3：LLM集成（目标2-3周 | 6-9个Session）

```
Session 3.1  实现Model Router → 三档模型选择+成本追踪
Session 3.2  实现Anthropic provider → API调用的重试+熔断
Session 3.3  实现Phase 2攻击面映射 → 便宜模型分类端点
Session 3.4  实现CPG切片提示构建 → 从CPG提取精确代码片段
Session 3.5  实现Phase 3假设生成 → 结构化漏洞假设输出
Session 3.6  实现Phase 4 L1确定性验证 → CPG路径确认
Session 3.7  实现Phase 4 L2 LLM验证 → 强模型验证
Session 3.8  实现会话管理器 → SQLite持久化
Session 3.9  端到端集成 → standard模式完整流程可用
```

### Phase 4：长任务能力（目标2-3周 | 6-9个Session）

```
Session 4.1  实现上下文管理器 → 三区段模型
Session 4.2  实现上下文结晶 → 轮次摘要
Session 4.3  实现检查点保存/恢复 → 中断后恢复
Session 4.4  实现代码向量检索 → Qdrant/ChromaDB集成
Session 4.5  实现增量分析 → Git diff驱动的部分重扫
Session 4.6  实现收敛检测 → VDR/EC/RWC/VCC指标
Session 4.7-4.9  长任务端到端测试 → 模拟数小时运行的稳定性
```

### Phase 5：质量与发布（目标2-3周 | 6-9个Session）

```
Session 5.1  实现可观测性 → structlog + Prometheus指标
Session 5.2  构建Golden Dataset → 25-30个核心测试case
Session 5.3  实现Eval框架 → DeepEval集成
Session 5.4  编写单元测试 → 确定性组件覆盖>80%
Session 5.5  编写集成测试 → mock LLM的端到端流程
Session 5.6  实现CLI完整命令 → resume/sessions/report/config
Session 5.7  性能优化 → CPG缓存、批量LLM调用
Session 5.8  安全加固 → Prompt注入防护、密钥管理审计
Session 5.9  文档编写 → README、安装指南、使用文档
```

---

## 四、第三步：每个Session的标准工作流

### 高效的Session结构

```
1. 开篇（2分钟）
   - 告诉Claude Code本次的目标和约束
   - 引用相关的设计文档章节
   - 如果需要，让Claude先读上次提交的diff回顾上下文

2. 规划（5-10分钟）
   - 让Claude Code做 EnterPlanMode（复杂改动时必用）
   - 你审核方案，给出反馈
   - 确认后开始执行

3. 执行（20-90分钟）
   - Claude Code写代码、写测试、运行测试
   - 你观察输出，发现问题及时纠正
   - 遇到大改动，分步提交

4. 验证（5-10分钟）
   - Claude Code运行测试套件
   - 你手动验证关键功能
   - 确认所有测试通过

5. 收尾（2分钟）
   - git commit，写清晰的commit message
   - 如果本次Session有重要的架构决策，写入 docs/adr/
   - 更新进度追踪文件
```

### 进度追踪文件（progress.md）

在项目根目录维护一个 `progress.md`，每个Session结束时更新：

```markdown
# HyqAgent 开发进度

## Phase 1: CPG Foundation
- [x] Session 1.1: tree-sitter安装和多语言解析 (commit: abc123)
- [x] Session 1.2: AST遍历器 (commit: def456)
- [ ] Session 1.3: 单文件调用图
- [ ] Session 1.4: 跨文件调用图
...

## 当前阻塞
- 无

## 下次Session目标
- Session 1.3: 实现单文件内的函数调用图构建
```

这个文件对 Claude Code 很有用——下次会话开始时让它读一下，就能快速了解进度。

---

## 五、第四步：保持Session之间的连续性

### 5.1 每个Session开始时的标准Prompt模板

```
继续开发 HyqAgent。请先执行以下操作来了解当前状态：

1. 读取 /root/hyqagent/progress.md 了解开发进度
2. 读取 /root/hyqagent/CLAUDE.md 了解项目规范
3. 查看上次提交: git log --oneline -5 && git diff HEAD~1 --stat

然后：本次Session的目标是 [具体目标]。
相关设计文档: [引用DESIGN-IMPLEMENTATION.md或其他文档的章节]。
```

### 5.2 当Session内容太多时怎么分割

如果一个Phase的内容超过了一次会话能完成的范围：

1. **先完成一个完整的、可运行的子功能**
2. **中间状态必须可编译、可测试**（不追求完美，但追求可验证）
3. **留下明确的"下一步"提示**

反例：
```
❌ "我们初步搭好了CPG框架，但还有很多TODO，下次继续。"
→ 下次Claude Code上来看到一堆TODO，不知道从哪里开始
```

正例：
```
✅ "Session 1.3完成：单文件调用图构建通过测试（3个test cases）。
   留下了跨文件调用的接口占位（cpg/call_graph_cross.py）。
   下次从Session 1.4开始，目标是实现跨文件调用追踪。"
→ 下次Claude Code明确知道接手的上下文
```

### 5.3 善用Claude Code的Agent模式处理子任务

Claude Code支持启动后台Agent执行独立任务。在HyqAgent开发中，以下场景特别适合：

```
"请同时做三件事：
1. [Agent 1] 给 cpg/parser.py 写完整的单元测试（15个test cases）
2. [Agent 2] 给 session/schema.sql 加迁移脚本（新增task_queue表）
3. [Agent 3] 更新文档 docs/adr/ 记录今天的架构决策

每个Agent完成后通知我。"
```

### 5.4 善用Claude Code的记忆系统

在项目中维护 `.claude/memory/` 目录，用于保存跨会话的重要上下文：

```
项目中有个关键发现可以存为记忆：
"/claude add-memory 'CPG跨文件调用图的最大挑战是Spring DI容器——
@Autowired注入的bean在静态import中不可见，需要解析Spring的XML/注解配置。'"
```

这会在后续的会话中自动加载相关记忆。

---

## 六、第五步：常见问题和应对策略

### Q1: Claude Code开始"忘记"之前做过什么了（上下文超限）

**症状**：Claude Code开始问"这个函数在哪定义的？"——明明刚才还在改这个文件。

**应对**：
- 会话中运行 `/compact` 可以手动触发上下文压缩
- 更主动的做法：每个Session拆的足够小（一次只做一个模块），不依赖会话内的"记忆"
- 依赖 CLAUDE.md + progress.md + git history 传递上下文

### Q2: Claude Code写的代码不符合预期风格

**应对**：
- 在 CLAUDE.md 中写清楚代码风格要求
- 在 Session 开始时明确："参考 src/hyqagent/cpg/parser.py 中的代码风格"
- 用 pre-commit hooks（ruff format + mypy）自动纠正

### Q3: Claude Code在复杂问题上"自作主张"，导致架构偏离设计

**应对**：
- 复杂改动前必须用 `EnterPlanMode`，你审核方案后再执行
- 引用设计文档："请严格按照 DESIGN-IMPLEMENTATION.md 第X章的接口定义来实现"
- 保持警惕：如果Claude Code的"简化"看起来改动了接口契约，立刻叫停

### Q4: 测试写不好，特别是涉及LLM的测试

**应对**：
- 确定性组件：直接写精确断言，`assert result == expected`
- 概率性组件（LLM调用）：先mock LLM输出，单独测试处理逻辑
- 真LLM测试：只放在Nightly Eval中，不在每次commit时跑

### Q5: 长时间Session中断了怎么办

**应对**：
- 确保关键改动及时git commit
- Claude Code通常会在会话结束前自动保存状态
- 下次Session从git log和progress.md恢复上下文

---

## 七、完整开发路线图（12-15周）

```
Week 1-4:  Phase 1 — CPG Foundation
          ├─ Week 1-2: tree-sitter + AST遍历 + 单文件调用图
          ├─ Week 2-3: 跨文件调用图 + 数据流图
          └─ Week 3-4: CPGQuery接口 + Flask提取器 + 端到端测试

Week 5-6:  Phase 2 — 确定性扫描器
          ├─ Week 5: 规则引擎 + 污点追踪
          └─ Week 6: CLI v0 + 测试验证

Week 7-9:  Phase 3 — LLM集成
          ├─ Week 7: Model Router + Provider适配器
          ├─ Week 8: 攻击面映射 + 假设生成
          └─ Week 9: 分层验证 + 会话管理

Week 10-12: Phase 4 — 长任务能力
          ├─ Week 10: 上下文管理 + 结晶 + 检查点
          ├─ Week 11: 代码检索 + 增量分析
          └─ Week 12: 收敛检测 + 稳定性测试

Week 13-15: Phase 5 — 质量与发布
          ├─ Week 13: 可观测性 + Golden Dataset + Eval框架
          ├─ Week 14: 测试覆盖 + CLI完善 + 性能优化
          └─ Week 15: 安全加固 + 文档 + v1.0发布
```

### 每周的节奏

```
周一: 规划本周目标 + 架构讨论（如果需要）
周二-周四: 开发Session（每天1-3个Session）
周五: 回顾 + 代码审查 + 测试 + 更新文档
```

---

## 八、附录：Session命令速查

### Claude Code 内部命令
```
/claude        询问项目相关的问题
/plan          进入规划模式（复杂改动前使用）
/compact       压缩当前会话的上下文
/review        代码审查当前变更
/test          运行测试
/commit        生成commit message并提交
```

### 开发常用命令
```bash
# 获取当前状态
git log --oneline -5
git diff HEAD~1 --stat

# 运行测试
uv run pytest tests/unit/ -x -v
uv run pytest tests/unit/test_cpg_parser.py::test_extract_functions -v

# 代码质量
uv run ruff check src/
uv run mypy src/

# 提交
git add -A && git commit -m "[Phase X] Session X.X: 具体描述"
```

### 开始一个新Session的标准命令（复制粘贴即可）
```
继续开发 HyqAgent。
1. 读取 progress.md
2. 读取 CLAUDE.md
3. git log --oneline -5
然后：[本次Session的目标]
```

---

> **核心原则**：
> 1. **一次只做一个Session** — 不贪多，每个Session都能独立验证
> 2. **CLAUDE.md 是命脉** — 花时间维护它，它会让每次会话的启动成本降到最低
> 3. **进度文件要诚实** — 清楚地记录已完成和未完成，这是Claude Code的"记忆"
> 4. **复杂改动先规划** — 使用 EnterPlanMode，你审核后再执行
> 5. **代码质量从第一天开始** — pre-commit hooks (ruff+mypy) + CI/CD，不欠技术债
