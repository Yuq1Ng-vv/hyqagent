# HyqAgent 架构详解（新手友好版）

> 适用读者：刚接触代码审计 / CPG / LLM 的新人
> 编写日期：2026-08-05
> 建议配套阅读：`ARCHITECTURE_OVERVIEW.md`（白皮书）、`DESIGN-IMPLEMENTATION.md`（实现蓝图）

---

## 一、这个项目是干什么的？

假设你是一家公司的安全工程师，老板让你检查一个新上线的 Web 应用有没有安全漏洞。你打开代码仓库——20 万行代码，几百个 API 接口，各种框架和中间件。你一个人一行一行看，可能要看几个星期，而且还可能漏掉关键漏洞。

HyqAgent 的目标就是：**让程序自动完成这件事**。

它做的事情可以浓缩成一句话：

> 读代码 → 理解代码结构 → 找出漏洞 → 告诉你漏洞在哪、有多严重、怎么修

---

## 二、为什么不用现成的工具？

市面上已经有 Semgrep、CodeQL、Bandit 这些"静态分析工具"。它们的工作原理是：**模式匹配**。

比如"检测 SQL 注入"的规则可能是：找到 `cursor.execute(` 这行代码，然后看它的参数是不是来自用户输入。如果是 → 报漏洞。

这个思路有**三个致命问题**：

| 问题 | 具体说明 | 实际例子 |
|------|---------|---------|
| **只能检测"有模式"的漏洞** | SQL 注入有固定模式（用户输入→数据库执行），但越权漏洞（IDOR）没有代码模式——它取决于业务逻辑"这个用户有没有权限看这条数据" | CodeQL 独立运行只能检出 27/120 个漏洞 |
| **误报多** | `cursor.execute(f"SELECT * FROM users WHERE id={id}")` 看起来危险，但如果前一行的 `id` 已经被 `int()` 强制转换了呢？模式匹配看不出来 | 传统 SAST 误报率通常在 20-40% |
| **看不懂跨文件的复杂数据流** | 用户输入在 `a.py` → 经过 `b.py` 处理 → 再经过 `c.py` 传给数据库。三跳之后，传统工具就断了 | 大多数工具只能追踪 1-2 跳 |

---

## 三、HyqAgent 的核心思路

HyqAgent 用两个东西互补，各取所长：

### 3.1 CPG（代码属性图）—— 精确的"代码地图"

CPG = **Code Property Graph**，是把代码变成一张图。想象一下把代码里的每个变量、每个函数调用都画成节点，用箭头连接它们的关系。

```
代码示例:
@app.route('/user/<id>')
def get_user(id):
    user = db.query(f"SELECT * FROM users WHERE id={id}")  # ← 这是 sink
    return user.name

对应的 CPG 图:
[HTTP请求 /user/<id>]  ← source（用户输入的入口）
    │
    ▼
[id 参数]  ──数据流──►  [db.query(...)]  ← sink（危险操作）
```

CPG 包含了**五种信息**，存在同一张图里：

| 图层 | 英文名 | 回答什么问题 | 用途 |
|------|--------|-------------|------|
| 语法树 | AST | 代码长什么样？有哪些函数/类/变量？ | 代码结构理解 |
| 调用图 | CALLS | 函数 A 调用了函数 B 吗？ | 调用链分析 |
| 数据流图 | DATA_FLOW | 变量 `id` 经过了哪些地方，最终到了哪里？ | 污点追踪的核心 |
| 控制流图 | CTRL_FLOW | if/else/循环是怎么走的？哪些代码路径可达？ | 可达性分析 |
| HTTP 路由图 | HTTP_ROUTE | 哪些 URL 对应哪些函数？ | Web 入口点识别 |

有了这张图，你就能精确回答："用户输入的 `id` 最终会不会到达 `db.query()`？中间有没有被过滤函数处理过？"

### 3.2 LLM（大语言模型）—— 理解"语义"

CPG 能告诉你"数据从哪流到哪"，但它回答不了这些问题：

- "这个越权漏洞能造成什么实际危害？"
- "这两个 Medium 级别的漏洞组合起来是不是 Critical？"
- "这段代码的设计意图是什么？是不是开发者故意不检查权限？"
- "这个业务逻辑有没有竞态条件？"

这种需要**理解业务含义**的问题，交给 LLM。

### 3.3 核心哲学：确定性先行，LLM 后行

```
能用正则 / tree-sitter / CPG 确定的事情 → $0 成本，100% 准确
CPG 确定不了的事情 → 才花钱调用 LLM
```

**数字说话**：大约 **40% 的扫描任务不花一分 LLM 的钱**。200 项检测项中，134 项（67%）可以纯确定性完成。

### 3.4 四大设计哲学一览

| 哲学 | 含义 | 为什么重要 |
|------|------|-----------|
| **单 Agent + 丰富工具 > 多 Agent** | 一个 Agent 配好工具，比多个 Agent 互相协调更高效 | 实验数据：MAS-Central 和 MAS-Decent（多 Agent 架构）检出率甚至不如单 Agent |
| **提出者 ≠ 裁决者** | 生成漏洞假设和验证漏洞用不同模型 | 防止"自己出的题自己判"，减少确认偏见 |
| **确定性先行，LLM 后行** | 正则/CPG 能做的事不花钱 | 省钱 + 零幻觉 |
| **模型级联经济学** | 便宜模型做简单任务，贵模型做复杂任务 | 成本比约 1:30:150 |

---

## 四、一次完整的扫描是怎么跑的？

当你敲下 `hyqagent scan ./myapp`，系统会经历**五个阶段**：

```
┌─────────────────────────────────────────────────┐
│  你的代码                                        │
│  ./myapp/                                       │
│  ├── app.py          ← Flask 主应用              │
│  ├── models.py       ← 数据库模型                │
│  ├── auth.py         ← 认证逻辑                  │
│  └── utils.py        ← 工具函数                  │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │  Phase 1: 确定性预扫描                │  💰 成本: $0
    │  "一眼就能看出来的问题"               │
    │                                      │
    │  • 硬编码的密码/API Key               │
    │  • eval()/exec()/os.system() 危险调用 │
    │  • DEBUG=True 没关                   │
    │  • 有 @app.route 但没加权限检查        │
    │  • CPG 发现 source→sink 路径没有过滤   │
    │                                      │
    │  覆盖约 20-35% 的漏洞类别             │
    └──────────────┬───────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │  Phase 2: 攻击面映射                  │  💰 成本: ~$0.01
    │  "这个项目有哪些入口可能被攻击？"      │
    │                                      │
    │  • 枚举所有 API 端点                  │
    │  • 分析每个端点的功能和风险等级        │
    │  • 按优先级打分排序                   │
    │  • 过滤出高风险端点进入下一阶段        │
    │                                      │
    │  使用模型: 便宜模型（Kimi K2 等）      │
    └──────────────┬───────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │  Phase 3: 假设生成                    │  💰 成本: ~$0.10/个
    │  "如果我是攻击者，我会怎么利用？"      │
    │                                      │
    │  核心创新：CPG 切片提示               │
    │  不是把整个文件塞给 LLM，              │
    │  而是只提取数据流路径上的关键代码行     │
    │                                      │
    │  输出：结构化的漏洞假设                │
    │  { cwe_id, severity, attack_scenario, │
    │    source, sink, data_flow_path }     │
    │                                      │
    │  使用模型: 中等模型（Claude Sonnet）    │
    └──────────────┬───────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │  Phase 4: 分层验证                    │  💰 成本: ~$0.50/个(高价值)
    │  "这个假设是真的漏洞还是误报？"         │
    │                                      │
    │  ┌────────────────────────────┐      │
    │  │ L1 确定性验证（$0 成本）     │      │
    │  │ • CPG 查路径是否真实存在     │      │
    │  │ • source/sink 类型是否匹配  │      │
    │  │ • 代码位置是否准确          │      │
    │  └────────────────────────────┘      │
    │              ↓                        │
    │  ┌────────────────────────────┐      │
    │  │ L2 LLM 验证（强模型）       │      │
    │  │ 五问审查：                  │      │
    │  │ 1. 路径确实可达吗？          │      │
    │  │ 2. 条件能被绕过吗？          │      │
    │  │ 3. 过滤函数够不够？          │      │
    │  │ 4. 框架有额外保护吗？        │      │
    │  │ 5. 综合判断：真漏洞/误报？   │      │
    │  └────────────────────────────┘      │
    │                                      │
    │  互补机制（防漏报）：                  │
    │  • 反向 Sink 分析：从危险函数倒推      │
    │  • 盲扫 LLM 通道：不依赖 Phase 1 结果  │
    │  • Completeness Critic："我们漏了什么" │
    │                                      │
    │  使用模型: 强模型（Claude Opus 等）     │
    └──────────────┬───────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────┐
    │  Phase 5: 报告生成                    │  💰 成本: $0
    │  "整理成人类能看懂的格式"              │
    │                                      │
    │  支持三种输出格式：                    │
    │  • JSON — 程序处理                   │
    │  • Markdown — 人类阅读               │
    │  • SARIF — 集成到 CI/CD 工具          │
    │                                      │
    │  每个发现包含：                        │
    │  • 代码位置（文件+行号）               │
    │  • 完整数据流路径                      │
    │  • 严重度 + CWE 编号                  │
    │  • 修复建议                            │
    │  • 验证历史                            │
    └──────────────────────────────────────┘
```

---

## 五、代码是怎么组织的？

### 5.1 目录全景图

🟢 = 已完成　　🔵 = 进行中　　⬜ = 计划中

```
src/hyqagent/
│
├── core/                          ← 🟢 基础层（已完成）
│   ├── protocols.py               ← ⭐ 最重要！所有模块的接口定义
│   ├── state.py                   ← 扫描状态的数据结构
│   └── events.py                  ← 审计日志的 12 种事件类型
│
├── cpg/                           ← 🔵 CPG 引擎（进行中，Sessions 1.2-1.9）
│   ├── parser.py                  ← ✅ tree-sitter 解析器（支持 Python/JS/Java）
│   ├── traversal.py               ← ✅ AST 遍历器（DFS 前序/后序）
│   ├── types.py                   ← ✅ 共享数据类（FunctionNode/ClassNode/ImportNode）
│   ├── callgraph.py               ← ✅ 单文件调用图（Session 1.4）
│   ├── callgraph_builder.py       ← ✅ 跨文件调用图构建器（Session 1.5）
│   ├── languages/                 ← ✅ LanguageProvider 策略模式（Session 1.5）
│   │   ├── base.py                ←   抽象基类（14个抽象成员）
│   │   ├── python.py              ←   PythonAdapter
│   │   ├── javascript.py          ←   JavaScriptAdapter
│   │   └── java.py                ←   JavaAdapter
│   ├── data_flow.py               ← 🔜 数据流图（Session 1.6）
│   ├── query.py                   ← ⬜ CPG 查询接口（Session 1.7）
│   ├── taint_rules.yaml           ← ⬜ 污点源/汇的配置文件
│   ├── sanitizers.yaml            ← ⬜ 过滤函数的配置文件
│   └── frameworks/                ← ⬜ 框架提取器（Flask/Django/Spring）
│
├── scanner/                       ← ⬜ 扫描引擎（Phase 3 实现）
│   ├── orchestrator.py            ← 扫描流水线的"指挥中心"
│   ├── deterministic.py           ← Phase 1：确定性规则扫描
│   ├── mapper.py                  ← Phase 2：攻击面映射
│   ├── hypothesis.py              ← Phase 3：LLM 假设生成
│   ├── validator.py               ← Phase 4：分层验证
│   └── rules/                     ← 确定性规则配置（secrets/dangerous_calls/config）
│
├── models/                        ← ⬜ 模型路由（Phase 3 实现）
│   ├── router.py                  ← 三级模型调度（便宜/中等/强）
│   ├── budget.py                  ← 预算管理（默认 $5/项目）
│   └── providers/                 ← LLM API 适配器（Anthropic/OpenAI 兼容）
│
├── session/                       ← ⬜ 会话管理（Phase 3 实现）
│   ├── manager.py                 ← 会话 CRUD
│   ├── belief.py                  ← 贝叶斯置信度更新
│   ├── checkpoint.py              ← 检查点保存/恢复（支持中断续扫）
│   └── schema.sql                 ← SQLite 数据库表结构
│
├── memory/                        ← ⬜ 上下文管理（Phase 4 实现）
│   ├── context.py                 ← 三区段上下文模型（固定+长期+工作）
│   ├── crystallizer.py            ← 上下文结晶（防 LLM 记忆溢出）
│   └── retriever.py               ← 代码语义搜索（"这段我分析过吗？"）
│
├── observability/                 ← ⬜ 可观测性（Phase 4 实现）
│   ├── tracer.py                  ← OpenTelemetry 分布式追踪
│   ├── cost_tracker.py            ← 成本追踪（精确到每个发现花了多少钱）
│   ├── metrics.py                 ← Prometheus 指标暴露
│   └── audit_trail.py             ← 审计链（ESAA 事件溯源 + SHA-256 防篡改）
│
├── prompts/                       ← ⬜ Prompt 模板（Phase 3 实现）
│   ├── system/                    ← 系统提示词（语义版本管理）
│   ├── few_shot/                  ← Few-shot 示例
│   └── shared/                    ← 输出格式模板
│
├── api/                           ← ⬜ CLI 入口（Phase 2 实现）
│   ├── cli.py                     ← 命令行（click 框架）
│   └── config.py                  ← 配置管理（pydantic-settings）
│
└── report/                        ← ⬜ 报告生成（Phase 3 实现）
    ├── json_report.py
    ├── markdown_report.py
    └── sarif_report.py
```

### 5.2 模块依赖关系（谁靠谁）

```
CLI (api/cli.py)          ← 用户入口，唯一做"依赖注入"的地方
  │
  ├── Orchestrator (scanner/orchestrator.py)  ← 指挥中心
  │     │
  │     ├── CPG Engine      ← 提供精确的代码分析能力
  │     ├── DeterministicScanner ← Phase 1，不花 LLM 的钱
  │     ├── AttackSurfaceMapper  ← Phase 2，便宜 LLM
  │     ├── HypothesisGenerator  ← Phase 3，中等 LLM
  │     ├── Validator            ← Phase 4，强 LLM + CPG
  │     └── ReportGenerator      ← Phase 5，纯组装
  │
  ├── ModelRouter         ← 决定用什么模型、花多少钱
  ├── SessionManager      ← 数据库存状态 + 信念系统
  ├── ContextManager      ← 管理 LLM 的"记忆窗口"
  └── Observability       ← 日志/追踪/指标/审计链
```

**关键规则**：每个模块只依赖"接口"（`protocols.py` 中定义的抽象类），不依赖具体实现。比如 Orchestrator 依赖的是 `CpgAnalyzer` 协议，而不是某个具体的 CPG 引擎。这样以后换 CPG 后端（tree-sitter → Joern）或换数据库（SQLite → PostgreSQL），只需要写一个新的实现类，**不改任何现有代码**。这就是面向对象设计中的"依赖倒置原则"。

### 5.3 实现顺序

```
protocols.py（定义所有抽象，无依赖）✅
    → cpg/types.py（共享数据类，打破循环依赖）✅
    → cpg/languages/（LanguageProvider 抽象基类 + 三种语言适配器）✅
    → cpg/parser.py（tree-sitter 解析，委托给 Provider）✅
    → cpg/traversal.py（AST 遍历，依赖 parser）✅
    → cpg/callgraph.py（单文件调用图，依赖 parser + languages）✅
    → cpg/callgraph_builder.py（跨文件调用图，依赖 callgraph）✅
    → cpg/data_flow.py（数据流，依赖 callgraph）📋
    → cpg/frameworks/（框架提取器，依赖 parser）📋
    → cpg/query.py（查询接口，依赖以上全部）📋
    → scanner/deterministic.py（Phase 1，依赖 query）📋
    → models/（LLM 提供者 + 路由 + 预算）📋
    → scanner/mapper.py → scanner/hypothesis.py → scanner/validator.py 📋
    → session/（数据库 + 信念系统 + 检查点）📋
    → observability/（追踪 + 指标 + 审计）📋
    → memory/（上下文 + 结晶 + 检索）📋
    → scanner/orchestrator.py（组装一切）📋
    → api/cli.py（唯一做依赖注入的地方）📋
    → report/（最后实现，纯组装）📋
```

---

## 六、重要的设计决策（为什么要这么设计？）

### 决策 1：单 Agent + 多视角，不是多 Agent

很多类似项目会启动多个 AI Agent 并行工作（一个查 SQL 注入，一个查 XSS，等等）。HyqAgent 选择了**一个 Agent + 三种视角**：

```
同一段代码，同一个 Agent，不同的 Prompt，隔离的上下文：

Pass 1: Security Auditor（审计员视角）
  "你是安全审计员。找出这段代码中所有可被利用的漏洞。"

Pass 2: Attacker（攻击者视角）
  "你是攻击者。审计员说这段代码是安全的。证明他们错了。
   尝试绕过所有防护措施。"

Pass 3: Completeness Critic（完整性审查）
  "审计员和攻击者都看过了。他们漏了什么？
   哪些漏洞类型没被检查？哪些假设可能是错的？"
```

**为什么不做多 Agent？** 实验数据说话：

| 架构 | 检出率 | 成本/发现 | 结论 |
|------|--------|----------|------|
| 单 Agent + 工具 | 50.8% | $0.058 | 性价比最优 |
| 3 Agent 独立 | 64.2% | $0.143 | 检出率最高，但 2.5x 成本 |
| 中心化多 Agent | 未超越单 Agent | — | 编排器成瓶颈 |
| 对等投票多 Agent | 未超越单 Agent | — | 投票保守导致漏检 |

真正的杠杆点不是"更多 Agent"，而是"更好的工具"——特别是 CPG。

### 决策 2：漏洞分"三六九等"，不是一刀切

不同严重度的漏洞值得不同的挖掘深度：

| 漏洞等级 | CVSS 分数 | 预算占比 | 挖掘层数 | 验收标准 |
|----------|-----------|---------|---------|---------|
| **CRITICAL** | 9.0-10.0 | 40% | L1-L7 全量 | 100% L7 人工签字 |
| **HIGH** | 7.0-8.9 | 30% | L1-L5 必选 | 95% L4 验证率 |
| **MEDIUM** | 4.0-6.9 | 20% | L1+L3 必选 | L1 规则 100% 覆盖 |
| **LOW** | 0.1-3.9 | 7% | L1 扫描 | 盲区清单 |
| **INFO** | 0 | 3% | L1 自动 | 自动汇总 |

**七层挖掘阶梯**：

| 层 | 方法 | 成本/发现 | 适用 |
|----|------|----------|------|
| L1 | 确定性规则引擎（正则+CPG） | ~$0 | 默认必选 |
| L2 | CPG 反向分析（sink→source 回溯） | ~$0.01 | 默认必选 |
| L3 | LLM 假设生成（中等模型+CPG 切片） | ~$0.10 | 中置信+ |
| L4 | LLM 深度验证（强模型+完整上下文） | ~$0.50 | HIGH+ |
| L5 | 对抗性审查（攻击者视角审视"安全"路径） | ~$0.25 | CRITICAL+HIGH |
| L6 | 动态 PoC 验证（沙箱隔离执行） | ~$2.00 | CRITICAL |
| L7 | 人工签字（安全专家独立审查） | 人力成本 | CRITICAL |

**为什么这样分配？** CISA KEV 2025 数据：OS 命令注入 18 个 KEV（#1）、反序列化 14 个（#2）。CRITICAL 漏洞遗漏代价极大——MOVEit 单漏洞造成 $9.2B 损失。所以预算向高危倾斜。

### 决策 3：提出漏洞的人不能是验证漏洞的人

同一个模型既"发现"漏洞又"验证"漏洞 = 自己给自己打分，容易产生确认偏见。

HyqAgent 的做法：
- **假设生成**用中等模型（Claude Sonnet）——成本低
- **验证**用强模型（Claude Opus）——可靠，而且是不同模型家族的

这种"检察官-法官分离"的设计借鉴了 OpenHack 的安全审计实践。

### 决策 4：宁可漏报，不可误报

误报（说一个地方有漏洞，其实没有）比漏报（有漏洞但没说）伤害更大。因为一旦用户看到误报，就不再信任这个工具了。

**HyqAgent 的三层防线**：

```
第一层：CPG 架构级隔离
  → CPG 图不存在 source→sink 路径 → 直接拒绝

第二层：L1 确定性验证（$0 成本）
  → source/sink 类型不匹配 → 拒绝
  → 代码位置不准确 → 拒绝

第三层：L2 LLM 验证（强模型五问）
  → 路径可达性、条件绕过、过滤充分性、框架保护、综合判断
```

再加上从中分析文章提炼的改进：
- 跨轮覆盖状态追踪（R2 不重复 R1 的工作）
- 置信度自动分级（CPG 路径存在 → confidence≥0.7；不存在 → ≤0.3）
- 输出截断检测（哨兵标记防 LLM 输出丢失）

### 决策 5：长任务可持续运行数小时甚至数天

大型项目（20 万行代码）不可能几分钟扫完。HyqAgent 设计了完整的"长任务"保障：

| 机制 | 解决的问题 |
|------|-----------|
| **三区段上下文模型** | LLM 的"记忆"有限（200K tokens），需要把固定知识、长期记忆、当前工作分开放 |
| **上下文结晶** | 每 50 轮自动压缩总结，防止记忆溢出 |
| **检查点系统** | 随时可以中断（Ctrl+C），下次 `hyqagent resume` 从断点继续，<1 秒恢复 |
| **五个收敛指标** | 什么时候算"扫描完成"？不是靠感觉，而是五个数学指标全部达标 |
| **预算自动降级** | 钱快花完时自动从强模型降级到中等模型再降到便宜模型，绝不超预算 |

---

## 七、当前进度：我们在哪？

```
Phase 1: CPG Foundation（代码属性图基础层）

  ✅ Session 1.1 — 项目骨架
     pyproject.toml、核心协议定义、事件类型
  ✅ Session 1.2 — tree-sitter 单文件解析器
     支持 Python/JavaScript/Java 三种语言
  ✅ Session 1.3 — AST 遍历器
     DFS 前序/后序遍历、节点过滤、导航搜索工具
  ✅ Session 1.4 — 单文件调用图
     支持 Python/JS/Java，已解析/未解析分类
  ✅ Session 1.5 — LanguageProvider 重构 + 跨文件调用图
     策略模式可扩展架构（添加语言=1文件+1行注册）
     CallGraphBuilder 支持相对/绝对导入解析

  🔜 Session 1.6 — 数据流图构建          ← 下一步
  ⬜ Session 1.7 — CPG 查询接口
  ⬜ Session 1.8 — Flask 框架提取器
  ⬜ Session 1.9 — 端到端 CPG 测试
  ⬜ Sessions 1.10-1.12 — 边界情况修复

Phase 2: 确定性扫描器（未开始）
Phase 3: LLM 集成（未开始）
Phase 4: 长任务能力（未开始）
Phase 5: 质量与发布（未开始）
```

**质量门禁**：240 个 pytest 测试全部通过，ruff 零警告，mypy strict 模式零错误。

---

## 八、关键概念速查表

| 术语 | 全称 | 一句话解释 |
|------|------|-----------|
| **CPG** | Code Property Graph | 代码的"地图"——AST + 调用图 + 数据流图 + 控制流图 + HTTP 路由图的统一表示 |
| **SAST** | Static Application Security Testing | 静态应用安全测试——不运行代码，只读源码找漏洞 |
| **Source** | — | 污点源——用户输入进入系统的位置（如 `request.args.get()`） |
| **Sink** | — | 污点汇——危险操作发生的位置（如 `cursor.execute()`） |
| **Sanitizer** | — | 过滤函数——对输入做清洗的函数（如 `re.escape()`、`int()`） |
| **数据流** | Data Flow | 变量从 source 出发，经过各种函数处理，最终到达 sink 的路径 |
| **IDOR** | Insecure Direct Object Reference | 越权漏洞——用户 A 能访问用户 B 的数据 |
| **幻觉** | Hallucination | LLM "编造"不存在的代码或漏洞 |
| **ESAA** | Event-Sourced Autonomous Agent | 事件溯源自治 Agent——所有决策不可变追记，SHA-256 链防篡改 |
| **VDR** | Vulnerability Discovery Rate | 漏洞发现率——新发现的漏洞数量是否趋于零 |
| **EC** | Endpoint Coverage | 端点覆盖率——已分析的 API 端点百分比 |
| **置信度** | Confidence | 贝叶斯概率——漏洞假设有多大概率是真的（0.0-1.0） |

---

## 九、想深入了解？

按知识深度递进阅读：

| 顺序 | 文档 | 内容 |
|------|------|------|
| 1 | **本文** ← 你在这 | 新手友好的架构全景 |
| 2 | [`ARCHITECTURE_OVERVIEW.md`](../ARCHITECTURE_OVERVIEW.md) | 项目白皮书，技术决策的完整论证 |
| 3 | [`DESIGN-IMPLEMENTATION.md`](../DESIGN-IMPLEMENTATION.md) | 12 章实现蓝图，每个模块的接口定义 |
| 4 | [`CODE-AUDIT-SKILL-ANALYSIS.md`](./CODE-AUDIT-SKILL-ANALYSIS.md) | 业界 code-audit skill 方案的深度分析 |
| 5 | [`COVERAGE-GAP-ANALYSIS.md`](./COVERAGE-GAP-ANALYSIS.md) | 覆盖盲区分析 + 七种缓解方案 |
| 6 | [`progress.md`](../progress.md) | 开发进度追踪（每次 Session 更新） |

---

> **一句话记住 HyqAgent**：
>
> **CPG 画地图，LLM 做判断。确定性的事情不花钱，不确定的事情才找 AI。**
> **找到的每个漏洞都必须有证据链，不能凭空编造。**
