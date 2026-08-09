# HyqAgent 长任务持续运行 — 完整架构方案

> 编制时间：2026年8月2日
> 研究方法：5个专业Agent并行研究 + 30+次WebSearch + 多维度交叉验证
> 核心命题：让Agent在几GB级别的大型代码库上持续运行数天到数周，不需人类专家干预，直到多轮核对后确认不存在已知漏洞

---

## 目录

1. [架构全景图](#一架构全景图)
2. [记忆与上下文管理](#二记忆与上下文管理)
3. [信念系统与假设生命周期](#三信念系统与假设生命周期)
4. [工作流编排与事件溯源](#四工作流编排与事件溯源)
5. [检查点与恢复机制](#五检查点与恢复机制)
6. [代码库分析策略](#六代码库分析策略)
7. [收敛性保证与完成标准](#七收敛性保证与完成标准)
8. [可观测性与审计追踪](#八可观测性与审计追踪)
9. [容错与优雅降级](#九容错与优雅降级)
10. [技术选型总览](#十技术选型总览)

---

## 一、架构全景图

### 1.1 总体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     HyqAgent 长任务运行时                          │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  systemd 守护进程  │  │  Signal Handler  │  │ Disk Monitor  │  │
│  │  Restart=always   │  │  SIGTERM→检查点   │  │  85%警告       │  │
│  └──────────────────┘  └──────────────────┘  └───────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              项目编排层 (Temporal / Prefect)               │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────────┐  │   │
│  │  │ Phase 1 │→│ Phase 2 │→│ Phase 3 │→│ Phase 4 & 5 │  │   │
│  │  │ 预扫描   │  │ 攻击面   │  │ 假设生成  │  │ 验证+报告   │  │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └────────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │             事件溯源层 (ESAA 风格)                          │   │
│  │  Agent → JSON意图 → Orchestrator验证 → activity.jsonl     │   │
│  │  所有动作不可变追加记录，SHA-256哈希链验证                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  CPG Engine      │  │  Belief System   │  │ Context Mgr   │  │
│  │  (Joern/增量)    │  │  (SQLite信念库)   │  │ (3区段模型)   │  │
│  └──────────────────┘  └──────────────────┘  └───────────────┘  │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  Vector Search   │  │  Checkpoint Mgr  │  │ Observability  │  │
│  │  (Qdrant语义检索) │  │  (SQLite+JSON)   │  │ (OTel+LangFuse)│  │
│  └──────────────────┘  └──────────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 一条核心公式

> **一个优秀的长期运行Agent = 持久化的记忆 + 可恢复的工作流 + 有策略的探索 + 严格的验证闭环 + 透明的运行过程**

### 1.3 五个Agent的研究分工

| Agent | 研究方向 | 关键产出 |
|:------|:--------|:--------|
| Agent 1 | 记忆持久化与状态恢复 | 三区段上下文模型、信念系统SQL Schema、上下文结晶协议 |
| Agent 2 | 工作流编排与事件溯源 | ESAA-Security架构、Temporal vs Prefect对比、动态任务图 |
| Agent 3 | 大代码库分析策略 | 四层分析架构、风险评分公式、五级自适应深度、多指标收敛 |
| Agent 4 | 可观测性与多轮验证 | OTel + LangFuse、三层验证循环、VSAT完整性度量 |
| Agent 5 | 检查点恢复与容错 | 检查点Schema、动态ETA、优雅降级、进程守护 |

---

## 二、记忆与上下文管理

### 2.1 三区段上下文模型

LLM上下文窗口有限（200K tokens），不能一次性加载所有代码和历史。采用三区段结构：

| 区段 | Token预算 | 内容 | 生命周期 |
|:-----|:---------|:-----|:--------|
| **固定区段** | ~5K tokens | 系统prompt、审计规则、漏洞分类、Agent角色 | 整个会话（Anthropic Prompt Cache缓存） |
| **长期记忆 M(t)** | ~30K tokens | 已完成分析阶段的结晶摘要、关键发现、信念系统摘要 | 整个会话（随分析进展更新） |
| **工作记忆 I(k)(t)** | ~60K tokens | 最近K轮交互的原文（分析的代码、工具输出、推理） | 滑动窗口 |

总计 ~95K tokens，在200K窗口内留有充足空间给代码片段。

### 2.2 Prompt Caching 集成

```python
prompt = [
    # Cache Point 1: 系统prompt + 漏洞分类 (稳定, 高重用)
    {"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}},
    # Cache Point 2: 长期记忆 / 结晶状态 (缓慢变化)
    {"type": "text", "text": long_term_memory_doc, "cache_control": {"type": "ephemeral"}},
    # Not cached: 工作记忆 (每次轮次变化)
    {"type": "text", "text": recent_turns},
]
```

**预期节省**: 90% 成本降低，85% 延迟降低（Anthropic官方数据）。5分钟缓存TTL在Agent活跃时自动续期。

### 2.3 上下文结晶协议

每N轮（默认50轮）或工作记忆超过80%预算时触发：

```markdown
## 分析阶段摘要
- 阶段: SQL注入审计 - Controllers
- 已分析文件: 23个
- 关键发现: 3个（假设ID: hyp_a1, hyp_a2, hyp_a3）
- 已确认: hyp_a1 (confidence 0.92)
- 已拒绝: hyp_a2 (经过参数化查询确认安全)
- 覆盖状态: 模块A 100%, 模块B 60%

## 已做决策
- 跳过 notification_service.py: 仅print()无用户输入

## 待解决问题
- 自定义ORM包装器 my_db.query() 的参数化状态不确定
```

参考：Factory AI的Anchored Iterative Summarization（评分3.70/5.0，对比粗粒度压缩的3.35/5.0）。

### 2.4 向量化代码检索

- **存储**: Qdrant（生产）/ ChromaDB（原型）
- **切片粒度**: 函数/方法级别（使用tree-sitter AST切分）
- **语义检索**: "这段代码我之前分析过吗？" — 相似度>85%的自动复用结论
- **混合检索**: ripgrep(精确) + tree-sitter(结构) + Qdrant(语义) + Joern(数据流)

---

## 三、信念系统与假设生命周期

### 3.1 核心数据模型

```sql
-- 每个漏洞假设
CREATE TABLE hypotheses (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,     -- CWE-89, CWE-79, etc.
    status TEXT NOT NULL DEFAULT 'proposed',
    -- proposed → investigating → supporting_evidence → confirmed
    --                         → refuting_evidence → rejected
    prior_probability REAL NOT NULL,      -- 初始估计
    current_confidence REAL NOT NULL,     -- 贝叶斯更新后
    confidence_history TEXT NOT NULL DEFAULT '[]',  -- JSON: [{ts, conf, reason}]
    file_path TEXT NOT NULL,
    line_start INTEGER, line_end INTEGER,
    function_name TEXT,
    analysis_round INTEGER DEFAULT 1,
    depends_on TEXT,         -- JSON: 依赖的其他假设
    conflicts_with TEXT,     -- JSON: 互斥的假设
    parent_hypothesis TEXT,
    created_at TIMESTAMP, updated_at TIMESTAMP
);

-- 证据项
CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT REFERENCES hypotheses(id),
    type TEXT NOT NULL,      -- supporting|refuting|neutral
    weight REAL NOT NULL,    -- 0.0-1.0 证据强度
    description TEXT NOT NULL,
    source TEXT NOT NULL,    -- data_flow_analysis|semgrep|CPG_query|llm_reasoning
    code_snippet TEXT,
    created_at TIMESTAMP
);

-- 置信度更新日志
CREATE TABLE confidence_updates (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT REFERENCES hypotheses(id),
    old_confidence REAL, new_confidence REAL,
    evidence_id TEXT, update_reason TEXT,
    created_at TIMESTAMP
);
```

### 3.2 贝叶斯置信度更新

```python
def update_confidence(hypothesis, evidence):
    prior = hypothesis.current_confidence
    if evidence.type == "supporting":
        likelihood_true = 0.9 * evidence.weight
        likelihood_false = 0.1
    elif evidence.type == "refuting":
        likelihood_true = 0.1
        likelihood_false = 0.9 * evidence.weight
    else:
        likelihood_true = likelihood_false = 0.5

    marginal = likelihood_true * prior + likelihood_false * (1 - prior)
    posterior = (likelihood_true * prior) / marginal
    return posterior
```

### 3.3 假设依赖图

- `A depends_on B`: B被拒绝 → A自动降级
- `A conflicts_with C`: 确认一个 → 降低另一个的置信度
- 图遍历传播：确认/拒绝一个假设后，自动更新所有关联假设

---

## 四、工作流编排与事件溯源

### 4.1 ESAA-Security 事件溯源架构（推荐直接采用）

这是与HyqAgent需求最匹配的学术方案（arXiv:2603.06365, MIT许可）：

```
Agent（认知层）→ 发出结构化JSON意图
        ↓
Orchestrator（确定性）→ 验证Schema，追加到日志，应用效应
        ↓
Event Store（activity.jsonl）→ 不可变，仅追加
        ↓
Materialized View（roadmap.json）→ 供Agent使用的衍生投影
```

**六条审计不变量**：
1. **Claim-before-work**: 工作开始前必须声明任务
2. **Complete-after-work**: 完成任务需要验证证据
3. **Prior-status consistency**: Agent必须重述其认为的状态
4. **Lock ownership**: 只有任务所有者可以完成它
5. **Boundary discipline**: 制品写入仅限complete事件
6. **Done immutability**: 已完成任务不能被静默重新打开

**SHA-256可验证审计链**: `esaa verify` 重放整个activity.jsonl，重新计算投影哈希并与存储值比较。

**参考实现**: [github.com/elzobrito/esaa-core](https://github.com/elzobrito/esaa-core) (MIT, Python)

### 4.2 编排引擎选择

| 维度 | Temporal.io (推荐) | Prefect (备选) |
|:-----|:-------------------|:---------------|
| 失败恢复粒度 | **指令级别** - 在Activity内部精确恢复 | 任务级别 - 从任务开始重试 |
| 工作流最长持续时间 | **数月至数年**（生产验证） | 数小时至数天 |
| 动态子任务 | `start_child_workflow()` | `.map()` 运行时DAG |
| Python集成 | 良好（必须遵守确定性规则） | **优秀**（原生Python） |
| 操作复杂度 | 中高（需Temporal Server） | **低**（Prefect Cloud或自托管） |

**推荐**: **Temporal.io** — 如果接受操作开销。云端生产环境中已有Replit Agent 3、OpenAI Codex web agent等验证案例。

**备选**: **Prefect + SQLite检查点** — 更简单的Python集成，但需自行实现长时间任务的中间检查点。

### 4.3 动态任务图

```
Phase 0: Recon（扫描代码库，构建攻击面清单）
    |
Phase 1-N: 动态发现循环
    ├── 发现：函数A有风险 → 生成"分析A的所有调用者"子任务
    ├── 发现：新模式 → 生成"反向追踪所有source"子任务
    └── 发现：漏洞cluster → 生成"分析同级端点"子任务
```

**安全限制**（防止无限扩展）：

| 限制项 | 推荐值 |
|---|---|
| 最大生成深度 | 3（Agent→子级→孙子级） |
| 每会话最大Agent总数 | 12-50 |
| 最大并发Agent | 5-10 |
| 每Agent超时 | 15-60分钟 |
| 熔断器：连续失败 | 3次 |

---

## 五、检查点与恢复机制

### 5.1 检查点存储架构

**双重持久化层**：

| 层 | 存储 | 内容 | 用途 |
|---|---|---|---|
| **执行检查点** | SQLite (LangGraph SqliteSaver) | Agent图状态、消息、工具调用历史 | 崩溃恢复（精确恢复到中断点） |
| **领域状态文件** | JSON文件 | 分析进度、模块队列、信念系统摘要 | 快速状态恢复（不需重放历史） |

### 5.2 检查点触发策略（混合驱动）

```
事件驱动（主要触发源）:
├─ 每个Phase完成后
├─ 每完成一个hypothesis的生成/验证
└─ 每确认/拒绝一个漏洞时

时间驱动（安全网）:
├─ 每5分钟（无事件时）
└─ 空闲超过2分钟时

阈值驱动（资源保护）:
├─ Token消耗每增加10%总预算
└─ 磁盘使用超过80%

信号驱动（进程保护）:
├─ 收到SIGTERM（优雅关闭）
└─ 收到SIGUSR1（手动触发检查点）
```

### 5.3 恢复流程（RTO < 1秒）

```
hyqagent resume <session-id>
    │
    ├─ Step 1: 加载最新检查点 (< 50ms)
    ├─ Step 2: 验证完整性 (< 100ms)
    │         └─ PRAGMA integrity_check + JSON可解析性
    │         └─ 失败 → 回退到上一个检查点（最多3次）
    ├─ Step 3: 重建任务队列 (< 100ms)
    │         └─ running → 重置为pending
    ├─ Step 4: 重建CPG连接 (< 500ms, 如有缓存)
    ├─ Step 5: 生成恢复摘要 → 注入系统prompt (~500 tokens)
    │         └─ "当前在做什么 + 关键发现 + 失败过的路径 + 下一步"
    └─ Step 6: 从队列恢复执行
```

**核心创新**: 恢复时不重放全部历史，而是注入一个~2000 token的"状态摘要"，让Agent快速回到上下文。

### 5.4 增量分析支持

```python
def incremental_analysis(repo, prev_commit, curr_commit):
    changed_files = git_diff_files(repo, prev_commit, curr_commit)
    changed_funcs = extract_changed_functions(changed_files)
    
    # 影响分析：找到所有调用者
    impacted_callers = cpg_query("cpg.method('changed_func').caller.name")
    
    # 仅重新分析受影响代码
    analysis_scope = changed_funcs + impacted_callers
    
    # 使受影响假设失效（confidence *= 0.5）
    invalidate_hypotheses_for_files(changed_files)
```

---

## 六、代码库分析策略

### 6.1 四层分析架构

| 层 | 范围 | Token预算 | LLM需求 | 产出 |
|---|------|---------|--------|------|
| **L0 架构层** | 整个仓库 | ~500-2000 | 无（确定性） | architecture.json: 模块列表、依赖图、技术栈 |
| **L1 攻击面层** | 每组端点 | ~2000-5000 | 便宜模型 | attack-surface.json: 所有入口点+风险评分 |
| **L2 数据流层** | 每条污点路径 | ~1000-5000 | CPG确定+便宜模型分类 | taint-flows.json: source→sink路径 |
| **L3 深度分析层** | 每条高风险路径 | ~3000-15000 | 强模型 (Opus/GPT-5.2) | 逐行安全审查 |

**关键数据**: CPG程序切片可减少 **67-91%** 的代码量（LLMxCPG论文）。对500K行代码库，~200端点，预估总token预算 800K-2M，约 $3-15/次完整审计。

### 6.2 风险评分公式

```
risk_score = severity_base × reachability_mult × exploitability_mult × data_sensitivity_mult
```

- **severity_base**: shell exec=10, SQL=8, 文件写=7, 模板渲染=7, 反序列化=8
- **reachability_mult**: 无认证HTTP=1.0, 已认证=0.85, 消息队列=0.7, 内部代码=0.3
- **exploitability_mult**: taint flow确认=1.2, 未知=0.7, 已有消毒=0.4
- **data_sensitivity_mult**: PII/凭据=1.2, 内部数据=0.9, 公开数据=0.7

### 6.3 五级自适应分析深度

| 级别 | 触发条件 | 内容 | Token预算 | 模型 |
|:-----|:--------|:-----|:--------|:-----|
| **L0: 扫描** | 所有文件 | 文件名+函数签名正则匹配 | 0 | 无 |
| **L1: 签名** | L0发现危险模式 | 函数签名+参数类型分析 | ~200/函数 | Haiku |
| **L2: CPG追踪** | L1显示污点类型 | CPG source→sink路径追踪 | ~500/路径 | CPG确定+Haiku |
| **L3: 深度审查** | L2确认污点流+risk≥5 | 程序切片+调用者/被调用者上下文 | 3K-8K/路径 | Sonnet |
| **L4: 上下文分析** | L3发现可能漏洞+risk≥8 | 全模块上下文+中间件+数据模型 | 8K-20K/模块 | Opus |

### 6.4 快速排除规则

```
自动降至L0：
├─ *.test.*, *_test.*, *.spec.*, __tests__/
├─ vendor/, node_modules/, third_party/
├─ 自动生成文件（检测 "// Code generated by"）
└─ 零项目内部导入的文件（独立脚本/配置）
```

### 6.5 动态优先级调整

| 信号 | 调整动作 |
|---|---|
| CRITICAL漏洞在模块M中被确认 | M内所有排队项 ×1.3 |
| 同一个漏洞类型在≥3个位置出现 | 同类sink的所有未分析端点 ×1.2 |
| N次连续深度分析无发现 | 该模块剩余项 ×0.8 |
| 饥饿避免 | 最低优先级项占≥10%分析槽位，老化加速 |

---

## 七、收敛性保证与完成标准

### 7.1 三层验证循环

**Tier 1 — 饱和扫描（每个漏洞类内）**:
1. Discovery Agent扫描 → 初始发现
2. Verification Agent独立确认或反驳（必须生成PoC或解释为何不可利用）
3. Adversarial Agent尝试证伪每个"安全"判定
4. 收敛判断：连续N轮无新确认发现 AND 零成功的对抗证伪
5. 安全阀：5轮后仍在增长 → 升级到人工（不收敛本身就是发现）

**Tier 2 — 完整性审查（漏洞类之间）**:
Completeness Critic（最强模型）结构化追问：
- 我们没分析哪些漏洞类别？
- 我们跳过了哪些代码路径？跳过原因是否合理？
- Discovery Agent做了哪些可能错误的假设？
- 有没有框架特定的漏洞模式未检查？

**Tier 3 — 跨类对抗审查**:
Red Team Agent检查"安全"发现的链式组合是否构成利用链。

### 7.2 多维度收敛标准

借鉴VSAT论文（Zenodo 2026）的 C_struct × C_hat 完整度模型和Green Fuzzing的饱和框架：

| 指标 | 含义 | 收敛阈值 |
|---|---|---|
| **VDR** (漏洞发现率) | 连续无新HIGH+发现 | W=3轮, E=0 |
| **EC** (端点覆盖率) | analyzed_endpoints / total | ≥ 95% |
| **RWC** (风险加权覆盖率) | Σ(risk_score of analyzed) / Σ(risk_score of all) | ≥ 98% |
| **VCC** (漏洞类覆盖率) | 已检查CWE类 / 总目标CWE类 | ≥ 90% |
| **C_hat** (Chao2估计) | 多视角重叠统计估计未发现数 | ≥ 0.85 |

### 7.3 何时可以报告"已完成"

所有以下条件同时满足时，Agent可以输出最终结论：

1. ✅ VDR = 0 持续3轮
2. ✅ EC ≥ 95%
3. ✅ RWC ≥ 98%
4. ✅ VCC ≥ 90%
5. ✅ Critic Agent判定"无未处理盲区"
6. ✅ 所有CRITICAL发现经过L7人工签字（deep模式）

### 7.4 何时必须升级到人工

| 场景 | 必须动作 |
|---|---|
| 5轮后某漏洞类仍未饱和 | "分析未收敛，可能存在复杂漏洞面" |
| 独立视角之间不一致 | "视角A和B在发现X上存在分歧" |
| 检测到自定义/未知框架 | "模块使用未识别框架，自动化分析不可靠" |
| C_hat < 0.70 (>30%估计未发现) | "完整度估计过低，需扩展分析" |
| 覆盖率 < 70% | "大量代码未被分析" |

### 7.5 最终输出格式

> **"经过充分分析，该项目中不存在以下 35 种类型的已知漏洞（OWASP Top 10 + CWE-915 + CWE-862 + ...），分析覆盖了 92% 的代码路径（1,847/2,008），置信度 87%。以下 3 个模块因使用自定义序列化框架而标记为'不确定，需要人工审查'：`custom_codec.py`, `legacy_auth.py`, `payment_gateway.py`。完整审计追踪可在 dashboard 中查看。"**

---

## 八、可观测性与审计追踪

### 8.1 技术栈

```
OTel GenAI SDK → OTLP Collector → LangFuse (自托管)
                                 → ClickHouse (长期分析)
                                 → Grafana (实时仪表盘)
```

每个Span记录：

| Span类型 | 必需属性 |
|---|---|
| **LLM调用** | model, input/output tokens, cache_read tokens, duration, cost, full prompt(可选) |
| **工具调用** | tool name, input args, return value/error, duration |
| **Agent轮次** | conversation.id, session.id, step.number |
| **假设状态变更** | hypothesis ID, old_state→new_state, triggering evidence |
| **评估/护栏** | groundedness_score, hallucination_score |

### 8.2 成本归因

每个Span标记 `finding_id` + `vuln_class`，支持按漏洞的成本核算：

> "发现SQL注入漏洞CVE-89-0421花费$2.34（LLM tokens: $1.80，CPG查询: $0.04，人工审查: $0.50）"

### 8.3 审计追踪

**三平面模型**：

| 平面 | 内容 | HyqAgent示例 |
|---|---|---|
| **证据平面** | 证据来源、时效性、权威性 | 文件路径+行范围+git blob hash+修改时间戳 |
| **决策追踪平面** | 每个中间检查、工具调用、策略评估 | "分析auth.py:142-200，确认JWT验证正确" |
| **结果平面** | 决策后效应、修正、操作员覆盖 | "F-0421从CRITICAL降级为LOW（对抗审查后）" |

**SHA-256哈希链**: 每条日志含前一条的SHA-256哈希，形成防篡改链。定期向外部见证发布哈希。

**跳过决策记录**: 每个"不分析某模块"的决定都需记录原因，并经过reviewer确认。

### 8.4 进度追踪

- **三层进度模型**: 阶段进度 + 任务类型进度 + 成果进度
- **动态ETA**: 三方法组合（线性回归 + 指数平滑 + 移动平均），权重随数据积累自适应
- **定期报告**: 每2小时 + 每Phase完成时输出进度摘要

---

## 九、容错与优雅降级

### 9.1 分层失败处理

| 错误类型 | 处理策略 |
|---|---|
| HTTP 429 (限流) | 指数退避 + jitter + Retry-After尊重 + 队列重排 |
| HTTP 5xx (服务端错误) | 指数退避 + 模型降级尝试 |
| Network Timeout | 线性退避，最多3次 |
| Token预算耗尽 | 裁剪MEDIUM/LOW，保留CRITICAL+HIGH |
| 磁盘空间不足 | 压缩旧日志 → 清理旧检查点 → 紧急检查点 → 优雅退出 |
| 上下文长度超限 | 自动压缩历史 → 重试1次 |
| 代码语法错误 | 直接标记needs_human，不重试 |

### 9.2 模型降级链

```
Opus → Sonnet → Haiku → 纯规则模式（零LLM成本）
```

连续失败3次触发降级，成功调用自动恢复。

### 9.3 进程守护 (systemd)

```ini
[Service]
ExecStart=/usr/local/bin/hyqagent serve
Restart=always
RestartSec=10
StartLimitBurst=3        # 60秒内最多重启3次，防止crash-loop
MemoryHigh=8G
MemoryMax=12G
```

### 9.4 优雅关闭

```
SIGTERM → 保存检查点 → 标记所有running任务为pending
       → 写入execution_state → 清空临时文件 → exit(0)
```

---

## 十、技术选型总览

| 关注点 | 推荐方案 | 理由 |
|:------|:--------|:-----|
| **LLM API** | Claude Sonnet/Opus | Prompt caching, 200K窗口, 强代码推理 |
| **Agent框架** | LangGraph + 自定义记忆层 | 内置checkpointer，持久化执行 |
| **工作流引擎** | Temporal.io (主) / Prefect (备选) | 指令级恢复，动态子工作流，数月持续运行经验证 |
| **事件溯源** | ESAA模式 (SQLite activity.jsonl) | SHA-256验证链，完整审计性，MIT许可 |
| **上下文管理** | 三区段模型 + 结构化晶体化 | Factory AI基准最佳 (3.70/5.0) |
| **信念系统** | SQLite + 关系Schema | ACID, 便携, 零基础设施 |
| **检查点** | LangGraph SqliteSaver + JSON领域状态 | 双恢复层: 执行恢复 + 快速上下文重建 |
| **代码向量检索** | Qdrant (生产) / ChromaDB (原型) | 语义相似检索 + 函数级切片 |
| **CPG分析** | Joern | 2024漏洞检测文献最常引用工具 |
| **可观测性** | OTel GenAI SDK + 自托管LangFuse | 开源, 强成本追踪, 数据自主 |
| **进程守护** | systemd | Linux标准, 自动重启, 资源限制 |
| **增量分析** | Git diff + Joern部分CPG重建 | 仅重分析变更代码+受影响调用者 |

---

## 附录：参考来源

### 学术论文
1. ESAA: "Event Sourcing for Autonomous Agents", arXiv:2602.23193
2. ESAA-Security: "Event-Sourced Architecture for Security Audits", arXiv:2603.06365
3. VSAT: "Measurable-Completeness Multi-Lens LLM Auditing", Zenodo 2026
4. "Green Fuzzing: Saturation-Based Fuzzer Termination", ISSTA 2023
5. LLMxCPG: "Context-Aware Vulnerability Detection Through CPG-Guided LLMs", USENIX 2025
6. "Auditable LLM Autonomy for Operational Decision-Making", ScienceDirect 2026

### 开源项目
- ESAA Core: github.com/elzobrito/esaa-core (MIT)
- ESAA-Security: github.com/elzobrito/ESAA-Security (MIT)
- codebadger: github.com/Lekssays/codebadger
- Convergo: github.com/gomilesf/convergo
- LangFuse: github.com/langfuse/langfuse (MIT)
- Temporal SDK: github.com/temporalio/sdk-python (MIT)

### 行业基准
- Factory AI Context Compression Evaluation (2025)
- Anthropic Prompt Caching Benchmarks
- Windmill Workflow Engine Benchmark (2025)
- Big-Vul标注质量: 仅54.3%准确 → 对基准评估的影响

---

> **核心原则**:
> 1. Agent从不直接变更状态 — 只发出结构化意图，由确定性Orchestrator验证后执行
> 2. 所有信息都必须持久化 — 中断后可恢复，决策可追溯，结论可验证
> 3. 不同危害等级的漏洞需要不同的挖掘深度 — 宁可多花时间，不能遗漏CRITICAL
> 4. "已完成"是可度量、可验证的标准 — 不是Agent自己说的
> 5. 不收敛本身就是关键发现 — 说明代码库安全状况复杂，需要人工介入
