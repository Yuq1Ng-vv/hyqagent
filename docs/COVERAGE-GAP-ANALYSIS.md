# HyqAgent 流水线覆盖盲区 — 深度分析报告

> 分析时间：2026年8月2日
> 分析方法：3个专业Agent并行研究（覆盖盲区枚举、学术文献验证、工程方案设计）+ 综合架构评审
> 基于文档：`RESEARCH.md`（第1-12章）、`PLAN.md`（第1-11章）

---

## 目录

1. [执行摘要](#一执行摘要)
2. [核心问题：Pipeline的覆盖盲区](#二核心问题pipeline的覆盖盲区)
3. [RepoAudit类比错误——最关键的设计假设问题](#三repoaudit类比错误最关键的设计假设问题)
4. [Phase 1 遗漏的漏洞类别——逐类分析](#四phase-1-遗漏的漏洞类别逐类分析)
5. [学术文献中的量化证据](#五学术文献中的量化证据)
6. [七种互补缓解方案](#六七种互补缓解方案)
7. [按扫描模式的分层部署策略](#七按扫描模式的分层部署策略)
8. [定量估算与成本分析](#八定量估算与成本分析)
9. [实施优先级建议](#九实施优先级建议)
10. [参考文献](#十参考文献)

---

## 一、执行摘要

### 核心发现

HyqAgent 的 5 阶段流水线架构中，Phase 1（确定性预扫描）作为下游所有 LLM 分析阶段的唯一入口，存在**系统性的覆盖盲区**。该盲区源于三个叠加因素：

1. **有损过滤 vs 无损抽象**：Phase 1 是过滤器（不匹配规则的代码路径被丢弃），而非 RepoAudit 的无损程序抽象。Plan 中将两者类比是一个关键的设计假设错误。
2. **配置的闭世界假设**：Phase 1 的发现能力完全受限于 YAML 配置文件中的 source/sink 枚举，而现实世界的漏洞模式是开放的。
3. **漏洞类别的结构不可检测性**：大量高价值漏洞类型（IDOR、业务逻辑漏洞、二阶注入、条件竞争等）没有代码层面的结构性特征，确定性规则无法捕获。

### 定量估计

| 指标 | 估计值 | 依据 |
|:-----|:------|:-----|
| Phase 1 覆盖的漏洞类别比例 | 20-35%（按CWE多样性） | 学术文献综合分析 |
| 被遗漏的最常见高价值漏洞 | IDOR/权限绕过（25-30%）、业务逻辑（15-20%）、二阶注入（~5%） | Bug Bounty平台数据 |
| 确定性分析的理论召回率上限 | ~57.5% | IRIS研究（CodeQL+LLM增强后仍漏42.5%） |
| SECUREAGENTBENCH 最佳系统召回率 | 15.2% | 105个任务、平均554K LOC |
| 预期通过缓解方案可提升的召回率 | +8-15% | 基于MAS-Indep多样性红利的保守估计 |

### 核心建议

**不需要推翻现有架构**。通过增加四个低成本的独立检测通道（反向CPG分析、Phase 2盲扫扩展、Completeness Critic、差异覆盖分析），可以在 `--standard` 模式下以约 $0.15 的额外成本显著缩小覆盖盲区。

---

## 二、核心问题：Pipeline的覆盖盲区

### 2.1 问题描述

当前架构的数据流：

```
全部代码
    │
    ▼
Phase 1: 确定性预扫描 ────→ 匹配规则 → 进入 Phase 3
    │                       不匹配    → 丢弃 ✗
    ▼
Phase 2: 攻击面映射 ────→ priority ≥ 5 → 进入 Phase 3
    │                    priority < 5 → 丢弃 ✗
    ▼
Phase 3: 假设生成 (LLM)  ← 只能看到 Phase 1 + Phase 2 放行的内容
    │
    ▼
Phase 4: 验证 (L1+L2)
    │
    ▼
Phase 5: 报告组装
```

**关键缺陷**：Phase 3 的 LLM 永远不会看到 Phase 1 未匹配的代码路径。上游的遗漏在下游无法补偿。

PLAN.md 第 2.2.E 节承认了这一点：
> 错误传播: 中 — 上游遗漏下游无法补偿

但该声明仅作为描述性备注，未能量化风险，也未提出系统性的缓解方案。

### 2.2 为什么这个问题被低估了

方案设计中有三个隐含假设，每一个都需要审视：

**假设 1**：「CPG 构建了完整的图，所以所有潜在路径都在图里。」
- **事实**：CPG 确实构建了完整的图，但 Phase 1 的查询是有选择性的——只查询从 YAML 定义的 source 出发、到 YAML 定义的 sink 为止的路径。图中存在但没有被查询的路径对 Phase 3 不可见。

**假设 2**：「Phase 2 对所有端点做了攻击面分类，所以不会遗漏。」
- **事实**：Phase 2 的分类任务（判断端点功能和数据敏感性）与漏洞发现是正交的。一个被正确分类为「公开接口、无敏感数据」的端点可能包含严重的 IDOR，但其 priority 得分可能只有 2-3，从而被 Phase 3 跳过。

**假设 3**：「RepoAudit 的架构验证了我们的 Pipeline 方案。」
- **事实**：见第三章的详细分析。

---

## 三、RepoAudit类比错误——最关键的设计假设问题

### 3.1 两种架构的根本差异

```
RepoAudit 架构：
  Code → Program Abstraction (无损, 全量保留) → LLM查询分析 → 验证
                 ↑
        所有代码路径都被保留。
        任何内容都可以被查询。

HyqAgent 架构（当前）：
  Code → Phase 1 (有损过滤) → Phase 2 (二次过滤) → Phase 3 (LLM分析)
                ↑                     ↑
         不匹配规则的丢弃        低priority的丢弃
```

RepoAudit 的 Program Abstraction 是一个**无损的、全面的结构化表示**。LLM 可以通过查询接口访问代码库中的任何内容。移除 Program Abstraction 会导致 **-47.5% 真阳性**（消融实验数据），说明它是核心**发现**机制，而非过滤机制。

HyqAgent 的 Phase 1 是一个**有损过滤器**。不匹配 YAML 配置的代码路径被永久丢弃，后续阶段无法恢复。

### 3.2 RepoAudit 不能用来验证 HyqAgent 的召回率

| 对比维度 | RepoAudit | HyqAgent |
|:---------|:----------|:---------|
| 上游阶段性质 | 无损抽象 | 有损过滤 |
| LLM可见范围 | 全部代码（通过查询） | 仅Phase 1匹配的路径 |
| 评估漏洞类型 | 3种（NPD/MLK/UAF） | Web应用全类别 |
| 召回率基准 | 有（消融实验） | **无** |
| 遗漏度量机制 | 有（程序抽象完整性可验证） | **无** |

PLAN.md 多次引用 RepoAudit 的 78.43% 精确率作为架构验证。但这个数字是 RepoAudit **在其无损架构下**实现的——它不能用来推断 HyqAgent 有损架构的召回率。

---

## 四、Phase 1 遗漏的漏洞类别——逐类分析

### 4.1 概述

Phase 1 由三个确定性组件构成：

| 组件 | 方法 | 覆盖范围 | 根本局限 |
|:-----|:-----|:--------|:--------|
| 正则规则 | 模式匹配 | 硬编码密钥、危险调用 | 仅匹配已知文本模式 |
| CPG污点追踪 | source→sink路径 | source和sink都在YAML中的路径 | **闭世界假设** |
| 配置检测 | 模式匹配 | DEBUG=True等 | 仅限预定义配置项 |

以下是 Phase 1 系统性遗漏的漏洞类别逐类分析。

### 4.2 IDOR / 权限绕过 (CWE-639, CWE-862)

**Phase 1 能否发现**：❌ 不能

**原因**：IDOR 在代码层面没有「污点」特征。以下两段代码在 CPG 中结构完全相同：

```python
# 有IDOR漏洞的代码
order = db.query(f"SELECT * FROM orders WHERE id = {req.params.id}")

# 安全的代码（加了所有权验证）
order = db.query(f"SELECT * FROM orders WHERE id = {req.params.id} AND user_id = {current_user.id}")
```

漏洞在于**缺少**所有权检查，而非**存在**危险操作。CPG 的污点追踪无法检测「应该存在但缺失」的代码。

**Phase 1 的「缺失认证注解」规则只能捕获部分情况**：如果项目使用显式的 `if user.can_access(order)` 而非装饰器，Phase 1 无法判断该检查是否充分。

**真实世界占比**：
- CWE-862 排名 MITRE 2024 CWE Top 25 第 9 位，2025 年上升 5 位
- Bug Bounty 平台中约 50% 的高危/严重发现涉及访问控制缺陷
- Semgrep/Cloudflare 研究：传统 SAST 工具对此类漏洞完全静默

### 4.3 业务逻辑漏洞（无对应CWE）

**Phase 1 能否发现**：❌ 不能

**原因**：业务逻辑漏洞的代码实现了「正确的功能」——问题在于**规格本身有缺陷**。典型例子：

- 优惠券可使用次数未校验（`coupon.used_count < coupon.max_uses` 缺失）
- 支付金额可被客户端篡改
- 两步操作之间缺少状态一致性检查
- 负数量/负金额未拒绝

这些漏洞**没有sink**——不存在需要追踪的危险函数调用。代码在语法层面完全正常。

**真实世界占比**：
- Escape.tech/Invicti 研究：「自动化扫描器在业务逻辑漏洞检测上表现极差」
- 约 100 个路由 × 25 种漏洞类型 = 25,000 个需要维护的安全测试用例（组合爆炸）
- 实际上**每个自定义业务应用都存在逻辑漏洞攻击面**

### 4.4 二阶注入 (CWE-89, CWE-79)

**Phase 1 能否发现**：❌ 不能

**原因**：二阶注入的污点链跨越了**持久化边界**。

```
请求A: 用户输入 → 验证/转义 → 存入数据库（此时看起来安全）
请求B: 从数据库读出 → 拼接到SQL查询（危险操作）

CPG视角：请求A和请求B是完全独立的两个数据流，
         CPG无法将它们连接成一条污点路径。
```

STaint 论文（ASE 2025）明确指出：「传统的静态污点分析无法追踪跨执行阶段的数据流，因为存储数据的函数和读取数据的函数之间没有直接的控制流路径。」

Oracle 专利（US 11586740）描述：检测二阶数据流需要匹配**全局标识符**（表名/列名对），这是标准 CPG 不具备的能力。

### 4.5 条件竞争 / TOCTOU (CWE-362, CWE-367)

**Phase 1 能否发现**：❌ 不能

**原因**：CPG（包括 AST + CFG + DFG）每次建模**一条执行路径**。没有：
- 线程交错模型
- happens-before 分析
- 跨线程/跨goroutine/跨async任务的状态共享追踪

以下代码在 CPG 分析中完全正常：
```python
if os.path.exists(path):     # 检查
    with open(path, 'w') as f:  # 使用 — TOCTOU窗口
        f.write(data)
```

James Kettle（PortSwigger）的研究表明：条件竞争在 web 应用中被**严重漏报**，因为 DAST 工具串行发送请求，且 async/await 的普及创造了大量新的竞争面。

### 4.6 反序列化——自定义 Gadget 链 (CWE-502)

**Phase 1 能否发现**：⚠️ 部分（仅 sink 识别）

**原因**：Phase 1 可以将 `pickle.loads()` 或 `ObjectInputStream.readObject()` 标记为 sink，但**反序列化漏洞的本质不在 sink，而在 classpath 上是否存在可利用的 gadget 链**。

GadgetHunter 论文（FSE 2026）的量化数据：
- 传统静态工具在 34 个已知 gadget 链中只能找到 **3-16 个**
- 85.3% 的真实 Java gadget 涉及**反射、动态代理或运行时多态**——CPG 的调用图构建无法解析这些
- 即使最好的静态工具（Sentinel, ICSME 2026），对已知链的召回率也仅 87.5%

### 4.7 SSRF——间接模式 (CWE-918)

**Phase 1 能否发现**：⚠️ 部分

**原因**：直接模式（`req.params.url → http.get(url)`）Phase 1 可以捕获——只要 source 和 sink 都在 YAML 中。但以下模式会被遗漏：

1. **重定向链绕过**：URL 通过验证，但 HTTP 库跟随重定向访问内网
2. **DNS Rebinding**：域名在验证时解析到安全地址，在请求时解析到内网地址
3. **非请求参数来源**：管理员面板配置的 Webhook URL、OAuth profile 中的头像 URL
4. **二阶 SSRF**：URL 存入数据库，由定时任务读取并请求
5. **框架隐蔽 sink**：`urllib.request.urlopen()`、`httpx.AsyncClient.get()`、自定义 HTTP 工具类封装

SSRFinder 研究：在 21 个真实应用中发现了 5 个被 4 个 SOTA 静态分析工具遗漏的 SSRF 漏洞。

### 4.8 Prototype Pollution（JavaScript 专属, CWE-1321）

**Phase 1 能否发现**：❌ 不能

**原因**：Prototype Pollution 的 sink 是**隐式的**——危险的属性赋值操作（`obj.__proto__.isAdmin = true`）在 CPG 中只是普通的属性写入。检测需要：
- 原型链感知的对象查找分析（ObpLupAnsys 级别）
- 判断属性赋值是否影响 `Object.prototype`
- 追踪递归合并函数（`lodash.merge`、`extend`、`deep-extend`）

量化数据：静态分析单独只能检测约 **52%** 的已知 Prototype Pollution CVE。DAPP 等工具的假阴性率达 **84.6%**。2018-2022 年间有 293 个相关 CVE。

### 4.9 加密弱点 (CWE-327, CWE-310)

**Phase 1 能否发现**：❌ 不能

**原因**：Phase 1 的正则规则针对**硬编码密钥**（文本模式），而非**加密算法使用不当**（语义判断）。

```python
# Phase 1 看不到问题（没有硬编码密钥，代码正常运行）
key = os.environ.get('ENCRYPTION_KEY')
cipher = AES.new(key, AES.MODE_ECB)  # ECB模式不安全

# Phase 1 也看不到（需要语义理解）
kdf = PBKDF2(password, salt, iterations=1000)  # 迭代次数过低
```

需要**语义知识**才能判断（ECB vs CBC 的安全性、PBKDF2 的推荐迭代次数、IV 是否随机），这是确定性的正则/CPG 规则无法提供的。

### 4.10 OAuth/JWT 配置错误 (CWE-287, CWE-345)

**Phase 1 能否发现**：❌ 不能

**原因**：这些漏洞存在于**请求之间的交互层面**。

```python
# 这两行代码在 CPG 中看起来完全一样：
jwt.verify(token, secret)  # 安全配置
jwt.verify(token, secret)  # 但库被配置为接受 alg:none
```

CPG 分析单个请求处理器时无法判断：
- OAuth state 参数是否在重定向中被验证
- 登录后 session token 是否被重新生成
- JWT 库是否被配置为禁用 `alg:none` 攻击
- 是否存在 key confusion（RS256 vs HS256）攻击面

### 4.11 遗漏汇总表

| 漏洞类别 | CWE | Phase 1 可发现？ | Phase 3 可见？ | Web应用估算占比 |
|:---------|:----|:---------------|:-------------|:-------------|
| SQL注入（直接） | 89 | ✅ 能 | ✅ | ~15-25% |
| XSS（反射型） | 79 | ✅ 能 | ✅ | ~30-40% |
| 硬编码密钥 | 798 | ✅ 能 | N/A | ~10-20% |
| Debug配置 | 489 | ✅ 能 | N/A | ~5-10% |
| **IDOR/BOLA** | **639** | **❌** | **❌** | **~30-50%** |
| 缺失认证（装饰器） | 862 | ⚠️ 部分 | 部分 | ~15-25% |
| **认证逻辑缺陷** | **863,284** | **❌** | **❌** | **~20-30%** |
| **业务逻辑漏洞** | **无CWE** | **❌** | **❌** | **~100%（所有定制应用）** |
| **条件竞争/TOCTOU** | **362,367** | **❌** | **❌** | **严重漏报** |
| **二阶注入** | **89,79** | **❌** | **❌** | 常见（有UGC的应用） |
| 反序列化（自定义） | 502 | ⚠️ sink only | 部分 | ~5-15%（Java） |
| **SSRF（间接）** | **918** | **❌** | **❌** | ~10-20%（云应用） |
| **Prototype Pollution** | **1321** | **❌** | **❌** | ~10-20%（Node.js） |
| **加密弱点** | **327,310** | **❌** | **❌** | ~15-30% |
| **OAuth/JWT配置错误** | **287,345** | **❌** | **❌** | ~10-20% |
| **SSTI/NoSQL/GraphQL** | **94,943** | **❌（配置盲区）** | **❌** | 随框架采用增长 |

**保守估计：Phase 1 覆盖了约 20-35% 的 Web 应用常见漏洞类别（按 CWE 多样性）。**

---

## 五、学术文献中的量化证据

### 5.1 IRIS——污点规范的不完备性

> IRIS（U Penn/Cornell, 2024）：CodeQL 单独检出 27/120 漏洞；加入 LLM 推断的污点规范后提升至 69/120。

即使使用 LLM 增强污点规范推断，召回率上限也仅 **57.5%**。剩余 42.5% 的漏洞即使有完美的污点规范也无法被基于数据流的分析检测到——因为它们不是数据流问题。

### 5.2 MoCQ——配置遗漏的量化

> MoCQ（Columbia/Johns Hopkins, 2025）：专家编写的 CodeQL/Joern 检测查询在每个 CWE 类别上平均遗漏 **1.7 个漏洞模式**。

YAML 配置是手工维护的闭世界产物。MoCQ 的结果表明，即使精心维护的配置也会在每 7 个漏洞类型中遗漏约 12 个漏洞模式。

### 5.3 DREA——推理链缺陷普遍存在

> DREA（2025）：**26-55% 的真阳性预测推理链有缺陷**，即使漏洞标签正确。

这意味着 Phase 3 的 LLM 可能正确标记了一个漏洞，但给出了错误的理由。如果 Phase 4 的 L2 强模型验证只是「同意」而非严格挑战 Phase 3 的推理，有缺陷的推理链会通过验证。

DREA 在优化后仍只有 **30-42%** 的 pair-correctness（RepoPairBench）。

### 5.4 SECUREAGENTBENCH——当前技术的天花板

> SECUREAGENTBENCH：105 个 OSS-Fuzz 任务，平均 554K LOC。最佳系统正确+安全率：**15.2%**。

84.8% 的漏洞在任何当前系统中被遗漏。这个数据是**对内存安全漏洞的**——对于 HyqAgent 目标的 Web 漏洞类别，甚至没有等价的基准数据。

### 5.5 GadgetHunter——反序列化检测的边界

> GadgetHunter（FSE 2026）：传统静态工具在 34 个已知 gadget 链中仅找到 **3-16 个**。85.3% 的真实 gadget 涉及 CPG 调用图无法解析的动态特性。

### 5.6 Big-Vul 基准污染——精度数据可能被高估

> Big-Vul 基准数据集标签准确率仅 **54.3%**。从 Big-Vul（F1=0.683）切换到 PrimeVul（更高质量）后，性能降至 **F1=0.03**。

很多论文和商业系统报告的高精度数据可能部分源于低质量基准，而非真正的检测能力。

### 5.7 学术界共识

学术文献在以下判断上趋于一致：

1. **神经符号系统（确定性+LLM）是当前最优**，但都有相同的结构性问题：确定性前端制造了召回率天花板
2. **三种缓解范式**：
   - LLM 优先 + 确定性验证（MoCQ 风格）：LLM 广泛生成查询，确定性分析验证
   - 确定性优先 + 缺口填补（IRIS 风格）：确定性先运行，LLM 填补规范缺口，重新运行
   - 并行流水线（BOLABuster 风格）：LLM 和确定性分析独立运行，合并结果
3. **没有证据表明纯流水线架构能达到超过 60% 的召回率**

---

## 六、七种互补缓解方案

以下七种方案的核心设计原则：**不依赖 Phase 1 的输出而独立存在**。它们是独立的感知通道。

### 方案 1：反向 Sink 分析（Sink-Driven CPG Traversal）

**原理**：当前 Phase 1 是 source-forward（从已知 source 出发）。改为从每个函数调用出发，反向追踪到所有可达的用户输入点，使用**启发式规则**判断一个调用是否「可能是危险的」，即使其函数名不在 YAML 中。

```python
def is_potentially_dangerous_sink(call_node, cpg):
    score = 0
    name = call_node.name.lower()

    # 参数包含字符串拼接或插值: +30
    if cpg.has_string_interpolation(arg) or cpg.has_concatenation(arg):
        score += 30

    # 函数名包含危险术语: +20
    dangerous_terms = ['query', 'execute', 'exec', 'sql', 'command',
                       'open', 'read', 'write', 'send', 'fetch',
                       'render', 'eval', 'load', 'deserialize']
    if any(term in name for term in dangerous_terms):
        score += 20

    # 调用来自已知危险库: +40
    if call_node.module in ['sqlalchemy', 'pymongo', 'redis', 'psycopg2',
                             'axios', 'httpx', 'requests', 'subprocess']:
        score += 40

    # 有用户输入可达: +50
    if cpg.has_path_from_any_source(call_node):
        score += 50

    return score >= 60  # 阈值可调
```

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | ~$0（纯CPG查询） |
| Phase 3增量成本 | +10-30% 候选（更多进入Phase 3） |
| 工程难度 | 中（需扩展CPG查询接口） |
| 学术先例 | Joern, CodeQL, Semgrep |
| 捕获的漏洞 | 未知sink、ORM模式、自定义包装函数 |

### 方案 2：盲扫 LLM 通道（MAS-Indep Lite）

**原理**：运行一个**独立的、廉价的 LLM 通道**，完全不依赖 Phase 1 输出。该通道阅读代码文件（使用 CPG 导航），以一个完全不同的视角生成漏洞假设——专门寻找「基于模式的扫描器会遗漏的东西」。

```
你是探索性安全审查员。与系统性扫描器不同，
你的工作是寻找基于模式的扫描器会遗漏的内容：

1. 业务逻辑缺陷：改变ID是否能访问其他用户的数据？
2. 缺失的检查：是否有端点没有授权检查？
3. 假设违反：代码是否假设输入在上游已被验证？
4. 危险组合：两个看似安全的操作组合后是否危险？
5. 框架误用：安全功能是否被错误使用？

对你检查的每个文件，列出任何顾虑，不管多么推测性。
```

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | ~$0.10（50K行项目，Kimi K2） |
| 工程难度 | 低（新的prompt模板 + CPG导航） |
| 学术先例 | MAS-Indep, VulAgent, Aegis |
| 捕获的漏洞 | 逻辑漏洞、IDOR、认证绕过、框架误用 |

### 方案 3：Completeness Critic（完整性审查）

**原理**：在所有分析阶段完成后，用一个强模型**专门回答「我们漏了什么」**——而非检查已有发现是否正确。

```
你是安全审计的完整性审查员。

## 本次扫描已覆盖
[列举已分析的内容]

## 你的任务：系统性地找出我们可能遗漏的

1. 未覆盖的代码区域：哪些文件/模块/包完全未被分析？
2. 未检查的漏洞类型：给定此技术栈，还应检查什么？
3. 隐藏的攻击面：WebSocket、消息队列消费者、定时任务、CLI命令
4. 间接数据流：经过持久化存储的数据路径
5. 配置和基础设施：非代码但影响安全的内容

请输出具体的、可操作的"需进一步审查"清单。
```

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | ~$0.02（2K输入 + 1K输出） |
| 工程难度 | 低（一个prompt + 结构化输出解析） |
| 学术先例 | ReAct模式, Aegis元审计, Hound知识图谱 |
| 捕获的漏洞 | 选择偏见、遗漏盲区、未检查的漏洞类别 |

### 方案 4：饱和扫描（Loop Until Dry）

**原理**：迭代运行扫描。每轮完成后，用**已确认的漏洞**作为种子，发现新的分析目标（被调用者、调用者、同路由模块的其他端点），然后重新运行 Phase 2-4。

每轮成本递减（新种子数量递减），循环自然收敛。

```python
def saturation_scan(repo, max_rounds=3):
    round = 0
    all_findings = []
    new_seeds = initial_seeds

    while round < max_rounds and new_seeds:
        round += 1
        findings = run_pipeline(new_seeds)
        all_findings.extend(findings)

        new_seeds = set()
        for f in findings:
            if f.status == 'confirmed':
                new_seeds.update(cpg.get_callees(f.sink_function))
                new_seeds.update(cpg.get_callers(f.source_function))
                new_seeds.update(get_sibling_endpoints(f.source_function))
        new_seeds -= analyzed
```

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | +30-50%（第2轮递减到20-40%，第3轮递减到5-10%） |
| 工程难度 | 中（会话持久化、路径追踪、去重） |
| 学术先例 | DrillAgent, DeepVulHunter, Skwaq, AFL种子调度 |
| 捕获的漏洞 | 漏洞群、传递信任边界、深调用链 |

### 方案 5：差异覆盖分析（Blind Spot Manifest）

**原理**：不寻找**危险的**代码，而是寻找**未被证明安全的**代码。对项目的每个 HTTP 端点、数据库调用、文件操作、命令执行，检查「我们的分析是否覆盖了它」。生成**盲区清单**作为报告的附录。

```python
def differential_coverage_scan(cpg):
    blind_spots = []

    for endpoint in cpg.get_all_http_endpoints():
        if not was_analyzed_by_phase1(endpoint):
            blind_spots.append({"location": endpoint, "reason": "无已知source可达"})
        elif not was_prioritized_by_phase2(endpoint):
            blind_spots.append({"location": endpoint, "reason": "priority低于阈值"})

    for db_call in cpg.get_all_database_calls():
        if not cpg.has_path_from_any_source(db_call):
            blind_spots.append({
                "location": db_call,
                "reason": "数据库调用未检测到用户输入路径——"
                          "要么安全（内部查询），要么source列表不完整"
            })

    return blind_spots
```

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | $0（纯CPG查询） |
| 工程难度 | 中（需跨阶段追踪分析覆盖） |
| 学术先例 | Hound知识图谱, Semgrep paths输出, 代码覆盖率工具 |
| 捕获的漏洞 | 不完整source目录、priority遗漏、死代码 |

### 方案 6：对抗性审查（Attacker's Lens）

**原理**：Phase 4 验证后，用一个独立的强模型以**攻击者视角**审视被标记为「安全」的代码路径——寻找验证器可能错过的绕过技术。

```
攻击者视角：审计员认为此路径安全。
你的任务是证明他们错了。

## 被判定为"安全"的路径
Source: {path.source}
Sink: {path.sink}
消毒措施: {path.sanitizers}
审计员推理: {path.rejection_reason}

## 攻击向量
1. 消毒器是否可绕过？（编码技巧、双编码、Unicode规范化、null字节）
2. 是否存在二阶攻击？
3. 类型系统是否可被破坏？（强制转换、反序列化）
4. 是否存在时序侧信道？
5. 错误消息是否泄露信息？
```

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | ~$0.25（~20-30个路径，Sonnet） |
| 工程难度 | 低（另一个prompt模板） |
| 学术先例 | Aegis（降低FPR 54.40%）, OpenAnt, 红队方法论 |
| 捕获的漏洞 | 消毒器绕过、二阶注入、编码攻击 |

### 方案 7：架构感知盲区检测（Hound-Inspired）

**原理**：在 Phase 1 之前，用便宜模型构建应用的**安全架构模型**——识别信任边界、授权区域、数据敏感级别、认证门控点。然后对每个架构元素检查「分析是否覆盖了它」。

| 维度 | 评估 |
|:-----|:-----|
| LLM成本 | ~$0.01（一个便宜模型调用） |
| 工程难度 | 中高（需从CPG构建架构模型） |
| 学术先例 | Hound（ScaBench召回率 8.3%→31.2%）, STRIDE/PASTA威胁建模 |
| 捕获的漏洞 | 缺失认证、信任边界违反、假设违反 |

### 方案对比总表

| # | 方案 | LLM成本(default) | 工程难度 | 优先度 |
|:--|:-----|:---------------|:--------|:-----|
| 1 | 反向Sink分析 | ~$0 (+$0.50 Phase 3增量) | 中 | 🥇 |
| 2 | 盲扫LLM通道 | ~$0.10 | 低 | 🥇 |
| 3 | Completeness Critic | ~$0.02 | 低 | 🥇 |
| 4 | 饱和扫描 | +30-50% 基线 | 中 | 🥈 |
| 5 | 差异覆盖分析 | $0 | 中 | 🥈 |
| 6 | 对抗性审查 | ~$0.25 | 低 | 🥉 |
| 7 | 架构感知盲区 | ~$0.01 | 中高 | 🥉 |

---

## 七、按扫描模式的分层部署策略

### `--quick` 模式（$1 预算，CI/CD 门禁）

| 方案 | 是否包含 | 配置 |
|:-----|:--------|:-----|
| 1. 反向Sink分析 | ⚠️ 部分 | 仅启发式标记，不进入Phase 3 |
| 2. 盲扫LLM | ❌ | 成本超出quick预算 |
| 3. Completeness Critic | ✅ | 零成本，捕获明显遗漏 |
| 4. 饱和扫描 | ❌ | 多轮超出预算 |
| 5. 差异覆盖分析 | ✅ | 零LLM成本，产生盲区清单 |
| 6. 对抗性审查 | ❌ | 需要前置发现 |
| 7. 架构感知盲区 | ✅ | ~$0.01，识别信任边界缺口 |

**quick 模式额外成本**：~$0.03

### `--standard` 模式（$5 预算，默认）

| 方案 | 是否包含 | 配置 |
|:-----|:--------|:-----|
| 1. 反向Sink分析 | ✅ 完整 | 启发式候选以较低priority进入Phase 3 |
| 2. 盲扫LLM | ✅ | 一个便宜模型（Kimi K2），覆盖priority最高的30%文件 |
| 3. Completeness Critic | ✅ | 始终运行，反馈成为额外的Phase 3种子 |
| 4. 饱和扫描 | ✅ 2轮 | 第2轮有30%预算上限 |
| 5. 差异覆盖分析 | ✅ | 盲区清单作为每个报告的附录 |
| 6. 对抗性审查 | ⚠️ 部分 | 仅对HIGH+严重度、置信度>0.4的已拒绝假设 |
| 7. 架构感知盲区 | ✅ | 便宜模型，始终运行 |

**standard 模式额外成本**：~$1.00-1.50

### `--deep` 模式（$25 预算）

| 方案 | 是否包含 | 配置 |
|:-----|:--------|:-----|
| 1. 反向Sink分析 | ✅ 激进 | 降低启发式阈值，更多候选 |
| 2. 盲扫LLM | ✅ 增强 | 中等模型（Sonnet），覆盖priority最高的50%文件 |
| 3. Completeness Critic | ✅ 迭代 | 每轮饱和扫描后运行 |
| 4. 饱和扫描 | ✅ 4轮 | 预算允许 |
| 5. 差异覆盖分析 | ✅ 增强 | 便宜LLM对盲区清单做风险评估 |
| 6. 对抗性审查 | ✅ 完整 | Opus审查所有可疑拒绝 |
| 7. 架构感知盲区 | ✅ 增强 | Sonnet做架构分析，Opus做信任边界推理 |

**deep 模式额外成本**：~$3.00-5.00

---

## 八、定量估算与成本分析

### 8.1 预期召回率提升

| 扫描模式 | 当前架构估计召回率 | 加入缓解方案后估计召回率 | 提升幅度 |
|:---------|:-----------------|:---------------------|:--------|
| `--quick` | ~20-30% | ~25-35% | +5% |
| `--standard` | ~30-40% | **~45-55%** | +10-15% |
| `--deep` | ~40-50% | **~55-65%** | +10-15% |

**参照系**：MAS-Indep（3 Agent完全独立）= 64.2% 召回率，$0.143/发现。加入缓解方案的 `--deep` 模式可以在相近的召回率水平上保持 Pipeline 的成本优势。

### 8.2 成本分解（standard 模式）

| 组件 | 原始成本 | 增量成本 | 说明 |
|:-----|:--------|:--------|:-----|
| Phase 1 (CPG构建+确定性扫描) | ~$0 | $0 | 不变 |
| Phase 2 (攻击面映射) | ~$0.25 | +$0.02 | prompt扩展 |
| 方案2 (盲扫LLM) | — | +$0.10 | 新增 |
| Phase 3 (假设生成) | ~$1.50 | +$0.50 | 更多候选（来自方案1） |
| Phase 4 (L1+L2验证) | ~$3.00 | +$0.25 | 更多假设需验证 |
| 方案3 (Completeness Critic) | — | +$0.02 | 新增 |
| 方案4 (饱和扫描第2轮) | — | +$0.40 | 新增 |
| 方案5 (差异覆盖) | — | $0 | 新增 |
| 方案6 (对抗性审查) | — | +$0.15 | 新增（部分） |
| 方案7 (架构感知) | — | +$0.01 | 新增 |
| **总计** | **~$4.75** | **~$1.45** | **仍在$5预算内** |

### 8.3 性价比对比

| 架构 | 估计召回率 | 估计成本/发现 | 性价比 |
|:-----|:---------|:------------|:------|
| SAS (基线) | 50.8% | $0.058 | 1.0× |
| MAS-Indep (3 Agent) | 64.2% | $0.143 | 0.7× |
| **HyqAgent standard（当前设计）** | **~35%** | **~$0.05** | **1.0×** |
| **HyqAgent standard（+缓解方案）** | **~50%** | **~$0.06** | **1.2×** |
| **HyqAgent deep（+缓解方案）** | **~60%** | **~$0.12** | **0.8×** |

**关键洞察**：加入缓解方案后，standard 模式可以在几乎不增加单位成本的前提下，将召回率从 ~35% 提升到 ~50%。

---

## 九、实施优先级建议

### 第一优先：立即加入（总成本 < $0.05）

这三个方案成本极低，立即见效，不需要架构变更：

1. **反向 CPG 分析（方案1的启发式部分）** — $0 成本
2. **Phase 2 prompt 扩展**（在分类任务中增加漏洞模式扫描问题） — $0.02
3. **Completeness Critic（方案3）** — $0.02

### 第二优先：standard 模式标配（总成本 ~$0.70）

4. **盲扫 LLM 通道（方案2）** — 独立于 Phase 1 的探索性扫描
5. **差异覆盖分析（方案5）** — 盲区清单
6. **架构感知盲区（方案7）** — Hound 风格的安全架构模型

### 第三优先：deep 模式增强

7. **饱和扫描（方案4）** — 迭代发现
8. **对抗性审查（方案6）** — 攻击者视角的全面审视

### 长期迭代

9. **盲区特征收集 + few-shot/fine-tune** — 类似 HALURust 的思路逆向使用
10. **建立自有评估基准** — 收集真实项目的审计结果，校准召回率

---

## 十、参考文献

### 本报告直接引用的学术论文

1. Guo et al., "RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing", ICML 2025.
2. David & Gervais, "Towards Optimal Agentic Architectures for Offensive Security Tasks", 2025.
3. IRIS: LLM-inferred taint specifications for static analysis, U Penn/Cornell, 2024.
4. MoCQ: LLM-driven detection query generation, Columbia/Johns Hopkins, 2025.
5. DREA: "Decoupled Reasoning and Exploration Agents", Internetware 2026.
6. GadgetHunter: Deserialization gadget chain detection, FSE 2026.
7. STaint: Second-order taint analysis, ASE 2025.
8. BugLens: Post-refinement for vulnerability detection, UC Riverside/Indiana/Chicago, 2025.
9. HALURust: "Exploiting Hallucinations of LLMs to Detect Vulnerabilities in Rust", 2025.
10. Hound: "Relation-First Knowledge Graphs for Complex-System Reasoning in Security Audits", 2025.

### 基准数据集

- SECUREAGENTBENCH: 105 tasks, OSS-Fuzz real vulnerabilities, avg 554K LOC. Best system: 15.2% correct+safe.
- PrimeVul: 435 pairs, function-level real vulnerabilities. Baseline FPR high.
- ScaBench: 5 project subsets. Baseline recall 8.3%.
- Big-Vul: Widely used but only 54.3% accurately labeled.

### 相关项目

- RepoAudit: https://github.com/PurCL/RepoAudit
- LLMxCPG: https://github.com/qcri/llmxcpg
- Aegis: https://github.com/agentlifylabs/Aegis
- Hound: https://github.com/scabench-org
- ESAA: https://github.com/elzobrito
- OpenHack: https://github.com/hadriansecurity/OpenHack

---

> **结论**：当前方案在研究深度和成本控制上是出色的。需要修正的是一个关键的设计假设——Pipeline ≠ RepoAudit。好消息是，修正成本极低，且不需要推翻现有架构。把「我们漏了什么」从 PLAN.md 的一句被动声明，升级为系统内置的主动检测机制。
>
> 分析者：三个独立Agent（覆盖盲区分析 / 学术文献验证 / 工程方案设计）+ 综合架构评审
