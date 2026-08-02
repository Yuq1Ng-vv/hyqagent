# 白盒代码审计Agent — 深度研究报告

> 研究时间：2026年8月2日
> 研究方法：3个专业Agent并行研究 + 8轮Web搜索 + 3轮交叉辩论
> 覆盖范围：20+篇论文、15+个开源/商业项目、多个基准数据集

---

## 目录

1. [核心发现总览](#一核心发现总览)
2. [架构模式深度对比](#二架构模式深度对比)
3. [CPG + LLM：已验证的最优技术栈](#三cpg--llm已验证的最优技术栈)
4. [验证模块：从可选项到必选项](#四验证模块从可选项到必选项)
5. [幻觉问题与缓解策略](#五幻觉问题与缓解策略)
6. [模型选型与成本经济学](#六模型选型与成本经济学)
7. [动态验证与沙箱执行](#七动态验证与沙箱执行)
8. [信念系统与持久化记忆](#八信念系统与持久化记忆)
9. [已知系统全面对比](#九已知系统全面对比)
10. [学术基准与现实场景的差距](#十学术基准与现实场景的差距)
11. [数据飞轮与持续学习](#十一数据飞轮与持续学习)
12. [参考文献与项目索引](#十二参考文献与项目索引)

---

## 一、核心发现总览

### 1.1 最重要的五个发现

| # | 发现 | 数据支撑 | 置信度 |
|:--|:-----|:--------|:------|
| 1 | **"多Agent一定更好"是危险假设** — MAS-Central和MAS-Decent甚至不如单Agent | 600-run对照实验 | ⭐⭐⭐⭐⭐ |
| 2 | **CPG + LLM 是最优技术组合** — 结构精度与语义理解互补 | LLMxCPG(USENIX)、LLM4FPM、codebadger(ICSE) | ⭐⭐⭐⭐⭐ |
| 3 | **Validator是必选项** — 移除后误报率翻3.5倍 | RepoAudit消融实验 | ⭐⭐⭐⭐⭐ |
| 4 | **验证策略必须按漏洞类型定制** — 单一Validator无法覆盖所有漏洞 | 跨系统对比分析 | ⭐⭐⭐⭐ |
| 5 | **核心瓶颈是工程架构成熟度，而非模型能力** | DARPA AIxCC成本数据 + SEC-Bench Pro | ⭐⭐⭐⭐ |

### 1.2 帕累托最优前沿

```
检出率
  64% │                              ★ MAS-Indep ($0.143/发现)
      │                    ★ MAS-Hybrid
  50% │        ★ SAS ($0.058/发现)
      │  ★ SAS (cheap model)
  30% │
      └──────────────────────────────────────→ 成本/发现
        $0.05    $0.10    $0.15    $0.20
```

**关键洞察**：成本-质量前沿是非单调的。MAS-Central和MAS-Decent的协调开销完全吞噬了多Agent的收益。

---

## 二、架构模式深度对比

### 2.1 五大架构模式

#### A. 单Agent + 工具增强（SAS）

**代表系统**: SAS baseline (UCL研究), Claude Code安全审计

| 维度 | 评分 | 说明 |
|:-----|:-----|:-----|
| 检出率 | 50.8% | 基线水平 |
| 成本/发现 | **$0.058** | 最低 |
| 首次验证延迟 | **53s** | 最快 |
| 工程复杂度 | **最低** | 单Agent维护成本低 |
| 认知负荷 | 高 | 大项目面临context rot |
| 独立验证 | 无 | 自提自验，无checks-and-balances |

**适用场景**: CI/CD快速门禁、小项目(< 5万行)、已知漏洞模式扫描

#### B. 多Agent独立并行（MAS-Indep）

**代表系统**: MAS-Indep (UCL研究), ZubairLK/security-agents

| 维度 | 评分 | 说明 |
|:-----|:-----|:-----|
| 检出率 | **64.2%** | 最高 |
| 成本/发现 | $0.143 | 2.5x SAS |
| 首次验证延迟 | 111.9s | 2x SAS |
| 去重难度 | 高 | 同一漏洞被不同Agent以不同方式报告 |
| 多样性红利 | 高 | 不同视角捕获不同类型漏洞 |

**适用场景**: 发布前深度审计、高价值目标、多角度覆盖需求

#### C. 中心化编排（MAS-Central）

**代表系统**: OpenHack, Takumi, MAS-Central (UCL)

| 维度 | 评分 | 说明 |
|:-----|:-----|:-----|
| 检出率 | 未超越SAS | 编排器成为瓶颈 |
| 任务边界 | 清晰 | 每个子Agent职责明确 |
| 独立性 | 好 | 子Agent独立可替换 |
| 编排器风险 | **高** | 路由错误系统性传播 |

**关键教训**: 编排器的prompt高度复杂，维护成本高；且路由错误会导致漏检。

#### D. 对等投票（MAS-Decent）

**代表系统**: MAS-Decent (UCL)

| 维度 | 评分 | 说明 |
|:-----|:-----|:-----|
| 检出率 | 未超越SAS | 投票引入的保守偏见 |
| 精确率 | 较高 | 投票过滤了一些噪声 |

**关键教训**: 投票机制倾向于保守——只有多数Agent都同意的发现才能通过，导致漏检增加。

#### E. 流水线（Pipeline）

**代表系统**: RepoAudit, Revelio, AgentStalker, DREA

| 维度 | 评分 | 说明 |
|:-----|:-----|:-----|
| 可组合性 | 高 | 阶段可独立替换 |
| 成本可控 | 高 | 精确归因每阶段消耗 |
| 刚性 | 高 | 强制完整序列 |
| 错误传播 | 中 | 上游遗漏下游无法补偿 |

### 2.2 架构选择决策树

```
代码库规模
├─ < 5万行, 单一语言  ──→ SAS (Haiku/Sonnet单Agent)
├─ < 5万行, 多语言     ──→ SAS + 多语言CPG
├─ 5-20万行            ──→ SAS + CPG + 分层模型
├─ 20-100万行          ──→ MAS-Indep (3 Agent并行)
└─ > 100万行           ──→ Pipeline + 分模块MAS-Indep

审计目标
├─ CI/CD门禁 (< 2min)   ──→ SAS + 确定性规则为主
├─ PR Review (< 5min)   ──→ SAS + L1验证
├─ 发布审计 (< 1h)      ──→ MAS-Indep
└─ 合规审计 (< 8h)      ──→ Full Pipeline + 沙箱

预算约束
├─ < $1/项目            ──→ 纯确定性 + 便宜模型假设生成
├─ $1-5/项目            ──→ SAS + L1/L2验证
├─ $5-25/项目           ──→ MAS-Indep + 完整验证
└─ > $25/项目           ──→ 全量 + 沙箱PoC
```

---

## 三、CPG + LLM：已验证的最优技术栈

### 3.1 为什么CPG是必需品而非可选项

CPG解决的是LLM的根本弱点：长距离依赖追踪和精确结构分析。

**对比实验**（RepoAudit论文）：

| 方法 | 精确率 | 说明 |
|:-----|:------|:-----|
| 直接让LLM读全部代码 | ~30% | 上下文窗口不够，大量幻觉 |
| LLM + AST | ~55% | 有语法结构但缺数据流 |
| LLM + CPG | **78.43%** | 数据流精确 + 语义理解 |

**性能差异**（LLM4FPM论文）：
- 全量代码输入 → LLM: F1 ~40%
- CPG精确切片 → LLM: **F1 >99%** (Juliet数据集)

### 3.2 关键系统

| 系统 | 会议/年份 | CPG工具 | 创新点 |
|:-----|:---------|:--------|:------|
| **LLMxCPG** | USENIX 2025 | Joern | LLM生成CPGQL查询提取切片 |
| **LLM4FPM** | arXiv 2025 | Joern/自定义eCPG | 行级精确切片 + FARF算法 |
| **codebadger** | ICSE 2026 | Joern | MCP Server标准化CPG接口 |
| **Skwaq** | 开源项目 | LadybugDB | 图优先多Agent + 自改进循环 |
| **ClearAgent** | LMPL 2025 | 自定义 | 二进制级CPG + 漏洞验证 |

### 3.3 CPG构建的核心挑战

| 挑战 | 难度 | 解决方案 |
|:-----|:-----|:--------|
| 跨文件调用解析 | 中 | import/require静态分析 + 启发式 |
| 动态调用（反射、eval） | 高 | 保守over-approximation |
| 框架特定路由 | 中 | 框架提取器（Flask/Express/Spring） |
| 异步/回调数据流 | 高 | 基于Promise/Future的边标注 |
| C++虚函数/模板 | 很高 | 暂不处理（后续扩展） |

---

## 四、验证模块：从可选项到必选项

### 4.1 RepoAudit的决定性证据

**消融实验结果**：

| 移除的组件 | 真阳性变化 | 假阳性变化 | 成本变化 |
|:----------|:----------|:----------|:--------|
| **Validator** | -12% | **+245.5%** | -30% |
| Program Abstraction | **-47.5%** | +181.8% | -20% |
| Agent Memory（缓存） | -5% | +10% | **+300-400% (极端+3000%)** |

**结论**：Validator减少的假阳性价值远超其成本。缓存减少的成本远超其存储代价。Program Abstraction是真阳性发现的核心能力。

### 4.2 验证策略必须按漏洞类型定制

| 漏洞类型 | 最优验证方式 | 为什么 | 代表系统 |
|:--------|:------------|:------|:--------|
| **内存破坏** (BOF/UAF/NPD) | 编译+动态执行+Sanitizer | 需要运行时状态才能确认 | DrillAgent, Revelio |
| **注入类** (SQLi/XSS/CMDi) | 静态数据流验证 | 数据流路径清晰可追踪 | RepoAudit, VulAgent |
| **逻辑漏洞** (IDOR/Auth Bypass) | 多Agent对抗性推理 | 需要从攻击者和防御者双视角审视 | Aegis, OpenAnt |
| **共识协议漏洞** | 多实现交叉验证 | 单一实现看不出逻辑缺陷 | Agora SPECAnchoring |
| **加密误用** | 规则+模式匹配 | 确定性可判断（ECB vs CBC） | Semgrep确定性规则 |
| **反序列化** | 静态分析+已知gadget链检查 | 需要漏洞库知识 | RAG增强 |

### 4.3 六层验证金字塔

```
         ▲  L6: 交叉验证 (不同模型独立验证 + 投票)
        ▲▲  L5: 沙箱PoC执行 (Docker隔离 + Sanitizer插桩)
       ▲▲▲  L4: PoC自动生成 (DrillAgent/PoC-Adapt模式)
      ▲▲▲▲  L3: 路径条件可满足性 (LLM约束推理)
     ▲▲▲▲▲  L2: 数据流事实验证 (CPG确定性查询)
    ▲▲▲▲▲▲  L1: 代码模式匹配 (tree-sitter + 正则)
```

| 层级 | 成本/发现 | 适用所有漏洞？ | 建议 |
|:----|:---------|:-------------|:-----|
| L1 | ~$0 | 是 | **默认必选** |
| L2 | ~$0.01 | 有数据流路径的 | **默认必选** |
| L3 | ~$0.10 | 有条件分支的 | 中置信+ |
| L4 | ~$0.50 | 可生成PoC的 | HIGH+ |
| L5 | ~$2.00 | 可沙箱执行的 | CRITICAL |
| L6 | ~$0.50 | 是 | CRITICAL + 高不确定性 |

---

## 五、幻觉问题与缓解策略

### 5.1 幻觉的三种表现形式

| 类型 | 表现 | 危害 | 频率 |
|:-----|:-----|:-----|:-----|
| **假阳性漏洞** | 无中生有报告不存在的漏洞 | 浪费安全工程师时间 | 21.6% (RepoAudit无Validator) |
| **遗漏真漏洞** | 过度自信或上下文盲区导致漏报 | 安全风险 | 与代码长度、漏洞类型强相关 |
| **错误数据流推理** | 推理看似合理但路径不可达 | 最具欺骗性，难以人工识别 | 26-55%的真实阳性伴随有缺陷的推理链 |

### 5.2 模型幻觉率对比

| 模型 | 幻觉率 | 场景 | 来源 |
|:-----|:------|:-----|:-----|
| GPT-4.1 | 6.10% | 包名幻觉 | Churilov 2026 |
| Claude 3.7 Sonnet | ~5.41% | 包名幻觉 | Churilov 2026 |
| DeepSeek V3 | 5.89% | 包名幻觉 | Churilov 2026 |
| **商业模型平均** | **~5.2%** | 多种场景 | 多项研究综合 |
| **开源模型平均** | **~21.7%** | 多种场景 | 多项研究综合 |
| Claude 3.7 Sonnet (+Validator) | ~13.2% | 漏洞检测 | RepoAudit |
| DeepSeek R1 (+Validator) | ~11.5% | 漏洞检测 | RepoAudit |

**关键结论**：加上Validator后，所有模型在漏洞检测上的幻觉率都从~20%+降至~11-13%。Validator是通用的幻觉抑制剂。

### 5.3 六层幻觉防御体系

| 层级 | 技术 | 代表系统 | 幻觉抑制效果 |
|:-----|:-----|:--------|:-----------|
| L1 | 结构化CoT提示 | GPTVD | 精度+21.99% |
| L2 | RAG知识锚定 | DeepVulHunter | 准确率75.3% |
| L3 | 程序分析验证 | RepoAudit Validator | 误报-245.5% |
| L4 | 多模型交叉验证 | LLMpatronous | 消除单一模型偏见 |
| L5 | 执行反馈闭环 | DrillAgent, Verify Before You Fix | 消除不必要修复131.7% |
| L6 | 对抗性微调 | HALURust | F1=77.3%, +10% vs 传统 |

### 5.4 HALURust：逆向利用幻觉

**核心思路**：
1. 强制LLM假设代码有漏洞 → 对安全代码产生"幻觉报告"
2. 收集真漏洞的正确分析和安全代码的幻觉报告
3. 两类数据一起微调分类器
4. 分类器学会区分"真实漏洞的报告特征"vs"幻觉漏洞的报告特征"

**结果**：F1=77.3%，比传统代码微调方法提升~10%

**局限**：
- 仅在Rust单一语言验证
- 训练-推理分布偏移风险
- 不适合单独使用，适合作为辅助增强环节

---

## 六、模型选型与成本经济学

### 6.1 代码审计基准对比

**Factory.ai 代码审查基准** (2026年4月, 50个PR, 167个验证Bug):

| 模型 | Mean F1 | 成本/PR | 性价比 |
|:-----|:-------|:--------|:------|
| GPT-5.2 | **60.5%** | $1.25 | 48.4 |
| Claude Opus 4.6 | 59.8% | $3.11 | 19.2 |
| Claude Sonnet 4.6 | 57.9% | $1.15 | 50.3 |
| GLM-5.1 | 56.3% | $1.06 | 53.1 |
| Kimi K2.5 | 51.9% | **$0.41** | **126.6** |
| Gemini 3 Flash | 50.0% | $0.34 | 147.1 |

### 6.2 "Optimal Agentic Architectures"基准

| 模型 | 验证检出率 | 成本/发现 |
|:-----|:---------|:---------|
| Kimi K2 | **52.0%** | **$0.047** |
| GPT-5.2 | 未明确 | $0.258 |

### 6.3 模型Token成本对比 (per 1M tokens)

| 模型 | Input | Output | 综合成本比 |
|:-----|:------|:-------|:---------|
| GPT-5.2 | $1.75 | $14.00 | 基线 |
| Claude Opus 4.6 | $15.00 | $75.00 | ~5x |
| Claude Sonnet 4.6 | $3.00 | $15.00 | ~1x |
| Kimi K2-Thinking | $0.47 | $2.00 | **~0.15x** |
| Kimi K2 Instruct | $0.50 | $0.50 | **~0.07x** |
| GLM-5.2 | ~$0.50 | ~$1.00 | ~0.08x |

### 6.4 最优模型级联策略

```
                    任务量占比      模型选择         成本占比
确定性扫描            40%          无LLM             0%
攻击面分类/摘要       25%          Kimi K2 ($0.50)   ~1%
简单假设生成          15%          Kimi K2 ($0.50)   ~2%
复杂假设生成          10%          Sonnet ($3/$15)   ~15%
中置信验证            7%           Sonnet ($3/$15)   ~32%
高价值验证            3%           Opus ($15/$75)    ~50% ← 最大单项成本！

优化方向：
- 提高L1确定性验证的过滤率，减少进入强模型的任务量
- 缓存相似路径的验证结果
- 对低严重度发现直接使用中等模型验证
```

---

## 七、动态验证与沙箱执行

### 7.1 现实数据：从发现到PoC的巨大鸿沟

| 系统 | 领域 | PoC生成成功率 | 说明 |
|:-----|:-----|:------------|:-----|
| SEC-Bench Pro | V8 | **32-38.8%** | 183个V8漏洞 |
| SEC-Bench Pro | SpiderMonkey | **48.8%** | 最高水平 |
| PoCo | 智能合约 | 64% 正确PoC | 50/50可执行 |
| MAPTA | Web应用 | 76.9% 基准成功率 | XBOW基准 |
| DARPA AIxCC | 通用 | 77%发现，61%修补 | $359K总成本 |

### 7.2 沙箱执行的核心工程要素

```yaml
沙箱配置:
  隔离: Docker容器，每任务独立
  工具链: gcc/clang + ASAN + UBSAN + coverage插桩
  监控: 7层独立监控 (ebpf + syscall + network + file + process + memory + time)
  限制:
    memory: 2GB
    timeout: 30min
    network: 隔离 (防止exploit外连)
    pid: 限制
  防伪造:
    每次构建生成全新随机flag
    仅扫描真实应用响应
    拒绝Agent自报
  多镜像:
    漏洞版本 + 修复版本 + 最新版本 三镜像同时验证
```

### 7.3 动态验证的成本阶梯

| 模式 | 成本/漏洞 | 延迟 | 适用 |
|:-----|:--------|:-----|:-----|
| 快速静态扫描 | ~$0.05 | 秒级 | CI/CD门禁 |
| 静态+数据流验证 | ~$0.50 | 分钟级 | 常规审计 |
| +PoC生成 | ~$5.00 | 10-30分钟 | HIGH+漏洞 |
| +沙箱执行 | ~$20.00 | 30分钟-2小时 | CRITICAL漏洞 |
| 全量动态验证 | ~$20,000 | 数天 | DARPA AIxCC级竞赛 |

---

## 八、信念系统与持久化记忆

### 8.1 Hound（2025年9月）

**核心创新**：
- **关系优先知识图谱**：不冻结视图，而是分析师定义的持久化图（授权映射、价值流、调用图、不变量）
- **类型化注释**：(observation/assumption) 带字节偏移证据链接
- **漏洞假设生命周期**：`proposed → investigating → supported → refuted → confirmed/rejected`
- **上下文压缩**：超限时旧历史压缩为"记忆笔记"

**效果**：ScaBench微观召回率 8.3% → 31.2%

### 8.2 ESAA-Security（2025年3月）

**核心创新**：
- **事件溯源 + CQRS**：追加式事件日志是唯一真相来源
- **Agent不直接修改状态**：只发出结构化意图，由编排器验证后持久化
- **6个审计不变量**：claim-before-work, complete-after-work, prior-status consistency, lock ownership, boundary discipline, done immutability
- **确定性重放**：SHA-256链式验证

**规模**：4阶段、26任务、16安全领域、95可执行检查

### 8.3 BitsAI-CR（字节跳动，FSE 2025）

**生产规模**：12,000+周活用户，生产运行数月

**三个反馈通道**：
1. 用户直接点赞/踩 (实时)
2. 人工精度标注 (日采样≤10%，周度聚合)
3. Outdated Rate监控 (自动跟踪)

**Outdated Rate机制**：即使告警技术正确（高精度），如果开发者从不修改相关代码（低Outdated Rate），系统自动退役该规则。这解决了"理论上正确但实际无用"的问题。

**18周效果**：
- RuleChecker精度：27.9% → 62.6%
- ReviewFilter精度：35.6% → 75.0%

---

## 九、已知系统全面对比

### 9.1 学术系统

| 系统 | 会议/年份 | 架构 | Agent数 | 漏洞类型 | 精度 | 成本 | 开源 |
|:-----|:---------|:-----|:--------|:--------|:-----|:-----|:-----|
| **RepoAudit** | ICML 2025 | 3-stage pipeline | 3(逻辑) | NPD/MLK/UAF | 78.43% | $2.54/项目 | MIT ✅ |
| **DREA** | Internetware 2026 | 2-agent decoupled | 2 | Memory safety | 30-42% correct | 16-48x低于基线 | 未公开 |
| **Revelio** | arXiv 2026 | 2-stage pipeline | 2(逻辑) | Memory safety | 0% FP | ~$42/项目 | MIT ✅ |
| **VulAgent** | 2025 | Multi-perspective | 多 | 多类型 | 未明确 | 未明确 | 部分 |
| **Aegis** | 2025 | Meta-auditing | 3+ | 多类型 | 降低FPR 54.40% | 未明确 | MIT ✅ |

### 9.2 工业/开源系统

| 系统 | 组织 | 架构 | 特色 |
|:-----|:-----|:-----|:-----|
| **OpenHack** | Hadrian Security | 5-phase state machine | 检察官与法官分离，人类门控点 |
| **AgentStalker** | 开源 | 4-stage pipeline | Thin logic + thick orchestration |
| **Takumi** | Shisho.dev | Sequential multi-agent | Feature enumeration workflow |
| **Hound** | Bernhard Mueller | KG + 4-agent roles | 关系优先知识图谱@ |
| **ESAA-Security** | Elzo Brito | Event-sourced 4-phase | 密码学审计链 |
| **Spark** | Code Intelligence | Autonomous fuzzing | 44.7%更高代码覆盖率 |
| **WhiteFox** | UIUC | 2-agent framework | 编译器fuzzing，101个bug |

### 9.3 核心设计原则对比

| 原则 | 采用系统 | 未采用系统 | 判断 |
|:-----|:--------|:---------|:-----|
| 提出者≠批准者 | OpenHack, Aegis | RepoAudit, DREA | **强烈推荐** |
| 确定性先行 | DREA, Griffin AI | 早期系统 | **强烈推荐** |
| 分层模型 | DREA, Revelio, Griffin AI | 单一模型系统 | **推荐（按预算）** |
| 人类门控 | OpenHack, ESAA | 全自动系统 | **推荐（高风险场景）** |
| 事件溯源 | ESAA, Hound | 大多数学术系统 | **推荐（合规场景）** |

---

## 十、学术基准与现实场景的差距

### 10.1 基准层次

```
Level 1: Juliet Test Suite / SARD
  - 合成漏洞，模式固定
  - LLM可通过记忆而非推理解决
  - ⚠️ 已基本失效

Level 2: PrimeVul (435对)
  - 函数级真实漏洞，双文件对比
  - 难度显著提升，基线方法FPR高
  - ✅ 当前最佳函数级基准

Level 3: ScaBench
  - 更贴近真实，5个项目子集
  - 基线仅8.3%召回率
  - ✅ 更真实但仍有限

Level 4: SECUREAGENTBENCH (105任务, OSS-Fuzz)
  - 大型仓库(平均554K LOC)，真实历史漏洞
  - 最佳仅15.2%正确+安全率
  - ✅ 最接近真实场景

Level 5: 生产系统0-day (OpenAnt/RepoAudit实际发现)
  - 144个可复现漏洞 (OpenAnt)
  - 185个新bug, 174个已确认/修复 (RepoAudit)
  - ✅ 工业界事实标准
```

### 10.2 基准覆盖的漏洞类型

| 漏洞类型 | Juliet/SARD | PrimeVul | SECUREAGENTBENCH | 生产系统 |
|:--------|:-----------|:---------|:-----------------|:--------|
| Buffer Overflow | ✅ | ✅ | ✅ | ✅ |
| Use-After-Free | ✅ | ✅ | ✅ | ✅ |
| SQL Injection | ✅ | ❌ | 少量 | ✅ |
| XSS | ✅ | ❌ | ❌ | ✅ |
| IDOR | ❌ | ❌ | ❌ | ✅ |
| SSRF | ❌ | ❌ | ❌ | ✅ |
| 反序列化 | ❌ | ❌ | ❌ | ✅ |
| 逻辑漏洞 | ❌ | ❌ | ❌ | ✅ |
| 加密误用 | ❌ | ❌ | ❌ | 少量 |
| Mass Assignment | ❌ | ❌ | ❌ | ✅ |

**结论**：Web应用场景下最常见的漏洞类型（IDOR、SSRF、反序列化、逻辑漏洞）在学术基准中几乎不存在。这是最大的评估盲区。

---

## 十一、数据飞轮与持续学习

### 11.1 BitsAI-CR的工业实践

**反馈通道架构**：

```
用户反馈 (实时) ──→ 发现低质量规则 ──→ 立即降权
人工标注 (周度) ──→ 低精度规则 ──→ LLM重训练
Outdated Rate (周度) ──→ 高精度但低OR规则 ──→ 直接退役
```

**关键创新——Outdated Rate**：
```
OR = (被标记代码行在后续commit中被修改的次数) / (总告警次数)

高精度 + 高OR = 好规则 ✅
高精度 + 低OR = 理论上对但没人改 = 噪音 → 退役 ❌
低精度 + 高OR = 有用但太吵 → 优化 ⚠️
低精度 + 低OR = 纯噪音 → 立即退役 ❌
```

### 11.2 数据飞轮的五层安全防护

| 层级 | 防护措施 | 防什么 |
|:-----|:--------|:------|
| L1 | 双人盲审 + 人类专家准入 | 标签污染 |
| L2 | 隔离沙箱训练 + 金标准评估 | 确认偏见放大 |
| L3 | 漂移检测 + 自动回滚 | 分布漂移 |
| L4 | 红队测试 + 变异测试 | 对抗性投毒 |
| L5 | 联邦学习隔离 + 差分隐私 | 隐私泄露 + 模型记忆 |

### 11.3 持续学习的约束条件

- **不应遗忘**：新规则不能覆盖或降低旧规则的检测能力
- **人类代价预算**：约25%的用户仍受AI噪声困扰，目标逐步降低此比例
- **周级聚合而非实时更新**：提供天然安全缓冲

---

## 十二、参考文献与项目索引

### 学术论文

1. Guo et al., "RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing", ICML 2025. https://arxiv.org/abs/2501.18160
2. David & Gervais, "Towards Optimal Agentic Architectures for Offensive Security Tasks", 2025. https://arxiv.org/abs/2604.18718
3. LLMxCPG: "Context-Aware Vulnerability Detection Through Code Property Graph-Guided LLMs", USENIX Security 2025. https://github.com/qcri/llmxcpg
4. Chen et al., "LLM4FPM: Utilizing Precise and Complete Code Context to Guide LLM in Automatic False Positive Mitigation", 2025. https://arxiv.org/abs/2411.03079
5. Liu et al., "SecureReviewer: Enhancing LLMs for Secure Code Review through Secure-aware Fine-tuning", ICSE 2026. https://arxiv.org/abs/2510.26457
6. Jiao et al., "DeepVulHunter: Enhancing LLM Vulnerability Detection Through Multi-Round Analysis", J Intell Inf Syst, 2025.
7. HALURust: "Exploiting Hallucinations of LLMs to Detect Vulnerabilities in Rust", 2025. https://arxiv.org/abs/2503.10793
8. DrillAgent: "Execution-State-Aware LLM Reasoning for Automated Proof-of-Vulnerability Generation", 2025. https://arxiv.org/abs/2602.13574
9. PoCo: "Agentic Proof-of-Concept Exploit Generation for Smart Contracts", ACM TOSEM, 2025.
10. BitsAI-CR: "Automated Code Review via LLM in Practice", FSE 2025. https://arxiv.org/abs/2501.15134
11. Revelio: "Cost-Efficient Agentic Memory Safety Vulnerability Detection", 2026. https://arxiv.org/abs/2606.22263
12. DREA: "Decoupled Reasoning and Exploration Agents", Internetware 2026.
13. ESAA: "Event Sourcing for Autonomous Agents", 2026. https://arxiv.org/abs/2602.23193
14. ESAA-Security: "Event-Sourced Architecture for Security Audits", 2026. https://arxiv.org/abs/2603.06365
15. Hound: "Relation-First Knowledge Graphs for Complex-System Reasoning in Security Audits", 2025.
16. SEC-Bench Pro: "Can Language Models Solve Long-Horizon Software Security Tasks?", 2025. https://arxiv.org/abs/2605.26548
17. Agora: Multi-agent consensus protocol vulnerability detection, ICML 2026.
18. Aegis: Meta-auditing framework. https://github.com/agentlifylabs/Aegis
19. WhiteFox: "White-Box Compiler Fuzzing Empowered by LLMs", OOPSLA 2024.

### 开源项目

| 项目 | 仓库 | 许可 |
|:-----|:-----|:-----|
| RepoAudit | https://github.com/PurCL/RepoAudit | MIT |
| LLMxCPG | https://github.com/qcri/llmxcpg | Apache 2.0 |
| OpenHack | https://github.com/hadriansecurity/OpenHack | MIT |
| AgentStalker | https://github.com/Gach0ng/AgentStalker | MIT |
| codebadger | https://github.com/Lekssays/codebadger | 开源 |
| Aegis | https://github.com/agentlifylabs/Aegis | MIT |
| Hound | https://github.com/scabench-org | 开源 |
| ESAA | https://github.com/elzobrito | MIT |
| AnyPoC | https://github.com/zzjas/anypoc | 开源 |
| ZubairLK/security-agents | GitHub | 开源 |

### 基准数据集

| 基准 | 规模 | 类型 | 网址 |
|:-----|:-----|:-----|:-----|
| Juliet Test Suite | ~64,000用例 | 合成漏洞 | NIST SAMATE |
| SARD | 100,000+ | 合成+部分真实 | NIST SAMATE |
| PrimeVul | 435对 | 函数级真实漏洞 | GitHub |
| ScaBench | 5项目子集 | 仓库级 | scabench.org |
| SECUREAGENTBENCH | 105任务 | OSS-Fuzz真实漏洞 | GitHub |
| SEC-Bench Pro | 183 V8/SpiderMonkey | 浏览器引擎漏洞 | GitHub |
| Factory.ai Review | 50 PRs, 167 bugs | 生产代码审查 | factory.ai |
