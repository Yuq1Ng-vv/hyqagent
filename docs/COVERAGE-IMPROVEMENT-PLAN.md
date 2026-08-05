# HyqAgent 覆盖盲区最小化 — 综合方案

> **版本**: v1.0
> **日期**: 2026-08-05
> **研究方法**: 4 个独立 Agent 并行调研（学术文献 / 工业界工具 / CPG 层设计 / 流水线架构）+ 交叉综合
> **上游文档**: `COVERAGE-GAP-ANALYSIS.md`、`COVERAGE-MINIMIZATION-ARCHITECTURE.md`、`DESIGN-IMPLEMENTATION.md`

---

## 目录

1. [核心结论：好消息和坏消息](#一核心结论)
2. [问题量化：到底漏多少](#二问题量化)
3. [解法的四个支柱](#三解法的四个支柱)
4. [架构全景](#四架构全景)
5. [实施路线图（对齐当前 Session 进度）](#五实施路线图)
6. [关键设计决策](#六关键设计决策)
7. [参考论文与工具清单](#七参考论文与工具清单)

---

## 一、核心结论

### 坏消息

当前设计的五阶段流水线中，**Phase 1 作为有损过滤器**——不匹配 YAML 规则的代码路径被永久丢弃，下游 LLM 永远看不到。这导致：

- Phase 1 确定性规则仅覆盖约 **20-35%** 的 Web 漏洞类别（按 CWE 多样性）
- IDOR、业务逻辑、二阶注入、条件竞争等大量高价值漏洞在 Phase 1 就被丢弃
- 学术文献中纯流水线架构的理论召回率上限约 **57.5%**（IRIS 研究）

### 好消息（四个 Agent 的交叉验证）

1. **这个问题已经被系统性分析过**：`COVERAGE-GAP-ANALYSIS.md` 已经识别了问题并提出了 7 种缓解方案
2. **学术界 57.5% 天花板已被突破**：vEcho (65%)、ZeroFalse (F1=0.955)、Phoenix (F1=0.825)、MoCQ (recall 0.87) — 且都开源
3. **工业界的覆盖完整性也是普遍盲区**：Semgrep/CodeQL/Snyk 都不追踪"漏了什么"，Hound 和悬镜的覆盖度量做法可直接借鉴
4. **项目处于最佳介入时机**：CPG 基础层还在构建（Session 1.3），覆盖能力可以从源头上内建，而非日后补丁
5. **关键改造不需要推翻现有架构**：只需将 Phase 1 从"过滤器"改为"标注器"，增加 3-4 个独立检测通道

---

## 二、问题量化

### 2.1 Phase 1 系统性遗漏的漏洞类别

| 漏洞类型 | Phase 1 能否发现 | 遗漏原因 | 真实世界占比 |
|:---------|:---------------|:--------|:----------|
| SQL 注入（直接） | ✅ 能 | source/sink 在 YAML 中 | ~15-25% |
| XSS（反射型） | ✅ 能 | source/sink 在 YAML 中 | ~30-40% |
| **IDOR/BOLA** | **❌** | 漏洞在于缺少所有权检查，CPG 无法检测缺失 | Bug Bounty ~50% 高危 |
| **业务逻辑漏洞** | **❌** | 没有 sink，代码语法完全正常 | 每个定制应用都存在 |
| **条件竞争/TOCTOU** | **❌** | CPG 每次只建模一条执行路径 | async/await 普及后严重漏报 |
| **二阶注入** | **❌** | 污点链跨越持久化边界 | 有 UGC 的应用常见 |
| **认证逻辑缺陷** | **❌** | 漏洞在请求间交互层面 | ~20-30% |
| **加密弱点** | **❌** | 需要语义判断（ECB vs CBC 安全性） | ~15-30% |
| **OAuth/JWT 配置错误** | **❌** | 漏洞在请求间交互层面 | ~10-20% |
| **Prototype Pollution** | **❌** | sink 是隐式的—属性写入在 CPG 中只是普通赋值 | ~10-20% (Node.js) |
| **SSRF（间接模式）** | ⚠️ 部分 | 重定向链、DNS Rebinding、非请求参数来源 | ~10-20% |
| **反序列化（自定义）** | ⚠️ 部分 | 85.3% 的真实 gadget 涉及 CPG 无法解析的动态特性 | ~5-15% (Java) |

**保守估计：Phase 1 覆盖约 20-35%。这意味着 65-80% 的漏洞类别在当前架构中存在系统性遗漏风险。**

### 2.2 学术基准佐证

| 基准/研究 | 关键数据 |
|:----------|:--------|
| IRIS (2024) | CodeQL 单独检出 27/120 漏洞；LLM 增强后 69/120（上限 57.5%） |
| SECUREAGENTBENCH | 105 个任务，最佳系统正确+安全率 15.2% |
| vEcho (2026) | 检测率 65%，发现 51 个 0-day，突破 57.5% 天花板 |
| ZeroFalse (2026) | F1=0.955，精确率 >90%，召回率 0.914 |
| Phoenix (2026) | 用 14B 参数模型达到 F1=0.825（行为契约方法） |
| MAS-Indep (2026) | 3 个独立 Agent 达 64.2% 召回率—所有拓扑中最高 |

---

## 三、解法的四个支柱

### 支柱 1：Phase 1 从「过滤器」到「标注器」

**核心改动**：不丢弃任何代码路径。每个路径根据分析状态打上 10 种标签之一。

```
旧:  全部代码 → Phase 1 (过滤器) → 匹配 → Phase 3
                                  → 不匹配 → ✗ 丢弃

新:  全部代码 → Phase 1 (标注器) → 所有路径打标签 → Phase 2/3 根据标签分配预算
```

| 标签 | 含义 | 下游处理 |
|:-----|:-----|:--------|
| `confirmed_taint` | source+sink 都在 YAML，有完整数据流路径 | 强模型精确验证 |
| `sanitized_taint` | 有污点路径但有 sanitizer | 便宜模型先判断 sanitizer 充分性 |
| `heuristic_sink` | sink 不在 YAML 但启发式评分 >= 阈值 | 便宜模型初步审查 |
| `unreachable_sink` | 可疑 sink 存在但无已知 source 可达 | Completeness Critic 审查 |
| `exposed_no_source` | HTTP 端点存在但无 source→sink 路径 | 盲扫 LLM 专门审查（IDOR/逻辑漏洞） |
| `missing_auth_annotation` | 端点缺少认证装饰器 | Phase 2 强制高 priority |
| `trust_boundary_crossing` | 数据流跨越信任边界 | 强模型审查 |
| `architecture_deviation` | 实际代码偏离预期安全属性 | 强模型审查 |
| `uncovered_but_reachable` | 路径在图中但未被任何规则命中 | 盲区清单（不进入 Phase 3） |
| `no_known_source` | 路径终点是数据操作但起点不是 HTTP 参数 | 架构审查 |

### 支柱 2：五个独立检测通道并行运行

借鉴 MAS-Indep（独立通道优于协调通道）和学术界的多样性红利研究：

```
通道1: CPG 确定性标注     → source→sink 污点追踪 + 标签分配      [零 LLM 成本]
通道2: 盲扫 LLM           → "基于模式的扫描器会遗漏什么？"        [~$0.10-0.80]
通道3: 反向 Sink 分析     → 从所有函数调用反向追踪到用户输入        [零 LLM 成本]
通道4: 架构偏离检测       → 安全架构模型 vs 实际代码               [~$0.02-0.08]
通道5: 差异覆盖分析       → "我们分析了什么 vs 我们应该分析什么"   [零 LLM 成本]
```

**关键设计原则**：
- 通道之间**不共享过滤结果**（避免级联遗漏）
- 每个通道有不同的视角和盲区
- 最终通过 MergeEngine 合并（同一 sink+vuln_type 多通道发现 → 置信度提升 +0.1/每额外通道）
- 去重以 `(sink 文件+行号, vuln_type)` 为 key

### 支柱 3：覆盖完整性度量内建

从工业界调研发现：**覆盖完整性在工业界是普遍盲区的盲区**——Semgrep/CodeQL/Snyk 都不追踪"漏了什么"。只有 Hound（覆盖-vs-直觉两阶段，目标 ~90%）和悬镜（漏报率 <= 13%）有显式的覆盖度量。

HyqAgent 定义三层覆盖度量：

```
Level 1 — 图连通性覆盖: CPG 中多少 sink 节点有至少一条从已知 source 的可达路径
Level 2 — 检测规则覆盖: 已建模路径中有多少被至少一条检测规则/查询覆盖
Level 3 — 语义维度覆盖: 是否覆盖了数据流之外的漏洞维度（权限/业务逻辑/状态机）
```

综合度量指标：
- `endpoint_coverage_ratio` — 被分析的端点 / 总端点
- `risk_weighted_coverage` — 高 priority 端点权重更高的覆盖率
- `sink_coverage_ratio` — 被标记的 sink / 总 sink
- `dangerous_sink_coverage` — 危险标签的 sink / 潜在危险 sink
- `cwe_diversity_ratio` — 已检查的 CWE 类别 / 适用类别
- `completeness_score` — 加权综合评分 (0.0-1.0)，目标 standard >= 0.75, deep >= 0.90

### 支柱 4：预算感知的动态策略

三种扫描模式，按预算激活不同的通道组合和深度：

| 维度 | quick ($1) | standard ($5) | deep ($25) |
|:-----|:-----------|:--------------|:-----------|
| 通道1 (CPG 标注) | 完整 | 完整 | 完整（降低启发式阈值） |
| 通道2 (盲扫 LLM) | 不运行 | cheap, top 30% | Sonnet, top 50% |
| 通道3 (反向 Sink) | 精简 | 完整 | 激进（低阈值） |
| 通道4 (架构偏离) | 仅认证检测 | 完整 | 增强（Sonnet+Opus） |
| 通道5 (差异覆盖) | 完整 | 完整 | 增强（+风险评估） |
| Completeness Critic | 是 | 是 | 迭代（每轮饱和扫描后） |
| 对抗性审查 | 不运行 | 部分 | 完整（Opus） |
| 饱和扫描 | 不运行 | 1 轮 | 4 轮 |
| 预期召回率 | 25-35% | 45-55% | 55-65% |
| 目标 completeness | >= 0.50 | >= 0.75 | >= 0.90 |

**动态再平衡**：零成本通道（1/3/5）完成后，未使用的预算自动转移到高价值 LLM 验证阶段。

---

## 四、架构全景

### 4.1 顶层数据流

```
                          CPG 全图构建
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌────────────┐      ┌────────────┐      ┌────────────┐
   │ 通道1      │      │ 通道2      │      │ 通道3      │
   │ CPG 标注   │      │ 盲扫 LLM   │      │ 反向 Sink  │
   │ (零成本)   │      │ (LLM)      │      │ (零成本)   │
   └─────┬──────┘      └─────┬──────┘      └─────┬──────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
   ┌────────────┐      ┌────────────┐      ┌────────────┐
   │ 通道4      │      │ 通道5      │      │ Completeness│
   │ 架构偏离   │      │ 差异覆盖   │      │ Critic      │
   │ (LLM)      │      │ (零成本)   │      │ (LLM)       │
   └─────┬──────┘      └─────┬──────┘      └─────┬──────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                             ▼
                  ┌──────────────────┐
                  │   MergeEngine    │
                  │ 去重+合并+排序    │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  Phase 2         │
                  │  攻击面映射       │
                  │  (用标签调priority)│
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  Phase 3         │
                  │  LLM 假设生成     │
                  │  (按标签分配模型) │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  Phase 4         │
                  │  验证 (L1+L2)    │
                  │  + 对抗性审查     │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  饱和扫描?        │
                  │  (deep模式)      │
                  │  有新种子→回合并  │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  Phase 5         │
                  │  报告 + 盲区清单  │
                  │  + 覆盖度量      │
                  └──────────────────┘
```

### 4.2 学术灵感映射

| 学术成果 | HyqAgent 落点 |
|:---------|:------------|
| **Phoenix — 行为契约** | Phase 4 增加基于 Gherkin 安全契约的验证层。逆向工程安全期望 → 检查代码合规性。直接解决"缺失检测"问题 |
| **vEcho — 认知记忆 (EVP)** | 饱和扫描的种子传播逻辑——已确认漏洞的 sink 函数 → 找调用者/被调用者/同模块端点 |
| **MoCQ/LLMxCPG — LLM 生成查询** | 长期方向：Phase 1 的 YAML 配置可被 LLM 自动生成的 Joern 查询替代（打破闭世界假设） |
| **MAS-Indep — 独立通道** | 5 个通道独立运行，不共享过滤结果，延迟合并——实证证明独立通道优于协调通道 |
| **VulnHawk — 跨文件一致性** | 通道4 架构偏离检测——当 19 个端点有 @require_auth 而 1 个没有时，即使绕过所有确定性规则也能被检测 |
| **Hound — 关系优先知识图谱** | 覆盖-vs-直觉两阶段映射为通道1-5（广度覆盖）+ 饱和扫描（深度直觉） |
| **ZeroFalse — 按 CWE 定制提示** | Phase 3/4 使用 CWE 特定的微评分标准，而非通用提示 |

---

## 五、实施路线图（对齐当前 Session 进度）

当前进度：Session 1.3 完成（CPG 基础—AST 遍历器），接下来是 1.4（调用图）→ 1.5（跨文件调用图）→ 1.6（数据流图）→ 1.7（CPG 查询接口）。

### Phase A：CPG 层内建覆盖能力（Session 1.4-1.7 同步进行）

**前置条件**: 无（与当前 CPG 基础层同步构建）

| # | 任务 | 文件 | LLM 成本 | 优先级 |
|:--|:-----|:-----|:--------|:-----|
| A1 | 实现 `SinkDiscoverer` — 启发式 sink 发现引擎 | `cpg/discovery.py` | $0 | 🔴 P0 |
| A2 | 实现 `SourceCompletenessChecker` — source 完整性校验 | `cpg/discovery.py` | $0 | 🔴 P0 |
| A3 | 实现 `CoverageTracker` — 覆盖状态管理 | `cpg/coverage.py` | $0 | 🔴 P0 |
| A4 | 实现 `ArchitectureAnalyzer` — 轻量安全架构模型 | `cpg/coverage.py` | $0 | 🟡 P1 |
| A5 | 扩展 `CpgAnalyzer` 协议 — 增加 6 个覆盖查询方法 | `core/protocols.py` | $0 | 🔴 P0 |
| A6 | 为三种语言编写 tree-sitter query 模式（HTTP 路由、认证装饰器、危险调用） | `cpg/queries/` | $0 | 🟡 P1 |

**产出**: CPG 查询层原生支持覆盖查询，能回答"哪些 sink/source/endpoint 未被覆盖"。

### Phase B：流水线标注化改造（CPG 基础层完成后）

**前置条件**: CPG Query 接口完成（Session 1.7 完成）

| # | 任务 | 文件 | LLM 成本 | 优先级 |
|:--|:-----|:-----|:--------|:-----|
| B1 | 实现 `PathAnnotator` — 路径标注器 | `scanner/annotator.py` | $0 | 🔴 P0 |
| B2 | 实现 10 种 `PathLabel` 和标注逻辑 | `core/protocols.py` | $0 | 🔴 P0 |
| B3 | 实现通道3 `ReverseSinkChannel` — 反向 sink 分析 | `scanner/channels/reverse_sink.py` | $0 | 🔴 P0 |
| B4 | 实现通道5 `DifferentialCoverageChannel` — 差异覆盖 | `scanner/channels/differential_coverage.py` | $0 | 🔴 P0 |
| B5 | 实现 `BlindSpotManifest` 生成器 | `scanner/coverage_metrics.py` | $0 | 🟡 P1 |

**产出**: Phase 1 不再丢弃路径，所有路径打标签。三个零成本通道运行（1+3+5）。盲区清单作为报告附录。

### Phase C：LLM 通道 + 合并引擎（Model Router 完成后）

**前置条件**: Model Router + Provider 适配器完成

| # | 任务 | 文件 | LLM 成本 | 优先级 |
|:--|:-----|:-----|:--------|:-----|
| C1 | 实现通道2 `BlindScanChannel` — 盲扫 LLM | `scanner/channels/blind_scan.py` | ~$0.10 | 🟡 P1 |
| C2 | 实现通道4 `ArchitectureDeviationChannel` — 架构偏离 | `scanner/channels/architecture_deviation.py` | ~$0.03 | 🟡 P1 |
| C3 | 实现 `MergeEngine` — 多通道合并去重 | `scanner/merger.py` | $0 | 🔴 P0 |
| C4 | 实现 `CompletenessCritic` — 完整性审查员 | `scanner/completeness_critic.py` | ~$0.02 | 🟡 P1 |
| C5 | 编写盲扫 LLM 的 system prompt（探索性审查员视角） | `prompts/system/blind_scan.yaml` | $0 | 🟡 P1 |
| C6 | 编写行为契约模板（Gherkin 安全规范） | `prompts/system/gherkin_contracts.yaml` | $0 | 🟢 P2 |

**产出**: 5 通道全部运行，`--standard` 模式完整可用。预期召回率 45-55%。

### Phase D：深度模式增强（长任务能力阶段）

**前置条件**: 检查点机制 + 会话管理完成

| # | 任务 | 文件 | LLM 成本 | 优先级 |
|:--|:-----|:-----|:--------|:-----|
| D1 | 实现 `SaturationScanner` — 迭代饱和扫描 | `scanner/saturation.py` | +30-50% | 🟢 P2 |
| D2 | 实现 `AdversarialReviewChannel` — 对抗性审查 | `scanner/channels/adversarial_review.py` | ~$0.25 | 🟢 P2 |
| D3 | 实现 `CoverageAwareOrchestrator` — 覆盖感知编排器 | `scanner/orchestrator.py` | $0 | 🟡 P1 |
| D4 | 实现 `BudgetManager` 扩展 — 动态再平衡 | `models/budget.py` | $0 | 🟡 P1 |
| D5 | 实现 `CoverageMetrics` 完整计算 + 报告集成 | `scanner/coverage_metrics.py` | $0 | 🟡 P1 |

**产出**: `--deep` 模式完整可用。4 轮饱和扫描，Opus 级别对抗性审查。预期召回率 55-65%。

---

## 六、关键设计决策

### 决策 1：为什么选择 5 个通道而不是 3 个或 7 个？

DVDR-LLM 研究显示，增加超过 5-6 个多样化模型后额外收益很小。5 个通道覆盖了三个核心维度：
- **结构维度**（通道1 CPG + 通道3 反向 Sink）— 已知模式
- **语义维度**（通道2 盲扫 LLM）— 逻辑漏洞、缺失检查
- **架构维度**（通道4 架构偏离 + 通道5 差异覆盖）— 信任边界、盲区自知

### 决策 2：通道独立性 vs 信息共享？

MAS-Indep 实证：独立通道（64.2% 召回率）> 协调通道（MAS-Central 更低）。共享上下文导致思维同质化。**因此**：通道之间不传递过滤结果，仅在 MergeEngine 处合并。

### 决策 3：Phase 1 标签体系为什么是 10 种而不是更少？

10 种标签覆盖了三类信息：**数据流状态**（confirmed/sanitized/heuristic/unreachable）、**端点状态**（exposed_no_source/missing_auth）、**架构状态**（trust_boundary_crossing/architecture_deviation）。如果粒度太粗（如只有 3-4 种），下游无法区分处理策略，等于没做标注。

### 决策 4：为什么不直接用 LLM 替代 Phase 1？

Phoenix 的行为契约方法虽强（14B 模型 F1=0.825），但在 `--quick` 模式下需要零成本方案。CPG 确定性标注的成本为 0，且精确率远高于 LLM。两者的关系是**互补**而非替代：CPG 做广度覆盖 + 高精度标注，LLM 做语义推理 + 盲区探索。

### 决策 5：要不要用 LLM 自动生成 Joern/CodeQL 查询来替代 YAML 配置？

MoCQ 和 LLMxCPG 证明了这条路可行（recall 0.87），但它引入了 LLM 成本到 Phase 1，破坏了 `--quick` 的零成本保证。**决策**：Phase D 之后作为 `--deep` 模式的可选增强（`--llm-augmented-config`），不替代基础 YAML 配置。

---

## 七、参考论文与工具清单

### 可直接借鉴的开源实现

| 项目 | 链接 | 借鉴点 |
|:-----|:-----|:------|
| **LLMxCPG** | github.com/qcri/llmxcpg | CPG→LLM 切片 + 微调模型（USENIX Security 2025） |
| **VulWeaver** | github.com/weaver4VD/VulWeaver | LLM 增强的统一依赖图构建（跨语言动态调用解析） |
| **VulnHawk** | github.com/momenbasel/vulnhawk | 跨文件上下文比较——"这个处理程序为何没授权检查？" |
| **IRIS** | github.com/iris-sast/iris | 神经符号基线 + CWE-Bench-Java 数据集 |
| **AGHAST** | github.com/owasp-aghast/aghast | 混合 SAST+LLM 框架（OWASP 官方） |
| **AI Deep SAST** | github.com/cisco-open/ai-deep-sast | Cisco 生产级 Semgrep + tree-sitter + LLM 双层管线 |
| **LVRP** | github.com/theteatoast/local-vuln-research-pipeline | 穷举 source-to-sink 路径 + LLM 验证 |

### 关键论文速查

| 论文 | 年份 | 关键数据 | 对 HyqAgent 的启发 |
|:-----|:-----|:--------|:-----------------|
| vEcho | 2026.03 | 检测率 65%，51 个 0-day | 认知记忆模块（EVP）—已确认漏洞作为种子扩展搜索 |
| ZeroFalse | 2026.07 | F1=0.955, recall 0.914 | 按 CWE 定制微评分标准（10-20 条规则/CWE） |
| Phoenix | 2026.04 | 14B 模型 F1=0.825 | 行为契约（Gherkin）—安全期望 vs 实际代码 |
| MoCQ | 2025.04 | recall 0.87, 46 个新漏洞模式 | LLM 自动生成检测查询替代手写 YAML |
| MAS-Indep | 2026.04 | 64.2% 召回率, 独立优于协调 | 通道独立性设计 |
| DVDR-LLM | 2025 | 多文件召回率 +18% | 小模型（8-9B）召回率更高，多样化集成 |
| VulWeaver | 2026.04 | F1=0.75, 15 个确认漏洞 | LLM 增强调用图解析反射/多态 |
| LLMxCPG | 2025 | F1=0.8075, 68-91% 代码缩减 | CPG 切片 + 双模型架构 |
| BACFuzz | 2025 | 26 个此前未知的 BOLA/BFLA 漏洞 | 运行时验证 + 数据库层 oracle |

### 工业界对照

| 工具 | 检测方法 | 覆盖完整性 | HyqAgent 可借鉴 |
|:-----|:--------|:---------|:--------------|
| Semgrep | AST 模式匹配 | 无 | 不要重复其"规则密度≠完整性"的教训 |
| CodeQL | 声明式 QL | 手动诊断（partial flow） | 内建覆盖度量，不要学其事后诊断模式 |
| Snyk Code | 符号 AI + ML | 隐式（语义推理缩小盲区） | 符号检测+生成修复+符号验证三层闭环 |
| Bearer/Cycode | Tree-sitter + CIG | 两层盲区分类 | CPG 即升级版 CIG—覆盖状态作图为一级属性 |
| 悬镜 | 多模引擎 | 漏报率 <=13% 目标 | 从第一天起量化覆盖率 |
| Hound | 关系优先知识图谱 | 覆盖-vs-直觉两阶段, ~90% 目标 | 扩展关系维度 + 双阶段策略 |

---

## 附录：快速决策速查

- **Q: 要不要推翻现有五阶段流水线？** → **不**。只需将 Phase 1 从过滤改为标注，增加并行通道。
- **Q: 改动量大吗？** → Phase A（CPG 层内建）可以完全在当前 Session 1.4-1.7 中同步完成，零 LLM 成本。
- **Q: 会有性能影响吗？** → CPG 层覆盖查询全是内存图操作，遍历和标签分配的时间远小于 CPG 构建本身。
- **Q: 兼容性怎么办？** → 旧的线性流水线通过 `--mode=linear` 保留，新的多通道通过 `--mode=standard|deep` 启用。
- **Q: 最重要的单一改动是什么？** → **PathAnnotator（标注器）**。一旦 Phase 1 不再丢弃路径，所有下游都能看到完整的代码。这是零成本的改动，但解决了根本架构缺陷。
- **Q: 学术上最值得采用的新技术是什么？** → **Phoenix 的行为契约（Gherkin 安全规范）**。它直接解决"缺失检测"问题——将"有没有漏洞"转为"代码是否满足安全契约"。可以在 Phase 4 验证层增量引入。

---

> **结论**：HyqAgent 的覆盖盲区问题是真实的、可量化的、也是可解决的。最大的窗口机会是**现在**——CPG 层还在构建，覆盖能力可以内建而非打补丁。核心改动（PathAnnotator）零成本但解决根本问题。学术前沿和工业实践都验证了"独立多通道 + 标注而非过滤"的方向。
