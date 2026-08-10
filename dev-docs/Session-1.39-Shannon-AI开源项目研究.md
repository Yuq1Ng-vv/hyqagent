# Session 1.39 — Shannon AI 开源渗透测试项目研究

## 目标
研究 GitHub 46k+ Star 的 Shannon AI 自主渗透测试项目，分析其架构设计、技术选型、与 HyqAgent 的差异，提炼可借鉴的设计模式和改进方向。

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `dev-docs/Session-1.39-Shannon-AI开源项目研究.md` | **新建** | 本研究报告 |

## 一、Shannon 项目概述

**Shannon** 是一个基于 Claude Agent SDK 构建的全自主渗透测试 AI 系统，GitHub 46,000+ Stars，定位为"AI 驱动的自主安全测试平台"。

### 核心特点

| 维度 | Shannon | HyqAgent |
|------|---------|----------|
| **分析方式** | 直接阅读源码 + 动态验证 | CPG 图（静态分析）+ LLM 辅助 |
| **Agent 架构** | 多 Agent 协作（Temporal 编排） | 单 Agent + 丰富工具 |
| **模型策略** | Claude Opus/Sonnet 级联 | DeepSeek 为主（成本优先） |
| **核心理念** | "No Exploit, No Report" | "确定性先行，LLM 后行" |
| **漏洞发现** | Recon → Parallel Vuln Analysis | CPG source→sink → Hypothesis → Validation |
| **验证方式** | 真实利用验证（沙箱执行） | 可选沙箱动态验证（当前受限） |
| **报告输出** | 仅报告成功利用的漏洞 | 全量发现（含置信度分级） |

### 五阶段流水线

```
Pre-Recon (信息收集)
  → Recon (侦察：源码阅读 + 架构理解)
    → 5× Parallel Vuln Analysis (并行漏洞分析)
      → 5× Parallel Exploit (并行利用验证)
        → Report (报告生成)
```

**阶段详情**：

1. **Pre-Recon**：收集目标基本信息（技术栈、端口、服务版本）
2. **Recon**：深度阅读源码，理解架构、路由、认证机制、数据流
3. **Vuln Analysis**（5 并行）：不同视角/策略的漏洞分析师同时工作，各自独立发现
4. **Exploit**（5 并行）：每个发现的漏洞被独立验证，执行真实 PoC
5. **Report**：仅汇总成功利用的漏洞，附带利用截图和复现步骤

## 二、关键架构决策分析

### 2.1 为什么 Shannon 没有 source→sink 追踪？

Shannon 依赖 Claude Opus/Sonnet 的**强代码理解能力**，让模型直接阅读源码文件并推理漏洞，而非构建 CPG 做精确的数据流追踪。

**优劣势对比**：

| | Shannon 方式 | HyqAgent 方式 |
|------|-------------|--------------|
| **覆盖广度** | 依赖模型对代码的理解，可能遗漏深层调用链 | CPG 图保证 source→sink 全路径覆盖 |
| **精确度** | 模型可能产生幻觉路径 | 图遍历保证路径真实存在 |
| **成本** | 极高（Opus 级模型 + 全文件上下文） | 较低（CPG 预过滤 + DeepSeek） |
| **跨文件能力** | 依赖模型上下文窗口 | CPG 天然跨文件 |
| **语言支持** | 任何模型能理解的语言 | 需要 tree-sitter 语法支持 |

**结论**：Shannon 的"无 CPG"策略建立在 Opus 级模型的强代码推理能力之上。对 HyqAgent 而言，DeepSeek 级别的模型无法可靠替代 CPG 的精确追踪能力，因此 CPG 先行是正确的架构选择。

### 2.2 Temporal 编排 vs 单 Agent 循环

Shannon 使用 **Temporal**（分布式工作流引擎）编排多 Agent 协作：
- 支持超长任务（数小时级别）
- 自动重试、超时、检查点
- 并行执行（5 个漏洞分析师同时运行）

HyqAgent 采用**单 Agent + 收敛循环**：
- 更低的协调开销
- 确定性状态管理
- 适合中等规模目标

### 2.3 "No Exploit, No Report" 哲学

Shannon 只报告**成功利用**的漏洞，这带来两个效果：
- **零误报**：每个报告都是经过验证的真实漏洞
- **可能漏报**：难以利用的漏洞（如需要特定条件的 SSRF）会被丢弃

HyqAgent 当前策略是**全量报告 + 置信度标记**，这对安全研究人员更有价值（他们需要了解全部攻击面）。

## 三、Shannon 对 HyqAgent 的 7 条建议

### 建议 1：将动态验证提升为核心流水线阶段 ⭐⭐⭐

**现状**：动态验证在 HyqAgent 中是可选的（`SandboxExecutor`），且因 Docker 内存问题被用户推迟。

**Shannon 做法**：Exploit 阶段是强制性的——没通过利用验证的发现不会被写入报告。

**建议**：在解决内存问题后，将动态验证作为流水线的正式阶段（Phase 4.5），在 LLM Validation 之后、Report 之前：
```
Phase 3 (Hypothesis Gen) → Phase 4 (LLM Validation) → Phase 4.5 (Dynamic Verification) → Phase 5 (Report)
```

验证结果直接决定 finding 的 `confidence` 和是否出现在最终报告中。

### 建议 2：CWE 分组并行收敛 ⭐⭐⭐

**现状**：当前收敛循环按轮次串行，每轮处理全部 annotated paths。

**Shannon 做法**：5 个并行的漏洞分析师，各自从不同视角独立工作。

**建议**：按 CWE 类型分组并行收敛（如 SQLi 组、XSS 组、SSRF 组各自独立收敛），好处：
- 不同漏洞类型的收敛速度不同，互不阻塞
- 每个组的 LLM 上下文更聚焦（更少的干扰信息）
- 当前 `covered_fingerprints` 机制可以自然扩展到按组维护

### 建议 3：引入模型分级策略 ⭐⭐

**现状**：所有 LLM 调用统一使用 DeepSeek。

**Shannon 做法**：Claude Opus 做高价值推理（漏洞分析），Sonnet 做批量任务（信息提取），Haiku 做简单分类。

**建议**：在 HyqAgent 中引入模型分级：
- **L1 确定性匹配**：CPG 规则（当前已有）
- **L2 假设生成**：DeepSeek（当前已有）
- **L3 验证裁决**：DeepSeek（当前已有）
- **L4 动态利用**：轻量执行（待优化）
- **L5 报告总结**：无需 LLM（当前用模板）✅

可在高价值场景（高价值目标、关键漏洞）将 Hypothesis Gen 升级为 Claude Sonnet。

### 建议 4：Pre-Recon 信息收集阶段 ⭐⭐

**现状**：HyqAgent 直接进入 CPG 构建和扫描。

**Shannon 做法**：先做信息收集——技术栈识别、框架版本、中间件指纹。

**建议**：在 Phase 1 (CPG Build) 之前增加轻量级 Pre-Recon：
- 从 `package.json`/`requirements.txt`/`pom.xml` 提取依赖版本
- 匹配已知漏洞数据库（CVE 映射）
- 识别框架 → 加载框架专用 CPG 规则

这能让 CPG 规则选择更精准，同时直接报告已知 CVE（无需 LLM）。

### 建议 5：考虑模型上下文利用优化 ⭐⭐

**现状**：LLM 调用每次携带独立的代码片段和上下文。

**Shannon 做法**：利用 Claude 200K 上下文窗口，一次性加载大量相关源码让模型建立全局理解。

**建议**：
- 对中小型项目，可使用"全文件上下文"策略一次性加载核心模块
- 对大型项目，保持当前的分片策略但优化片段选择（按调用图相关性排序）
- 评估 DeepSeek 的上下文窗口能力是否支持更大的输入

### 建议 6：报告中的成功标准 ⭐

**现状**：报告包含所有置信度的 finding。

**Shannon 做法**：只报告成功利用的漏洞，每个漏洞附带实际利用截图/日志。

**建议**：在保持全量报告的同时，增加一个"已验证漏洞"摘要章节，突出展示通过动态验证的 finding（最高置信度）。这兼顾了"全面了解攻击面"和"立刻行动"两种需求。

### 建议 7：沙箱执行器轻量化 ⭐

**现状**：Docker 沙箱，每个容器 256MB 内存限制 + `remove=False` 导致容器泄漏。

**Shannon 做法**：利用 Claude Agent SDK 的沙箱执行环境（托管基础设施）。

**建议**：
- 短期：修复 `remove=False` 为 `remove=True`，添加容器生命周期管理
- 中期：为网络可验证类漏洞（SSRF、开放重定向、CORS）使用 `curl` subprocess 替代 Docker
- 长期：评估是否将利用验证交给更强大的模型（如 Claude 的 tool-use 能力）

## 四、HyqAgent 当前优势（不需改变的）

| 维度 | 优势 |
|------|------|
| **CPG 精确追踪** | source→sink 图遍历保证不遗漏数据流路径，这是 Shannon 不具备的 |
| **成本效率** | DeepSeek + 确定性规则组合远低于 Opus 级全模型方案 |
| **语言无关性** | CPG 层统一抽象，新增语言只需 tree-sitter 语法 |
| **信念系统** | 确定性+LLM+沙箱三重置信度比 Shannon 的二元判定更精细 |
| **收敛循环** | 多轮迭代逐步逼近，比 Shannon 的单次分析更彻底 |
| **报告全面性** | 全量发现（含盲区）vs Shannon 的仅报告成功利用 |

## 五、实施优先级建议

| 优先级 | 建议 | 理由 |
|--------|------|------|
| **P0** | 修复 Docker 沙箱内存泄漏 | 阻塞动态验证的所有后续工作 |
| **P1** | 动态验证提升为核心阶段 | 最大程度减少误报，对齐"No Exploit, No Report"理念 |
| **P1** | 沙箱执行轻量化 | 降低动态验证门槛 |
| **P2** | CWE 分组并行收敛 | 提升收敛效率和 LLM 上下文质量 |
| **P2** | Pre-Recon 信息收集 | 小投入、高回报（CVE 匹配 + 框架识别） |
| **P3** | 模型分级策略 | 需要成本收益评估（Claude 模型成本可能远超 DeepSeek） |
| **P3** | 上下文利用优化 | 需要大量实验确定最佳分片策略 |

## 六、关键参考

- Shannon GitHub: https://github.com/Shannon/ShannonAI (46k+ Stars)
- Shannon 论文/博客: 五阶段流水线架构详解
- Claude Agent SDK: Anthropic 官方多 Agent 编排框架
- Temporal: 分布式工作流引擎 (https://temporal.io)

## 质量门禁

本研究为纯调研报告，无代码变更，不需要运行 pytest/ruff/mypy。

## 设计反思

**关键洞察**：Shannon 和 HyqAgent 代表了两种不同的安全测试哲学——"强模型+多 Agent+实际利用" vs "精确追踪+单 Agent+置信度分级"。两者不是替代关系，而是互补关系。

HyqAgent 的核心竞争力在于 CPG 的精确性和低成本，不应该试图模仿 Shannon 的高成本模型策略。但 Shannon 的流水线设计（Pre-Recon、强制动态验证、并行分组）是语言无关的架构模式，值得直接借鉴。

**最有价值的发现**：Shannon 的 5 个并行漏洞分析师本质上是一种"多视角投票"机制——不同分析师的独立发现天然形成交叉验证。这比 HyqAgent 当前的"同一 LLM 多轮迭代"更接近人类的代码审计实践（多人交叉审计）。

## 下步衔接

下个 Session 建议：
1. 优先处理 Docker 沙箱修复（`remove=False` bug），这是后续所有动态验证工作的基础
2. 如果沙箱问题解决，直接推进动态验证核心化（流水线 Phase 4.5）
3. 如果沙箱问题需要更多时间，先做 Pre-Recon 信息收集（建议 4）——独立于沙箱，可立即实施
