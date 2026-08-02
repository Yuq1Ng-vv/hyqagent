# HyqAgent 参考文档索引

> 这些文档是项目研究和设计的完整记录，按用途分为四类。日常开发时无需全部阅读——先看根目录的 `ARCHITECTURE_OVERVIEW.md` 和 `DESIGN-IMPLEMENTATION.md`，遇到具体问题再按需深入。

---

## 📚 文档分类

### 研究基础（先有研究，后有设计）
| 文档 | 说明 | 何时阅读 |
|:-----|:-----|:--------|
| `RESEARCH.md` | 20+论文综述、15+系统对比、架构模式决策依据 | 需要理解"为什么选CPG+LLM"时 |
| `PLAN.md` | 原始设计方案，五阶段流水线和CPG Engine的首次完整描述 | 需要了解初始设计意图时 |

### 架构设计（核心系统设计）
| 文档 | 说明 | 何时阅读 |
|:-----|:-----|:--------|
| `COVERAGE-GAP-ANALYSIS.md` | 覆盖盲区分析——Phase 1漏掉哪些漏洞、如何缓解 | 关注召回率/遗漏问题时 |
| `severity_based_vulnerability_mining_framework.md` | 五级危害分类 × 七层挖掘阶梯，预算分配 | 需要理解挖掘深度策略时 |
| `WEB-VULN-FULL-MATRIX.md` | 180+漏洞类型全量矩阵 | 需要查具体漏洞类型的检测策略时 |
| `detection_matrix.json` | 200项ASVS对齐的结构化检测项（17大类） | 需要逐项对照检测能力时 |
| `LONG-RUNNING-AGENT-ARCHITECTURE.md` | 长任务持续运行方案：事件溯源、检查点、收敛性 | 实现会话管理/检查点功能时 |

### 工程实施（从设计到代码）
| 文档 | 说明 | 何时阅读 |
|:-----|:-----|:--------|
| `IMPLEMENTATION-GUIDE.md` | 实现前必读：关键风险清单、多Agent决策、MVP建议 | 开始写代码前必读 |
| `DEVELOPMENT-STANDARDS.md` | 生产级开发规范：SOLID、测试、可观测性、Prompt管理 | 搭建CI/CD和质量体系时 |
| `CLAUDE-CODE-DEVELOPMENT-GUIDE.md` | 用Claude Code完成开发的实操路线图 | 用Claude Code开发时参考 |

### 架构决策记录（ADRs）
| 目录 | 说明 |
|:-----|:-----|
| `adr/` | 架构决策记录——重要的设计决策及其上下文 |

---

## 🗺️ 阅读路线

### 新加入开发者
1. 根目录 `ARCHITECTURE_OVERVIEW.md` — 30分钟了解全貌
2. 根目录 `DESIGN-IMPLEMENTATION.md` — 了解模块接口和实现计划
3. `IMPLEMENTATION-GUIDE.md` — 了解关键风险和MVP策略

### 开始实现某个模块
1. 根目录 `DESIGN-IMPLEMENTATION.md` 找到对应章节
2. 按需查阅本目录下的深度设计文档
3. 参考 `DEVELOPMENT-STANDARDS.md` 了解代码规范

### 技术决策者
1. `ARCHITECTURE_OVERVIEW.md` 第4章（关键设计决策）
2. `RESEARCH.md` — 学术依据
3. `COVERAGE-GAP-ANALYSIS.md` — 已知局限和缓解方案
