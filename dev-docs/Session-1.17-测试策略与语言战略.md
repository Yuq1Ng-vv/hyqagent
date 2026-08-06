# Session 1.17 — Phase 1 质量评估与语言战略

## 目标
评估 Phase 1 完成质量，研究测试策略，确定后续语言扩展方向。

## 产出清单

| 文件 | 改动 | 说明 |
|------|------|------|
| `ARCHITECTURE_OVERVIEW.md` | 多处刷新 | CPG Engine→完成、8.1 节指标/表格更新、8.2 节移除已完成 Session |
| `DESIGN-IMPLEMENTATION.md` | 1 处 | cpg/ 目录标题 `部分实现`→`已完成` |
| `progress.md` | 重大更新 | Phase 1 header 统一、最终指标表（ureport2 数据）、模块/测试数刷新 |
| `docs/新手友好-HyqAgent架构详解.md` | 重大更新 | Section 七 全 16 个 Session 标记 ✅、5.3 实现顺序刷新、测试数 361→372、cpg/ 目录标记 🟢 |
| `.gitignore` | +1 行 | 排除 rwtests/（161MB 含二进制） |
| `memory/phase1-testing-strategy.md` | 新增 | 测试缺口分析 + 业界方法论 + 基准数据集 + 增强路线 |
| `memory/language-prioritization.md` | 新增 | PHP > Go 优先级排序 + 新语言加入时机分析 |

**总计**: 4 个文档刷新，2 个 memory 新增，1 个 .gitignore

## 实现过程

### 1. 文档同步（4 文件，100+ insertions）

Session 1.16 新增了大量实现（BUG 9-26 修复，ureport2 端到端验证），但四份核心文档不同程度过时。
基于 Explore agent 的交叉对比分析，系统性修复了所有不一致处：
- Phase 1 状态标记（部分实现→完成）
- 测试计数（302/361→372）
- 模块计数（16→23）
- 行数（~3,800→~5,700）
- Session 规划表（移除已完成的 1.8-1.16）
- 文件名错误（`data_flow.py`→`dataflow.py`）

### 2. 测试策略研究（4 agent 并行）

**Agent 1 — SAST 测试方法论**：研究 CodeQL/Semgrep/Joern 三家的测试基础设施。
关键发现：
- CodeQL 行内标注（`// $ hasValueFlow`）是数据流测试的黄金标准
- Semgrep 文件配对回归（target + pattern + expected）轻量且可跨语言
- Joern 的 `source.reachableBy(sink)` 模式适合 Pythonic DSL
- 业界 SAST 精确率仅 0.7、召回率仅 0.5，说明检测难度大

**Agent 2 — 测试覆盖缺口**：发现 10 类缺口，最严重：
- Django/FastAPI 各仅 2 个浅层测试，`extract_routes()` 从未被单测调用
- CPG 缓存零测试覆盖
- LanguageProvider 1,326 行代码仅间接测试

**Agent 3 — 项目目标→测试需求**：从 detection_matrix 反推出 8 个 Phase 2 就绪判定场景，
指出 Java ureport2 已满足，Python/JS 缺少对等验证。

**Agent 4 — 基准数据集调研**：
- OWASP BenchmarkJava/Python 提供带 ground truth 的精确率/召回率度量
- Juliet Test Suite 25K+ 用例支持按流复杂度梯度测试
- eyeballvul 35K+ 真实 CVE 跨语言可用
- vulnerable-node-api 填补了 JS 基准的空白

### 3. 行内标注框架讨论

用户问是否必要。分析结论：**长期计划，当前不优先**。
- 标注框架 ~200 行代码，本身开销不大
- 但当前更紧迫的是 Djang/FastAPI 测试和 Python/JS 端到端验证
- Phase 2 Scanner 阶段数据流测试用例规模化后，标注框架价值自然显现
- 已设计语法：`# $ source/sink/hasTaintFlow/MISSING/SPURIOUS`

### 4. 语言优先级分析

研究维度：Web 市场占比、漏洞密度、CVE 分布、SAST 工具竞争格局。

**核心结论：PHP 排第一，但 Java 优先打磨**

| 维度 | PHP | Go |
|------|-----|-----|
| Web 占比 | ~75% | <1% |
| SQL 注入率 | 56% | 数据太少 |
| XSS 率 | 86% | 数据太少 |
| 竞争真空 | CodeQL 不支持 | CodeQL/gosec 成熟 |
| 架构适配度 | 动态特性=CPG+LLM优势 | 静态类型=纯静态工具已够用 |

PHP 的压倒性优势：75% web、最高漏洞密度、CodeQL 不支持（深度语义 SAST 真空），
且 PHP 的动态特性（`$$var`、`__call`、`call_user_func`、`extract()`）恰好是 CPG+LLM 
架构相对于纯静态分析的最大优势所在。

### 5. 新语言加入时机

**不建议 Phase 2 期间加新语言。** 理由：

1. **Phase 2 Scanner 是核心差异化能力** — 五阶段流水线 + LLM 假设生成/验证是产品灵魂，
   先把这条路走通比多语言覆盖更重要
2. **当前三种语言已经覆盖了验证面** — Python（Flask/Django/FastAPI）、JS（Express）、
   Java（Spring）+ ureport2 给出了足够的反馈多样性
3. **加语言是乘法而非加法** — 新语言的 LanguageProvider（~400行）、框架提取器（~200行）、
   污点规则（~100行）、测试（~500行）、文档，全套下来至少 1,500+ 行 + 大量调试，
   会严重拖慢 Phase 2 进度
4. **PHP 的特殊挑战** — 动态特性（variable variables、magic methods、type juggling）需要
   更深的设计思考，CPG 层可能需要针对性的扩展，不适合当作"再来一门语言"快速追加

**推荐时机：Phase 2 Scanner 跑通首个端到端漏洞检测后。**
到时候我们有：
- Scanner 流水线已稳定运行
- 积累了足够多的跨语言测试经验
- Java 生态打磨充分（用户主要语言）
- 对 CPG 层需要向 LLM 暴露什么信息有清晰认知

此时加 PHP 是"验证架构通用性"而非"分心做新语言"。

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| `git add -A` 误将 rwtests/ 加入暂存区 | rwtests/ 未在 .gitignore 中 | 添加 `rwtests/` 到 .gitignore，git reset 撤销误添加 |
| memory 文件 git 不可见 | memory 路径在 `/root/.claude/`，不在 git repo 内 | memory 系统独立于 git，通过文件系统持久化 |

## 质量门禁
- ruff: 无新增（本 Session 仅文档/memory 修改）
- mypy: 无变化
- pytest: 372 passed（无代码变更）
- git: 2 个 commit（文档同步 + .gitignore）

## 设计反思

### 做得好
- 4 个 agent 并行调研，覆盖测试方法论、缺口分析、需求映射、数据集四个维度，1.5 小时内得到 ~600 行结构化报告
- 文档同步采用了 Explore agent 先做交叉对比分析再系统性修复的方式，比人工逐文件查找高效得多
- 承认行内标注框架"不是最优先"而非盲目上马，保持了焦点
- 语言分析从市场数据、漏洞密度、竞争格局三个维度交叉验证，结论扎实

### 可改进
- rwtests/ 应在第一次放入时就加入 .gitignore（已修复）
- 测试策略研究产出很丰富但尚未执行，需要下次 Session 落地
- 缺少一个 Session 产出的 checklist 机制，容易遗漏文档更新

### 下步衔接
1. **Django/FastAPI 测试补齐** — 当前最严重缺口
2. **Python 真实项目端到端验证** — VulnShop 或 BenchmarkPython
3. **Java 继续做深** — 用户主要项目语言
4. 行内标注框架和 PHP 都暂不启动，等 Java 和 Phase 2 Scanner 稳固后再议
