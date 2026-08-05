# HyqAgent 覆盖盲区最小化架构方案

> 版本: v1.0
> 日期: 2026-08-05
> 基于: `COVERAGE-GAP-ANALYSIS.md` (第六章: 七种缓解方案) + `DESIGN-IMPLEMENTATION.md` (第三章: 扫描引擎) + `protocols.py` (当前核心抽象)

---

## 目录

1. [设计目标](#一设计目标)
2. [核心改造一: Phase 1 从过滤器到标注器](#二核心改造一phase-1-从过滤器到标注器)
3. [核心改造二: 多通道并行架构](#三核心改造二多通道并行架构)
4. [核心改造三: 预算感知的覆盖策略](#四核心改造三预算感知的覆盖策略)
5. [核心改造四: 覆盖完整性度量体系](#五核心改造四覆盖完整性度量体系)
6. [数据流图与组件交互](#六数据流图与组件交互)
7. [协议与接口扩展](#七协议与接口扩展)
8. [各扫描模式配置策略](#八各扫描模式配置策略)
9. [实施路线图](#九实施路线图)

---

## 一、设计目标

### 1.1 当前架构的根本缺陷

```
                    ┌──────────────┐
    全部代码 ──────>│  Phase 1     │──── 匹配规则 ────> Phase 3 (LLM)
                    │  有损过滤器   │
                    │              │──── 不匹配 ────> ✗ 丢弃
                    └──────────────┘
```

**关键缺陷**: Phase 3 的 LLM 永远不会看到 Phase 1 未匹配的代码路径。这是一个**不可恢复的信息损失**。

定量证据 (来自 COVERAGE-GAP-ANALYSIS.md):
- Phase 1 仅覆盖约 20-35% 的 Web 漏洞类别 (按 CWE 多样性)
- IRIS 研究: 即使有完美的污点规范, 基于数据流的分析召回率上限仅 57.5%
- SECUREAGENTBENCH: 最佳系统正确+安全率 15.2%
- IDOR / 业务逻辑 / 二阶注入 / 条件竞争等大量高价值漏洞无代码结构特征

### 1.2 改造后的目标架构

```
                    ┌──────────────┐
    全部代码 ──────>│  Phase 1     │──── 所有路径都保留 ────> 下游可见
                    │  无损标注器   │      (附带标签)
                    │              │
                    └──────────────┘

    同时, 四个独立检测通道并行运行, 各自从不同视角审视代码:

    通道1 (CPG 确定性):  source→sink 污点追踪
    通道2 (盲扫 LLM):    不看 Phase 1 结果, 独立探索性扫描
    通道3 (反向 Sink):   从所有可疑调用反向追踪
    通道4 (架构偏离):    预期安全属性 vs 实际代码
```

### 1.3 设计原则

1. **确定性先行, LLM 后行** — 便宜的 CPG 查询永远先于昂贵的 LLM 调用
2. **通道独立性** — 每个检测通道有自己的视角, 不共享过滤结果 (避免级联遗漏)
3. **标签而非丢弃** — 所有代码路径都保留, 不同标签影响下游处理策略和预算分配
4. **预算感知** — 始终知道花了多少钱, 还剩多少钱, 钱应该优先花在哪里
5. **盲区自知** — 系统明确知道并告知用户 "我们可能漏了什么"

---

## 二、核心改造一: Phase 1 从过滤器到标注器

### 2.1 路径标签体系

每条代码路径 (从 HTTP 入口到每一条数据流终点) 被打上以下标签之一:

```python
from enum import Enum

class PathLabel(str, Enum):
    """代码路径标签 — 定义下游处理策略"""

    # ─── 确定性确认的污点路径 ───
    CONFIRMED_TAINT = "confirmed_taint"
    # 含义: source 和 sink 都在 YAML 中, CPG 确认了完整数据流路径, 无有效 sanitizer
    # 下游: Phase 3 直接用强模型做精准验证, Phase 4 L1 可确定性确认

    SANITIZED_TAINT = "sanitized_taint"
    # 含义: 污点路径存在, 但有 sanitizer 介入
    # 下游: Phase 3 判断 sanitizer 是否充分 (编码绕过 / 二阶攻击面)
    # 预算: 低优先 (sanitizer 正确实现的大概率安全)

    # ─── 启发式标记 ───
    HEURISTIC_SINK = "heuristic_sink"
    # 含义: sink 不在 YAML 中, 但启发式评分 > 阈值 (函数名含危险词 + 参数拼接 + 来自已知危险库)
    # 下游: Phase 3 低置信度审查, 优先用便宜模型
    # 来源: 反向 Sink 分析 (通道3)

    UNREACHABLE_SINK = "unreachable_sink"
    # 含义: 可疑 sink 存在, 但 CPG 未找到从任何 source 到它的路径
    # 原因可能是: (a) 确实是内部安全调用 (b) source 枚举不全 (c) 数据流经过持久化边界断开
    # 下游: Completeness Critic 审查, 标记为盲区

    # ─── 入口点标签 ───
    EXPOSED_NO_SOURCE = "exposed_no_source"
    # 含义: HTTP 端点存在, 但 CPG 未找到从参数到任何 sink 的路径
    # 这并不意味着安全 — 可能是 IDOR (缺少所有权检查)、source 枚举不全等
    # 下游: 通道2 (盲扫 LLM) 专门审查

    MISSING_AUTH_ANNOTATION = "missing_auth_annotation"
    # 含义: 端点缺少已知认证装饰器 (@login_required 等)
    # 下游: Phase 2 提升 priority, Phase 3 以 IDOR/权限绕过视角审查

    # ─── 未覆盖标记 ───
    UNCOVERED_BUT_REACHABLE = "uncovered_but_reachable"
    # 含义: 该路径在 CPG 图中存在, 但未被任何分析通道审查 (不在 YAML 中, 启发式也未命中)
    # 下游: 差异覆盖分析 (通道5) 将其纳入盲区清单

    NO_KNOWN_SOURCE = "no_known_source"
    # 含义: 路径终点是数据操作 (DB/文件/网络), 但起点不是已知的 HTTP 参数源
    # 原因: 可能是定时任务 / 消息队列消费者 / 内部 RPC 调用
    # 下游: 通道4 (架构偏离) 审查, Completeness Critic 标记

    # ─── 架构标记 ───
    TRUST_BOUNDARY_CROSSING = "trust_boundary_crossing"
    # 含义: 数据流跨越了信任边界 (如: 低权限区 → 高权限区)
    # 下游: Phase 2 强制 HIGH priority, Phase 3 用强模型审查
    # 来源: 通道4 (架构感知)

    ARCHITECTURE_DEVIATION = "architecture_deviation"
    # 含义: 实际代码偏离了预期安全属性 (如: 应该只读的端点执行了写操作)
    # 下游: Phase 3 用强模型审查
    # 来源: 通道4 (架构偏离检测)
```

### 2.2 标签对下游处理策略的影响

| 标签 | Phase 2 priority | Phase 3 模型 | Phase 4 策略 | 预算优先级 |
|:-----|:----------------|:------------|:-----------|:---------|
| `confirmed_taint` | 8-10 | MID/STRONG (按复杂度) | L1+L2 完整 | 最高 |
| `sanitized_taint` | 4-7 | CHEAP (先便宜判断) | 仅 L2 (对抗性) | 低 |
| `heuristic_sink` | 5-7 | CHEAP/MID | L2 轻量 | 中 |
| `unreachable_sink` | 3-5 | 不进 Phase 3 | Completeness Critic | 极低 |
| `exposed_no_source` | 6-8 | MID (盲扫) | 通道2 入口 | 高 |
| `missing_auth_annotation` | 8-10 | MID/STRONG | L2 (授权视角) | 高 |
| `uncovered_but_reachable` | 1-3 | 不进 Phase 3 | 盲区清单 | 零 |
| `no_known_source` | 2-4 | 不进 Phase 3 | 架构审查 | 极低 |
| `trust_boundary_crossing` | 9-10 | STRONG | L2 完整 | 最高 |
| `architecture_deviation` | 8-10 | STRONG | L2 完整 | 最高 |

### 2.3 标注器的实现

```python
class PathAnnotator:
    """新 Phase 1 — 无损标注器, 取代旧的有损过滤器。

    遍历 CPG 中所有端点 → 数据流路径, 为每条路径打上 PathLabel。
    路径不被丢弃, 而是根据标签进入不同的下游处理队列。
    """

    def __init__(
        self,
        cpg_query: CPGQuery,
        taint_config: TaintConfig,       # taint_rules.yaml
        heuristic_config: HeuristicConfig, # 启发式评分规则
        framework_extractors: list[BaseFrameworkExtractor],
    ):
        ...

    async def annotate_all_paths(self) -> AnnotatedPathGraph:
        """核心方法: 遍历所有路径, 返回带标签的路径图。

        返回结构:
        AnnotatedPathGraph {
            endpoints: list[AnnotatedEndpoint],    # 每个 HTTP 端点
            paths: list[AnnotatedPath],            # 每条数据流路径
            all_sinks: list[AnnotatedSink],        # 每个函数调用 (含非 YAML sink)
            blind_spots: list[BlindSpot],          # 完全未被分析的代码区域
            stats: AnnotationStats,                # 各类标签的数量分布
        }
        """
        ...

    async def _label_path(self, path: DataFlowPath) -> PathLabel:
        """为单条路径确定标签。

        规则优先级 (高 → 低):
        1. source 在 YAML && sink 在 YAML && 无 sanitizer → CONFIRMED_TAINT
        2. source 在 YAML && sink 在 YAML && 有 sanitizer → SANITIZED_TAINT
        3. sink 不在 YAML && 启发式评分 >= 阈值 → HEURISTIC_SINK
        4. sink 不在 YAML && 启发式评分 < 阈值 && source 可达 → UNREACHABLE_SINK
        5. 端点存在但无任何 source→sink 路径 → EXPOSED_NO_SOURCE
        6. 端点缺少认证注解 → MISSING_AUTH_ANNOTATION (可与上叠加)
        7. 路径在图中但未被任何规则命中 → UNCOVERED_BUT_REACHABLE
        """
        ...

    async def _heuristic_sink_score(self, call_node: Node) -> tuple[float, str]:
        """启发式评分 — 判断一个不在 YAML 中的函数调用是否可能是危险 sink。

        评分维度:
        - 函数名含危险词 (query, execute, exec, command, open, read, write,
          send, fetch, render, eval, load, deserialize): +20
        - 参数包含字符串拼接/插值: +30
        - 调用来自已知危险库 (sqlalchemy, pymongo, redis, psycopg2,
          axios, httpx, requests, subprocess): +40
        - 有用户输入可达: +50
        - 在循环/条件分支中: +10
        - 是自定义包装函数 (内部调用了已知 sink): +15

        返回 (score, reason_string)
        阈值: >= 60 → HEURISTIC_SINK, < 60 → UNREACHABLE_SINK
        """
        ...

    def get_paths_by_label(
        self, graph: AnnotatedPathGraph, label: PathLabel
    ) -> list[AnnotatedPath]:
        """按标签筛选路径"""
        ...

    def get_blind_spot_report(self, graph: AnnotatedPathGraph) -> BlindSpotReport:
        """生成盲区报告 — 哪些代码区域完全没有被覆盖"""
        ...
```

### 2.4 标注对后续阶段的影响

**Phase 2 (攻击面映射)**: 不再过滤, 而是接收所有端点。对每个端点:
- 使用 PathLabel 调整 priority 计算 (如: `trust_boundary_crossing` → priority 直接设为 9+)
- `exposed_no_source` 端点的 priority 不因 "无已知 source" 而降低
- 输出: 所有端点按 priority 排序 (不截断)

**Phase 3 (假设生成)**: 接收所有路径, 按标签和 priority 分配预算:
- `confirmed_taint` + priority >= 8 → 强模型精确验证
- `heuristic_sink` + priority >= 5 → 便宜模型初步审查
- `exposed_no_source` + priority >= 6 → 盲扫 LLM 审查 (通道2)
- `uncovered_but_reachable` → 不进入 Phase 3 (进入盲区清单)

**Phase 4 (验证)**: 根据标签调整验证深度:
- `confirmed_taint` → L1 确定性验证 + L2 LLM 完整验证
- `sanitized_taint` → 仅 L2 (对抗性视角: "sanitizer 是否可绕过?")
- `heuristic_sink` → L2 轻量验证 (便宜模型)

---

## 三、核心改造二: 多通道并行架构

### 3.1 架构全景

```
                         ┌─────────────────────────────────────┐
                         │          CPG 构建 (共享基础)          │
                         │    AST + CFG + DFG + HTTP_ROUTE      │
                         └──────────────┬──────────────────────┘
                                        │
                ┌───────────────────────┼───────────────────────┐
                │                       │                       │
                ▼                       ▼                       ▼
    ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
    │ 通道1: CPG 确定性  │   │ 通道2: 盲扫 LLM    │   │ 通道3: 反向 Sink   │
    │                   │   │                   │   │                   │
    │ source→sink 追踪  │   │ 不依赖 Phase1     │   │ 从每个函数调用     │
    │ YAML 污点规则     │   │ 探索性安全审查     │   │ 反向追踪到输入     │
    │ + sanitizer 判断  │   │ "基于模式的扫描    │   │ 启发式评分标记     │
    │                   │   │  器会遗漏什么?"    │   │ 未知/包装的 sink  │
    │ 产出: 标签路径图   │   │ 产出: 独立假设集   │   │ 产出: 启发式候选   │
    └────────┬──────────┘   └────────┬──────────┘   └────────┬──────────┘
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     │
                                     ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                    通道4: 架构偏离检测                            │
    │  用便宜 LLM 构建安全架构模型 → 对比实际 CPG → 发现偏离            │
    │  产物: trust_boundary_crossing / architecture_deviation 标签     │
    └───────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                    通道5: 差异覆盖分析 (零 LLM 成本)              │
    │  "我们分析了什么 vs 我们应该分析什么"                              │
    │  产物: BlindSpotManifest (盲区清单)                               │
    └───────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │                    合并 & 去重 & 优先级排序                       │
    │  MergeEngine: 同一漏洞被多通道发现 → 合并为一个假设 (证据叠加)    │
    │  PriorityScheduler: 按 (severity × confidence × label_priority)   │
    └───────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │              Phase 3: LLM 假设生成 (消费合并后的候选)             │
    └───────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │              Phase 4: 验证 (L1 确定性 + L2 LLM)                   │
    └───────────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
    ┌───────────────────────────────────────────────────────────────────┐
    │              Phase 5: 报告 (含盲区清单 + 覆盖完整性度量)          │
    └───────────────────────────────────────────────────────────────────┘
```

### 3.2 通道 1: CPG 确定性污点追踪 (传统 Phase 1 升级版)

**职责**: 无损遍历所有代码路径, 标注而非过滤。

**输入**: CPG 全图

**处理**:
1. 从每个 HTTP 端点参数出发, 追踪数据流到每个可达的 sink
2. 对照 `taint_rules.yaml` 判断 source/sink 是否已知
3. 检查路径上是否有 sanitizer
4. 为每条路径打上 PathLabel (见第二章标签体系)
5. 不丢弃任何路径

**产出**:
- `AnnotatedPathGraph` — 全量路径 + 标签
- 标签分布统计: CONFIRMED_TAINT N 条, HEURISTIC_SINK M 条, ...

**LLM 成本**: $0

**实现要点**:
- 必须完成 CPG 构建后运行 (依赖完整的 AST+DFG)
- 污点传播规则仍来自 YAML (闭世界), 但 "不匹配" 不再是终点
- 对每个 sink 调用都需要检查, 不限于 YAML 定义的 sink

### 3.3 通道 2: 盲扫 LLM (MAS-Indep Lite)

**职责**: 完全独立于通道1, 以 "探索性安全审查员" 视角阅读代码, 寻找通道1 遗漏的漏洞。

**原理 (来自 COVERAGE-GAP-ANALYSIS.md 方案2)**:
```
通道1 (CPG 确定性) 擅长: 已知 source→sink 模式的污点追踪
通道2 (盲扫 LLM)   擅长: 逻辑漏洞、IDOR、缺失检查、框架误用
两者视角正交 — 合并后互补
```

**输入**:
- CPG 提取的文件/函数列表 (用于导航)
- 被标记为 `exposed_no_source` 和 `missing_auth_annotation` 的端点 (重点审查)
- **不接收**通道1 的污点追踪结果 (保持独立性)

**处理**:
```python
class BlindScanChannel:
    """独立盲扫 LLM 通道 — 不依赖通道1 输出。"""

    def __init__(self, llm_provider: LlmProvider, cpg_query: CPGQuery):
        ...

    async def scan_endpoint(self, endpoint: AnnotatedEndpoint) -> list[BlindHypothesis]:
        """对一个端点做独立的探索性安全审查。

        使用专门的 system prompt:
        "你是探索性安全审查员。与系统性扫描器不同,
         你的工作是寻找基于模式的扫描器会遗漏的内容:
         1. 业务逻辑缺陷: 改变 ID 是否能访问其他用户的数据?
         2. 缺失的检查: 是否有端点没有授权检查?
         3. 假设违反: 代码是否假设输入在上游已被验证?
         4. 危险组合: 两个看似安全的操作组合后是否危险?
         5. 框架误用: 安全功能是否被错误使用?"
        """
        ...

    async def scan_batch(
        self,
        endpoints: list[AnnotatedEndpoint],
        max_tokens: int = 50000,
        model: str = "cheap",
    ) -> list[BlindHypothesis]:
        """批量扫描 (控制 token 消耗)。

        优先扫描:
        1. exposed_no_source 标签的端点
        2. missing_auth_annotation 标签的端点
        3. Phase 2 高 priority 的端点
        """
        ...

    def select_target_files(
        self,
        all_endpoints: list[AnnotatedEndpoint],
        mode: str = "standard",
    ) -> list[AnnotatedEndpoint]:
        """按模式选择目标文件比例:
        - quick:   0% (不运行)
        - standard: top 30% priority 的端点
        - deep:    top 50% priority 的端点
        """
        ...
```

**产出**: `list[BlindHypothesis]` — 与通道1 视角正交的漏洞假设

**LLM 成本 (对 50K 行项目)**:
- cheap 模型 (Kimi K2): ~$0.10 (standard, top 30%)
- mid 模型 (Sonnet): ~$0.50 (deep, top 50%)

**独立性保证**:
- 不在 prompt 中包含 "Phase 1 已经发现 X" 这类信息
- 不接收通道1 产出的任何假设作为输入
- 独立运行, 可以并行

### 3.4 通道 3: 反向 Sink 分析

**职责**: 从 "所有函数调用" 出发, 反向追踪到用户输入。目的不是找到已知漏洞, 而是发现不在 YAML 中的危险 sink 模式。

**原理 (来自 COVERAGE-GAP-ANALYSIS.md 方案1)**:
```
传统 Phase 1:  source (已知) → 追踪 → sink (已知)
反向 Sink 分析: sink (所有函数调用) → 反向追踪 → source (任意用户输入)
```

**输入**:
- CPG 全图
- `taint_rules.yaml` (已知 source 列表, 用于判断 "是否有用户输入可达")
- 启发式评分规则

**处理**:
```python
class ReverseSinkChannel:
    """反向 Sink 分析通道 — 从调用点反向找源头。"""

    def __init__(self, cpg_query: CPGQuery, heuristic_config: HeuristicConfig):
        ...

    async def analyze_all_calls(self) -> list[HeuristicCandidate]:
        """遍历 CPG 中所有函数调用, 对每个调用:

        1. 检查是否在 YAML sink 列表中 → 是, 跳过 (通道1 会处理)
        2. 检查是否在 YAML source 列表中 → 是, 跳过 (这是 source, 不是 sink)
        3. 计算启发式危险评分
        4. 如果评分 >= 阈值, 反向追踪到所有可达的用户输入
        5. 如果找到可达用户输入, 标记为 HEURISTIC_SINK
        6. 如果找不到, 标记为 UNREACHABLE_SINK
        """
        ...

    def _compute_danger_score(self, call_node: Node) -> tuple[float, str]:
        """启发式危险评分。

        维度:
        A. 函数名含危险词汇 (query/execute/command/open/etc):           +20
        B. 参数包含字符串拼接或插值:                                     +30
        C. 调用来自已知危险库 (sqlalchemy/redis/axios/subprocess/etc):  +40
        D. 调用在循环或条件分支中:                                       +10
        E. 调用是自定义包装函数 (内部调用了已知 sink):                    +15
        F. 调用在 try-except 中 (可能吞异常):                            +5
        G. 返回 HTTP 响应 (可能是信息泄露):                               +10

        阈值: >= 60 → 标记为 HEURISTIC_SINK
        """
        ...

    async def _trace_backward(self, call_node: Node, max_depth: int = 10) -> list[SourceNode]:
        """从 call_node 反向追踪数据流, 找到所有可达的用户输入源。"""
        ...

    async def analyze(self) -> ReverseSinkResult:
        """返回:
        - heuristic_candidates: 启发式标记的候选 (tag: HEURISTIC_SINK)
        - unreachable_sinks: 可疑但无已知 source 可达 (tag: UNREACHABLE_SINK)
        - stats: 总共检查了 N 个调用, 标记了 M 个候选
        """
        ...
```

**产出**: `list[HeuristicCandidate]` — 不在 YAML 中的潜在危险调用

**LLM 成本**: $0 (纯 CPG 查询)

**关键价值**: 发现 YAML 未覆盖的:
- 自定义 ORM 包装函数 (`db.find_user(id)`)
- 采用新框架的 HTTP 客户端 (`httpx.AsyncClient.get(url)`)
- 消息队列消费者 (`@kafka_listener` 的 `process_message()`)

### 3.5 通道 4: 架构偏离检测

**职责**: 构建安全架构模型, 与 CPG 中实际代码对比, 发现架构层面的安全偏离。

**原理 (来自 COVERAGE-GAP-ANALYSIS.md 方案7 + Hound)**:
```
预期安全属性 (预期)  vs  实际代码 (CPG)
    ↓                        ↓
    └──────── 对比 ──────────┘
              ↓
    架构偏离 → 潜在漏洞
```

**输入**:
- CPG 提取的端点列表、路由结构、权限装饰器
- 项目配置 (框架类型、中间件列表)

**处理**:
```python
class ArchitectureDeviationChannel:
    """架构偏离检测通道。"""

    def __init__(self, llm_provider: LlmProvider, cpg_query: CPGQuery):
        ...

    async def build_security_model(self) -> SecurityArchitectureModel:
        """用便宜 LLM 构建预期安全架构模型。

        输入: 项目结构、框架、路由列表、中间件
        输出: SecurityArchitectureModel {
            trust_boundaries: list[TrustBoundary],  # 信任边界
            auth_gates: list[AuthGate],             # 认证门控点
            sensitivity_zones: list[SensitivityZone], # 数据敏感区
            expected_properties: list[SecurityProperty], # 预期安全属性
        }
        成本: ~$0.01 (Kimi K2)
        """
        ...

    async def detect_deviations(self) -> list[ArchitectureDeviation]:
        """对比安全模型与实际 CPG, 检测偏离:

        1. 信任边界违反: 低权限区的数据直接流入高权限区
        2. 认证门控缺失: 应该有 @login_required 的端点没有
        3. 敏感数据暴露: INFO 级别端点返回了 CRITICAL 级别数据
        4. 安全属性违反: "只读端点" 实际执行了写操作

        例如:
        - 安全模型预期: /api/users/:id 应该有权限检查
        - CPG 实际: 该端点无 @require_auth, 也无代码中的 user_id 校验
        → TRUST_BOUNDARY_CROSSING 或 ARCHITECTURE_DEVIATION
        """
        ...

    async def analyze(self) -> ArchitectureResult:
        ...
```

**产出**:
- `SecurityArchitectureModel` — 安全架构模型
- `list[ArchitectureDeviation]` — 架构偏离列表
- 对应标签: `trust_boundary_crossing`, `architecture_deviation`

**LLM 成本**: ~$0.01 (构建模型) + ~$0.02 (偏离检测) ≈ $0.03

### 3.6 通道 5: 差异覆盖分析 (零 LLM 成本)

**职责**: 不寻找危险代码, 而是寻找 "未被证明安全的代码"。

**原理 (来自 COVERAGE-GAP-ANALYSIS.md 方案5)**:
```
全部代码
  ├── 已被通道1/2/3/4 分析过 → 有结论 (安全或不安全)
  └── 未被任何通道分析 → 盲区 (不知道安全还是不安全)
```

**处理**:
```python
class DifferentialCoverageChannel:
    """差异覆盖分析通道 — 零 LLM 成本。"""

    def __init__(self, cpg_query: CPGQuery):
        ...

    async def compute_coverage(
        self,
        annotated_graph: AnnotatedPathGraph,
        analyzed_by_other_channels: set[str],  # 被分析过的东西的文件路径/函数名
    ) -> BlindSpotManifest:
        """计算: '我们分析了什么 vs 我们应该分析什么'

        检查清单:
        - [ ] 每个 HTTP 端点是否被至少一个通道分析?
        - [ ] 每个数据库调用是否能追溯到用户输入? (不能 → 标记)
        - [ ] 每个文件操作是否能追溯到用户输入?
        - [ ] 每个命令执行是否能追溯到用户输入?
        - [ ] 每个网络请求是否能追溯到用户输入?
        - [ ] 是否检查了所有框架的配置?
        - [ ] 是否检查了所有中间件?
        - [ ] 是否检查了 WebSocket 处理器?
        - [ ] 是否检查了消息队列消费者?
        - [ ] 是否检查了定时任务?

        对每个 "否", 生成一个 BlindSpot 条目。
        """
        ...

    async def generate_manifest(self) -> BlindSpotManifest:
        """生成结构化盲区清单。

        BlindSpotManifest {
            uncovered_endpoints: list[BlindSpot],
            uncovered_db_calls: list[BlindSpot],
            uncovered_file_ops: list[BlindSpot],
            uncovered_command_execs: list[BlindSpot],
            uncovered_network_calls: list[BlindSpot],
            uncovered_configs: list[BlindSpot],
            uncovered_middleware: list[BlindSpot],
            uncovered_websocket: list[BlindSpot],
            uncovered_queues: list[BlindSpot],
            uncovered_cronjobs: list[BlindSpot],
            summary: CoverageSummary,  # 覆盖率统计
        }
        """
        ...
```

**LLM 成本**: $0

**关键价值**:
- 让用户明确知道 "我们可能漏了什么"
- 为覆盖完整性报告提供数据源
- 在 `--deep` 模式下作为饱和扫描的种子来源

### 3.7 合并引擎 (MergeEngine)

**职责**: 多通道独立运行后, 合并各自产生的假设, 去重, 优先级排序。

```python
class MergeEngine:
    """多通道假设合并、去重、优先级排序。"""

    def __init__(self):
        ...

    def merge(
        self,
        channel1_paths: AnnotatedPathGraph,           # 通道1: 带标签路径
        channel2_hypotheses: list[BlindHypothesis],   # 通道2: 盲扫假设
        channel3_candidates: list[HeuristicCandidate], # 通道3: 启发式候选
        channel4_deviations: list[ArchitectureDeviation], # 通道4: 架构偏离
        channel5_blind_spots: BlindSpotManifest,      # 通道5: 盲区清单
    ) -> MergeResult:
        """合并五个通道的产出。

        合并策略:
        1. 按 (sink_location, vuln_type) 分组 — 相同 sink+类型的假设是同一漏洞
        2. 同组的假设合并:
           - 保留最具体的 source→sink 路径
           - 多个通道标记同一漏洞 → 提升置信度 (+0.1 每额外通道)
           - 通道1 (CPG 确定性) 的路径证据作为锚点
           - 通道2/3 (LLM) 的推理作为补充证据
        3. 去重: 相同的 source + sink + vuln_type → 合并
        4. 排序: 按 priority_score 降序
        """
        ...

    def _compute_priority_score(
        self, hypothesis: MergedHypothesis
    ) -> float:
        """综合优先级评分。

        priority_score = (
            severity_weight(severity) * 0.35 +
            confidence * 0.25 +
            label_priority(label) * 0.20 +
            channel_count * 0.10 +          # 多通道发现的权重更高
            attack_surface_priority * 0.10   # Phase 2 的端点 priority
        )

        severity_weight: CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5, LOW=0.2, INFO=0.1
        label_priority: confirmed_taint=1.0, heuristic_sink=0.7, exposed_no_source=0.5
        """
        ...

    def _deduplicate(
        self, hypotheses: list[Any]
    ) -> list[MergedHypothesis]:
        """去重逻辑:

        两个假设视为相同当:
        - sink 的文件+行号相同
        - vuln_type 相同

        合并时:
        - 保留更完整的 data_flow_path
        - 置信度取 max (不取平均, 避免稀释强信号)
        - 添加 origin_channels 字段记录来源
        """
        ...
```

### 3.8 饱和扫描循环 (SaturationScanner) — deep 模式特有

```python
class SaturationScanner:
    """迭代饱和扫描 — 用已确认的漏洞作为种子发现新的分析目标。

    每轮:
    1. 用已确认的漏洞中的 sink_function, 找到:
       - 它的被调用者 (谁调用了这个 sink?)
       - 它的调用者 (这个 sink 还调用了什么?)
       - 同路由模块的其他端点 (相邻攻击面)
    2. 新发现的候选进入下一轮
    3. 没有新候选或达到 max_rounds 时停止

    成本自然递减 (每轮候选减少), 循环自然收敛。
    """

    def __init__(self, orchestrator: "CoverageAwareOrchestrator", max_rounds: int = 4):
        ...

    async def run(
        self, initial_findings: list[ConfirmedFinding]
    ) -> SaturationResult:
        round_num = 0
        all_findings = list(initial_findings)
        new_seeds = self._extract_seeds(initial_findings)

        while round_num < self.max_rounds and new_seeds:
            round_num += 1
            # 对新种子运行通道1+3 (比完整扫描便宜)
            round_findings = await self._run_lightweight_scan(new_seeds)
            all_findings.extend(round_findings)

            # 从新发现中提取下一轮种子
            new_seeds = self._extract_seeds(round_findings) - self._already_analyzed

        return SaturationResult(
            total_findings=all_findings,
            rounds=round_num,
            new_per_round=[...],
        )

    def _extract_seeds(
        self, findings: list[ConfirmedFinding]
    ) -> set[SeedPoint]:
        """从已确认漏洞提取新分析目标:
        - 漏洞 sink 函数的所有被调用者
        - 漏洞 source 函数的所有调用者
        - 同路由模块的所有端点
        """
        ...
```

---

## 四、核心改造三: 预算感知的覆盖策略

### 4.1 预算结构体

```python
@dataclass
class CoverageBudget:
    """覆盖扫描预算 — 按通道和阶段分配。"""

    total_budget: float
    scan_mode: str  # "quick" | "standard" | "deep"

    # 各通道的分配 (占 total 的比例)
    allocation: dict[str, float] = field(default_factory=dict)

    # 动态追踪
    spent: dict[str, float] = field(default_factory=dict)
    reserved: dict[str, float] = field(default_factory=dict)  # 对未来阶段的预留

    # 优先级队列
    hypothesis_queue: list[PrioritizedHypothesis] = field(default_factory=list)

    def can_spend(self, channel: str, estimated_cost: float) -> bool:
        """检查是否有足够预算"""
        return self.spent.get(channel, 0) + estimated_cost <= self.allocation.get(channel, 0)

    def spend(self, channel: str, cost: float) -> None:
        """记录支出"""
        self.spent[channel] = self.spent.get(channel, 0) + cost

    def rebalance(self) -> None:
        """动态再平衡: 将未使用预算从已完成通道转移到高优先级通道。

        规则:
        - 通道1 和通道3 是零成本的, 预算溢出到通道2
        - 如果 Phase 4 发现许多高分候选, 从 Phase 3 转移预算到 Phase 4
        - Completeness Critic ($0.02) 最终保障 — 始终预留
        """
        ...

    def get_remaining_by_priority(self) -> dict[int, float]:
        """按优先级返回剩余预算 — 用于决定哪些假设值得验证"""
        ...


class BudgetManager:
    """预算管理器 — 扩展原 plans/models/budget.py 的设计。"""

    def __init__(self, scan_mode: str, total_budget: float | None = None):
        # 默认预算映射
        DEFAULT_BUDGETS = {
            "quick": 1.0,
            "standard": 5.0,
            "deep": 25.0,
        }
        self.total_budget = total_budget or DEFAULT_BUDGETS[scan_mode]
        self.scan_mode = scan_mode
        self.budget = self._create_budget()

    def _create_budget(self) -> CoverageBudget:
        """按扫描模式创建初始分配。"""
        ...

    async def check_and_route(
        self,
        hypothesis: PrioritizedHypothesis,
        task_complexity: int,
    ) -> ModelSpec | None:
        """预算感知的模型路由:
        1. 检查该 hypothesis 所属通道是否有剩余预算
        2. 如果预算不足, 尝试降级模型 (STRONG→MID→CHEAP)
        3. 如果所有降级路径都没有预算, 跳过该假设 (进入盲区清单)
        """
        ...

    def should_run_channel(self, channel: str) -> bool:
        """判断某通道在当前模式下是否应该运行。

        决策矩阵 (见第五章详细配置):
        - quick:  通道1(是) + 通道3(精简) + 通道5(是)
        - standard: 通道1/2/3/4/5(是)
        - deep:   全部 + 饱和扫描
        """
        ...
```

### 4.2 预算分配矩阵

| 通道/阶段 | quick ($1) | standard ($5) | deep ($25) |
|:---------|:-----------|:--------------|:-----------|
| CPG 构建 | $0 | $0 | $0 |
| 通道1 (CPG 标注) | $0 | $0 | $0 |
| 通道2 (盲扫 LLM) | — | $0.15 (top 30%) | $0.80 (top 50%, Sonnet) |
| 通道3 (反向 Sink) | $0 | $0 | $0 |
| 通道4 (架构偏离) | ~$0.02 | ~$0.03 | ~$0.08 (Sonnet 增强) |
| 通道5 (差异覆盖) | $0 | $0 | $0 |
| Phase 2 (攻击面映射) | ~$0.15 | ~$0.30 | ~$0.60 |
| Phase 3 (假设生成) | ~$0.40 | ~$1.60 | ~$5.00 |
| Phase 4 (L1 验证) | $0 | $0 | $0 |
| Phase 4 (L2 验证) | ~$0.30 | ~$2.20 | ~$8.00 |
| Completeness Critic | ~$0.02 | ~$0.02 | ~$0.05 (迭代) |
| 对抗性审查 | — | ~$0.15 | ~$0.50 |
| 饱和扫描 (额外轮次) | — | ~$0.40 (1轮) | ~$1.50 (3轮) |
| 报告生成 | $0 | $0 | $0 |
| **预留余量** | ~$0.11 | ~$0.15 | ~$8.47 |
| **总计** | **~$1.00** | **~$5.00** | **~$25.00** |

### 4.3 预算动态再平衡算法

```python
def rebalance_budget(budget: CoverageBudget, phase_results: dict) -> CoverageBudget:
    """动态再平衡 — 在管道运行过程中重新分配预算。

    触发时机: 每个 Phase 完成后。

    核心逻辑:
    1. 通道1 产出大量 CONFIRMED_TAINT 路径 → 增加 Phase 3/4 预算
    2. 通道2 产出大量 IDOR/逻辑漏洞假设 → 增加 Phase 4 强模型预算
    3. 通道5 发现大量盲区 → 考虑从低优先级假设转移预算到盲区探索
    4. 所有通道产出很少 → 保留预算, 不浪费

    具体策略:
    - 如果 confirmed_taint + heuristic_sink > 50 个:
      从通道2 转移 30% 预算到 Phase 4 L2 验证
    - 如果 exposed_no_source > 端点总数的 30%:
      增加通道2 预算 (需要更多盲扫覆盖)
    - 如果 uncovered_but_reachable > 20%:
      从 Phase 3 转移 10% 预算到饱和扫描 (探索盲区)
    """

    total_high_value = (
        phase_results.get("confirmed_taint_count", 0)
        + phase_results.get("heuristic_sink_count", 0)
    )

    blind_spot_ratio = phase_results.get("uncovered_ratio", 0)

    # 情景1: 高价值候选很多 → 增加验证预算
    if total_high_value > 50:
        transfer = budget.allocation.get("channel2_blind_scan", 0) * 0.3
        budget.allocation["phase4_l2_validation"] += transfer
        budget.allocation["channel2_blind_scan"] -= transfer

    # 情景2: 盲区比例高 → 增加盲扫和饱和扫描预算
    if blind_spot_ratio > 0.3:
        transfer = budget.allocation.get("phase3_hypothesis", 0) * 0.1
        budget.allocation["saturation_scan"] = budget.allocation.get("saturation_scan", 0) + transfer
        budget.allocation["phase3_hypothesis"] -= transfer

    return budget
```

---

## 五、核心改造四: 覆盖完整性度量体系

### 5.1 度量指标定义

```python
@dataclass
class CoverageMetrics:
    """覆盖完整性度量 — 回答 "我们分析得多彻底?" """

    # ─── 端点级覆盖 ───
    endpoint_coverage_ratio: float
    """HTTP 端点被至少一个通道分析的比率
    公式: analyzed_endpoints / total_endpoints
    目标: standard >= 0.80, deep >= 0.95
    """

    endpoint_risk_weighted_coverage: float
    """风险加权端点覆盖率 — 高 priority 端点权重更高
    公式: sum(priority_i × covered_i) / sum(priority_i)
    其中 covered_i = 1 如果该端点被任何通道分析, 否则 0
    目标: standard >= 0.90, deep >= 0.98
    """

    # ─── 调用点覆盖 ───
    sink_coverage_ratio: float
    """函数调用点被标记 (label != uncovered_but_reachable) 的比率
    公式: labeled_sinks / total_sinks
    目标: standard >= 0.70
    """

    dangerous_sink_coverage: float
    """被标记为危险 (confirmed_taint / heuristic_sink / sanitized_taint) 的调用点比率
    公式: dangerous_labeled_sinks / total_potentially_dangerous_sinks
    "potentially_dangerous" 由启发式评分 >= 30 定义
    目标: standard >= 0.85
    """

    # ─── 漏洞类别覆盖 ───
    cwe_diversity_ratio: float
    """被检查的 CWE 类别数 / 与目标技术栈相关的总 CWE 类别数
    公式: checked_cwe_categories / applicable_cwe_categories
    目标: standard >= 0.60, deep >= 0.85
    """

    # ─── 信任边界覆盖 ───
    trust_boundary_coverage: float
    """被分析的信任边界交叉点比率
    公式: analyzed_trust_crossings / total_trust_crossings
    目标: deep >= 0.90
    """

    # ─── 完整性评分 ───
    completeness_score: float
    """综合覆盖完整性评分 (0.0 - 1.0)
    公式: 各指标加权平均
      endpoint_coverage: 0.15
      risk_weighted_coverage: 0.25
      sink_coverage: 0.15
      dangerous_sink_coverage: 0.20
      cwe_diversity: 0.15
      trust_boundary: 0.10 (仅 deep 模式; 其他模式权重重新分配)
    目标: standard >= 0.75, deep >= 0.90
    """

    # ─── 盲区指标 ───
    blind_spot_count: int
    """盲区条目总数"""

    blind_spot_by_category: dict[str, int]
    """按类别分布的盲区: {"uncovered_endpoint": N, "unreachable_sink": M, ...}"""

    coverage_gap_risk_score: float
    """盲区风险评分 (0.0 - 1.0) — 盲区中可能包含高危漏洞的估计可能性
    影响因素: 盲区代码的复杂度、是否跨越信任边界、是否处理用户数据
    """
```

### 5.2 覆盖率计算流程

```
CPG 全图构建完毕
    │
    ├── 提取: all_endpoints, all_sinks, all_trust_crossings
    │
通道1 标注完毕
    │
    ├── 统计: labeled_paths, covered_sinks, covered_endpoints
    │
通道2/3/4/5 完毕
    │
    ├── 统计: additional_covered (被通道2/3/4额外覆盖的)
    │
Phase 4 验证完毕
    │
    ├── 确认: confirmed_findings, covered_cwe_categories
    │
    ▼
CoverageMetrics.compute()
```

### 5.3 盲区清单的结构化输出

```python
@dataclass
class BlindSpot:
    """单个盲区条目。"""

    location: CodeLocation
    category: str  # "uncovered_endpoint" | "unreachable_sink" | "uncovered_db_call" | ...
    reason: str    # 为什么这个区域未被覆盖
    estimated_risk: str  # "high" | "medium" | "low" | "unknown"
    risk_rationale: str  # 风险评估理由
    suggested_action: str  # 建议的下一步
    related_path_label: PathLabel | None  # 关联的标签

    # 示例:
    # BlindSpot(
    #     location=CodeLocation(file="routes/admin.py", line=42),
    #     category="uncovered_endpoint",
    #     reason="缺少认证注解但无已知 source→sink 路径",
    #     estimated_risk="high",
    #     risk_rationale="admin 路径 + 无认证 = 潜在 IDOR/权限绕过",
    #     suggested_action="建议人工审查该端点的权限控制逻辑",
    #     related_path_label=PathLabel.MISSING_AUTH_ANNOTATION,
    # )


@dataclass
class BlindSpotManifest:
    """盲区清单 — 报告的覆盖完整性附录。"""

    session_id: str
    generated_at: str
    metrics: CoverageMetrics
    blind_spots: list[BlindSpot]

    # 按风险等级分组
    high_risk: list[BlindSpot]
    medium_risk: list[BlindSpot]
    low_risk: list[BlindSpot]

    # 摘要
    summary: str  # "共发现 47 个盲区, 其中 8 个高风险。"

    # 可视化数据 (供前端消费)
    treemap_data: dict  # 用于渲染代码覆盖树图

    def to_report_section(self) -> str:
        """生成 Markdown 格式的盲区报告章节。"""
        ...
```

### 5.4 Completeness Critic (完整性审查)

在 Phase 4 完成后运行, 用强模型系统性地回答 "我们漏了什么"。

```python
class CompletenessCritic:
    """完整性审查员 — 在所有分析完成后运行的元分析。"""

    def __init__(self, llm_provider: LlmProvider):
        ...

    async def review(self, context: CompletenessContext) -> CriticReport:
        """用强模型系统性地审查覆盖完整性。

        输入 context 包含:
        - 已分析的代码区域清单
        - 已确认的漏洞列表
        - 盲区清单
        - 技术栈信息
        - 框架信息
        - 当前扫描模式

        审查维度:
        1. 未覆盖的代码区域: 哪些文件/模块/包完全未被分析?
        2. 未检查的漏洞类型: 给定此技术栈, 还应检查什么?
        3. 隐藏的攻击面: WebSocket/消息队列消费者/定时任务/CLI 命令
        4. 间接数据流: 经过持久化存储的数据路径 (二阶注入)
        5. 配置和基础设施: 非代码但影响安全的内容
        6. 框架特定风险: 该框架的已知陷阱

        System prompt:
        "你是安全审计的完整性审查员。
         ## 本次扫描已覆盖
         [列举已分析的内容]
         ## 你的任务: 系统性地找出我们可能遗漏的
         1. 未覆盖的代码区域
         2. 未检查的漏洞类型
         3. 隐藏的攻击面
         4. 间接数据流
         5. 配置和基础设施
         ## 请输出具体的、可操作的 '需进一步审查' 清单。"
        """
        ...

    async def suggest_next_steps(
        self, critic_report: CriticReport
    ) -> list[CandidateSeed]:
        """将完整性审查的建议转化为具体的分析种子。

        例如:
        "未检查 GraphQL 端点的注入风险"
        → 将 GraphQL 端点加入通道2 的扫描目标
        """
        ...
```

---

## 六、数据流图与组件交互

### 6.1 顶层数据流

```
                              用户触发扫描
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │     CLI (api/cli.py)      │
                    │  解析 --mode / --budget   │
                    └──────────┬───────────────┘
                               │
                               ▼
          ┌────────────────────────────────────────────┐
          │     CoverageAwareOrchestrator               │
          │     (scanner/orchestrator.py — 新实现)      │
          │                                             │
          │  1. 创建 CoverageBudget (按模式分配)        │
          │  2. 编排并行通道                            │
          │  3. 调度 MergeEngine                        │
          │  4. 驱动 Phase 2-3-4-5                      │
          │  5. 管理饱和扫描循环                        │
          │  6. 运行 CompletenessCritic                 │
          │  7. 生成 BlindSpotManifest                  │
          └──────────┬─────────────────────────────────┘
                     │
         ┌───────────┼───────────┬───────────┬───────────┐
         │           │           │           │           │
         ▼           ▼           ▼           ▼           ▼
    ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
    │通道1    │ │通道2    │ │通道3    │ │通道4    │ │通道5    │
    │CPG 标注 │ │盲扫 LLM │ │反向 Sink│ │架构偏离 │ │差异覆盖 │
    │(零成本) │ │(LLM)    │ │(零成本) │ │(LLM)    │ │(零成本) │
    └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
         │           │           │           │           │
         └───────────┴───────────┴───────────┴───────────┘
                             │
                             ▼
              ┌──────────────────────────┐
              │      MergeEngine         │
              │  去重 + 合并 + 优先级排序 │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │     Phase 2: 攻击面映射  │
              │  (用 label 调整 priority) │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │   Phase 3: 假设生成 (LLM) │
              │   按优先级消费合并结果    │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │  Phase 4: 验证 (L1 + L2) │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │ CompletenessCritic       │
              │ "我们漏了什么?"           │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │  饱和扫描? (deep 模式)    │
              │  有新种子? → 回到合并     │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │     Phase 5: 报告生成    │
              │  含 CoverageMetrics +     │
              │  BlindSpotManifest        │
              └──────────────────────────┘
```

### 6.2 Orchestrator 状态机

```python
class ScanPhase(str, Enum):
    """扫描编排状态机阶段。"""

    INIT = "init"
    CPG_BUILDING = "cpg_building"
    CHANNELS_RUNNING = "channels_running"
    MERGING = "merging"
    ATTACK_SURFACE_MAPPING = "attack_surface_mapping"  # Phase 2
    HYPOTHESIS_GENERATING = "hypothesis_generating"     # Phase 3
    VALIDATING = "validating"                           # Phase 4
    COMPLETENESS_REVIEW = "completeness_review"
    SATURATING = "saturating"                           # 饱和扫描 (deep)
    REPORTING = "reporting"                             # Phase 5
    DONE = "done"
    ERROR = "error"


class CoverageAwareOrchestrator:
    """覆盖感知的扫描编排器。

    替代旧 orchestrator.py 的线性流水线。
    """

    def __init__(
        self,
        cpg_query: CPGQuery,
        llm_provider: LlmProvider,
        budget_manager: BudgetManager,
        path_annotator: PathAnnotator,
        blind_scan: BlindScanChannel,
        reverse_sink: ReverseSinkChannel,
        architecture_deviation: ArchitectureDeviationChannel,
        differential_coverage: DifferentialCoverageChannel,
        merge_engine: MergeEngine,
        mapper: AttackSurfaceMapper,
        hypothesis_gen: HypothesisGenerator,
        validator: Validator,
        completeness_critic: CompletenessCritic,
        saturation_scanner: SaturationScanner | None,
        report_gen: ReportGenerator,
    ):
        ...

    async def run(self, target_path: str, mode: str) -> ScanResult:
        """主编排流程。"""
        ...

    async def _run_channels_parallel(self) -> ChannelResults:
        """并行运行通道1/3/4/5。

        通道2 (盲扫 LLM) 是否运行取决于模式。
        通道1 必须先完成 (为通道3/4/5 提供标注的路径图)。
        通道3/4/5 可以并行 (都只读 CPG)。
        """
        ...
```

---

## 七、协议与接口扩展

### 7.1 新增协议

以下协议需要添加到 `core/protocols.py`:

```python
# ─── 路径标注协议 ───

class PathLabel(str, Enum):
    """代码路径标签"""
    CONFIRMED_TAINT = "confirmed_taint"
    SANITIZED_TAINT = "sanitized_taint"
    HEURISTIC_SINK = "heuristic_sink"
    UNREACHABLE_SINK = "unreachable_sink"
    EXPOSED_NO_SOURCE = "exposed_no_source"
    MISSING_AUTH_ANNOTATION = "missing_auth_annotation"
    UNCOVERED_BUT_REACHABLE = "uncovered_but_reachable"
    NO_KNOWN_SOURCE = "no_known_source"
    TRUST_BOUNDARY_CROSSING = "trust_boundary_crossing"
    ARCHITECTURE_DEVIATION = "architecture_deviation"


@dataclass
class AnnotatedPath:
    """一条被标注的代码路径。"""
    id: str
    source: CodeLocation
    sink: CodeLocation
    data_flow_steps: list[DataFlowStep]
    label: PathLabel
    secondary_labels: list[PathLabel] = field(default_factory=list)
    heuristic_score: float = 0.0
    sanitizers: list[CodeLocation] = field(default_factory=list)
    confidence: float = 0.0  # 初始置信度


@dataclass
class AnnotatedEndpoint:
    """一个被标注的 HTTP 端点。"""
    id: str
    route: str
    methods: list[str]
    handler_location: CodeLocation
    paths: list[AnnotatedPath]
    labels: list[PathLabel]
    has_auth: bool | None  # True/False/None(不确定)
    priority: int = 5


@dataclass
class AnnotatedPathGraph:
    """全量路径标注图。"""
    endpoints: list[AnnotatedEndpoint]
    all_paths: list[AnnotatedPath]
    all_sinks: list[CodeLocation]
    stats: "AnnotationStats"


@dataclass
class AnnotationStats:
    """标注统计。"""
    total_endpoints: int
    total_paths: int
    total_sinks: int
    by_label: dict[PathLabel, int]


class PathAnnotatorProtocol(Protocol):
    """路径标注器协议。"""

    async def annotate_all_paths(self) -> ToolResult[AnnotatedPathGraph]: ...

    def get_paths_by_label(
        self, label: PathLabel
    ) -> list[AnnotatedPath]: ...

    async def heuristic_sink_score(
        self, call_node: Any
    ) -> tuple[float, str]: ...


# ─── 多通道协议 ───

@dataclass
class BlindHypothesis:
    """盲扫 LLM 产生的假设。"""
    id: str
    endpoint_id: str
    vuln_type: str
    severity: FindingSeverity
    confidence: float
    description: str
    reasoning: str
    source_location: CodeLocation | None
    sink_location: CodeLocation | None


@dataclass
class HeuristicCandidate:
    """反向 Sink 分析产生的候选。"""
    id: str
    sink_location: CodeLocation
    danger_score: float
    danger_reasons: list[str]
    reachable_sources: list[CodeLocation]
    label: PathLabel  # HEURISTIC_SINK or UNREACHABLE_SINK


@dataclass
class SecurityArchitectureModel:
    """安全架构模型。"""
    trust_boundaries: list[dict[str, Any]]
    auth_gates: list[dict[str, Any]]
    sensitivity_zones: list[dict[str, Any]]
    expected_properties: list[dict[str, Any]]


@dataclass
class ArchitectureDeviation:
    """架构偏离。"""
    id: str
    deviation_type: str  # "missing_auth" | "boundary_violation" | "property_violation"
    location: CodeLocation
    expected: str  # 预期行为描述
    actual: str    # 实际行为描述
    severity: FindingSeverity
    label: PathLabel  # TRUST_BOUNDARY_CROSSING or ARCHITECTURE_DEVIATION


@dataclass
class BlindSpot:
    """盲区条目。"""
    location: CodeLocation
    category: str
    reason: str
    estimated_risk: str
    risk_rationale: str
    suggested_action: str
    related_path_label: PathLabel | None


@dataclass
class BlindSpotManifest:
    """盲区清单。"""
    session_id: str
    metrics: "CoverageMetrics"
    blind_spots: list[BlindSpot]
    high_risk: list[BlindSpot]
    medium_risk: list[BlindSpot]
    low_risk: list[BlindSpot]
    summary: str


# ─── 覆盖度量协议 ───

@dataclass
class CoverageMetrics:
    """覆盖完整性度量。"""
    endpoint_coverage_ratio: float
    endpoint_risk_weighted_coverage: float
    sink_coverage_ratio: float
    dangerous_sink_coverage: float
    cwe_diversity_ratio: float
    trust_boundary_coverage: float
    completeness_score: float
    blind_spot_count: int
    blind_spot_by_category: dict[str, int]
    coverage_gap_risk_score: float


# ─── 合并协议 ───

@dataclass
class MergedHypothesis:
    """合并后的假设。"""
    id: str
    vuln_type: str
    severity: FindingSeverity
    confidence: float
    source: CodeLocation | None
    sink: CodeLocation | None
    data_flow_path: list[DataFlowStep]
    origin_channels: list[str]  # ["channel1", "channel2"] 等
    path_label: PathLabel
    priority_score: float
    evidence: list[dict[str, Any]]


@dataclass
class MergeResult:
    """合并结果。"""
    merged_hypotheses: list[MergedHypothesis]
    stats: dict[str, Any]
    blind_spot_manifest: BlindSpotManifest
```

### 7.2 对现有 protocol 的修改

**`VulnerabilityHypothesis`** (原有) — 添加字段:

```python
@dataclass
class VulnerabilityHypothesis:
    # ... 原有字段保持不变 ...
    path_label: PathLabel | None = None        # 新增: 路径标签
    origin_channels: list[str] = field(default_factory=list)  # 新增: 来源通道
    channel_confidence_votes: dict[str, float] = field(default_factory=dict)  # 新增: 各通道置信度
```

### 7.3 现有 `CpgAnalyzer` 协议增量

`CpgAnalyzer` 协议已定义 `find_path`, `find_sources`, `find_sinks`, `get_sanitizers`, `slice_path` — 这些是多通道分析的基础。需要添加:

```python
# 新增方法 (添加到 CpgAnalyzer 协议)
async def get_all_http_endpoints(self) -> ToolResult[list[dict[str, Any]]]: ...
"""获取所有 HTTP 端点 (路由 + 方法 + handler + 参数 + 装饰器)"""

async def get_all_function_calls(self) -> ToolResult[list[dict[str, Any]]]: ...
"""获取所有函数调用节点 (支持按模块/类型过滤)"""

async def find_reachable_sources(
    self, call_node: dict[str, Any], max_depth: int = 10
) -> ToolResult[list[dict[str, Any]]]: ...
"""反向追踪: 从 call_node 出发找到所有可达的用户输入源"""

async def get_call_chain_reverse(
    self, func_name: str
) -> ToolResult[list[dict[str, Any]]]: ...
"""反向调用链: 找到所有调用 func_name 的函数"""
```

---

## 八、各扫描模式配置策略

### 8.1 `--quick` 模式 ($1 预算)

**定位**: CI/CD 门禁扫描, 快速阻断明显漏洞。返回值作为 CI 的 pass/fail 判定。

**通道配置**:

| 通道 | 是否运行 | 配置 |
|:-----|:--------|:-----|
| 通道1 (CPG 标注) | 完整 | 所有路径标注, 不丢弃 |
| 通道2 (盲扫 LLM) | 不运行 | 成本超出 quick 预算 |
| 通道3 (反向 Sink) | 精简 | 仅对 priority >= 7 的端点做反向分析 |
| 通道4 (架构偏离) | 精简 | 仅检测认证门控缺失 |
| 通道5 (差异覆盖) | 完整 | 生成盲区清单 |
| Completeness Critic | 完整 | $0.02, 捕获明显遗漏 |

**Phase 3 配置**:
- 仅处理 `confirmed_taint` + `trust_boundary_crossing` + `architecture_deviation` 的路径
- 全部用 CHEAP 模型
- 复杂度 > 7 的路径跳过 (留给 standard/deep)

**Phase 4 配置**:
- L1 确定性验证 (零成本) 全部运行
- L2 LLM 验证: 仅 CRITICAL + HIGH 严重度, CHEAP 模型

**产出**:
- 确定性漏洞列表 (confirmed)
- 盲区清单 (BlindSpotManifest)
- Completeness Critic 报告
- CI pass/fail 判定 (基于 CRITICAL/HIGH 漏洞数)

**CI 集成示例**:
```bash
# .github/workflows/security-scan.yml
hyqagent scan . --quick --exit-code
# exit code 1: 发现 CRITICAL/HIGH, 阻塞 PR
# exit code 0: 通过 (但盲区清单附加到 PR comment)
```

### 8.2 `--standard` 模式 ($5 预算)

**定位**: 默认模式, 性价比最优。适合日常开发和 PR review。

**通道配置**:

| 通道 | 是否运行 | 配置 |
|:-----|:--------|:-----|
| 通道1 (CPG 标注) | 完整 | 所有路径标注 |
| 通道2 (盲扫 LLM) | 完整 | cheap 模型 (Kimi K2), top 30% priority 端点 |
| 通道3 (反向 Sink) | 完整 | 所有可疑调用做启发式评分 |
| 通道4 (架构偏离) | 完整 | cheap 模型构建安全模型 + 对比检测 |
| 通道5 (差异覆盖) | 完整 | 零成本 |
| Completeness Critic | 完整 | $0.02 |
| 对抗性审查 | 部分 | 仅对 HIGH+ 严重度、置信度 > 0.4 的已拒绝假设 |
| 饱和扫描 | 1 轮 | 第2轮有 30% 预算上限 |

**Phase 3 配置**:
- `confirmed_taint`: MID 模型
- `heuristic_sink`: CHEAP 模型
- `exposed_no_source`: 进入通道2 盲扫
- `trust_boundary_crossing`: MID/STRONG 模型 (按复杂度)

**Phase 4 配置**:
- L1 确定性验证: 全部
- L2 LLM 验证: CRITICAL/HIGH → MID; MEDIUM → CHEAP; LOW → 跳过

**产出**:
- 完整漏洞报告 (JSON + Markdown + SARIF)
- BlindSpotManifest
- CoverageMetrics
- Completeness Critic 报告
- 成本归因 (每个发现花了多少钱)

### 8.3 `--deep` 模式 ($25 预算)

**定位**: 最彻底的分析, 适合安全审计、渗透测试前置、合规审查。

**通道配置**:

| 通道 | 是否运行 | 配置 |
|:-----|:--------|:-----|
| 通道1 (CPG 标注) | 完整 | 所有路径标注, 降低启发式阈值 |
| 通道2 (盲扫 LLM) | 增强 | Sonnet 模型, top 50% priority 端点 |
| 通道3 (反向 Sink) | 激进 | 降低启发式阈值 (>= 40 即标记) |
| 通道4 (架构偏离) | 增强 | Sonnet 构建安全模型, Opus 做信任边界推理 |
| 通道5 (差异覆盖) | 增强 | cheap LLM 对盲区做风险评估 |
| Completeness Critic | 迭代 | 每轮饱和扫描后运行 |
| 对抗性审查 | 完整 | Opus 审查所有可疑拒绝 |
| 饱和扫描 | 4 轮 | 迭代发现 |

**Phase 3 配置**:
- `confirmed_taint` + 复杂度 >= 6: STRONG 模型
- `heuristic_sink`: MID 模型
- `trust_boundary_crossing`: STRONG 模型
- 不对 Phase 3 做预算削减 (deep 模式下假设生成是核心价值)

**Phase 4 配置**:
- L1 确定性验证: 全部
- L2 LLM 验证: CRITICAL → STRONG; HIGH → MID/STRONG; MEDIUM → MID; LOW → CHEAP

**deep 模式特有**:
- 饱和扫描 (4 轮): 每次发现新漏洞后, 将其作为种子探索相邻代码
- 盲区风险评估 (cheap LLM): 对盲区清单做自动风险评估
- 增量 Completeness Critic: 每轮饱和扫描后重新审查
- Sonnet 级别架构分析 + Opus 信任边界推理

**产出**:
- 完整漏洞报告 (所有模式共有的)
- 饱和扫描迭代记录 (每轮新发现了什么)
- BlindSpotManifest + 风险评估
- CoverageMetrics (目标 completeness_score >= 0.90)
- Completeness Critic 报告 (含迭代)
- 成本归因 + 性价比分析

### 8.4 配置策略对比总表

| 维度 | quick ($1) | standard ($5) | deep ($25) |
|:-----|:-----------|:--------------|:-----------|
| **通道1 (CPG 标注)** | 完整 | 完整 | 完整 (降低阈值) |
| **通道2 (盲扫 LLM)** | 不运行 | cheap, top 30% | Sonnet, top 50% |
| **通道3 (反向 Sink)** | 精简 (高 priority) | 完整 | 激进 (低阈值) |
| **通道4 (架构偏离)** | 精简 (仅认证) | 完整 (cheap LLM) | 增强 (Sonnet+Opus) |
| **通道5 (差异覆盖)** | 完整 | 完整 | 增强 (+风险评估) |
| **Completeness Critic** | 是 | 是 | 迭代 |
| **对抗性审查** | 不运行 | 部分 | 完整 |
| **饱和扫描** | 不运行 | 1 轮 | 4 轮 |
| **Phase 3 模型** | CHEAP only | CHEAP→MID | MID→STRONG |
| **Phase 4 模型** | 仅 CRITICAL+HIGH | CHEAP→MID | STRONG/Opus |
| **目标 completeness_score** | >= 0.50 | >= 0.75 | >= 0.90 |
| **预期召回率** | 25-35% | 45-55% | 55-65% |
| **适用场景** | CI/CD 门禁 | 日常开发 | 安全审计 |

---

## 九、实施路线图

### 9.1 分阶段实施

#### Phase A: 基础改造 (与当前 CPG Foundation 同步)

**前置条件**: CPG Query 接口完成 (当前路线图 Session 1.7)

1. **实现 PathAnnotator** (`scanner/annotator.py`)
   - 在现有 CPG 查询基础上, 实现路径遍历和标签分配
   - 实现启发式评分函数
   - 产出 `AnnotatedPathGraph`

2. **实现通道3 (反向 Sink 分析)** (`scanner/channels/reverse_sink.py`)
   - 零 LLM 成本, 纯 CPG 查询
   - 可以与 PathAnnotator 共享启发式评分逻辑

3. **实现通道5 (差异覆盖分析)** (`scanner/channels/differential_coverage.py`)
   - 零 LLM 成本, 纯 CPG 查询
   - 产出 `BlindSpotManifest`

#### Phase B: LLM 通道 (在 LLM 集成阶段)

**前置条件**: Model Router + Provider 适配器完成

4. **实现通道2 (盲扫 LLM)** (`scanner/channels/blind_scan.py`)
   - System prompt 模板
   - 目标文件选择逻辑
   - 预算感知的 token 控制

5. **实现通道4 (架构偏离检测)** (`scanner/channels/architecture_deviation.py`)
   - 安全架构模型构建 (cheap LLM)
   - 偏离检测逻辑
   - 与 CPG 实际结构的对比

6. **实现 CompletenessCritic** (`scanner/completeness_critic.py`)
   - System prompt 模板
   - 盲区清单 → 建议种子 的转换

#### Phase C: 编排与合并 (在扫描引擎集成阶段)

7. **实现 MergeEngine** (`scanner/merger.py`)
   - 去重逻辑
   - 多通道证据合并
   - 优先级评分

8. **实现 CoverageAwareOrchestrator** (`scanner/orchestrator.py`)
   - 并行通道编排
   - 状态机
   - 预算动态再平衡

9. **实现 BudgetManager 扩展** (`models/budget.py` 扩展)
   - 多通道分配
   - 动态再平衡算法
   - 降级路由

10. **实现 CoverageMetrics** (`scanner/coverage_metrics.py`)
    - 度量计算
    - 报告集成

#### Phase D: 深度模式 (在长任务能力阶段)

11. **实现 SaturationScanner** (`scanner/saturation.py`)
    - 种子提取
    - 迭代循环
    - 收敛检测

12. **实现对抗性审查** (`scanner/channels/adversarial_review.py`)
    - System prompt 模板
    - 已拒绝假设的二次审查

### 9.2 新增文件清单

```
src/hyqagent/scanner/
├── annotator.py               # 新增: PathAnnotator — Phase 1 改造为标注器
├── orchestrator.py            # 修改: CoverageAwareOrchestrator 替代旧线性流水线
├── merger.py                  # 新增: MergeEngine — 多通道合并
├── coverage_metrics.py        # 新增: CoverageMetrics 计算
├── completeness_critic.py     # 新增: CompletenessCritic
├── saturation.py              # 新增: SaturationScanner (deep 模式)
├── channels/
│   ├── __init__.py
│   ├── base.py                # 新增: BaseChannel 抽象
│   ├── cpg_annotation.py      # 新增: 通道1 — CPG 确定性标注 (可合并到 annotator.py)
│   ├── blind_scan.py          # 新增: 通道2 — 盲扫 LLM
│   ├── reverse_sink.py        # 新增: 通道3 — 反向 Sink 分析
│   ├── architecture_deviation.py  # 新增: 通道4 — 架构偏离检测
│   ├── differential_coverage.py   # 新增: 通道5 — 差异覆盖分析
│   └── adversarial_review.py      # 新增: 对抗性审查 (deep 模式)
├── deterministic.py           # 修改: 整合标注逻辑
├── validator.py               # 修改: 整合对抗性审查
└── rules/                     # 已有
    └── heuristic_rules.yaml   # 新增: 启发式评分规则配置

src/hyqagent/models/
└── budget.py                  # 修改: 扩展为 CoverageBudget + 动态再平衡

src/hyqagent/core/
└── protocols.py               # 修改: 新增 PathLabel, AnnotatedPath 等协议

src/hyqagent/cpg/
└── query.py                   # 修改: 新增 get_all_http_endpoints 等方法
```

### 9.3 向后兼容性

- 旧的 `Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5` 线性调用方式保留, 作为 `--mode=linear` (或默认行为)
- 新的多通道模式通过 `--mode=standard|deep` 启用
- `--quick` 模式使用精简版新架构
- 所有新增组件遵循现有的 `protocols.py` 接口规范, 通过 DI 注入

---

## 附录A: 参考文档

| 文档 | 相关内容 |
|:-----|:--------|
| `COVERAGE-GAP-ANALYSIS.md` | 第六章: 七种缓解方案的完整设计 + 方案对比 |
| `DESIGN-IMPLEMENTATION.md` | 第三章: 扫描引擎接口设计 + 模块依赖图 |
| `protocols.py` | 核心抽象接口 — 所有新组件实现这些协议 |
| `PLAN.md` | 第四章: 原始五阶段流水线设计 |
| `LONG-RUNNING-AGENT-ARCHITECTURE.md` | 第二章: 上下文模型; 第五章: 检查点机制 |

## 附录B: 术语表

| 术语 | 含义 |
|:-----|:-----|
| PathLabel | 代码路径标签 — 描述路径在分析中的状态 |
| AnnotatedPathGraph | 全量路径标注图 — Phase 1 改造后的产出 |
| 盲扫 LLM | 不看 Phase 1 结果、独立探索的 LLM 通道 |
| 反向 Sink 分析 | 从函数调用反向追踪到用户输入 |
| 启发式评分 | 判断不在 YAML 中的调用是否可能是危险 sink |
| 差异覆盖分析 | 对比 "我们分析了什么" vs "我们应该分析什么" |
| 架构偏离 | 预期安全属性与实际代码的不一致 |
| Completeness Critic | 在所有分析完成后系统性地审查 "我们漏了什么" |
| 饱和扫描 | 用已确认漏洞作为种子迭代发现更多漏洞 |
| 对抗性审查 | 攻击者视角审视被标记为 "安全" 的路径 |
| MergeEngine | 多通道假设合并、去重、排序引擎 |
| CoverageMetrics | 覆盖完整性度量指标集合 |
| BlindSpotManifest | 盲区清单 — 报告中 "我们可能漏了什么" 的结构化输出 |
| 预算再平衡 | 在管道运行中根据中间结果动态重新分配预算 |
