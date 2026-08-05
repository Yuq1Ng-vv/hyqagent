# HyqAgent 详细设计实现文档

> 基于9份源文档综合编制：`RESEARCH.md`、`PLAN.md`、`COVERAGE-GAP-ANALYSIS.md`、`severity_based_vulnerability_mining_framework.md`、`detection_matrix.json`、`WEB-VULN-FULL-MATRIX.md`、`LONG-RUNNING-AGENT-ARCHITECTURE.md`、`IMPLEMENTATION-GUIDE.md`、`DEVELOPMENT-STANDARDS.md`
>
> **用途**：作为后续开发和维护测试的可执行蓝图。
>
> **当前状态**：Phase 1 (CPG Foundation) 进行中。已完成 Session 1.1-1.6，CPG 模块已实现 ~5,300 行代码、372 个 pytest，覆盖 tree-sitter 解析、AST 遍历、LanguageProvider 可扩展架构、单文件/跨文件调用图、数据流分析、CPG 图构建与查询、YAML 污点规则、五种框架提取器。Scanner/Models/Session 等模块仍为设计阶段（仅 `__init__.py` 骨架）。

---

## 一、项目初始化与工程搭建

### 1.1 项目骨架生成

**Python版本**: 3.12+（匹配Ruff target-version和mypy配置）

**构建系统**: uv（比Poetry快10-100倍，详见 `DEVELOPMENT-STANDARDS.md` 第5.3节）

**项目布局**: src-layout（PEP 517），镜像测试结构

```
hyqagent/
├── src/hyqagent/              # 源码根目录
│   ├── core/                  # ✅ 已实现 — 领域层，纯业务逻辑，零外部依赖
│   │   ├── protocols.py       # ⭐ 核心抽象接口（6个协议：BaseTool/CpgAnalyzer/AuditRepository/LlmProvider）
│   │   ├── state.py           # AgentState + AuditState 类型定义
│   │   └── events.py          # 12种事件类型定义（ESAA模式）
│   ├── cpg/                   # ✅ 部分实现 — CPG Engine（详见下方标注）
│   │   ├── parser.py          # ✅ tree-sitter多语言解析器（通过LanguageProvider委托到语言适配器）
│   │   ├── traversal.py       # ✅ AST遍历器（DFS前序/后序、节点过滤、导航工具）
│   │   ├── callgraph.py       # ✅ 单文件调用图（SingleFileCallGraph，支持Python/JS/Java）
│   │   ├── callgraph_builder.py # ✅ 跨文件调用图构建器（索引→导入解析→跨文件调用边）
│   │   ├── types.py           # ✅ 共享数据类（FunctionNode/ClassNode/ImportNode/CallEdge）
│   │   ├── languages/         # ✅ LanguageProvider策略模式（base.py + python/js/java适配器）
│   │   │   ├── __init__.py    #    Provider注册表 + 懒加载 + 扩展名检测
│   │   │   ├── base.py        #    LanguageProvider抽象基类（14个抽象成员）
│   │   │   ├── python.py      #    PythonAdapter
│   │   │   ├── javascript.py  #    JavaScriptAdapter
│   │   │   └── java.py        #    JavaAdapter
│   │   ├── data_flow.py       # ✅ 数据流分析 — def-use chain + 跨函数追踪 + BFS 污点传播
│   │   ├── graph.py           # ✅ CPG图构建器 — NetworkX MultiDiGraph (AST/CALLS/DATA_FLOW)
│   │   ├── query.py           # ✅ CPG查询接口 — find_path/sources/sinks/call_chain/slice_path
│   │   ├── taint_rules.yaml   # ✅ 污点规则 — Python/JS/Java × 9 种漏洞类别
│   │   ├── sanitizers.yaml    # 📋 计划中 — Sanitizer函数配置
│   │   └── frameworks/        # ✅ 框架提取器 — Flask/Django/FastAPI/Express/Spring + TaintRuleLoader
│   ├── scanner/               # 📋 设计阶段 — 扫描引擎（详见PLAN.md 第四章）
│   │   ├── orchestrator.py    # 扫描流水线编排
│   │   ├── deterministic.py   # Phase 1: 确定性规则
│   │   ├── mapper.py          # Phase 2: 攻击面映射
│   │   ├── hypothesis.py      # Phase 3: 假设生成
│   │   ├── validator.py       # Phase 4: 验证(L1+L2)
│   │   └── rules/             # 确定性规则
│   ├── models/                # 📋 设计阶段 — 模型路由（详见PLAN.md 第六章）
│   │   ├── router.py          # 模型路由
│   │   ├── budget.py          # 预算管理
│   │   └── providers/         # LLM Provider适配
│   ├── session/               # 📋 设计阶段 — 会话与信念系统
│   │   ├── manager.py         # 会话CRUD
│   │   ├── belief.py          # 信念系统
│   │   ├── checkpoint.py      # 检查点管理
│   │   └── schema.sql         # 数据库Schema
│   ├── memory/                # 📋 设计阶段 — 上下文与记忆管理
│   │   ├── context.py         # 三区段上下文模型
│   │   ├── crystallizer.py    # 上下文结晶协议
│   │   └── retriever.py       # 代码检索
│   ├── observability/         # 📋 设计阶段 — 可观测性
│   │   ├── tracer.py          # OTel集成
│   │   ├── cost_tracker.py    # 成本追踪
│   │   ├── metrics.py         # Prometheus指标
│   │   └── audit_trail.py     # ESAA决策追踪
│   ├── prompts/               # 📋 骨架 — Prompt模板
│   │   ├── system/            # 系统提示词
│   │   ├── few_shot/          # Few-shot示例
│   │   └── shared/            # 共享模板
│   ├── api/                   # 📋 骨架 — CLI接口
│   │   ├── cli.py             # CLI入口（click框架）
│   │   └── config.py          # 配置管理（pydantic-settings）
│   └── report/                # 📋 骨架 — 报告生成
│       ├── json_report.py
│       ├── markdown_report.py
│       └── sarif_report.py
├── tests/                     # ✅ 镜像src/结构，361个测试
│   ├── test_cpg/              # CPG模块测试（parser/traversal/callgraph/callgraph_builder/dataflow）
│   ├── test_scanner/
│   ├── test_models/
│   └── test_session/
├── evals/                     # 📋 计划中 — Eval数据集
│   ├── golden_dataset.yaml
│   └── adversarial_cases.yaml
├── pyproject.toml
├── .env.example
├── .pre-commit-config.yaml
├── AGENTS.md
└── README.md
```

> **图例**：✅ 已实现　📋 设计/计划阶段

**关键依赖清单**:

| 用途 | 包名 | 备注 |
|:-----|:-----|:-----|
| 代码解析 | `tree-sitter` | 锁定版本（v0.23.1有segfault风险，详见IMPLEMENTATION-GUIDE.md 6.1节） |
| CPG分析 | `joern`（CLI工具） | Python前端相对成熟；Lambda数据流断裂为已知bug |
| 图存储/查询 | `networkx` | MultiDiGraph存储五种边类型 |
| Agent编排 | `langgraph` | 内置SqliteSaver checkpointer |
| LLM接口 | `anthropic` | Prompt Caching支持 |
| 结构化日志 | `structlog` | snake_case事件名，非自由文本（详见DEVELOPMENT-STANDARDS.md 2.2节） |
| 重试 | `tenacity` | 指数退避+jitter |
| 熔断器 | `circuitbreaker` | 防止级联故障 |
| 配置管理 | `pydantic-settings` | SecretStr防泄露 |
| CLI框架 | `click` | 比argparse更适合CLI工具 |
| 测试框架 | `pytest` | 确定性+概率性统一框架 |
| 代码质量 | `ruff` + `mypy --strict` | Ruff不做类型检查 |
| 终端输出 | `rich` | 彩色输出、进度条 |
| 依赖管理 | `uv` | CI中2秒sync完成 |
| Eval框架 | `deepeval` / `braintrust` | CI/CD友好开源方案 |
| 向量检索 | `qdrant-client`（生产）/ `chromadb`（原型） | 语义相似检索 |
| Prompt模板 | `jinja2` + `pyyaml` | 逻辑数据分离 |

### 1.2 开发环境配置

**`.env.example`模板**:

```bash
# LLM Providers
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...          # Kimi/GLM兼容用
# Database
HYQAGENT_DATABASE_URL=sqlite:///~/.hyqagent/state.db
# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
LANGFUSE_PUBLIC_KEY=pk-...
LANGFUSE_SECRET_KEY=sk-...
# Budget
HYQAGENT_DEFAULT_BUDGET=5.0
```

**`.pre-commit-config.yaml`**: 见 `DEVELOPMENT-STANDARDS.md` 第3.3节完整配置（ruff--fix, ruff-format, mypy--strict, trailing-whitespace, end-of-file-fixer, check-yaml, detect-private-key, gitleaks）

**`pyproject.toml`核心配置**:

```toml
[project]
name = "hyqagent"
requires-python = ">=3.12"

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = ["E","F","W","B","I","N","D","UP","S","C4","SIM","RUF"]

[tool.mypy]
python_version = "3.12"
strict = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

**CI/CD三级漏斗**（详见 `DEVELOPMENT-STANDARDS.md` 第3.4节）:

| 阶段 | 触发 | 内容 | 时间上限 |
|:-----|:-----|:-----|:--------|
| Stage 1: Pre-commit | git commit | Ruff+mypy+确定性单元测试 | <2min |
| Stage 2: PR Checks | PR | 全部单元测试+集成测试(mock LLM)+快速Eval(10 cases)+安全扫描 | <15min |
| Stage 3: Nightly | 定时 | 完整Golden Dataset验证(20次重跑)+对抗性测试+性能基准 | 1-3h |

### 1.3 核心抽象层实现 (`core/protocols.py`)

> 详细规范见 `DEVELOPMENT-STANDARDS.md` 第1.4节。这是整个项目中最重要的文件——所有模块通过协议通信，永不直接import具体实现。

```python
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from abc import ABC, abstractmethod

# ---------- 统一返回类型 ----------
@dataclass
class ToolResult:
    """每个工具都返回这个结构。success=False时error必填。"""
    success: bool
    tool_name: str
    result: Any = None
    error: str | None = None
    metadata: dict = field(default_factory=dict)

# ---------- 工具层 ----------
class BaseTool(ABC):
    """ISP原则：只暴露(name, description, parameters, execute)"""
    @property
    @abstractmethod
    def name(self) -> str: ...
    @property
    @abstractmethod
    def description(self) -> str: ...
    @property
    @abstractmethod
    def parameters(self) -> dict: ...  # JSON Schema
    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult: ...

# ---------- CPG分析器协议 ----------
@runtime_checkable
class CpgAnalyzer(Protocol):
    """Joern和tree-sitter后端都满足此契约（LSP原则）"""
    async def extract_cpg(self, code: str, file_path: str) -> ToolResult: ...
    async def query_cpg(self, query: str) -> ToolResult: ...
    async def get_data_flows(self, variable: str, file_path: str) -> ToolResult: ...

# ---------- 存储协议 ----------
class AuditRepository(ABC):
    """SQLite/PostgreSQL透明切换（DIP原则）"""
    @abstractmethod
    async def save_finding(self, run_id: str, finding: dict) -> str: ...
    @abstractmethod
    async def get_findings(self, run_id: str, severity: str | None = None) -> list[dict]: ...

# ---------- LLM Provider协议 ----------
@runtime_checkable
class LlmProvider(Protocol):
    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict: ...
    async def count_tokens(self, messages: list[dict], model: str) -> int: ...
```

**依赖注入模式**（详见 `DEVELOPMENT-STANDARDS.md` 第1.5节）:

```python
# api/cli.py — 唯一做DI的地方
def main(target_path: str):
    settings = get_settings()
    cpg_analyzer = JoernCpgAnalyzer(settings.joern_cli_path)
    repository = SqliteAuditRepository(settings.database_url)
    graph = build_orchestrator_graph(
        cpg_analyzer=cpg_analyzer,
        repository=repository,
    )
    result = graph.invoke({"target_path": target_path})
```

**异步/同步决策矩阵**: 见 `DEVELOPMENT-STANDARDS.md` 第1.6节。规则：Joern子进程和LLM API用async；tree-sitter解析用sync；SQLite用`sync + asyncio.to_thread()`；所有Tool `execute()`统一用`async def`。

---

## 二、CPG Engine实现 (`cpg/`)

> 详细设计见 `PLAN.md` 第三章、`IMPLEMENTATION-GUIDE.md` 第1章。CPG是整个系统的基石——这是HyqAgent相对DeepAudit/VulAgent/RepoAudit的结构性优势。

**模块职责**: 解析源码构建Code Property Graph（AST+CALLS+DATA_FLOW+CTRL_FLOW+HTTP_ROUTE五层图），提供结构化查询接口，使LLM无需直接阅读全量代码。

### 2.1 tree-sitter集成 ✅ 已实现

**公开接口**（Session 1.2 实现，Session 1.5 通过 LanguageProvider 重构）:

```python
class Parser:
    """多语言tree-sitter解析器封装。
    
    通过 LanguageProvider 策略模式委托语言特定操作。
    添加新语言 = 新增一个 LanguageProvider 子类 + 一行注册，Parser 零改动。
    """
    def __init__(self, languages: list[str] | None = None): ...
    def parse_file(self, file_path: str) -> Tree: ...
    def parse_code(self, code: str, language: str) -> Tree: ...
    def extract_functions(self, tree: Tree, language: str) -> list[FunctionNode]: ...
    def extract_classes(self, tree: Tree, language: str) -> list[ClassNode]: ...
    def extract_imports(self, tree: Tree, language: str) -> list[ImportNode]: ...
    def get_language(self, file_path: str) -> str: ...        # 公开方法
    def get_provider(self, language: str) -> LanguageProvider: ...  # 公开方法
```

**LanguageProvider 策略模式**（`cpg/languages/`，Session 1.5 新增）:

```python
class LanguageProvider(ABC):
    """每种语言实现此接口。添加 Go 只需新增一个文件。"""
    name: str              # "python", "javascript", ...
    extensions: list[str]  # [".py", ".pyi"]
    
    # 语法（懒加载 — cached_property）
    _ts_module              # tree_sitter 语法包（首次访问才 import）
    
    # 查询字符串
    function_query / class_query / import_query
    
    # 节点解析
    extract_function_name / extract_parameters / extract_decorators
    extract_base_classes / build_import_node
    build_function_node / build_class_node
    
    # 调用图支持
    call_node_type / func_def_types
    extract_callee_info
```

**重构数据**（Session 1.5）：parser.py 671→260 行（-61%），callgraph.py 382→260 行（-32%），删除 ~250 行语言特定硬编码。

**关键踩坑**: 锁定tree-sitter版本，`v0.23.1`在复杂查询时segfault率约7-9%。Workaround: 查询外围包重试循环。详见 `IMPLEMENTATION-GUIDE.md` 第6.1节。

**依赖**: 无（纯CPU密集型，sync调用）

### 2.2 调用图构建 ✅ 已实现

**单文件调用图**（`cpg/callgraph.py`，Session 1.4 实现，Session 1.5 重构）:

```python
class SingleFileCallGraph:
    """单文件调用图。支持 Python/JS/Java 三种语言。
    通过 LanguageProvider 委托语言特定的调用提取。"""
    def __init__(self, parser: Parser): ...
    def build(self, file_path: str) -> SingleFileCallGraph: ...
    
    # 查询接口
    def get_callees(self, func_id: str) -> list[str]: ...
    def get_callers(self, func_id: str) -> list[str]: ...
    def has_edge(self, caller: str, callee: str) -> bool: ...
    
    # 属性
    functions: dict[str, FunctionNode]   # 文件中所有函数
    calls: list[CallEdge]                # 已解析的调用边
    unresolved: list[UnresolvedCall]     # 未解析调用（供跨文件使用）
```

**跨文件调用图**（`cpg/callgraph_builder.py`，Session 1.5 新增）:

```python
class CallGraphBuilder:
    """跨文件调用图构建。"""
    def __init__(self, parser: Parser): ...
    def add_directory(self, dir_path: str) -> None: ...   # 递归遍历项目
    def add_file(self, file_path: str) -> None: ...       # 单文件索引
    def resolve_imports(self) -> dict[str, str]: ...       # 返回 {import_name: resolved_file_path}
    def build_calls(self) -> list[CallEdge]: ...           # 跨文件调用边列表
```

**支持的导入模式**（Python）:
- `from utils import helper` → 查找 `utils.py` 中的 `helper`
- `from ..utils import helper` → 相对导入，向上查找
- `from models import create_user` → 查找 `models.py`
- `import os` → 标准库，不解析

**已知局限**：Java 导入解析（`import com.example.Foo`）需在 Session 1.8 框架提取器中处理；循环导入未检测；同名函数使用 first-definition-wins。

**最大风险**: 跨文件调用图是P0级阻塞风险（详见 `IMPLEMENTATION-GUIDE.md` 第2章）。策略：先支持无反射/无DI的Python项目；动态import直接丢弃调用边（GitLab Orbit实践）；Spring DI暂缓。

**依赖**: `Parser`（注入）

### 2.3 AST 遍历器 ✅ 已实现

**公开接口**（`cpg/traversal.py`，Session 1.3 实现）:

```python
class Traverser:
    """基于 tree-sitter TreeCursor 的 AST 遍历器。"""
    def __init__(self, tree: Tree, language: str): ...
    
    # 遍历模式
    def traverse_pre_order(self) -> Iterator[Node]: ...    # DFS 前序遍历
    def traverse_post_order(self) -> Iterator[Node]: ...   # DFS 后序遍历
    def traverse_subtree(self, root: Node) -> Iterator[Node]: ...  # 子树遍历
    
    # 过滤选项
    named_only: bool           # 仅具名节点（跳过标点/括号等）
    node_types: set[str] | None  # 按节点类型过滤
    
    # 导航工具
    def get_children(self, node: Node) -> list[Node]: ...
    def get_parent(self, node: Node) -> Node | None: ...
    def get_ancestors(self, node: Node) -> list[Node]: ...
    def ancestor_of_type(self, node: Node, *types: str) -> Node | None: ...
    
    # 搜索工具
    def find_first(self, node_type: str) -> Node | None: ...
    def find_all(self, node_type: str) -> list[Node]: ...
    def count(self, node_type: str) -> int: ...

**依赖**: `Parser`（注入）

### 2.4 数据流图构建 ✅ 已实现

> Session 1.6 完成。详见 `dev-docs/Session-1.6-数据流图构建.md`。

**公开接口**:

```python
class DataFlowBuilder:
    """def-use chain分析 + 跨函数数据流追踪 + 基础污点传播。"""
    def __init__(self, call_graph: CallGraphBuilder): ...
    def build_def_use_chains(self, func_id: str) -> list[DefUsePair]: ...
    def trace_cross_function(self, var_name: str, from_func: str, to_func: str) -> list[DataFlowStep]: ...
    def propagate_taint(self, source_node: Node, max_depth: int = 10) -> list[TaintPath]: ...
```

**已知局限**: Joern Lambda数据流断裂（已知bug，不在roadmap）。CPG内Lambda引用外部变量时数据流丢失。详见 `IMPLEMENTATION-GUIDE.md` 第2.1节。

**依赖**: `CallGraphBuilder`（注入）

### 2.5 框架特定提取器

**公开接口**:

```python
class BaseFrameworkExtractor(ABC):
    """框架提取器基类。新框架只需继承并实现extract_routes。"""
    @abstractmethod
    def extract_routes(self, file_path: str) -> list[HttpEndpoint]: ...
    """返回: [{route, methods, handler_func, params, decorators}]"""
    @abstractmethod
    def extract_auth_requirements(self, endpoint: HttpEndpoint) -> AuthInfo: ...

# 具体实现: FlaskExtractor, DjangoExtractor, FastAPIExtractor, ExpressExtractor, SpringExtractor
```

**扩展方式**: 实现`BaseFrameworkExtractor`，注册到`FRAMEWORK_EXTRACTORS`字典。每个提取器是纯确定性的（tree-sitter或正则即可），详见 `PLAN.md` 第3.4节。

**依赖**: `Parser`（注入）

### 2.6 污点源/汇配置

**`taint_rules.yaml`格式**:

```yaml
sources:
  python:
    - pattern: "request.args.get"
      category: http_param
    - pattern: "request.form.get"
      category: http_param
    # ... 详见PLAN.md第3.5节完整列表
sinks:
  sql_injection:
    python:
      - "cursor.execute"
      - "session.execute"
    # 按漏洞类型组织，每种语言独立配置
sanitizers:
  python:
    - pattern: "re.escape"
      sanitizes: ["xss", "sql_injection"]
```

**`sanitizers.yaml`格式**: 同上结构，按sanitizer函数→可防护的漏洞类型映射。

### 2.7 CPG查询接口

**公开接口**（详见 `PLAN.md` 第3.6节）:

```python
class CPGQuery:
    """CPG上层查询接口。底层可切换Joern/tree-sitter+NetworkX后端。"""
    def __init__(self, graph: nx.MultiDiGraph): ...
    def find_path(self, source_node: str, sink_node: str) -> list[Path]: ...
    def find_sources(self, sink_node: str) -> list[Node]: ...
    def find_sinks(self, source_node: str) -> list[Node]: ...
    def get_sanitizers(self, path: Path) -> list[Node]: ...
    def get_call_chain(self, func_a: str, func_b: str) -> Path | None: ...
    def slice_path(self, path: Path, context_lines: int = 3) -> str: ...
    """提取路径上关键节点的代码片段（仅相关行！不是整个函数）"""
```

**依赖**: `networkx.MultiDiGraph`（由builder.py构建后注入）

---

## 三、扫描引擎实现 (`scanner/`)

> 详细设计见 `PLAN.md` 第四章。五阶段流水线，覆盖盲区缓解方案见 `COVERAGE-GAP-ANALYSIS.md` 第六章。

**模块职责**: 编排五阶段扫描流水线，从确定性预扫描到LLM验证到报告组装。

### 3.1 Phase 1: 确定性预扫描

**公开接口**:

```python
class DeterministicScanner:
    """零LLM成本的确定性漏洞发现。"""
    def __init__(self, cpg_query: CPGQuery, rules_dir: str): ...
    async def scan_secrets(self, file_path: str) -> list[Finding]: ...
    """正则规则: 硬编码密钥/密码 (详见 secrets.yaml)"""
    async def scan_dangerous_calls(self, file_path: str) -> list[Finding]: ...
    """正则规则: eval/exec/os.system等 (详见 dangerous_calls.yaml)"""
    async def scan_cpg_taint(self) -> list[Finding]: ...
    """CPG污点追踪: source→sink无消毒路径直接标记"""
    async def scan_missing_auth(self) -> list[Finding]: ...
    """检测有@app.route但缺少@login_required的端点"""
    async def scan_config_issues(self) -> list[Finding]: ...
    """DEBUG=True, SECRET_KEY='dev', CORS allow_origin='*'"""
```

**覆盖盲区**: Phase 1仅覆盖约20-35%的Web漏洞类别（按CWE多样性）。IDOR、业务逻辑、二阶注入、条件竞争等大量高价值漏洞无代码结构性特征，确定性规则无法捕获。详见 `COVERAGE-GAP-ANALYSIS.md` 第四章。

**依赖**: `CPGQuery`（注入）

### 3.2 Phase 2: 攻击面映射

**公开接口**:

```python
class AttackSurfaceMapper:
    """用便宜LLM分类每个API端点的功能和风险。"""
    def __init__(self, llm: LlmProvider, cpg_query: CPGQuery): ...
    async def classify_endpoint(self, endpoint: HttpEndpoint) -> EndpointClassification: ...
    """返回: {function_type, trust_boundary, data_sensitivity, priority(1-10)}"""
    async def filter_high_priority(self, endpoints: list[HttpEndpoint], threshold: int = 5) -> list[HttpEndpoint]: ...
```

**成本**: ~$0.01（200个端点, Kimi K2, 详见PLAN.md第4.3节）

**依赖**: `LlmProvider`（注入）, `CPGQuery`（注入）

### 3.3 Phase 3: 假设生成

**公开接口**:

```python
class HypothesisGenerator:
    """CPG切片提示构建 + 结构化漏洞假设输出。"""
    def __init__(self, llm: LlmProvider, cpg_query: CPGQuery): ...
    async def generate_for_endpoint(self, endpoint: HttpEndpoint) -> list[Hypothesis]: ...
    async def generate_prompt(self, endpoint: HttpEndpoint) -> str: ...
    """核心创新: CPG切片提示——prompt中仅包含相关代码，不是整个文件"""
    def assess_complexity(self, data_flow_path: list[DataFlowStep]) -> int: ...
    """复杂度评分1-10: 数据流跳数+跨文件+异步/反射 (详见PLAN.md第4.4节)"""
```

**核心创新**: CPG切片提示设计（详见 `PLAN.md` 第4.4节）。`slice_path(path, context_lines=3)`只提取路径经过的具体语句，而非整个函数。这是相对"全量代码塞入prompt"的决定性优势。

**依赖**: `LlmProvider`（注入）, `CPGQuery`（注入）

### 3.4 Phase 4: 分层验证

**公开接口**:

```python
class Validator:
    """L1确定性验证 + L2 LLM验证 + 补充机制。"""
    def __init__(self, llm: LlmProvider, cpg_query: CPGQuery): ...
    # L1: 确定性验证（零LLM成本）
    async def validate_deterministic(self, hypothesis: Hypothesis) -> ValidationResult: ...
    """验证: 路径存在性、source/sink类型匹配、代码一致性"""
    # L2: LLM验证（强模型）
    async def validate_llm(self, hypothesis: Hypothesis, include_tests: bool = True) -> ValidationResult: ...
    """5问验证: 路径可达性、条件绕过、消毒充分性、框架保护、综合判断"""
    # 补充机制（详见 COVERAGE-GAP-ANALYSIS.md 第六章）
    async def reverse_sink_analysis(self) -> list[Hypothesis]: ...
    """方案1: 从所有sink反向追踪到用户输入"""
    async def blind_scan(self, files: list[str]) -> list[Hypothesis]: ...
    """方案2: 独立盲扫LLM通道，不依赖Phase 1输出"""
    async def completeness_critic(self, analyzed: dict) -> list[BlindSpot]: ...
    """方案3: 完整性审查——"我们漏了什么？" """
```

**预期过滤率**: L1过滤掉约30-40%的Phase 3产出（明显误报）。详见 `PLAN.md` 第4.5节。

**补充机制**: 三个独立感知通道，不依赖Phase 1输出。详见 `COVERAGE-GAP-ANALYSIS.md` 第六章第1-3方案。

**依赖**: `LlmProvider`（注入）, `CPGQuery`（注入）

### 3.5 Phase 5: 报告组装

**公开接口**:

```python
class ReportGenerator:
    """JSON/Markdown/SARIF输出 + 证据链组装。"""
    def generate_json(self, findings: list[ConfirmedFinding], session_id: str) -> str: ...
    def generate_markdown(self, findings: list[ConfirmedFinding], session_id: str) -> str: ...
    def generate_sarif(self, findings: list[ConfirmedFinding], session_id: str) -> str: ...
    def build_evidence_chain(self, finding: ConfirmedFinding) -> dict: ...
    """组装: 确定性证据 + LLM验证证据 + PoC可行性"""
```

**输出结构**: 见 `PLAN.md` 第4.6节完整JSON Schema（含id, cwe, severity, confidence, location, data_flow, evidence_chain, remediation, validation_history）。

**依赖**: 无外部依赖（纯组装）

---

## 四、模型路由系统 (`models/`)

> 详细设计见 `PLAN.md` 第六章、`RESEARCH.md` 第六章。

**模块职责**: 按任务类型和复杂度路由到三档模型，管理预算和成本追踪。

### 4.1 Model Router

**公开接口**:

```python
class ModelRouter:
    """三档模型: CHEAP(Kimi K2/GLM) / MID(Sonnet) / STRONG(Opus/GPT-5.2)。
    成本比 ≈ cheap:mid:strong = 1:30:150"""
    CHEAP_MODELS = ["kimi-k2-instruct", "glm-5.1"]
    MID_MODELS = ["claude-sonnet-4-6"]
    STRONG_MODELS = ["claude-opus-4-6", "gpt-5.2"]

    def route(self, task: Task) -> ModelSpec: ...
    """路由决策矩阵:
    - 代码分类/摘要 → CHEAP
    - 攻击面分析 → CHEAP
    - 假设生成(简单路径) → CHEAP
    - 假设生成(复杂路径) → MID
    - 假设生成(逻辑漏洞) → STRONG
    - 确定性验证(L1) → 无LLM
    - LLM验证(L2, 中置信) → MID
    - LLM验证(L2, 高价值) → STRONG (confidence>0.7 且 severity>=HIGH)
    """
    def _assess_complexity(self, task: Task) -> int: ...
    """复杂度评分: 数据流跳数+跨文件+异步/反射 (详见PLAN.md第6.1节)"""
```

**依赖**: 无

### 4.2 Budget Manager

**公开接口**:

```python
class BudgetManager:
    """默认每项目$5预算。分配: Phase2=5%, Phase3=30%, Phase4=60%, misc=5%"""
    DEFAULT_BUDGET = 5.0
    DEFAULT_ALLOCATION = {
        'phase2_mapping': 0.05,
        'phase3_hypothesis': 0.30,
        'phase4_l2_validation': 0.60,
        'misc': 0.05,
    }

    def check_and_route(self, task: Task, remaining_budget: float) -> ModelSpec | None: ...
    """预算不足时自动降级: STRONG→MID→CHEAP→跳过"""
    def estimate_cost(self, task: Task, model: ModelSpec) -> float: ...
    def get_remaining_budget(self, session_id: str) -> float: ...
```

**依赖**: `ModelRouter`（注入）

### 4.3 Provider适配器

**公开接口**:

```python
class AnthropicProvider:
    """Anthropic SDK封装 + Prompt Caching + 重试/熔断。"""
    def __init__(self, api_key: str, max_retries: int = 5): ...
    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict: ...
    """自动添加cache_control断点在系统prompt和长期记忆（详见LONG-RUNNING-AGENT-ARCHITECTURE.md 2.2节）"""
    async def count_tokens(self, messages: list[dict], model: str) -> int: ...

class OpenAICompatProvider:
    """OpenAI兼容Provider（Kimi/GLM/GPT通用接口）。"""
    def __init__(self, api_key: str, base_url: str, max_retries: int = 5): ...
    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict: ...
    async def count_tokens(self, messages: list[dict], model: str) -> int: ...
```

**重试策略**（详见 `DEVELOPMENT-STANDARDS.md` 第5.1节）:

```python
@retry(
    retry=retry_if_exception_type((ConnectionError, TimeoutError)) | 
           retry_if_result(lambda r: r.status_code in {429, 500, 502, 503, 504}),
    stop=stop_after_attempt(5) | stop_after_delay(60),
    wait=wait_exponential_jitter(initial=1, max=30),
)
async def robust_request(url: str) -> Response: ...

@circuit(failure_threshold=5, recovery_timeout=60, expected_exception=ConnectionError)
def query_external_service(query: str) -> dict: ...
```

**依赖**: `anthropic` SDK / `httpx`

---

## 五、会话与信念系统 (`session/`)

> 详细设计见 `PLAN.md` 第五章、`LONG-RUNNING-AGENT-ARCHITECTURE.md` 第三/五章。

**模块职责**: 持久化会话状态、管理漏洞假设生命周期（状态机+贝叶斯置信度）、检查点保存与恢复。

### 5.1 SQLite Schema

**核心表**（详见 `PLAN.md` 第5.1节完整DDL）:

| 表名 | 用途 | 关键列 |
|:-----|:-----|:-----|
| `sessions` | 会话元数据 | id, repo_path, branch, commit_hash, status, config(JSON), stats(JSON) |
| `file_index` | 文件索引（支持增量扫描） | session_id, file_path, file_hash(SHA256), language, loc |
| `cpg_nodes` | CPG节点索引 | session_id, node_type, name, file_path, start_line, end_line, metadata(JSON) |
| `hypotheses` | 漏洞假设 | status, vuln_type, cwe_id, severity, confidence(REAL贝叶斯), source/sink位置, data_flow_path(JSON), evidence_chain(JSON) |
| `validations` | 验证记录 | hypothesis_id, validation_type, model, verdict, confidence_delta, reasoning, evidence(JSON), tokens_used, cost |
| `model_calls` | 模型调用日志（成本追踪） | session_id, phase, model, input_tokens, output_tokens, cost, latency_ms |

**长任务扩展表**（详见 `LONG-RUNNING-AGENT-ARCHITECTURE.md` 第三/五章）:

| 表名 | 用途 |
|:-----|:-----|
| `evidence` | 证据项（supporting/refuting/neutral + weight） |
| `confidence_updates` | 置信度更新日志（old→new + evidence_id） |
| `task_queue` | 任务队列（pending/running/completed/failed） |
| `execution_state` | 执行状态（LangGraph SqliteSaver） |
| `checkpoint_index` | 检查点索引 |

**SQLite生产配置**（详见 `DEVELOPMENT-STANDARDS.md` 第5.2节）:

```sql
PRAGMA journal_mode = WAL;          -- 读写可并发
PRAGMA synchronous = NORMAL;        -- WAL模式下安全
PRAGMA busy_timeout = 10000;        -- 遇锁等待10秒
PRAGMA cache_size = -2000;          -- 2MB缓存
-- 所有写入使用 BEGIN IMMEDIATE
-- 定期执行 PRAGMA wal_checkpoint   -- 防止WAL文件无限增长（详见IMPLEMENTATION-GUIDE.md第6.3节）
```

### 5.2 信念系统

**公开接口**:

```python
class BeliefSystem:
    """假设状态机 + 贝叶斯置信度更新 + 依赖图传播。"""

    STATUS_TRANSITIONS = {
        'proposed': ['investigating', 'rejected'],
        'investigating': ['l1_validated', 'rejected'],
        'l1_validated': ['l2_validated', 'rejected'],
        'l2_validated': ['confirmed', 'rejected', 'inconclusive'],
        'confirmed': ['reported'],
        'reported': [],   # 终态
        'rejected': [],   # 终态
        'inconclusive': ['investigating'],  # 可重新调查
    }

    def update_confidence(self, hypothesis: Hypothesis, evidence: Evidence, strength: float) -> float: ...
    """贝叶斯更新: P(vuln|evidence) = P(evidence|vuln) * P(vuln) / P(evidence)
    简化: supporting → confidence += strength*(1-confidence)
         refuting   → confidence *= (1-strength*confidence)"""

    # 假设依赖图操作（详见 LONG-RUNNING-AGENT-ARCHITECTURE.md 第3.3节）
    def add_dependency(self, hypothesis_id: str, depends_on: str) -> None: ...
    def add_conflict(self, hypothesis_id: str, conflicts_with: str) -> None: ...
    def propagate_confidence(self, changed_hypothesis_id: str) -> None: ...
    """确认/拒绝一个假设后，自动更新所有关联假设的置信度"""
```

**依赖**: 数据库连接（注入）

### 5.3 检查点管理

**公开接口**:

```python
class CheckpointManager:
    """混合驱动检查点: 事件/时间/阈值/信号。恢复RTO<1秒。"""

    def save_checkpoint(self, session_id: str, trigger: str) -> str: ...
    """trigger类型: event(phase_end)/time(every_5min)/threshold(token_10pct)/signal(SIGTERM)"""
    def load_checkpoint(self, session_id: str) -> CheckpointState: ...
    def verify_integrity(self, session_id: str) -> tuple[bool, list[str]]: ...
    """SHA-256链式验证 (详见 DEVELOPMENT-STANDARDS.md 第2.6节)"""
    def generate_recovery_summary(self, state: CheckpointState) -> str: ...
    """生成<2000 tokens的"状态快照"，注入恢复后的系统prompt (详见 LONG-RUNNING-AGENT-ARCHITECTURE.md 第5.3节)"""
```

**触发策略**: 事件驱动（每个Phase完成/每个假设变更）+ 时间驱动（每5分钟）+ 阈值驱动（Token消耗每10%）+ 信号驱动（SIGTERM优雅关闭, SIGUSR1手动触发）。详见 `LONG-RUNNING-AGENT-ARCHITECTURE.md` 第5.2节。

**增量分析支持**: 文件变更检测→影响分析（找到所有调用者）→仅重分析受影响代码→使受影响假设置信度*0.5失效。详见 `LONG-RUNNING-AGENT-ARCHITECTURE.md` 第5.4节。

**依赖**: 数据库连接（注入）

---

## 六、上下文与记忆管理 (`memory/`)

> 详细设计见 `LONG-RUNNING-AGENT-ARCHITECTURE.md` 第二章。

**模块职责**: 管理有限上下文窗口（200K tokens），实现三区段模型、上下文结晶协议和代码检索。

### 6.1 三区段上下文模型

**公开接口**:

```python
class ContextManager:
    """三区段: 固定5K(系统prompt, Prompt Cache缓存) + 长期30K(结晶摘要) + 工作60K(滑动窗口)"""

    def __init__(self, system_prompt: str): ...
    def build_context(self, long_term_memory: str, recent_turns: list[dict]) -> list[dict]: ...
    """返回可直接发给LLM的messages列表，包含cache_control断点。
    详见 LONG-RUNNING-AGENT-ARCHITECTURE.md 第2.2节"""
    def estimate_usage(self) -> float: ...
    """返回当前工作记忆占用的比例(0.0-1.0)"""
```

**依赖**: 无

### 6.2 上下文结晶

**公开接口**:

```python
class ContextCrystallizer:
    """每N轮(默认50)或工作记忆>80%时触发结晶。"""

    def should_crystallize(self, round_count: int, usage_ratio: float) -> bool: ...
    def crystallize(self, recent_turns: list[dict], current_state: dict) -> str: ...
    """生成结构化结晶文档:
    ## 分析阶段摘要: 已分析文件数、关键发现、覆盖状态
    ## 已做决策: 跳过某文件的原因
    ## 待解决问题: 未确定的分析障碍
    详见 LONG-RUNNING-AGENT-ARCHITECTURE.md 第2.3节"""
```

**依赖**: 无（纯文本处理）

### 6.3 代码检索

**公开接口**:

```python
class CodeRetriever:
    """混合检索: ripgrep(精确) + tree-sitter(结构) + Qdrant(语义) + Joern(数据流)"""

    def __init__(self, vector_store: str = "chromadb"): ...
    async def index_file(self, file_path: str) -> None: ...
    """用tree-sitter AST切分函数/方法，向量化存储"""
    async def semantic_search(self, query: str, top_k: int = 5) -> list[CodeChunk]: ...
    """'这段代码我分析过吗？' — 相似度>85%自动复用结论"""
    async def hybrid_search(self, query: str, file_pattern: str | None = None) -> list[CodeChunk]: ...
```

**依赖**: `chromadb`/`qdrant-client`（生产切换）

---

## 七、可观测性体系 (`observability/`)

> 详细设计见 `DEVELOPMENT-STANDARDS.md` 第二章、`LONG-RUNNING-AGENT-ARCHITECTURE.md` 第八章。

**模块职责**: OpenTelemetry追踪、结构化日志、成本追踪、Prometheus指标、ESAA决策审计。

### 7.1 OpenTelemetry集成

**公开接口**:

```python
class ObservabilityManager:
    """OTel GenAI SDK + LangFuse自托管。"""

    def __init__(self, otlp_endpoint: str, langfuse_keys: dict): ...
    def trace_llm_call(self, model: str, input_tokens: int, output_tokens: int, 
                       cache_read_tokens: int, duration_ms: int, cost: float,
                       phase: str, hypothesis_id: str | None = None) -> Span: ...
    def trace_tool_call(self, tool_name: str, input_args: dict, 
                        result: Any, duration_ms: int) -> Span: ...
    def trace_state_change(self, hypothesis_id: str, old_state: str, 
                           new_state: str, evidence_id: str) -> Span: ...
```

**依赖**: `opentelemetry-sdk`, `langfuse`

### 7.2 结构化日志

**规范**（详见 `DEVELOPMENT-STANDARDS.md` 第2.2节）:
- DEBUG: CPG构建细节、原始LLM prompt（生产禁用）
- INFO: 业务事件（阶段转换、假设状态变更、检查点保存）
- WARNING: 已处理边缘情况（速率限制、模型降级、磁盘>70%）
- ERROR: 需关注故障（LLM重试耗尽、CPG崩溃、检查点损坏）
- CRITICAL: 系统级故障（数据库不可达、所有模型宕机）
- 命名规范: `logger.info("hypothesis_confirmed", session_id=..., hypothesis_id=..., confidence=0.92)`（snake_case事件名，非自由文本）

### 7.3 成本追踪

**公开接口**:

```python
class CostTracker:
    """按session/phase/hypothesis归因成本。"""

    def record_call(self, model: str, input_tokens: int, output_tokens: int,
                    phase: str, hypothesis_id: str | None = None) -> None: ...
    def get_cost_by_finding(self, hypothesis_id: str) -> float: ...
    """回答: '发现HYQ-0421花了多少钱？'"""
    def get_cost_by_phase(self, phase: str) -> float: ...
    def get_total_cost(self, session_id: str) -> float: ...
```

**Prometheus指标**（详见 `DEVELOPMENT-STANDARDS.md` 第2.4节）:
- `hyqagent_llm_calls_total` (Counter, by model/phase/status)
- `hyqagent_llm_cost_usd_total` (Counter)
- `hyqagent_llm_latency_seconds` (Histogram, P50/P95/P99)
- `hyqagent_findings_total` (Counter, by severity/cwe)
- `hyqagent_endpoint_coverage_ratio` (Gauge)
- `hyqagent_budget_spent_usd` (Gauge)

**告警规则**: 预算>60%(warning)/>85%(critical); LLM错误率>10%(warning)/>30%(critical); 覆盖率<70%(warning); 30分钟无活动(critical)。详见 `DEVELOPMENT-STANDARDS.md` 第2.5节。

### 7.4 决策追踪（Audit Trail）

**公开接口**:

```python
class DecisionTraceStore:
    """ESAA模式: Agent→JSON意图→Orchestrator验证→activity.jsonl。SHA-256链式验证。"""

    def append_event(self, event: DecisionEvent) -> str: ...
    """返回该事件的SHA-256哈希，含前一条哈希"""
    def verify_integrity(self, session_id: str) -> tuple[bool, list[str]]: ...
    """重放activity.jsonl，验证哈希链完整性"""
    def get_decision_justification(self, session_id: str, step: int) -> dict: ...
    """'为什么Agent跳过了这个文件？' → 返回原因和证据"""
    def replay_session(self, session_id: str) -> list[DecisionEvent]: ...
    """按时间顺序重放全部决策"""
```

**六条审计不变量**（详见 `DEVELOPMENT-STANDARDS.md` 第2.6节 + `LONG-RUNNING-AGENT-ARCHITECTURE.md` 第4.1节）:
1. Claim-Before-Work, 2. Complete-After-Work, 3. Prior-Status Consistency, 4. Lock Ownership, 5. Boundary Discipline, 6. Done Immutability

**依赖**: 数据库连接（注入）

---

## 八、CLI接口 (`api/`)

> 详细设计见 `PLAN.md` 第七章。

**模块职责**: 命令行入口 + 配置管理 + 信号处理。

### 8.1 命令结构

```
hyqagent init                                # 生成 ~/.hyqagent/config.yaml
hyqagent scan ./myapp                        # 标准扫描 (--mode=standard --max-cost=5.0)
hyqagent scan ./myapp --quick                # 快速扫描 (--mode=sas --max-cost=1.0)
hyqagent scan ./myapp --deep                 # 深度扫描 (--mode=deep --max-cost=25.0)
hyqagent scan ./myapp --lang python --framework flask
hyqagent scan ./myapp --vuln-types sqli,xss,ssrf
hyqagent scan ./myapp --incremental          # 仅扫描变更文件
hyqagent resume <session-id>                 # 续扫（<1秒恢复，详见LONG-RUNNING-AGENT-ARCHITECTURE.md 5.3节）
hyqagent sessions list                       # 查看所有会话
hyqagent sessions show <session-id>          # 查看会话详情
hyqagent report <session-id> --format json   # 生成报告 (json/markdown/sarif)
hyqagent config show                         # 查看当前配置
hyqagent config set models.mid claude-sonnet-4-6
```

### 8.2 配置文件

**`~/.hyqagent/config.yaml`格式**（详见 `PLAN.md` 第7.2节）:

```yaml
models:
  cheap:
    provider: anthropic
    model: claude-sonnet-4-6   # 实际可用kimi/glm覆盖
    api_key: ${ANTHROPIC_API_KEY}
  mid:
    provider: anthropic
    model: claude-sonnet-4-6
    api_key: ${ANTHROPIC_API_KEY}
  strong:
    provider: anthropic
    model: claude-opus-4-6
    api_key: ${ANTHROPIC_API_KEY}

scan:
  default_mode: standard
  max_cost_per_project: 5.0
  phase_timeout_seconds:
    cpg_build: 300
    deterministic: 60
    hypothesis: 600
    validation: 900
  parallel_workers: 4

frameworks:
  python: [flask, django, fastapi]
  javascript: [express, nextjs]
  java: [spring, jax-rs]

output:
  default_format: markdown
  report_dir: ./hyqagent-reports
  include_evidence: true
  include_remediation: true
```

### 8.3 信号处理

```python
class SignalHandler:
    """SIGTERM→保存检查点→优雅退出; SIGUSR1→手动触发检查点"""

    def __init__(self, checkpoint_mgr: CheckpointManager): ...
    def setup_handlers(self) -> None: ...
    """注册 SIGTERM, SIGUSR1 信号处理器"""
    async def graceful_shutdown(self, signum: int) -> None: ...
    """保存检查点→标记running任务为pending→清空临时文件→exit(0)"""
```

**依赖**: `CheckpointManager`（注入）

---

## 九、测试策略

> 详细设计见 `DEVELOPMENT-STANDARDS.md` 第三章。

### 9.1 五层LLM测试模型

| 层级 | 内容 | 工具 | 确定性 |
|:-----|:-----|:-----|:------|
| L1: 单元测试 | 确定性代码（CPG查询、规则引擎、配置解析） | pytest + 精确断言 | 100% |
| L2: 集成测试 | LLM+API+RAG端到端 | pytest + mock LLM | 确定性(mock) |
| L3: 功能测试 | 完整工作流，语义相似度评估 | DeepEval, Braintrust | 概率性 |
| L4: 回归测试 | 版本化Golden Dataset，多次重跑 | Promptfoo | 统计性 |
| L5: 人工评估 | 语义质量、业务正确性 | 标注平台 | 人工 |

**核心隔离原则**: 确定性组件传统pytest测试mock LLM；概率性组件Eval框架多次重跑+统计阈值。架构层面的隔离：LLM输出→确定性后处理验证（格式检查、字段完整性）；低置信度→回退确定性规则路径。详见 `DEVELOPMENT-STANDARDS.md` 第3.2节。

### 9.2 确定性组件测试

**测试要点**:
- `test_cpg/test_parser.py`: 验证tree-sitter解析正确性（已知fixture代码样本）
- `test_cpg/test_call_graph.py`: 验证跨文件调用边正确性
- `test_cpg/test_data_flow.py`: 验证source→sink数据流路径完整性
- `test_scanner/test_deterministic.py`: 验证Phase 1各规则产出正确（mock CPGQuery）
- `test_session/test_belief.py`: 验证贝叶斯更新数学正确性
- `test_models/test_router.py`: 验证路由决策矩阵逻辑

### 9.3 概率性组件测试

**Golden Dataset构建**（详见 `IMPLEMENTATION-GUIDE.md` 第2.2节和5.2节）:
- 25-30个核心case，从WebGoat/DVWA/VulnPy手动提取
- 覆盖5种MVP漏洞类型：命令注入、SQL注入、反序列化、路径遍历、硬编码密钥
- 分dev集（迭代用）和test集（最终验证，不可查看）
- 已知Big-Vul标签准确率仅54.3%，PrimeVul上StarCoder2从F1=68.26%暴跌到F1=3.09%——**没有任何专门针对Web漏洞的高质量标注基准**

**Eval-Driven Development循环**: Eval定义→Prompt迭代→评估→分析→优化。关键规则：先写eval再写prompt/代码；限制eval迭代次数防过拟合；生产误报/漏报持续回流到dataset；使用bootstrap/McNemar检验确认改善统计显著。详见 `DEVELOPMENT-STANDARDS.md` 第3.5节。

### 9.4 CI/CD集成（三级漏斗）

详见第1.2节CI/CD配置。Stage 1(pre-commit)阻断commit，Stage 2(PR)阻断merge，Stage 3(Nightly)生成报告人工审核。

---

## 十、实现阶段划分

### Phase 1: CPG Foundation（目标3-4周）🔄 进行中

> 详见 `PLAN.md` 第八章 Phase 1 + `IMPLEMENTATION-GUIDE.md` 第1.1节。

**产出标准**: 能对Python Flask项目做完整CPG分析（调用图+数据流图+框架路由提取+查询接口）。

**任务分解**:
1. ✅ tree-sitter集成：安装Python/JS/Java语法，实现Parser + Traverser（Session 1.2-1.3）
2. ✅ 单文件调用图：SingleFileCallGraph，支持Python/JS/Java（Session 1.4）
3. ✅ LanguageProvider可扩展架构：策略模式重构，添加语言=1文件+1行注册（Session 1.5）
4. ✅ 跨文件调用图：CallGraphBuilder，import解析+跨文件调用边（Session 1.5）
5. ✅ 基础加固：边界测试+性能基线+契约验证，240 tests（Session 1.5后续）
6. ✅ 数据流图构建：def-use chain分析、跨函数数据流追踪、BFS 污点传播（Session 1.6）
7. ✅ 框架提取器：Flask/Django/FastAPI/Express/Spring 五种框架（Session 1.8）
8. 📋 Taint配置：taint_rules.yaml初版（Python+Flask 5种漏洞的source/sink）
9. ✅ CPG查询接口 + CPG图构建 + YAML污点规则（Session 1.7）
10. 📋 端到端CPG测试：用已知CVE项目验证（Session 1.9）

> 图例：✅ 已完成　📋 计划中

### Phase 2: 确定性扫描器（目标1-2周）

> 详见 `PLAN.md` 第八章 Phase 2。

**产出标准**: `hyqagent scan --quick`可用，纯确定性扫描输出JSON。

**任务分解**:
1. 规则引擎：secrets.yaml + dangerous_calls.yaml + config_issues.yaml
2. CPG污点追踪引擎：source→sink无消毒路径直接标记
3. 缺失认证注解检测
4. CLI v0：最简命令行入口

### Phase 3: LLM集成（目标2-3周）

> 详见 `PLAN.md` 第八章 Phase 3。

**产出标准**: `hyqagent scan`（standard模式）可用，CPG+LLM完整流水线。

**任务分解**:
1. Model Router: 三档模型定义+路由决策矩阵+复杂度评分
2. Provider适配器: Anthropic + OpenAI-compatible + 重试/熔断
3. 攻击面映射: 端点分类prompt + 优先级过滤
4. 假设生成: CPG切片提示构建 + 结构化输出 + 复杂度评分
5. 分层验证: L1确定性验证 + L2 LLM验证（5问）
6. 会话管理: SQLite schema + 假设生命周期 + 贝叶斯更新
7. 报告生成: JSON/Markdown/SARIF + 证据链组装
8. CostTracker集成

### Phase 4: 长任务能力（目标2-3周）

> 详见 `LONG-RUNNING-AGENT-ARCHITECTURE.md` 全文。

**产出标准**: 支持大型代码库数天持续运行，支持中断恢复。

**任务分解**:
1. 三区段上下文模型 + Prompt Caching集成
2. 上下文结晶协议: N轮触发 + 结构化摘要模板
3. 代码检索: 向量化 + 混合检索（ripgrep+tree-sitter+Qdrant+Joern）
4. 检查点管理: 混合驱动保存 + 快速恢复（RTO<1秒）+ 增量分析
5. 收敛检测: VDR/EC/RWC/VCC/C_hat多指标
6. 补充机制: 反向Sink分析 + 盲扫LLM通道 + Completeness Critic（详见COVERAGE-GAP-ANALYSIS.md 第六章）
7. 对抗性审查（方案6） + 差异覆盖分析（方案5）
8. 饱和扫描（方案4）
9. Observability完整集成: OTel+LangFuse+Prometheus+ESAA审计链
10. 信号处理: SIGTERM优雅关闭 + SIGUSR1手动检查点

### Phase 5: 质量与发布（目标2-3周）

**产出标准**: 生产可用v1.0，完整测试套件和文档。

**任务分解**:
1. Golden Dataset构建（25-30个核心case）
2. 确定性组件单元测试全覆盖
3. Eval框架集成（DeepEval/Braintrust）+ 回归测试（20次重跑）
4. CI/CD三级漏斗配置
5. 安全加固：Prompt注入五层防护 + API Key轮换 + 依赖安全审计
6. AGENTS.md编写（150-300行，详见DEVELOPMENT-STANDARDS.md 5.4节）
7. 性能优化：CPG缓存、批量LLM调用并行化
8. Docker化：多阶段构建 + uv加速

---

## 十一、模块接口契约

### 模块依赖图

```
CLI (api/cli.py)
  ├── Config (api/config.py) —— pydantic-settings
  ├── Orchestrator (scanner/orchestrator.py)
  │     ├── CPGQuery (cpg/query.py) ← [Parser, Traverser, SingleFileCallGraph, CallGraphBuilder, DataFlowBuilder, FrameworkExtractor]
  │     ├── DeterministicScanner (scanner/deterministic.py) ← CPGQuery
  │     ├── AttackSurfaceMapper (scanner/mapper.py) ← LlmProvider, CPGQuery
  │     ├── HypothesisGenerator (scanner/hypothesis.py) ← LlmProvider, CPGQuery
  │     ├── Validator (scanner/validator.py) ← LlmProvider, CPGQuery
  │     └── ReportGenerator (report/*.py)
  ├── ModelRouter (models/router.py) → BudgetManager (models/budget.py) → LlmProvider (models/providers/*.py)
  ├── SessionManager (session/manager.py) ← [BeliefSystem, CheckpointManager, DecisionTraceStore]
  ├── ContextManager (memory/context.py) ← [ContextCrystallizer, CodeRetriever]
  └── ObservabilityManager (observability/tracer.py) ← [CostTracker, MetricsCollector, DecisionTraceStore]
```

> ✅ 已实现: Parser, Traverser, SingleFileCallGraph, CallGraphBuilder, LanguageProvider, types, core/protocols|state|events
> 📋 计划中: DataFlowBuilder, CPGQuery, FrameworkExtractor, 及 scanner/models/session/memory/observability 全部模块

### 模块接口快速索引

| 模块 | 路径 | 核心公开接口 | 注入依赖 | 状态 |
|:-----|:-----|:-----------|:--------|:-----|
| 核心协议 | `core/protocols.py` | `BaseTool`, `CpgAnalyzer`, `AuditRepository`, `LlmProvider`, `ToolResult` | 无 | ✅ |
| 解析器 | `cpg/parser.py` | `Parser.parse_file/code`, `extract_functions/classes/imports`, `get_language/provider` | `LanguageProvider` | ✅ |
| AST遍历 | `cpg/traversal.py` | `Traverser.traverse_pre/post_order/subtree`, `find_first/all`, `get_children/parent/ancestors` | `Tree` | ✅ |
| 语言适配器 | `cpg/languages/` | `LanguageProvider` 抽象基类 + `PythonAdapter`/`JSAdapter`/`JavaAdapter` | `tree-sitter` 语法包 | ✅ |
| 共享类型 | `cpg/types.py` | `FunctionNode`, `ClassNode`, `ImportNode`, `CallEdge`, `UnresolvedCall` | 无 | ✅ |
| 单文件调用图 | `cpg/callgraph.py` | `SingleFileCallGraph.build`, `get_callees/callers`, `has_edge` | `Parser` | ✅ |
| 跨文件调用图 | `cpg/callgraph_builder.py` | `CallGraphBuilder.add_directory/file`, `resolve_imports`, `build_calls` | `Parser` | ✅ |
| 数据流分析 | `cpg/dataflow.py` | `DataFlowBuilder.build_def_use_chains`, `trace_cross_function`, `propagate_taint` | `Parser`, `CallGraphBuilder` | ✅ |
| CPG图构建 | `cpg/graph.py` | `CPGGraphBuilder.add_file/directory`, 构建 MultiDiGraph (AST/CALLS/DATA_FLOW) | `Parser`, `CallGraphBuilder`, `DataFlowBuilder` | ✅ |
| CPG查询 | `cpg/query.py` | `CPGQuery.find_path/sources/sinks`, `get_call_chain`, `slice_path`, `get_sanitizers` | `nx.MultiDiGraph` | ✅ |
| 确定性扫描 | `scanner/deterministic.py` | `scan_secrets/dangerous_calls/cpg_taint/missing_auth/config_issues` | `CPGQuery` | 📋 |
| 攻击面映射 | `scanner/mapper.py` | `classify_endpoint`, `filter_high_priority` | `LlmProvider`, `CPGQuery` | 📋 |
| 假设生成 | `scanner/hypothesis.py` | `generate_for_endpoint`, `assess_complexity` | `LlmProvider`, `CPGQuery` | 📋 |
| 分层验证 | `scanner/validator.py` | `validate_deterministic`, `validate_llm`, `reverse_sink_analysis`, `blind_scan`, `completeness_critic` | `LlmProvider`, `CPGQuery` | 📋 |
| 模型路由 | `models/router.py` | `ModelRouter.route`, `BudgetManager.check_and_route` | 无 | 📋 |
| 会话管理 | `session/manager.py` | `create/load/save/delete_session` | 数据库连接 | 📋 |
| 信念系统 | `session/belief.py` | `update_confidence`, `add_dependency`, `propagate_confidence` | 数据库连接 | 📋 |
| 检查点 | `session/checkpoint.py` | `save/load_checkpoint`, `verify_integrity`, `generate_recovery_summary` | 数据库连接 | 📋 |
| 上下文管理 | `memory/context.py` | `build_context`, `estimate_usage` | 无 | 📋 |
| 上下文结晶 | `memory/crystallizer.py` | `should_crystallize`, `crystallize` | 无 | 📋 |
| 代码检索 | `memory/retriever.py` | `index_file`, `semantic_search`, `hybrid_search` | `chromadb`/`qdrant` | 📋 |
| 成本追踪 | `observability/cost_tracker.py` | `record_call`, `get_cost_by_finding/phase` | 数据库连接 | 📋 |
| 审计追踪 | `observability/audit_trail.py` | `append_event`, `verify_integrity`, `replay_session` | 数据库连接 | 📋 |

### 关键集成顺序

1. ✅ `core/protocols.py` — 定义所有抽象（Session 1.1）
2. ✅ `cpg/types.py` — 共享数据类，打破循环依赖（Session 1.5）
3. ✅ `cpg/languages/base.py` — LanguageProvider 抽象基类（Session 1.5）
4. ✅ `cpg/languages/{python,js,java}.py` — 语言适配器（Session 1.5）
5. ✅ `cpg/parser.py` — tree-sitter 封装，委托给 Provider（Session 1.2, 1.5 重构）
6. ✅ `cpg/traversal.py` — AST 遍历器（Session 1.3）
7. ✅ `cpg/callgraph.py` — 单文件调用图（Session 1.4, 1.5 重构）
8. ✅ `cpg/callgraph_builder.py` — 跨文件调用图（Session 1.5）
9. ✅ `cpg/data_flow.py` — 数据流+污点追踪（依赖 callgraph，Session 1.6）
10. 📋 `cpg/frameworks/flask.py` — 框架提取器（依赖 parser，Session 1.8）
11. ✅ `cpg/query.py` + `cpg/graph.py` — CPG 图构建 + 查询接口（Session 1.7）
12. 📋 `scanner/deterministic.py` — 确定性扫描（依赖 query）
13. 📋 `models/providers/anthropic.py` — LlmProvider 协议实现
14. 📋 `models/router.py` + `models/budget.py`
15. 📋 `scanner/mapper.py` → `scanner/hypothesis.py` → `scanner/validator.py`
16. 📋 `session/schema.sql` → `session/manager.py` → `session/belief.py` → `session/checkpoint.py`
17. 📋 `observability/` — tracer, cost_tracker, audit_trail
18. 📋 `memory/context.py` → `memory/crystallizer.py` → `memory/retriever.py`
19. 📋 `scanner/orchestrator.py` — 组装所有组件，依赖注入
20. 📋 `api/cli.py` — CLI 入口
21. 📋 `report/*.py` — 报告生成

> 图例：✅ 已完成　📋 计划中

---

## 十二、风险与缓解

> 完整风险清单详见 `IMPLEMENTATION-GUIDE.md` 第二章。以下提取TOP 10。

| # | 风险 | 阻塞程度 | 缓解策略 | 源文档 |
|:--|:-----|:--------|:--------|:-----|
| 1 | **跨文件调用图（反射/DI/动态import）** | P0—卡住1-2周 | 先支持无反射/无DI的Python项目；动态import直接丢弃调用边（GitLab Orbit实践）；Spring DI暂缓 | `IMPLEMENTATION-GUIDE.md` 2.1节 |
| 2 | **测试基准不存在** | P0—持续性阻塞 | 手动构造25-30个已知漏洞的WebGoat/DVWA/VulnPy回归集；Big-Vul标签准确率仅54.3%，不可用 | `IMPLEMENTATION-GUIDE.md` 2.2节 |
| 3 | **框架传播器被低估** | P1—初版1-2周 | 从Flask一种框架开始，只做request→sink直接路径；每种新框架+7天 | `IMPLEMENTATION-GUIDE.md` 2.1节 |
| 4 | **LLM验证可复现性仅17-25%** | P1—设计层面 | temperature=0 + 多次交叉验证 + L1确定性验证权重更高 | `IMPLEMENTATION-GUIDE.md` 2.1节 |
| 5 | **tree-sitter segfault** | P2—渐进消耗 | 锁定版本，查询外加retry loop；CI中7-9%失败率 | `IMPLEMENTATION-GUIDE.md` 6.1节 |
| 6 | **Joern Lambda数据流断裂** | P2—已知无修复计划 | 已知bug，不在roadmap。接受此限制 | `IMPLEMENTATION-GUIDE.md` 2.1节 |
| 7 | **LLM过度自信幻觉** | P2—质量风险 | 每个发现必须有CPG可验证的代码证据；无代码证据的发现自动降级 | `IMPLEMENTATION-GUIDE.md` 2.1节 |
| 8 | **SQLite WAL checkpoint饥饿** | P2—静默故障 | 监控WAL文件大小，定期`PRAGMA wal_checkpoint`；一个未关闭读事务就能阻止 | `IMPLEMENTATION-GUIDE.md` 6.3节 |
| 9 | **Phase 1有损过滤遗漏漏洞** | P2—架构层面 | 七种缓解方案（反向Sink分析/盲扫LLM/Completeness Critic/饱和扫描/差异覆盖/对抗性审查/架构感知）。详见 `COVERAGE-GAP-ANALYSIS.md` 第六章。standard模式额外成本~$1.45，仍在$5预算内 | `COVERAGE-GAP-ANALYSIS.md` 全文 |
| 10 | **Prompt缓存TTL与长任务不匹配** | P3—增加成本 | 缓存断点放在系统prompt（1h TTL），不放在对话历史；5分钟缓存TTL在Agent活跃时自动续期 | `IMPLEMENTATION-GUIDE.md` 2.1节 |

---

## 附录：源文档索引

| 文档 | 大小 | 核心内容 | 本设计文档引用章节 |
|:-----|:-----|:--------|:----------------|
| `RESEARCH.md` | 25KB | 20+论文综述；架构模式对比（SAS/MAS-Indep/Central/Decent/Pipeline）；CPG+LLM最优技术栈验证；幻觉防御体系；模型选型经济分析 | 四、九 |
| `PLAN.md` | 35KB | 五阶段流水线详细设计；CPG五层图结构；污点源/汇配置；信念系统状态机；Model Router三档模型；CLI命令结构；Phase 1-4路线图 | 二、三、四、五、八、十 |
| `COVERAGE-GAP-ANALYSIS.md` | 33KB | Phase 1有损过滤vs RepoAudit无损抽象的关键设计假设错误；20-35%漏洞类别覆盖的定量分析；七种互补缓解方案；按扫描模式的分层部署 | 三、九、十二 |
| `severity_based_vulnerability_mining_framework.md` | 27KB | 五级危害分类（CRITICAL/HIGH/MEDIUM/LOW/INFO）；七层挖掘阶梯（L1-L7）；CISA KEV 2025数据驱动的预算分配（CRITICAL 40%）；各层验收标准 | 三、十 |
| `detection_matrix.json` | 142KB | 200项ASVS对齐的结构化检测项；17大类（INPUT/AUTH/CONFIG等）；每项含确定性/LLM/动态验证标志、严重度、CWE编号 | 三（引用） |
| `WEB-VULN-FULL-MATRIX.md` | 18KB | 180+漏洞类型x五级危害x四级检测可行性（A-E）完整矩阵；预算和时间的分配总表；动态优先级调整规则 | 三（引用） |
| `LONG-RUNNING-AGENT-ARCHITECTURE.md` | 27KB | 三区段上下文模型；ESAA事件溯源+六条审计不变量；检查点机制（四种触发策略）；双层恢复；四层代码分析；收敛标准（VDR/EC/RWC/VCC/C_hat）；容错退避策略 | 五、六、七 |
| `IMPLEMENTATION-GUIDE.md` | 14KB | 核心决策：不按sink生成子Agent；CPG跨文件调用图最大风险；基准数据集不存在；单Agent+多视角最优第一阶段架构；推荐Phase 2架构；MVP建议（5种漏洞/Flask/7周） | 一、十、十二 |
| `DEVELOPMENT-STANDARDS.md` | 20KB | SOLID原则应用；src-layout项目结构；protocols.py抽象层；五层LLM测试模型；三级CI漏斗；Eval-Driven Development；Prompt即代码（YAML+Jinja2版本化）；五层注入防护；tenacity重试+Circuit Breaker；SQLite WAL最佳实践；uv依赖管理；AGENTS.md标准；数据飞轮反馈循环 | 一、七、九 |
