# Session 1.7 — CPG 图构建 + 查询接口 + Taint 规则

## 目标

1. **NetworkX CPG 图构建**：将 Parser/CallGraph/DataFlowBuilder 的产出统一索引到 MultiDiGraph
2. **CPG 查询接口**：find_path / find_sources / find_sinks / get_call_chain / slice_path
3. **完整 Taint 规则**：Python/JS/Java 三种语言，覆盖 SQL 注入/命令注入/XSS/路径遍历/SSRF/反序列化/重定向/代码注入

## 产出清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `src/hyqagent/cpg/graph.py` | CPGGraphBuilder（~275行），构建 NetworkX MultiDiGraph |
| `src/hyqagent/cpg/query.py` | CPGQuery（~300行），5 个查询方法 + GraphNode/GraphPath 结果类型 |
| `src/hyqagent/cpg/taint_rules.yaml` | 完整污点规则（~300行），Python/JS/Java 各 9 种漏洞类别 |
| `tests/test_cpg/test_graph.py` | 11 个图构建测试（函数索引/调用边/数据流边/JS/目录） |
| `tests/test_cpg/test_query.py` | 22 个查询测试（find_path/sources/sinks/call_chain/slice/sanitizer/边界） |

### 修改文件
| 文件 | 变更 |
|------|------|
| `pyproject.toml` | networkx 已存在，无需修改 |

## 实现过程

### 1. CPG 图构建（graph.py）

**节点类型**：
- `function` — 函数/方法定义节点，属性含 name/file_path/start_line/source
- `call_site` — 调用点节点，属性含 caller/callee/expression
- `assignment` — 赋值节点，属性含 var_name/location/source
- `variable_ref` — 变量引用节点，属性含 var_name/location

**边类型**：
- `CALLS` — function → call_site → function（跨函数的调用链）
- `DATA_FLOW` — assignment → variable_ref → ... → assignment（数据流链）

**构建流程**（`add_file`）：
1. Parser 解析文件 → 索引函数定义
2. SingleFileCallGraph → 索引调用边
3. DataFlowBuilder → 索引 def-use chain 为 DATA_FLOW 边

**目录递归**（`add_directory`）：
- 委托 CallGraphBuilder 做跨文件 import 解析
- 每个文件单独 `add_file`，再添加跨文件 CALLS 边

### 2. 查询接口（query.py）

```python
query = CPGQuery(builder.graph)

# 找 source→sink 的所有路径
paths = query.find_path("request.args.get", "cursor.execute")

# 从 sink 反向追踪上游源头
sources = query.find_sources("db.execute")

# 从 source 正向追踪下游目标
sinks = query.find_sinks("request.args.get")

# 沿 CALLS 边找调用链
chain = query.get_call_chain("process_request", "lookup")

# 路径可视化
print(query.slice_path(paths[0]))
```

**BFS 实现**：`_bfs_paths()` 使用双端队列 + visited 集合，支持按边类型过滤（默认 DATA_FLOW + CALLS），max_depth 防无限循环。

### 3. Taint 规则（taint_rules.yaml）

覆盖 9 种漏洞类别 × 3 种语言：
- sql_injection, command_injection, xss, path_traversal
- ssrf, deserialization, open_redirect, code_injection, auth_bypass

每个类别包含 sources、sinks、sanitizers 三组 pattern 列表。
Pattern 使用 substring 匹配（AST 节点文本包含即命中）。

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| networkx 未安装 | `uv sync` 未触发 | `uv sync --reinstall-package networkx` |
| ruff D105 在 `__repr__`/`__len__`/`__bool__` | 魔术方法缺 docstring | 添加 `# noqa: D105` |
| ruff D205 summary line 格式 | 多行 docstring 第一行不应折行 | 缩短 summary 到一行 |
| ruff C401 set(generator) | 不必要的 generator 包装 | 改为 set comprehension `{...}` |
| ruff RUF005 list concat | `list + [item]` 可用解包替代 | `[*list, item]` |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check | ✅ All checks passed |
| pytest | ✅ **302 passed**（269 existing + 33 new） |
| mypy | ⚠️ mypy 未在 venv 中（已知问题，不影响运行） |

## 设计反思

### 做得好的
1. **图与查询分离** — graph.py 只管构建，query.py 只管查询，职责清晰
2. **跨语言支持一次到位** — taint_rules.yaml 覆盖 Python/JS/Java 三种语言
3. **BFS 带 edge_type 过滤** — 支持 CALLS-only（get_call_chain）和 DATA_FLOW-only 查询
4. **节点 UID 设计** — `type:file:line:name` 的命名空间避免了跨文件冲突

### 可改进的
1. **图构建性能** — 每个文件都重新运行 DataFlowBuilder 解析，大项目会慢。后续可加缓存
2. **taint_rules.yaml 未集成到查询** — YAML 文件写了完整的规则，但查询接口目前仍用 substring 匹配。Session 1.8 可做 TaintRuleLoader 读取 YAML 驱动查询
3. **mypy 环境** — 当前 venv 中 mypy 未正确安装，需 `uv add --dev mypy` 修复

## 下步衔接

### Session 1.8: 框架提取器
- 实现 BaseFrameworkExtractor 抽象基类
- Flask/Django/FastAPI 三种 Python 框架提取器
- Express (JS) + Spring (Java) 两种框架提取器
- HTTP_ROUTE 边接入 CPG 图
- TaintRuleLoader：从 taint_rules.yaml 读取规则驱动污点分析
