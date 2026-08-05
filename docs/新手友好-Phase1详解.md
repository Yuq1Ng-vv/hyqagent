# HyqAgent Phase 1 详解（新手友好 · 明日分享用）

> **读这个能理解**: Phase 1 实际做了什么、怎么做的、能做到什么程度。
> **不是**: 完整产品的介绍——Phase 1 只是地基，扫描器/LLM/报告都还没做。

---

## 零、先弄清楚：Phase 1 是什么、不是什么

**Phase 1 是一个代码分析引擎**，能读懂 Python/JS/Java 代码的结构和数据流。

| ✅ 能做到 | ❌ 还做不到 |
|----------|-----------|
| 解析代码，找出所有函数、类、调用关系 | 自动发现漏洞（扫描器是 Phase 2） |
| 追踪变量从哪定义、在哪使用 | 调用 LLM 做语义判断（LLM 是 Phase 3） |
| 画出跨文件的数据流路径 | 保存扫描结果到数据库（Session 是 Phase 4） |
| 识别 Flask/Django/Express/Spring 的路由 | 生成 JSON/SARIF 报告（Report 是 Phase 5） |
| 加载 9 类 × 3 语言的污点规则 | 运行 `hyqagent scan` 命令（CLI 是 Phase 5） |

**一句话**：Phase 1 是把代码变成一张可查询的"地图"，后续 Phase 在这张地图上做漏洞检测。

---

## 一、核心概念：把代码变成图

### 1.1 传统工具怎么做？

Semgrep、CodeQL 这类工具用**模式匹配**——写好规则"如果看到 `cursor.execute(` 且参数来自 `request.args`，就报 SQL 注入"。

问题是：规则是人写的，写不完所有情况。IDOR（越权漏洞）根本没有固定的代码模式。

### 1.2 Phase 1 怎么做？

把代码解析成一张**多层次的图**，然后在这张图上做查询。图里有三种信息：

```
代码:                         图中的节点和边:
                              
@app.route("/search")        ┌──────────────────┐
def search():                │  HTTP端点         │
    q = request.args["q"]    │  /search [GET]    │
    sql = f"SELECT *         │  handler: search  │
           WHERE q='{q}'"    └────────┬─────────┘
    db.execute(sql)                   │ (CALLS 边)
                                      ▼
                             ┌──────────────────┐
                             │  函数: search     │
                             └────────┬─────────┘
                                      │ (DATA_FLOW 边)
                                      ▼
                             ┌──────────────────┐
                             │  赋值: q = ...    │──→ 使用: f"...{q}"
                             └────────┬─────────┘
                                      │
                                      ▼
                             ┌──────────────────┐
                             │  赋值: sql = ...  │──→ 使用: db.execute(sql)
                             └──────────────────┘
                                      │ (CALLS 边)
                                      ▼
                             ┌──────────────────┐
                             │  函数: execute    │  ← SINK!
                             └──────────────────┘
```

有了这张图，查询"从 `request.args` 到 `db.execute` 有没有路径？"就是图上的最短路径搜索。

---

## 二、管道分 7 步，一步一步看

### 第 1 步：解析（Parser）

**输入**: 一个 `.py` / `.js` / `.java` 文件
**输出**: 一棵语法树（AST）

```python
from hyqagent.cpg.parser import Parser

parser = Parser()
tree = parser.parse_file("app.py")

# 提取所有函数
funcs = parser.extract_functions(tree, "python")
for f in funcs:
    print(f"{f.name}() @ line {f.start_line}")
# 输出:
# index() @ line 7
# search() @ line 11
# ...
```

每个函数提取出：函数名、参数列表、起止行号、是否方法、装饰器。

支持 Python / JavaScript / Java 三种语言，通过 LanguageProvider 策略模式——每种语言一个适配器，添加新语言只需新增一个文件。

### 第 2 步：构建调用图（CallGraph）

**输入**: AST
**输出**: 谁调用了谁

```python
from hyqagent.cpg.callgraph import SingleFileCallGraph

cg = SingleFileCallGraph(parser)
cg.build_from_file("app.py")

for edge in cg.edges:
    print(f"{edge.caller} → {edge.callee} @ line {edge.call_line}")
# 输出:
# search → search_posts @ line 15    (跨文件，unresolved)
# search → str @ line 17             (内置函数，unresolved)
```

单文件内能解析的直接标记 `is_resolved=True`，解析不了的（外部函数、内置函数）留作 `UnresolvedCall` 供跨文件解析。

**跨文件调用图**（CallGraphBuilder）：扫描整个项目目录，解析 import 语句，把 app.py 中的 `db.search_posts()` 和 db.py 中的 `search_posts()` 函数定义关联起来。

### 第 3 步：数据流分析（DataFlow）

**输入**: AST + 函数节点
**输出**: 每个变量在哪定义、在哪使用（def-use chain）

```python
from hyqagent.cpg.dataflow import DataFlowBuilder

df = DataFlowBuilder(parser)

# 对 search() 函数做 def-use 分析
chains = df.build_def_use_chains(tree, func_node, "python")
for du in chains:
    print(f"{du.var_name}: def @ {du.def_location}, uses @ {du.use_locations}")
# 输出:
# q:   def @ app.py:12, uses @ [app.py:13, app.py:15]
# sql: def @ app.py:14, uses @ [app.py:15]
```

可以清楚看到：`q` 在第 12 行定义（来自 `request.args`），在第 13 行被拼入 `f"SELECT ... WHERE q='{q}'"`，在第 15 行作为 `db.execute(sql)` 的参数——这就是一条完整的污点传播链。

### 第 4 步：构建 CPG 图（CPGGraphBuilder）

**输入**: AST + 调用图 + 数据流
**输出**: 一张 NetworkX 图，包含所有信息

```python
from hyqagent.cpg.graph import CPGGraphBuilder

builder = CPGGraphBuilder(parser)
builder.add_directory("./myapp")

print(builder)
# CPGGraphBuilder(files=7, nodes=156, edges=203)

# 图中有三种边类型:
# - AST:       语法父子关系
# - CALLS:     函数 A → 函数 B
# - DATA_FLOW: 变量从定义流向使用
```

### 第 5 步：查询图（CPGQuery）

**输入**: CPG 图 + 查询条件
**输出**: 路径、来源、去向

```python
from hyqagent.cpg.query import CPGQuery

query = CPGQuery(builder.graph)

# 找从 request.args 到 cursor.execute 的所有路径
paths = query.find_path("request.args", ".execute(")
print(f"找到 {len(paths)} 条路径")

# 看第一条路径
print(query.slice_path(paths[0]))
# ┌─ [function] search @ app.py:11
# ├─ [assignment] q @ app.py:12  --[DATA_FLOW]-->
# ├─ [variable_ref] q @ app.py:13  --[DATA_FLOW]-->
# ├─ [assignment] sql @ app.py:14  --[DATA_FLOW]-->
# ├─ [variable_ref] sql @ app.py:15  --[CALLS]-->
# └─ [call_site] db.execute @ app.py:15

# 查看 search → execute 的调用链
chain = query.get_call_chain("search", "execute")
print(query.slice_path(chain))
```

### 第 6 步：识别框架端点（Framework Extractors）

**输入**: 源码文件
**输出**: 所有 HTTP 端点（路由、方法、参数、认证）

```python
from hyqagent.cpg.frameworks.flask import FlaskExtractor

ext = FlaskExtractor(parser)
routes = ext.extract_routes("app.py")

for r in routes:
    print(f"{r.methods} {r.route} → {r.handler_func}()  auth={r.auth_required}")
# 输出:
# ['GET'] / → index() auth=False
# ['GET'] /search → search() auth=False
# ['GET', 'POST'] /admin/ping → admin_ping() auth=True (@login_required)
```

五种框架各自有提取器，产出统一格式的 `HttpEndpoint`：

| 框架 | 路由写法 | 提取器 |
|------|---------|--------|
| Flask | `@app.route("/path")` | FlaskExtractor |
| Django | `urls.py` 中的 `path()` | DjangoExtractor |
| FastAPI | `@app.get("/path")` | FastAPIExtractor |
| Express | `app.get("/path", handler)` | ExpressExtractor |
| Spring | `@GetMapping("/path")` | SpringExtractor |

### 第 7 步：匹配污点规则（TaintRuleLoader）

**输入**: 源码文本 + `taint_rules.yaml`
**输出**: 这段代码属于哪类漏洞

```python
from hyqagent.cpg.taint_loader import TaintRuleLoader

loader = TaintRuleLoader()

# 检查 source
cat = loader.match_source("python", "request.args.get('id')")
print(cat)  # → "sql_injection"（或 xss/command_injection 等——request.args 是通用入口）

# 检查 sink
cat = loader.match_sink("python", "cursor.execute(sql)")
print(cat)  # → "sql_injection"

# 查看某条路径上所有匹配的类别
cats = loader.match_all_sources("python", "request.args.get('name')")
print(cats)  # → ["auth_bypass", "code_injection", "command_injection", ...]
```

`taint_rules.yaml` 包含 9 种漏洞类别 × 3 种语言：

| # | 类别 | 典型 Source | 典型 Sink |
|---|------|-----------|----------|
| 1 | SQL 注入 | `request.args.get` | `cursor.execute(` |
| 2 | 命令注入 | `request.form.get` | `os.system(` |
| 3 | XSS | `request.args.get` | `render_template_string(` |
| 4 | 路径遍历 | `request.args.get('file')` | `open(user_path)` |
| 5 | SSRF | `request.args.get('url')` | `requests.get(url)` |
| 6 | 反序列化 | `request.data` | `pickle.loads(data)` |
| 7 | 开放重定向 | `request.args.get('next')` | `redirect(url)` |
| 8 | 代码注入 | `request.args.get('expr')` | `eval(expr)` |
| 9 | 认证绕过 | `request.cookies.get` | `.is_authenticated` |

---

## 三、端到端示例

下面用 Phase 1 分析一个真实的微型漏洞应用：

```python
# microblog/app.py (简化版)
@app.route("/search")
def search():
    q = request.args.get("q")           # ← SOURCE
    posts = db.search_posts(q)          # ← 数据流向 db 层
    return str(posts)

# microblog/db.py
class Database:
    def search_posts(self, keyword):
        sql = f"SELECT * FROM posts WHERE title LIKE '%{keyword}%'"
        return self.cursor.execute(sql)  # ← SINK
```

**运行完整管道**：

```python
parser = Parser()
builder = CPGGraphBuilder(parser)
builder.add_directory("microblog/")
query = CPGQuery(builder.graph)

# 1. 发现了几个端点？
ext = FlaskExtractor(parser)
routes = ext.extract_routes("microblog/app.py")
# → 7 个端点：/, /hello, /search, /user/<id>, /post/<id>, /admin/ping, /admin/exec

# 2. /search 有没有认证？
user_route = [r for r in routes if r.handler_func == "search"][0]
# → auth_required=False  ← 注意！

# 3. request.args → cursor.execute 有路径吗？
paths = query.find_path("request.args", ".execute(")
# → 1 条路径，经过 search() → search_posts() → execute()

# 4. 这条路径有没有经过 sanitizer？
query.get_sanitizers(paths[0])
# → []（没有——int()、escape() 都没出现）

# 5. 匹配污点规则
loader = TaintRuleLoader()
loader.match_source("python", "request.args.get('q')")  # → sql_injection
loader.match_sink("python", "cursor.execute(sql)")       # → sql_injection
```

**结论**：`/search` 端点存在从用户输入到 SQL 执行的无消毒路径，且无认证保护——这是一个真实的 SQL 注入漏洞。

---

## 四、Phase 1 的数字

| 指标 | 值 |
|------|-----|
| 源模块 | 22 个 |
| 生产代码 | ~5,300 行 |
| 测试 | 372 个（全通过） |
| 支持语言 | Python / JavaScript / Java |
| 支持框架 | Flask / Django / FastAPI / Express / Spring |
| 污点规则 | 9 类别 × 3 语言 |
| 已知 bug | 0（经 7 个独立 Agent 交叉验证） |
| LLM 依赖 | 零（纯确定性） |

---

## 五、项目结构速览

```
src/hyqagent/
├── core/                    基础层
│   ├── protocols.py         抽象接口（所有模块通过协议通信）
│   ├── state.py             状态类型
│   └── events.py            事件类型
│
├── cpg/                     CPG 引擎 ← Phase 1 的核心
│   ├── parser.py            多语言解析器
│   ├── traversal.py         AST 遍历器
│   ├── types.py             共享数据类
│   ├── callgraph.py         单文件调用图
│   ├── callgraph_builder.py 跨文件调用图
│   ├── dataflow.py          数据流分析
│   ├── graph.py             NetworkX 图构建
│   ├── query.py             图查询接口
│   ├── taint_rules.yaml     污点规则
│   ├── taint_loader.py      规则加载器
│   ├── languages/           语言适配器（Python/JS/Java）
│   └── frameworks/          框架提取器（Flask/Django/FastAPI/Express/Spring）
│
├── scanner/                 📋 扫描引擎（Phase 2）
├── models/                  📋 模型路由（Phase 3）
├── session/                 📋 会话管理（Phase 4）
├── memory/                  📋 上下文管理（Phase 4）
├── observability/           📋 可观测性（Phase 4）
├── prompts/                 📋 Prompt 模板（Phase 3）
├── api/                     📋 CLI 入口（Phase 5）
└── report/                  📋 报告生成（Phase 5）
```

---

## 六、给明天分享的几个要点

1. **这不是一个能跑的命令行工具**——Phase 1 是库，不是应用。可以在 Python 脚本里 import 使用，但没有 `hyqagent scan` 命令。

2. **CPG 是所有后续功能的基础**——扫描器（Phase 2）的规则引擎、假设生成（Phase 3）的代码切片提示、都需要 CPG 提供精确的代码结构。

3. **三语言支持不是事后加的**——LanguageProvider 策略模式从 Session 1.5 就设计好了，添加第四种语言只需一个文件。

4. **372 个测试是真实的安全网**——不是 demo 代码。每次改动后 `uv run pytest tests/` 1 秒内跑完全部。

5. **架构文档已经诚实了**——`ARCHITECTURE_OVERVIEW.md` 顶部有明确的 Phase 进度警告框，不会误导读者以为全部功能都已实现。
