# Session 1.8 — 框架提取器（五种框架一次到位）

## 目标

实现五种主流 Web 框架的 HTTP 路由提取器，自动识别端点、参数来源、认证要求，
以统一 `HttpEndpoint` 格式接入 CPG 图。纯确定性 tree-sitter AST 解析，零 LLM。

## 产出清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `cpg/frameworks/base.py` | HttpEndpoint/RouteParam dataclass + BaseFrameworkExtractor ABC + 通用工具 |
| `cpg/frameworks/flask.py` | Flask 提取器（`@app.route` 装饰器 + `request.args/form/json` 等 source） |
| `cpg/frameworks/fastapi.py` | FastAPI 提取器（`@app.get/post` + Query/Body/Path 参数解析） |
| `cpg/frameworks/django.py` | Django 提取器（`urls.py` path/re_path 解析 + views 函数匹配） |
| `cpg/frameworks/express.py` | Express 提取器（`app.get/post` 方法调用 + middleware 识别） |
| `cpg/frameworks/spring.py` | Spring 提取器（`@GetMapping/@PostMapping` 注解 + `@PreAuthorize` 安全） |
| `cpg/taint_loader.py` | TaintRuleLoader — 从 `taint_rules.yaml` 加载结构化规则 |
| `tests/test_cpg/fixtures/flask_sample.py` | Flask 测试样本（4 个端点含 auth） |
| `tests/test_cpg/fixtures/express_sample.js` | Express 测试样本（4 个端点含 middleware） |
| `tests/test_cpg/fixtures/spring_sample.java` | Spring 测试样本（5 个端点含 `@PreAuthorize`） |
| `tests/test_cpg/test_frameworks.py` | 33 个测试（Base 3 + Flask 9 + Express 6 + Spring 7 + TaintLoader 8） |

### 修改文件
| 文件 | 变更 |
|------|------|
| `cpg/taint_rules.yaml` | 修复 YAML 中 `@` 字符的引号问题 |

## 实现过程

### 1. 统一端点表示

```python
@dataclass
class HttpEndpoint:
    route: str  # "/users/<id>" 或 "/users/:id"
    methods: list[str]  # ["GET", "POST"]
    handler_func: str  # 处理函数名
    file_path: str
    line: int
    params: list[RouteParam]
    auth_required: bool  # @login_required / middleware / @PreAuthorize
    auth_decorators: list[str]
    framework: str  # "flask"|"django"|"fastapi"|"express"|"spring"
    source_lines: list[str]  # 处理函数内的 taint source 行
```

五种框架用同一种数据结构，上层查询接口无需关心框架差异。

### 2. 各框架提取策略

**Flask**：遍历 `decorated_definition` → 检查 decorator → `call` → `attribute` 是否以 `.route` 结尾 → 提取第一个 string 参数为 route → 解析 keyword_argument `methods=[...]`。

**FastAPI**：同 Flask 的 decorator 模式，但方法名是 HTTP verb（get/post/put/delete...）。额外解析函数签名的 `typed_parameter` + `typed_default_parameter`，从 default 值中识别 `Query()`/`Body()`/`Path()`/`Form()`/`Header()`/`Cookie()` 获取参数来源。

**Django**：两阶段——先解析 `*urls*.py` 文件中的 `path("route", view_func)` 调用（正则匹配），建立 route→view 映射；再解析 `views.py` 中匹配的函数，提取 auth decorator 和 source。

**Express**：遍历 `call_expression` → 检查 `member_expression` 的 property 是否为 HTTP verb → 第一个 string 参数为 route → 中间 identifier 为 middleware → 最后 identifier 为 handler。

**Spring**：遍历 `method_declaration` → 检查 `modifiers` 中的 annotation 是否匹配 `@GetMapping/@PostMapping/...` → 提取 annotation 中的 string 参数为 route → 从 formal_parameter 的 modifiers 中识别 `@PathVariable/@RequestParam/@RequestBody/@RequestHeader`。

### 3. TaintRuleLoader

从 `taint_rules.yaml` 加载规则，提供：
- `rules_for(language)` — 按语言获取所有规则
- `match_source(language, text)` — 检查文本是否匹配 source pattern
- `match_sink(language, text)` — 检查文本是否匹配 sink pattern

### 4. 关键技术决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 框架检测 | `detect()` 快速检查 | 避免对每个文件跑完整提取 |
| Django URL 解析 | 正则 `path("...", ...)` | tree-sitter 不解析 Python 字符串内容 |
| Spring annotation | modifiers 文本 substring | 避免遍历 annotation 子结构的复杂性 |
| 路径参数 | 正则 `<type:name>` / `{name}` / `:name` | 三种框架各有自己的语法 |

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| YAML parse error: `@` character | `@RequestParam` 等未加引号 | 所有含 `@` 的值用双引号包裹 |
| Flask route 全是 "/" | `args.children[0]` 是 `(` 而非 string | 改用 `named_children` 跳过括号 |
| detect 误报 dataflow.py 为 Flask | dataflow.py 包含 `from flask import request` | Flask detect 增加 `Flask(__name__)` 或 `.route(` 检查 |
| ruff D102 公共方法缺 docstring | ABC 实现方法无 docstring | `# noqa: D102`（基类已有文档） |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check | ✅ All checks passed |
| pytest | ✅ **335 passed**（302 existing + 33 new） |

## 设计反思

### 做得好的
1. **统一 HttpEndpoint** — 五种框架产出同一结构，上层零适配
2. **纯确定性** — 全部 tree-sitter + 正则，零 LLM 成本
3. **detect() 快速过滤** — 只对匹配框架的文件跑完整提取
4. **TaintRuleLoader 可复用** — Session 2.x Scanner 可直接使用

### 可改进的
1. **Django 跨文件** — 当前只匹配同文件的 URL config；生产需支持 `include()` 嵌套和外键 URL 配置
2. **FastAPI 依赖注入** — 未处理 `Depends()` 链和 middleware-level auth
3. **HTTP_ROUTE 边未接入 CPGGraphBuilder** — 底层已准备好，但 graph.py 集成未在本 Session 完成
4. **NestJS/Next.js 等衍生框架** — Express 提取器可覆盖大部分，但路由装饰器语法需额外处理

## 下步衔接

### Session 1.9: 端到端 CPG 测试
- 用已知 CVE 项目验证完整 CPG 链路
- 框架提取器 → CPG 图 → 查询接口 全链路集成测试
- 验证 source→sink 路径发现的正确性
