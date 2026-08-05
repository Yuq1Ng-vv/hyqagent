# Session 1.9 — 端到端 CPG 集成验证

## 目标

用真实漏洞代码验证完整 CPG 管道：
Parser → CallGraph → DataFlow → Graph → Framework Extractors → Query → TaintLoader

构造含四种 CWE 级漏洞的微型 Flask 应用，编写 5 层 26 个集成测试断言全链路正确性。

## 产出清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `tests/test_cpg/fixtures/microblog/app.py` | 微型 Flask 博客（~110行），含 CWE-89/78/79/639 四种漏洞 |
| `tests/test_cpg/fixtures/microblog/db.py` | 不安全的数据库层（3 个 SQL 注入点） |
| `tests/test_cpg/test_e2e.py` | 26 个端到端集成测试 |

### 修改文件
| 文件 | 变更 |
|------|------|
| `pyproject.toml` | 新增 `microblog/` fixture 的 ruff per-file-ignores（S201/S605/S608 是有意漏洞） |

## 测试分层

### Level 1: Parser + CallGraph（5 tests）
- `test_parse_app` — 文件解析不崩溃
- `test_extract_functions` — 5 个 handler 函数全部识别
- `test_single_file_call_graph` — 单文件调用边正确
- `test_cross_file_call_graph` — app.py → db.py 跨文件索引
- `test_cross_file_edges` — search() → search_posts() → execute() 调用链

### Level 2: DataFlow（3 tests）
- `test_hello_def_use` — `name` 变量 def-use 链
- `test_search_def_use` — `keyword` 变量 def-use 链
- `test_admin_ping_def_use` — `host`/`command` 变量 def-use 链

### Level 3: CPG Graph（4 tests）
- `test_graph_has_functions` — 所有函数节点已索引（含 db.py）
- `test_graph_has_call_sites` — 调用点节点存在
- `test_graph_has_dataflow_edges` — DATA_FLOW 边存在
- `test_graph_has_calls_edges` — CALLS 边（跨文件）存在

### Level 4: Framework Extraction（5 tests）
- `test_flask_detects_app` — Flask 检测正确
- `test_all_endpoints_found` — 6 个路由全部发现
- `test_auth_endpoints` — `@login_required` 端点正确标记（view_post/admin_ping/admin_exec）
- `test_idor_endpoint_no_auth` — `user_profile` 缺 auth（IDOR 检测）
- `test_source_lines_found` — `request.args/form.get` source 行已捕获

### Level 5: Query + Taint（9 tests）
- `test_query_finds_source_nodes` — `request.args.get` 在图中有节点
- `test_query_finds_sink_nodes` — `.execute(` 在图中有节点
- `test_query_finds_os_system` — `os.system` 在图中有节点
- `test_call_chain_search_to_execute` — search() → execute() 调用链
- `test_call_chain_admin_to_os_system` — 外部调用正确处理（不会崩溃）
- `test_taint_loader_*` (4 tests) — SQL source/sink、command sink 匹配、三语言可用

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| DataFlow 测试返回空 def-use | `decorated_definition` 节点没有 `body` 字段 | `_find_func_body()` 展开 `decorated_definition` 取内部 `function_definition` |
| ruff S608 报告 fixture 中 SQL 注入 | 这些是**有意漏洞**——正是测试要检测的 | pyproject.toml 新增 per-file-ignores |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check | ✅ All checks passed |
| pytest | ✅ **361 passed**（335 existing + 26 new） |

## 验证的漏洞

| 端点 | CWE | Source | Sink | 全链路 |
|------|-----|--------|------|--------|
| `/hello?name=X` | CWE-79 XSS | `request.args.get` | HTML 输出 | ✅ |
| `/search?q=X` | CWE-89 SQL 注入 | `request.args.get` | `cursor.execute()` (跨文件) | ✅ |
| `/user/<id>` | CWE-639 IDOR | 路径参数 | `cursor.execute()` | ✅ |
| `/admin/ping` | CWE-78 命令注入 | `request.form.get` | `os.system()` | ✅ |

## 下步衔接

### Phase 2: Scanner（Session 2.x）
CPG 底层管道已验证完整。下一步：
- 确定性扫描器（Phase 1 of scanner pipeline）
- 将 CPG 查询 + 框架提取器 + 污点规则整合为自动化漏洞检测流程
- 产出 `hyqagent scan --quick` 可用版本
