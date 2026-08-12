# Session 1.44 — CPG 跨文件污点追踪修复与真实 CVE 验证

## 目标

修复 CPG 污点追踪管道中三个阻断 BFS 的 bug，使跨文件 cross-function taint tracking 能在真实 CVE 目标上打通，并客观评估结果质量。

## 产出清单

| 文件 | 变更 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/graph.py` | +117/-? | 三项核心修复 + CFG 兼容修复 |
| `src/hyqagent/scanner/orchestrator.py` | 修改 | `_phase_cpg_build` 和 `_ensure_scanner_modules` 改用 `add_directory()` |
| `src/hyqagent/api/cli.py` | 修改 | `_run_scan` 改用 `add_directory()` |
| `src/hyqagent/cpg/callgraph.py` | 已有 | `call_node_type` 作为 set 传递 (前次 session) |
| `src/hyqagent/cpg/languages/java.py` | 已有 | `call_node_type` 返回 `{"method_invocation","object_creation_expression"}` |
| `src/hyqagent/cpg/languages/python.py` | 已有 | `call_node_type` 返回 set |
| `src/hyqagent/cpg/languages/javascript.py` | 已有 | `call_node_type` 返回 set |
| `src/hyqagent/cpg/languages/base.py` | 已有 | `call_node_type` 返回类型改为 set |
| `tests/test_cpg/test_language_provider.py` | 已有 | `call_node_type` 测试适配 set |

## 实现过程

### 修复 1：NODE_PARAMETER → NODE_ASSIGNMENT 桥接 (graph.py step 4.55)

**问题**：`build_def_use_chains` (Phase 1.5) 为函数参数创建了 `NODE_ASSIGNMENT → NODE_VARIABLE_REF` 链，但 `NODE_PARAMETER` (step 1.5 创建) 没有指向这些节点的出边。跨函数边 `caller var_ref → callee NODE_PARAMETER` 到达后就断头了——BFS 无法继续。

**修复**：遍历所有 NODE_PARAMETER 节点，按 `(file_path, enclosing_function, var_name)` 匹配对应的 NODE_ASSIGNMENT，添加 DATA_FLOW 边。选择最小行号的 NODE_ASSIGNMENT（即函数体第一个赋值，对应参数隐式赋值）。

```python
for nid, ndata in self.graph.nodes(data=True):
    if ndata.get("node_type") != NODE_PARAMETER:
        continue
    # ... find best_aid by matching var_name + enclosing_function ...
    self.graph.add_edge(nid, best_aid, edge_type=EDGE_DATA_FLOW)
```

### 修复 2：重载方法 dict 碰撞 (graph.py BUG 30)

**问题**：`func_nodes` 和 `fn_tree_nodes` 用裸函数名做 key。Java 中 `AbstractResourceHandler.getResource` 有具体实现和抽象声明两个重载——dict 后写入者覆盖前写入者。被覆盖的方法的 def-use chain 永远不会被构建。

**修复**：Key 改为 `_fkey(name, start_line)` = `"name$startLine"`。遍历改用 `funcs` 列表保证所有重载都被处理。新增 `_func_start_lines` 字典做裸名→行号的 last-wins 索引（仅用于 CALLS 边的 caller/callee 解析，last-wins 是可接受的）。新增静态方法 `_resolve_bare_name()`。

### 修复 3：Scanner 使用 add_directory() 启用跨文件调用解析

**问题**：`_phase_cpg_build`、`_ensure_scanner_modules`、`_run_scan` 三个位置都使用 `for fp: builder.add_file(fp)` 逐个添加文件。`add_file()` 只做单文件内调用解析——CALLS 边无法跨文件。

**修复**：用 `os.path.commonpath(file_paths)` 找到项目公共根目录，改用 `builder.add_directory(common_root, use_cache=False)`。`add_directory()` 内部使用 `CallGraphBuilder` 做 import 解析和跨文件调用图构建。

### 修复 4：CFG 构建兼容 (graph.py `_build_cfg`)

**问题**：`_build_cfg` 遍历 `fn_tree_nodes.items()` 取到的 key 现在是 `_fkey`（`"name$line"`），但传给 `_find_func_node_id(path, fn_name)` 时 `_find_func_node_id` 用的是裸名匹配 `data.get("name") == fn_name`。

**修复**：用 `fn_key.rsplit("$", 1)[0]` 提取裸名。

```python
for fn_key, tree_node in fn_tree_nodes.items():
    fn_name = fn_key.rsplit("$", 1)[0]
    fid = self._find_func_node_id(path, fn_name)
```

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| spark CVE 扫描 0 条 TAINT-001 | NODE_PARAMETER 出边为 0，BFS 断头 | step 4.55 桥接 NODE_PARAMETER → NODE_ASSIGNMENT |
| AbstractResourceHandler.getResource def-use chain 缺失 | 重载方法 dict 碰撞，具体实现被抽象声明覆盖 | func_nodes key 改为 `name$start_line` |
| 跨文件 CALLS 边缺失（只有 4 条文件内） | scanner 三个入口都用 add_file()，不做跨文件调用解析 | 改用 add_directory() |
| `_build_cfg` 找不到 function 节点 | fn_tree_nodes key 变为 `name$line`，但 `_find_func_node_id` 匹配裸名 | `rsplit("$", 1)[0]` 提取裸名 |
| `os.path.commonpath()` 在扫描时报错 | `pathlib.Path` 没有 commonpath 方法 | 改用 `os.path.commonpath()` |
| `_ensure_scanner_modules` 的 common_root 计算繁琐 | 手动逐对计算 | 简化为 `os.path.commonpath(file_paths)` |

## 质量门禁

- **pytest**: 1493 passed, 2 skipped, 0 failures
- **ruff**: 无新增问题（22 项全部为预存）
- **mypy**: 无新增问题（全部为预存）
- **commit**: `5c874d2`

## 结果与客观评估

### 数据

| CVE 目标 | 类型 | 修复前 TAINT-001 | 修复后 TAINT-001 | 真实相关 | 评价 |
|----------|------|:---:|:---:|:---:|------|
| spark-CVE-2018-9159 | 路径穿越 | 4 | 80 | ~4 | ✅ **命中**：`request.getServletPath()` → `getResource(pathInContext)` |
| spring-cloud-gateway-CVE-2022-22947 | SPEL 注入 | 47 | 159 | ~4 | ⚠️ 抓到 `@PathVariable` → `parseExpression()` 但噪声极多 |
| spring-cloud-config-CVE-2020-5405 | 路径穿越 | 0 | 101 | ~14 | ✅ **命中**：`@PathVariable String name` → `new File(...)` 直接 CVE |
| xxl-job-CVE-2020-29204 | 硬编码 JWT | 2 | 110 | 0 | ❌ CVE 不是污点问题，全噪声 |
| commons-text-CVE-2022-42889 | 插值注入 | 0 | 0 | 0 | ❌ CVE 不是污点问题，0 是正确结果 |
| **合计** | | **53** | **450** | **~22** | **2/5 真实命中，~5% 有效率** |

### 坦率评价

**500 行的代码修复确实打通了 CPG 跨文件污点追踪管道。** 但 450 条 TAINT-001 里真正和 CVE 相关的不到 20 条。数量增长不是成就，精度才是瓶颈。

## 三个根本问题（下次解决）

### 问题 1：NODE_PARAMETER 分类过剩

同一个 `@RequestBody String data` 参数被同时标记为 `format_string + injection_general + sql_injection`（最多 5 个类别）。根因在 `_label_taint_nodes` 的 NODE_PARAMETER 分支：用 enclosing function 的整段 source（虽然是签名截断版）匹配 source 规则，`@RequestParam` 等注解一出现就把所有参数标成所有可能的类型。

**修复方向**：对 NODE_PARAMETER，只检查注解本身（`@RequestParam`、`@PathVariable` 等），不检查函数签名。一个参数被标记的类型不应来自函数体内代码。

### 问题 2：Sink 匹配太泛

`toString()`、`getString("常量")`、`getResponseBodyAsString()` 全被标为 sink。这些是通用工具方法，不构成实际注入点。大量 false positive 来自这类过度匹配。

**修复方向**：sink 规则需要白名单排除模式（`I18nUtil.getString`、`toString()` 等），或者在 BFS 到达 sink 后做代码片段的二次确认。

### 问题 3：非污点 CVE 类型覆盖缺失

5 个 CVE 中 2 个（xxl-job 硬编码密钥、commons-text StringSubstitutor 插值）不是 data-flow source→sink 模式。这些需要：
- 硬编码密钥：配置常量扫描（已有 SECRET 系列规则但未覆盖 JWT secret）
- StringSubstitutor：特定的 API 使用模式检测

## 下步衔接

**Session 1.45 目标**：降低 FAINT-001 噪声率，提升精度
1. **修复 NODE_PARAMETER 过度标记** — source 检测只看注解，不看函数体
2. **Sink 白名单/排除模式** — 过滤 `toString()`、`I18nUtil.getString` 等非注入点
3. **添加 commons-text StringSubstitutor 检测规则**
4. **添加 xxl-job JWT 硬编码密钥检测规则**
5. **目标**：5 个 CVE 中 ≥3 个真实命中，有效率从 ~5% 提升到 ≥20%
