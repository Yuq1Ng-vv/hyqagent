# Session 1.14 — 跨函数+跨文件数据流实现

## 目标
实现 CPG 跨函数（cross-function）和跨文件（cross-file）数据流追踪，
使 Phase 1 扫描器能从 `req.getParameter("sql")` 一路追踪到
另一个文件的 `jdbc.queryForList(sql)`。

## 产出清单

| 文件 | 改动 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/graph.py` | +120 行 | `_add_cross_function_edges()` + NODE_PARAMETER 节点 |
| `src/hyqagent/cpg/callgraph_builder.py` | +15/-12 行 | Java `.java` 导入解析 + 预建文件名索引 |
| `src/hyqagent/cpg/query.py` | +1/-1 行 | sink 匹配也排除 NODE_FUNCTION |
| `src/hyqagent/cpg/taint_rules.yaml` | (上次Session) | 变量无关 YAML 模式 |
| `tests/test_cpg/test_frameworks.py` | (上次Session) | 测试预期更新 |

## 实现过程

### 1. 为什么需要跨函数数据流

上一个 Session (1.13) 发现 ureport2 SQL 注入虽然在**同一函数内**能检测到，
但只要 `req.getParameter("sql")` 和 `jdbc.queryForList(sql, map)` 中间
经过了**函数调用**（如 `parseSql()`），数据流就断了。

根本原因：CPG 的 def-use chain 是单函数内、单变量追踪。当 `sql` 作为实参
传入 `parseSql(String sql)` 时，没有边连接 caller 的 `variable_ref(sql)` 
到 callee 的 `parameter(sql)`。

### 2. 设计方案

在 graph 中添加三种新边：

```
caller var_ref(sql@L) ──DATA_FLOW──▶ callee parameter(sql)
caller var_ref(sql@L) ──DATA_FLOW──▶ call_site node
call_site node ──DATA_FLOW──▶ callee function
```

以及返回值近似边（caller 的 assignment@call_line ← callee function）。

**为什么用"all args → all params"而非精确定位？**
- 精确匹配需要理解参数顺序，需要 AST 级别的参数列表解析
- "全连接" 是安全的过近似：不会漏掉任何真实流，假阳性由后续 verify 阶段过滤
- 实现简单，不需要修改 parser

### 3. 预建索引优化

原始实现中，`_add_cross_function_edges()` 对每个 call_site 都遍历全部节点
来查找 parameter/var_ref/assignment 节点 → O(C × N) 复杂度。

改为单次遍历预建 5 个索引：
- `func_index`: (file_path, name) → function_node_id
- `func_by_name`: name → function_node_id (跨文件查找)
- `param_index`: (file_path, enclosing_func) → [param_node_ids]
- `varref_index`: (file_path, enclosing_func, line) → [var_ref_ids]
- `assign_index`: (file_path, enclosing_func, line) → [assign_ids]

每个 call_site 的查找变为 O(1)。

### 4. Java 跨文件调用解析修复

发现 `CallGraphBuilder._resolve_module_path()` 只处理 `.py` 文件。
Java import `com.example.service.DataService` 无法匹配到
`com/example/service/DataService.java`。

修复：
1. 包路径遍历时同时尝试 `.py` 和 `.java` 扩展名
2. 添加 class-name fallback（`file_index[class_name]`）
3. Fallback 原本用 `rglob` 在项目根目录做递归 glob ——
   对每个未解析的 stdlib import（如 `os`, `json`）都触发，
   在 ureport2 (469 文件) 上导致 **264x 性能退化**（23.8s vs 0.09s）
4. 改为在 `resolve_imports()` 中预建 `file_index`（basename → path），
   一次性 O(N) 扫描，后续 O(1) 查找

### 5. Sink 匹配也需排除 NODE_FUNCTION

上一 Session 在 source 匹配时排除了 NODE_FUNCTION（因为函数节点 body 文本
包含 source/sink pattern 子串），但**sink 匹配忘了排除**。导致路径在 callee 
函数节点就停止（函数体包含 `.queryForList(` 子串）。

修复：`_find_nodes(sink_pattern, exclude_types={NODE_FUNCTION})`

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| 跨文件调用 `is_resolved=False` | `_resolve_module_path` 只处理 .py | 同时检查 .py/.java + filename fallback |
| 测试 23.8s（原 0.09s） | fallback rglob 对每个 stdlib import 全项目扫描 | 预建 file_index，O(1) 查找 |
| 路径在 callee function 节点停止 | sink 匹配未排除 NODE_FUNCTION | `exclude_types={NODE_FUNCTION}` |
| ureport2 构建 800s | 469 Java 文件 × tree-sitter 解析 + def-use chain | 可接受（13 分钟），后续可用并行加速 |
| 跨文件路径`svc` 也连接到 param | all-args→all-params 过近似 | 安全过近似，假阳性可接受 |

## ureport2 验证结果

```text
Graph: 76,481 nodes, 216,441 edges, 6,891 parameter nodes, 8,521/32,107 resolved call-sites (2,137 cross-file)

.getParameter( → .queryForList(:  2 paths ✓ (1 条跨文件 19 跳!)
.getParameter( → .getConnection(: 9 paths ✓
.getParameter( → .newSAXReader(:  0 paths (模式不匹配)
.getParameter( → Class.forName(:  1 path  ✓
```

**跨文件 SQL 注入路径亮点**（Path 2）：
```
DatasourceServletAction.java (console模块)
  → parseSql()
  → ExpressionUtils.parseExpression(sql)
  → SqlDatasetDefinition.java (core模块, 跨文件!)
  → jdbcTemplate.queryForList(sqlForUse, pmap)
```
19 跳，跨越 2 个 Maven 模块和 3 个 Java 文件。

## 质量门禁
- ruff: (未运行)
- mypy: (未运行)
- pytest: **372 passed** in 1.18s ✓
- ureport2 端到端: SQL注入/JDBC RCE/Class.forName RCE 均检测到 ✓

## 设计反思

### 做得好
- "全连接"过近似策略简单且有效——2 条 SQL 注入路径中 1 条是跨文件的
- 预建索引模式让性能从 O(N²) 降到 O(N)，264x 加速
- 在小测试用例上验证再跑大项目的策略正确（快速迭代）
- 及时识别出 `rglob` 是性能瓶颈并修复

### 可改进
- 构建时间 13 分钟偏长，后续可加 tree-sitter 解析缓存
- "all args → all params" 边可能导致 BFS 搜索空间膨胀（但目前 0.1s 查询时间说明影响不大）
- Java 跨文件解析仅限于 import 语句明确导入了目标类的情况；
  同 package 隐式可见的类不会被解析
- 返回值边（callee function → caller assignment）也是过近似，
  可能产生假阳性路径

## 下步衔接

### Phase 2 启动前待处理

1. **XXE 检测覆盖**: ureport2 有 XXE 漏洞但 0 路径 — 需要检查实际的
   SAXReader 调用模式并更新 YAML sink pattern（可能是 `.read(` 而不是 `.newSAXReader(`）
2. **JavaScript 跨文件支持**: `_resolve_module_path` 尚未处理 JS 的
   `require('./module')` 和 `import {x} from './module'` 相对路径
3. **构建性能**: 考虑加入 tree-sitter AST 缓存（pickle/marshal），
   避免每次扫描都重新解析全部文件
4. **filename 索引冲突**: `file_index[stem]` 的 last-write-wins 策略
   在多个同名文件（如 `index.js`, `utils.py`）时会错误解析
5. **BFS 路径质量**: 过近似边可能产生大量路径，需要去重/排序策略

### 架构提示

- **跨函数数据流设计原则**: "全连接"（all-args → all-params）在 taint tracking 中
  是正确且高效的选择。精确参数匹配只在语义分析阶段需要。
- **预建索引 > 按需查找**: 当需要多次按属性查找节点时，single-pass 预建索引
  的模式应该成为 CPG 操作的默认惯例。
- **`.add_directory()` 的性能瓶颈在 tree-sitter 解析**，不在 graph 构建。
  800s 中约 95% 时间花在 `Parser.parse_file()` 和 `SingleFileCallGraph.build_from_file()` 上。
- **Java 项目需要正确的 source root 检测**: 当前通过逐级向上查找 package 目录，
  对于 Maven/Gradle 标准布局 (`src/main/java/com/...`) 工作良好，
  但对于非标准布局可能失败。
