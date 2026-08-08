# Session 1.19 — propagate_taint 重构与精确参数匹配

## 目标
1. 移除 `DataFlowBuilder` 中约 150 行死代码（`propagate_taint` BFS 及其依赖方法）
2. 在 `CPGGraphBuilder` 中引入 `TaintRuleLoader`，构建时标记 NODE_SOURCE/NODE_SINK 等价标签
3. 增强 `CPGQuery`，通过 `taint_category` 标签做源/汇发现
4. 在 `_add_cross_function_edges` 中实现按位置实参→形参匹配

## 产出清单

### 修改文件
| 文件 | 变化 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/dataflow.py` | -274 行 | 移除 propagate_taint、_bfs_taint、_resolve_tainted_var、_find_pattern_matches、_is_descendant_of、_find_enclosing_func、set_taint_config |
| `src/hyqagent/cpg/graph.py` | +130 行 | 新增 _label_taint_nodes、call_args 提取、位置参数匹配、缓存后重标注 |
| `src/hyqagent/cpg/query.py` | +61 行 | 新增 _find_taint_nodes、find_path 支持 taint_loader、find_sources/find_sinks 识别 taint_category |
| `tests/test_cpg/test_dataflow.py` | -40 行 | 移除 TestTaintPropagation 死测试 (4 个) |
| `tests/test_cpg/test_e2e.py` | +77 行 | 新增 TestTaintGraphIntegration (8 个测试) |

## 实现过程

### 1. dataflow.py 死代码移除
**背景**：`propagate_taint()` 在 tree-sitter AST 上做 BFS 污点传播，而 `CPGGraphBuilder` 已经构建了 NetworkX 图，`CPGQuery.find_path()` 已经能在图上做 BFS。两者是重复实现，且 `propagate_taint` 的 AST 版本不遍历跨文件边。

**移除的方法**（全部调用方已在上一次 commit 确认为零）：
- `propagate_taint()` — 主入口 (108 行)
- `_bfs_taint()` — BFS 核心循环 (82 行)
- `_resolve_tainted_var()` — 解析污点变量 (21 行)
- `_find_pattern_matches()` — 子串搜索节点 (14 行)
- `_find_enclosing_func()` — 查找外围函数 (10 行，callgraph.py 有同名实现)
- `_is_descendant_of()` — 判断节点后代 (9 行)
- `set_taint_config()` — 设置污点配置 (从上一阶段已移除)
- `self._taint_config` — 配置存储

**保留的方法**：
- `build_def_use_chains()` — `CPGGraphBuilder.add_file()` 依赖
- `trace_cross_function()` — 对外接口
- `_node_in_range()`, `_loc_matches_def()`, `_fn_to_node()`, `_Assign`

同时修复了 `Parser` 类型未导入问题（添加到 `TYPE_CHECKING`）。

### 2. graph.py 污点标签 + 精确参数匹配

**2a. 污点标签（`_label_taint_nodes`）**
- `CPGGraphBuilder.__init__` 新增可选 `taint_loader: TaintRuleLoader | None` 参数
- 新增 `_label_taint_nodes(file_path, language)` 方法，在 `add_file()` 末尾调用
- 遍历所有 `NODE_ASSIGNMENT` 节点，用 `loader.match_source(language, source_text)` 和 `loader.match_sink(language, source_text)` 检查
- 匹配成功则设置 `taint_category` 属性（如 `"sql_injection"`, `"command_injection"`）
- 缓存加载后自动重新标注（因为缓存可能是在无 loader 时构建的）

**标注结果验证**（microblog 测试项目）：6 个节点被标注
```
auth_bypass: name = request.args.get("name", "World")
auth_bypass: keyword = request.args.get("q", "")
sql_injection: post = db.cursor.execute(select...)
auth_bypass: host = request.form.get("host") or request.args.get("host", ...)
auth_bypass: cmd = request.args.get("cmd", "ls")
command_injection: output = os.popen(cmd).read()
```

**2b. 调用实参提取**
- 在 `add_file()` 步骤 2（AST 遍历）中新增对 `call` 节点的处理
- 调用 `provider.extract_callee_info()` 获取被调用函数名
- 通过 `child_by_field_name("arguments")` 提取实参列表
- 查找外围函数，以 `(line, enclosing_function, callee_name)` 为键索引
- 存储在 `NODE_CALL_SITE` 节点的 `call_args` 属性

**2c. 位置参数匹配**
- 在 `_add_cross_function_edges` 中，检查 `NODE_CALL_SITE` 是否有 `call_args`
- 构建 `var_name → var_ref node_id` 查找表
- 将 callee 参数按 `param_index` 排序
- 对每个位置 i 的实参文本，查找对应 `var_name` 的 var_ref
- 创建 1-to-1 边：`var_ref[arg_i] → param[param_i]`
- 若 `call_args` 不存在或匹配失败，回退到全连接（安全过近似）

### 3. query.py 污点标签集成
- `find_path()` 新增可选 `taint_loader` 和 `language` 参数
- 新增 `_find_taint_nodes()` 方法：
  - 用 `taint_loader.match_source/sink()` 解析 pattern 对应的 taint_category
  - 优先搜索已标记 `taint_category` 属性的节点
  - 未找到标记节点时回退到子串匹配
- `find_sources()` / `find_sinks()` 更新为同时识别 `taint_category` 属性

### 4. 测试更新
新增 `TestTaintGraphIntegration` 类（8 个测试）：
- `test_graph_with_taint_loader` — 带 loader 的图构造器正常工作
- `test_taint_labeled_nodes_exist` — 至少 1 个节点被标注
- `test_find_sources_finds_labeled` — find_sources 识别标注节点
- `test_find_sinks_finds_labeled` — find_sinks 识别标注节点
- `test_find_path_with_taint_loader` — 带 loader 的路径查找不崩溃
- `test_find_path_taint_no_loader` — 无 loader 回退到子串匹配
- `test_call_args_stored_on_call_site` — call_args 正常存储
- `test_sanitizer_in_path` — 消毒器集成

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `test_taint_labeled_nodes_exist` 失败：0 个标注节点 | 缓存文件是在无 `taint_loader` 的上次运行中构建的 | 1) 在缓存加载后重新标注；2) 测试 fixture 使用 `use_cache=False` |
| `Fix B007` loop variable `nid` not used | `_label_taint_nodes` 循环中只用 `data` | 重命名为 `_nid` |
| `Fix F821` `Parser` undefined in dataflow.py | `Parser` 类型注解在 TYPE_CHECKING 外使用，之前被其他错误掩盖 | 添加到 `TYPE_CHECKING` 导入块 |

## 质量门禁
- **pytest**: 718 passed, 0 failed (从 710 增至 718，+8 新测试)
- **ruff**: 仅剩预存问题（N806, S301, D205, I001, E401, D401, F841），无新增错误
- **净代码行**: -64 行（-323 +259）

## 设计反思
- **做得好**：死代码移除干净利落（-274 行），标注机制与缓存兼容（加载后重标注），位置匹配保留安全回退
- **可改进**：`call_args` 提取依赖 tree-sitter `named_children`，对复杂实参（如 `f(x + 1, obj.method())`）可能失配。`taint_category` 标注未区分源/汇方向——同一节点被标注后，`find_sources` 和 `find_sinks` 都会匹配到。可在后续加入 `taint_role: "source" | "sink"` 区分
- **调用实参提取**仅在 `add_file()`（单文件）中执行，`add_directory()` 中跨文件 call site（line ~350）不自动提取。后续可补全

## 下步衔接
- **Task #10**: ureport2 回归测试（`tests/eval/`）—— Phase 1 最后一个待办项
- 完成 ureport2 测试后，Phase 2 可启动：scanner/ 流水线、多模型级联
