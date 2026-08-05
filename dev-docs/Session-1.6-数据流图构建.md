# Session 1.6 — 数据流图构建

## 目标

1. **LanguageProvider 扩展**：新增 3 个抽象成员（`assignment_types`、`extract_assignment_target`、`is_variable_identifier`），为数据流分析提供语言感知的 AST 查询能力
2. **DataFlowBuilder 实现**：`build_def_use_chains()`（函数内 def-use）、`trace_cross_function()`（跨函数追踪）、`propagate_taint()`（基础污点传播）

## 产出清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `src/hyqagent/cpg/dataflow.py` | DataFlowBuilder 类（~530行），实现三种数据流分析 |
| `tests/test_cpg/test_dataflow.py` | 29 个测试用例，覆盖 def-use/Python/JS/边界/污点配置 |
| `tests/test_cpg/fixtures/dataflow.py` | Python 测试样本（含赋值/跨函数/条件赋值/方法） |
| `tests/test_cpg/fixtures/dataflow.js` | JavaScript 测试样本 |

### 修改文件
| 文件 | 变更 |
|------|------|
| `src/hyqagent/cpg/languages/base.py` | 新增 3 个抽象成员 + `_validate()` 扩展 |
| `src/hyqagent/cpg/languages/python.py` | 实现 `assignment_types`/`extract_assignment_target`/`is_variable_identifier` |
| `src/hyqagent/cpg/languages/javascript.py` | 同上（JS 适配） |
| `src/hyqagent/cpg/languages/java.py` | 同上（Java 适配） |
| `src/hyqagent/cpg/types.py` | 新增 DefUsePair/DataFlowStep/TaintPath/TaintConfig 4 个 dataclass |

## 实现过程

### 1. LanguageProvider 扩展设计

新增 3 个抽象成员，每种语言独立实现：

- **`assignment_types: set[str]`** — 赋值节点类型集合
- **`extract_assignment_target(node) -> str | None`** — 从赋值节点提取被赋值变量名
- **`is_variable_identifier(node) -> bool`** — 判断标识符节点是否为变量引用（排除函数名/属性名/定义名）

Python 的 `is_variable_identifier` 需排除三种情况：
- `call` 节点的 `function` 字段（函数名如 `print(x)` 中的 `print`）
- `attribute` 节点的最后一个 named child（属性名如 `obj.attr` 中的 `attr`）
- 函数/类定义的 `name` 字段

### 2. Def-Use Chain 分析

核心算法（`build_def_use_chains`）：
1. Phase 1：遍历函数体，收集所有赋值节点及其目标变量名
2. Phase 2：对每个被赋值变量，遍历函数体找所有同名标识符引用，过滤定义点自身
3. 结果按定义位置排序

**关键决策**：使用 AST 遍历（Traverser）而非图查询——NetworkX CPG 图要到 Session 1.7 才建。

### 3. 跨函数追踪

`trace_cross_function()` 依赖 CallGraphBuilder：
1. 通过 `find_definition()` 定位 callee 所在文件
2. 解析 callee 文件，匹配函数名找到定义
3. 构建参数 → callee 体内 def-use 的映射

### 4. 污点传播

`propagate_taint()` 使用 BFS：
1. 遍历所有文件找 source 模式匹配
2. 对每个 source 向上查找包围函数和赋值目标
3. BFS 沿 def-use chain 和调用图传播，max_depth 控制深度
4. 到达 sink 时记录完整 TaintPath

Taint 配置通过 `set_taint_config(sources, sinks, sanitizers)` 设置，初版用 substring 匹配（YAML 配置文件留到 Session 1.7）。

### 5. 关键技术决策

| 决策 | 选择 | 理由 |
|------|------|------|
| Def-use 实现方式 | AST 遍历 | CPG 图未建，Traverser 足够 |
| Taint 匹配 | substring 匹配 | 初版够用，YAML 留到 Session 1.7 |
| 跨函数追踪 | 依赖 CallGraphBuilder | 复用已有组件 |
| Taint BFS | 队列 + visited 集合 | 标准 BFS，max_depth 防止无限循环 |

## 遇到的问题与修复

| 现象 | 原因 | 修复 |
|------|------|------|
| `Traverser` 无 `traverse_pre_order` 方法 | 实际 API 是 `traverse()` | 全部替换为 `traverse()` |
| `Node(0, 0)` 构造错误 | tree-sitter `Node` 不能从整数构造 | 改用直接字符串拼接 location |
| ruff SIM102 嵌套 if | 多个 adapter 的 `is_variable_identifier` 有嵌套 if-return | 合并为 `and` 条件 |
| ruff SIM103 | 末行 `if cond: return False; return True` | 改为 `return not (cond)` |
| ruff F841 未使用变量 | 测试中的 `funcs`、`provider` 变量 | 删除或改为 `_` |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check | ✅ All checks passed |
| ruff format | ✅ All files formatted |
| mypy --strict | ✅ Success: no issues in 31 source files |
| pytest | ✅ **269 passed** (240 existing + 29 new) |

## 设计反思

### 做得好的
1. **LanguageProvider 扩展自然** — 3 个新方法很好地融入了现有策略模式，每种语言的实现隔离清晰
2. **Def-use 核心算法简洁** — 两阶段遍历 + `_node_in_range` 过滤在 AST 层面足够高效
3. **测试覆盖充分** — 29 个用例覆盖 Python/JS 两种语言、正常路径/边界/深度嵌套/空函数/Unicode

### 可改进的
1. **跨函数 `trace_cross_function` 较薄** — 目前只实现了基本框架，实际的调用点→参数位置匹配未完成。需要用 CallGraphBuilder 找到调用 AST 节点后再匹配实参→形参
2. **Taint BFS 效率** — 每个 source 都独立 BFS，多 source 时重复遍历。后续可改为多源 BFS
3. **`_fn_to_node` 在 Traverser 中重复遍历** — 将 FunctionNode dataclass 转回 tree-sitter Node 需要全树搜索。Parser 可直接返回 Node+dataclass 对
4. **Taint 配置仍是 Python 字典** — YAML 文件版留到 Session 1.7

## 下步衔接

### Session 1.7: CPG 查询接口
- 实现 `cpg/query.py` — CPGQuery 类
- 将 DataFlowBuilder 的 def-use chain 和污点路径索引到查询接口
- 支持 `find_path`/`find_sources`/`find_sinks`/`slice_path` 等查询
- Taint 配置迁移到 `taint_rules.yaml`
