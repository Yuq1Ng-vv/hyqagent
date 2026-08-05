# Session 1.4 — 单文件调用图

## 目标
实现单文件调用图构建器 `cpg/callgraph.py`，基于 AST 遍历识别函数定义和调用表达式，构建 caller→callee 关系图，支持 Python/JavaScript/Java 三种语言。

**产出标准**: 支持三种语言的单文件内调用边解析（含简单调用、方法调用、链式调用、递归自环）、已解析/未解析分类、查询接口（get_callees/get_callers/has_edge）。

## 产出清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `src/hyqagent/cpg/callgraph.py` | SingleFileCallGraph 类（~380行），核心调用图引擎 |
| `tests/test_cpg/test_callgraph.py` | 69 个测试用例，覆盖 12 个测试类 |
| `tests/test_cpg/fixtures/callgraph.py` | Python 调用图测试用例（含类方法、嵌套函数、lambda、装饰器） |
| `tests/test_cpg/fixtures/callgraph.js` | JavaScript 调用图测试用例（含方法调用、async、箭头函数） |
| `tests/test_cpg/fixtures/callgraph.java` | Java 调用图测试用例（含多类方法调用、链式调用） |

### 修改文件
| 文件 | 变更 |
|------|------|
| `progress.md` | 标记 Session 1.4 完成，更新下次目标 |

## 实现过程

### 1. 数据结构设计

```python
@dataclass
class CallEdge:
    caller: str           # 调用方函数名
    callee: str           # 被调用方函数名（bare name: self.db.execute → execute）
    call_line: int        # 调用发生行号（1-indexed）
    full_expression: str  # 完整调用表达式文本
    is_resolved: bool     # True = callee 在本文件中有定义
    is_method_call: bool  # True = 对象方法调用（obj.method()）
    file_path: str        # 源文件路径

@dataclass 
class UnresolvedCall:
    """无法解析的调用 — Session 1.5 跨文件解析的候选"""
    callee, full_expression, call_line, caller, is_method_call, file_path
```

### 2. 核心构建流程

```
_build(tree, language, file_path)
  ├── Phase 1: 收集所有函数定义名
  │     └── 使用 Traverser 遍历 FUNC_DEF_TYPES 节点
  │     └── 提取函数名（Python 装饰器递归展开）
  │
  └── Phase 2: 遍历所有调用节点
        ├── 提取 callee 信息（bare name + full expression + is_method_call）
        ├── 查找最近的外层函数（ancestor_of_type）
        └── 名称匹配解析（bare name in function_names）
```

### 3. 三种语言的调用节点提取

| 语言 | 调用节点类型 | 函数表达式字段 | 简单调用 | 方法调用 |
|------|-------------|---------------|---------|---------|
| Python | `call` | `function` field | `identifier` → 直接取文本 | `attribute` → 取最后 named child |
| JavaScript | `call_expression` | `function` field | `identifier` → 直接取文本 | `member_expression` → 取 `property` field |
| Java | `method_invocation` | `name` field | `identifier` → 直接取文本 | 有 `object` field 即为方法调用 |

#### 实际案例（Python）:
```python
# request.args.get("user")
#   call
#     attribute              ← function field
#       attribute              request.args
#       identifier: get        ← bare name

# result = helper(a)
#   call
#     identifier: helper     ← function field, bare name
```

### 4. 外层函数查找策略

使用 `Traverser.ancestor_of_type()` 沿 AST 向上查找最近的函数定义节点。这使得嵌套函数内的调用归属于正确的外层函数。

```
def outer(x):            ← outer is found for helper(x) call
    def inner(y):
        val = helper(y) ← inner is found for helper(y) call
```

### 5. 关键技术决策

#### 决策 1: 名称匹配 vs 类型匹配
**选择**: 纯名称匹配（bare name in function_names）。  
**理由**: 单文件范围内，同名的两个方法（如不同类的 `__init__`）无法靠名称区分。精确的类型解析需要 Session 1.5 的跨文件分析和类型推断。  
**代价**: `A.foo()` 和 `B.foo()` 都解析到同一个 `foo`。

#### 决策 2: Lambda/箭头函数内的调用归属
**选择**: 归属到最近的有名外层函数。  
**理由**: Lambda/箭头函数匿名，没有可用名称。将其内的调用归属到外层有名函数是最合理的近似。  
**替代方案**: 生成合成名称如 `<lambda:line>`, 当前阶段不需要。

#### 决策 3: 装饰器函数不作为特殊处理
**选择**: `with_decorator` 作为普通函数收集。  
**理由**: 装饰器函数确实是一个函数定义，有其自身的调用边。名称匹配不会误解析（调用 `with_decorator` 才会匹配到它）。

### 6. 公开 API

```python
cg = SingleFileCallGraph(parser)
cg.build_from_file("app.py")           # 从文件构建
cg.build_from_tree(tree, "python")      # 从已解析的tree构建

# 属性
cg.edges           # list[CallEdge] — 全部调用边
cg.resolved_edges  # list[CallEdge] — 已解析（callee在文件中有定义）
cg.unresolved      # list[UnresolvedCall] — 未解析（外部/内置调用）
cg.function_names  # set[str] — 文件中定义的所有函数名

# 查询
cg.get_callees("foo")    # foo 调用了哪些函数（含未解析）
cg.get_callers("bar")    # 哪些函数调用了 bar（仅已解析）
cg.has_edge("a", "b")    # 是否存在已解析边 a→b

# 协议
len(cg)                  # 边总数
for edge in cg: ...      # 遍历所有边
repr(cg)                 # "SingleFileCallGraph(functions=16, edges=23, resolved=12)"
```

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| mypy 报 `unused-ignore`  | `# type: ignore[attr-defined]` 对 `_get_language` 不需要 — mypy 不强检查私有属性访问 | 移除 ignore 注释 |
| ruff D205 多行 docstring 格式 | 第一行 summary 和第二行 description 之间缺少空行 | 重写 docstring 为标准格式（summary + blank line + description） |
| Java fixture 被 ruff 检查  | `.java` 文件被 ruff 当作 Python 解析 | 确认 ruff 已通过 `extend-exclude` 排除 test fixtures 目录（配置在 pyproject.toml 中检查） |
| `build_twice_overwrites` 测试不稳定 | 第二次调用 build_from_file 完全覆盖状态（预期行为） | 测试验证的是覆盖后状态≠覆盖前状态 |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check (新文件) | ✅ All checks passed |
| ruff format (新文件) | ✅ Already formatted |
| mypy --strict src/ | ✅ Success: no issues found in 23 source files |
| pytest (全部) | ✅ 172 passed in 0.26s (103 existing + 69 new) |

## 设计反思

### 做得好的
1. **数据类设计简洁** — `CallEdge` 仅 6 个字段，`UnresolvedCall` 复用相同结构
2. **三种语言的提取逻辑统一** — 使用 `_extract_callee_info` 单入口 + 按语言分发，新增语言只需添加一个 `_extract_xxx_callee` 方法
3. **与 Traverser 无缝集成** — 利用 `ancestor_of_type` 天然解决了嵌套函数的调用归属问题
4. **无外部依赖** — `SingleFileCallGraph` 仅依赖 `Parser` 和 `Traverser`，完全确定性

### 可改进的
1. **`_get_language` 访问** — 目前通过 `parser._get_language(tree)` 访问私有方法。应考虑在 Parser 上暴露一个公开的 `get_language(tree)` 方法或在 parse 返回值中包含语言信息。这将在后续重构中处理。
2. **同名方法冲突** — 多类的同名方法会合并为一个调用方。在 Session 1.5 跨文件调用图中，可以引入 `ClassName.method_name` 的带前缀 ID 来区分。
3. **Java 静态导入** — `import static` 在当前实现中未处理，可能导致未解析调用。Session 1.5 将引入 import 解析来改善。

## 下步衔接

### Session 1.5: 跨文件调用图
- **核心任务**: 导入路径解析 → 跨文件模块定位 → 跨文件调用边解析
- **关键风险**: 反射/DI/动态 import（按 DESIGN-IMPLEMENTATION.md 第十二章风险1处理：先支持无反射的 Python 项目）
- **依赖**: 本 Session 的 `SingleFileCallGraph` + `Parser.extract_imports()`
- **输出**: `CallGraphBuilder` 类，支持 `add_file()` + `resolve_imports()` + 跨文件 `build_calls()`
