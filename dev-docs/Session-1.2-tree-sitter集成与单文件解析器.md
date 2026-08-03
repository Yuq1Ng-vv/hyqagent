# Session 1.2 — tree-sitter 集成与单文件解析器

> **日期**: 2026-08-03  
> **Phase**: Phase 1 — CPG Foundation  
> **产出**: `cpg/parser.py`（~670 行）、44 个测试、3 个 fixture 文件

---

## 一、目标

安装 tree-sitter 的 Python/JavaScript/Java 三种语法包，实现单文件解析器 `cpg/parser.py`。产出标准：能解析单个文件，提取函数名、类名、导入语句。

---

## 二、依赖安装

### 2.1 环境准备

系统中没有 `uv` 包管理器，通过官方脚本安装：

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# → uv 0.12.1 安装到 ~/.local/bin
```

### 2.2 版本选择过程

初始按设计文档约束安装 `tree-sitter>=0.23,<0.25`，得到 0.24.0：

```bash
uv add "tree-sitter>=0.23,<0.25"  # → tree-sitter==0.24.0
uv add tree-sitter-python tree-sitter-javascript tree-sitter-java
# → tree-sitter-python==0.25.0, tree-sitter-javascript==0.25.0, tree-sitter-java==0.23.5
```

**版本冲突发现**：tree-sitter 0.24.0 支持语言版本 13-14，但 `tree-sitter-python` 0.25.0 使用语言版本 15，导致 `ValueError: Incompatible Language version 15. Must be between 13 and 14`。

**解决方案**：升级 tree-sitter 核心到 0.26.0：

```bash
uv add "tree-sitter>=0.25,<0.27"  # → tree-sitter==0.26.0
```

### 2.3 最终依赖版本

| 包名 | 版本 |
|------|------|
| `tree-sitter` | 0.26.0 |
| `tree-sitter-python` | 0.25.0 |
| `tree-sitter-javascript` | 0.25.0 |
| `tree-sitter-java` | 0.23.5 |

---

## 三、实现过程

### 3.1 探索 tree-sitter AST 结构

在正式编码前，先对三种语言的 AST 结构做了详细探索。用 `walk()` 递归打印 AST 节点树，理解每种语言的节点类型层次。

**关键发现**：

| 语言 | 函数节点类型 | 类节点类型 | 导入节点类型 |
|------|-------------|-----------|-------------|
| Python | `function_definition`（可能包裹在 `decorated_definition` 中） | `class_definition` | `import_statement`, `import_from_statement` |
| JavaScript | `function_declaration`, `method_definition`, `arrow_function` | `class_declaration` | `import_statement` |
| Java | `method_declaration`, `constructor_declaration` | `class_declaration` | `import_declaration` |

**Python 装饰器注意**：当函数/类有装饰器时，AST 结构是 `decorated_definition → [decorator, function_definition]`，不是直接在 `function_definition` 上。

**JS 箭头函数注意**：`const handler = async (req, res) => {...}` 中，`arrow_function` 节点的 `name` 字段为空——名字在父级的 `variable_declarator → identifier` 中。需要通过 Query 的 `@func.name` 捕获来获取。

**JS 类继承注意**：`class Foo extends React.Component` 中，extends 子句在 `class_heritage` 下直接是 `identifier` 或 `member_expression`，没有独立的 `extends_clause` 节点。

### 3.2 API 设计

```python
class Parser:
    # 生命周期
    def __init__(self, languages: list[str] | None = None) -> None
    def parse_file(self, file_path: str | Path) -> Tree
    def parse_code(self, code: str, language: str) -> Tree

    # 提取器
    def extract_functions(self, tree: Tree, language: str | None = None) -> list[FunctionNode]
    def extract_classes(self, tree: Tree, language: str | None = None) -> list[ClassNode]
    def extract_imports(self, tree: Tree, language: str | None = None) -> list[ImportNode]
```

**返回值类型**：

```python
@dataclass
class FunctionNode:
    name: str
    start_line: int
    end_line: int
    source: str
    params: list[str]
    is_method: bool          # 是否在 class 内部
    class_name: str | None   # 所属类名（方法才有）
    decorators: list[str]    # @装饰器 列表

@dataclass
class ClassNode:
    name: str
    start_line: int
    end_line: int
    source: str
    base_classes: list[str]  # 父类/接口名称

@dataclass
class ImportNode:
    module: str              # 模块路径
    names: list[str]         # 导入的名称列表
    is_relative: bool        # 是否相对导入
    source: str              # 原始导入语句文本
```

### 3.3 核心技术点

**tree-sitter Query 用于结构化提取**：

每种语言每种提取目标都定义了专用的 tree-sitter Query。例如 Python 函数提取：

```scheme
(function_definition
  name: (identifier) @func.name
  parameters: (parameters) @func.params
) @function
(decorated_definition
  (function_definition
    name: (identifier) @func.name
    parameters: (parameters) @func.params
  ) @function
)
```

捕获标记 `@function`、`@func.name`、`@func.params` 在 `QueryCursor.matches()` 的返回 dict 中分别对应不同的节点列表。

**tree-sitter 0.26 API 迁移**：

0.26 版本废弃了旧的 `Query.captures()` 方法，改用 `QueryCursor`：
- `cursor.matches(root_node)` → `(pattern_index: int, {capture_name: [nodes]})` 迭代器
- `cursor.captures(root_node)` → `(capture_name: str, node: Node)` 迭代器

**语言与树的关联**：

`Tree` 对象不携带语言信息。Parser 内部用 `dict[int, str]` 维护 `id(tree) → language` 映射，`extract_*` 方法自动查找。也支持传入 `language=` 显式指定。

**去重机制**：

Python 的 Query 中有两个 pattern（裸函数和装饰函数），同一个 `function_definition` 可能被两次匹配。用 `set[(name, start_line)]` 去重。

### 3.4 遇到的坑与修复

| # | 问题 | 原因 | 修复 |
|---|------|------|------|
| 1 | `tree-sitter-python` 无法使用 | 语言版本 15 与 tree-sitter 0.24 不兼容 | 升级到 tree-sitter 0.26 |
| 2 | `Query.captures()` 不存在 | tree-sitter 0.26 API 变更 | 迁移到 `QueryCursor.matches()` |
| 3 | 箭头函数 `handler` 无法提取 | `arrow_function` 无 `name` 字段 | 从 `@func.name` 捕获获取名称 |
| 4 | JS 类 `extends React.Component` 为空 | 原代码查找不存在的 `extends_clause` 子节点 | 直接从 `class_heritage` 子节点读取 |
| 5 | `list_users(limit=100)` 参数为空 | `typed_default_parameter` 未被识别 | 添加此类型到参数提取逻辑 |
| 6 | 装饰器列表重复 | `_extract_decorators` 中有两份相同的 for 循环 | 删除重复代码 |
| 7 | `from flask import Flask` 的 module 显示为 `request` | `import_from_statement` 解析逻辑混乱 | 用 `was_import_kw` 标记区分模块名和导入名 |
| 8 | `lru_cache` 在方法上导致内存泄漏 | B019 lint 规则 | 改用手动 dict 缓存 `_query_cache` |

### 3.5 测试设计

**fixture 文件**（`tests/test_cpg/fixtures/`）：

- `sample.py`：含 5 个函数（含装饰器函数）、2 个类（含继承）、5 种 import 类型
- `sample.js`：含函数声明、箭头函数（const/var）、类方法、ES6 import、extends 成员表达式
- `sample.java`：含构造器、方法（含 throws 子句）、extends + implements、import 声明

**44 个测试用例覆盖**：

| 测试类 | 用例数 | 覆盖内容 |
|--------|--------|---------|
| `TestParserConstruction` | 3 | 默认语言、子集初始化、不支持语言报错 |
| `TestParseFile` | 5 | 三种语言解析、文件不存在、未知扩展名 |
| `TestParseCode` | 4 | 三种语言解析、未初始化语言报错 |
| `TestExtractPythonFunctions` | 6 | 函数计数、参数提取、方法归属、装饰器、行号 |
| `TestExtractJSFunctions` | 3 | 函数声明、类方法、箭头函数 |
| `TestExtractJavaMethods` | 3 | 方法声明、参数、全部方法属于类 |
| `TestExtractPythonClasses` | 3 | 类计数、继承关系、行号 |
| `TestExtractJSClasses` | 1 | 类声明 + extends |
| `TestExtractJavaClasses` | 1 | 类声明 + extends + implements |
| `TestExtractPythonImports` | 5 | 简单 import、from import、相对导入、通配符、别名 |
| `TestExtractJSImports` | 2 | 命名导入、默认导入 |
| `TestExtractJavaImports` | 2 | 全限定名导入、名称提取 |
| `TestEdgeCases` | 6 | 空文件、语法错误、嵌套函数、语言缓存、显式语言、节点类型 |

---

## 四、质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check | ✅ All checks passed |
| ruff format | ✅ 2 files already formatted |
| mypy --strict | ✅ Success: no issues found in 1 source file |
| pytest | ✅ 44 passed in 0.07s |

### 4.1 Ruff 配置调整

在 `pyproject.toml` 中新增对测试文件的宽松规则：

```toml
[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["D101", "D102", "D103", "D104", "S101"]
```

pytest 测试中不需要类/函数 docstring，`assert` 是 pytest 的标准断言方式。

### 4.2 mypy 配置

原有对测试文件的配置保持：

```toml
[[tool.mypy.overrides]]
module = ["tests.*"]
disallow_untyped_defs = false
```

---

## 五、文件变更清单

```
新增:
  src/hyqagent/cpg/parser.py              ← 多语言解析器核心（~670 行）
  tests/test_cpg/test_parser.py           ← 44 个测试用例
  tests/test_cpg/fixtures/sample.py       ← Python 测试用代码
  tests/test_cpg/fixtures/sample.js       ← JavaScript 测试用代码
  tests/test_cpg/fixtures/sample.java     ← Java 测试用代码

修改:
  pyproject.toml                          ← tree-sitter 版本约束调整 + ruff 规则
  progress.md                             ← Session 1.2 标记完成
```

---

## 六、设计反思

**做得好的**：
- 先探索 AST 再写代码，避免了大量试错
- Query-based 提取比手写递归遍历更声明式、更易维护
- 用 `(name, start_line)` 去重而非修改 Query（Query 可读性更好）

**可改进的**：
- `_build_python_import` 方法仍然较复杂（通过遍历 AST 子节点解析），未来可考虑用更细粒度的 tree-sitter Query 直接捕获各部分
- 行号提取中 `[0] + 1` 转换（tree-sitter 内部 0-indexed）分散在多处，可统一封装
- 当前不支持嵌套函数/类的提取（只提取顶层），Session 1.3 的 AST 遍历器将解决

---

## 七、下步衔接

Session 1.3 实现 `cpg/traversal.py`——基于 `TreeCursor` 的通用 AST 深度优先遍历器，支持节点类型过滤，为后续调用图和数据流分析提供基础遍历能力。
