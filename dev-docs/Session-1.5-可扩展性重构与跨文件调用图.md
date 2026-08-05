# Session 1.5 — LanguageProvider 重构 + 跨文件调用图

## 目标

1. **可扩展性重构**：引入 `LanguageProvider` 策略模式，添加第四种语言（如 Go）只需新增一个文件 + 一行注册
2. **跨文件调用图**：实现 `CallGraphBuilder`，支持多文件项目导入解析和跨文件调用边

## 产出清单

### 新增文件
| 文件 | 说明 |
|------|------|
| `src/hyqagent/cpg/types.py` | 提取共享数据类（FunctionNode/ClassNode/ImportNode），打破循环依赖 |
| `src/hyqagent/cpg/languages/__init__.py` | Provider 注册表 + 懒加载 + 扩展名检测 |
| `src/hyqagent/cpg/languages/base.py` | LanguageProvider 抽象基类（14 个抽象成员） |
| `src/hyqagent/cpg/languages/python.py` | PythonAdapter（~240行） |
| `src/hyqagent/cpg/languages/javascript.py` | JavaScriptAdapter（~280行） |
| `src/hyqagent/cpg/languages/java.py` | JavaAdapter（~230行） |
| `src/hyqagent/cpg/callgraph_builder.py` | CallGraphBuilder 跨文件调用图（~280行） |
| `tests/test_cpg/test_callgraph_builder.py` | 21 个测试用例，覆盖索引/导入解析/跨文件边 |

### 修改文件
| 文件 | 变更 |
|------|------|
| `src/hyqagent/cpg/parser.py` | 671行→260行：删除所有语言特定代码，委托给 Provider；新增 `get_language()`/`get_provider()` 公开方法 |
| `src/hyqagent/cpg/callgraph.py` | 382行→260行：删除 `_CALL_NODE`/`_FUNC_DEF_TYPES`/所有 per-language 方法，委托给 Provider |
| `pyproject.toml` | 添加 ruff per-file-ignores 规则 |

### 删除的代码（parser.py）
- 4 个 module-level dict（_EXTENSION_MAP, _FUNCTION_QUERIES, _CLASS_QUERIES, _IMPORT_QUERIES）
- 3 个语言特定 import builder（_build_python_import 等，共 ~150 行）
- _extract_base_classes 的 if/elif 链（~35 行）
- _extract_params 和 _extract_decorators
- _build_function_node / _build_class_node 中的语言分支
- 两个 hardcoded `lang_modules` dict（_build_parser 和 _compile_query）
- 3 个 top-level tree-sitter 语法包 import

### 删除的代码（callgraph.py）
- _CALL_NODE / _FUNC_DEF_TYPES 两个 ClassVar
- _extract_python_callee / _extract_javascript_callee / _extract_java_callee（~65 行）
- _extract_callee_info 的 if/elif dispatch
- _extract_func_name（~25 行，委托给 provider）

## 实现过程

### 1. LanguageProvider 架构

#### 接口设计
```python
class LanguageProvider(ABC):
    """每种语言实现此接口。添加 Go 只需新增一个文件。"""
    
    # 元数据
    name: str              # "python", "javascript", ...
    extensions: list[str]  # [".py", ".pyi"]
    
    # 语法（懒加载 — cached_property）
    _ts_module              # tree_sitter 语法包（首次访问才 import）
    
    # 查询字符串
    function_query / class_query / import_query
    
    # 节点解析（从 parser.py 抽出）
    extract_function_name / extract_parameters / extract_decorators
    extract_base_classes / build_import_node
    build_function_node / build_class_node
    
    # 调用图（从 callgraph.py 抽出）
    call_node_type / func_def_types
    extract_callee_info
```

#### 数据类提取（types.py）
为避免 `parser.py` ↔ `languages/base.py` 循环依赖，将 `FunctionNode`/`ClassNode`/`ImportNode` 提至 `cpg/types.py`。两个模块都从此导入。

### 2. 重构过程中的关键问题

| 问题 | 原因 | 修复 |
|------|------|------|
| `get_provider` 签名错误 | 原设计接受 Tree，实际调用传入 str | 改为接受 `language: str` |
| JS 箭头函数参数提取失败 | `extract_parameters` 未处理 bare `identifier` 子节点 | 添加 `if child.type == "identifier"` 分支 |
| Python aliased import 丢失 | `_build_simple_import` 未处理 `aliased_import` 子节点 | 添加 `aliased_import` → 提取 `dotted_name` 的逻辑 |
| `Parser()` 不支持的语言错误信息不匹配测试 | registry 说 "Unknown" 而测试期望 "Unsupported" | 统一为 "Unsupported language" |
| _get_language 私有访问 | callgraph.py 和测试中使用了 `parser._get_language()` | 添加 `_get_language = get_language` 别名保持向后兼容 |

### 3. 跨文件调用图实现

`CallGraphBuilder` 工作流程：
1. `add_directory()` → 递归遍历项目，`add_file()` 每个已知语言的文件
2. `add_file()` → 用 `SingleFileCallGraph` 解析，收集函数定义 + 导入信息
3. `resolve_imports()` → 解析相对导入（`..utils`）和绝对导入（`from utils import X`）
4. `build_calls()` → 遍历各文件的 `UnresolvedCall`，查找 callee 是否在其他文件中定义 + 导入可达

#### 支持的导入模式
- `from utils import helper` → 查找 `utils.py` 中的 `helper`
- `from ..utils import helper` → 相对导入，向上查找 `utils.py`
- `from models import create_user` → 查找 `models.py`
- `import os` → 标准库，不解析

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| ruff check | ✅ All checks passed |
| ruff format | ✅ All files formatted |
| mypy --strict | ✅ Success: no issues in 12 source files |
| pytest | ✅ **193 passed** (172 existing + 21 new) |

## 设计反思

### 做得好的
1. **可扩展性达成** — 添加 Go 语言确实是 1 个文件 + 1 行注册，parser.py 和 callgraph.py 零改动
2. **懒加载生效** — `Parser(["python"])` 只加载 tree-sitter-python，不会 import JS/Java 语法包
3. **回退完全兼容** — 所有公开 API 不变，172 个旧测试无需修改
4. **跨文件调用图实用** — 成功解析相对导入（`..utils`）和绝对导入（`from X import Y`）

### 可改进的
1. **Java 导入解析** — 当前 `_resolve_module_path` 只处理 Python 导入语法。Java 的 `import com.example.Foo` 需要在 Session 1.8 的 Java 框架提取器中处理
2. **循环导入检测** — `_is_reachable` 使用简单匹配，不检测循环导入
3. **同名函数冲突** — `_all_functions` 使用 first-definition-wins 策略。跨文件的类型推断需要更精确的方法签名匹配

## 下步衔接

### Session 1.6: 数据流图构建
- 在调用图基础上实现 def-use chain 分析
- 跨函数数据流追踪
- 基础污点传播（taint_rules.yaml 驱动）
- 依赖：CallGraphBuilder + CPGQuery 接口（Session 1.7）
