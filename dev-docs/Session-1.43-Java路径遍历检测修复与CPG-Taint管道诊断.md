# Session 1.43 — Java 路径遍历检测修复与 CPG Taint 管道诊断

## 目标
诊断并修复 HyqAgent 对 Java 目标路径遍历（CWE-22）及其他漏洞类型的检测盲区，确保 CPG Taint 分析管道端到端可用。

## 产出清单

| 文件 | 变更 | 说明 |
|------|------|------|
| `src/hyqagent/scanner/rules/dangerous_calls.yaml` | +83 行 | 新增 DANGER-047~052 六条 Java 路径遍历规则 |
| `src/hyqagent/cpg/graph.py` | ~14 行修改 | 修复 NODE_PARAMETER 过度标记（17+ 类别误标） |
| `src/hyqagent/cpg/dataflow.py` | +22 行 | 新增参数→使用点数据流追踪（Phase 1.5） |

## 实现过程

### 1. CPG Taint 管道诊断

逐层追踪 `find_path` 调用链：

```
DeterministicScanner.scan_cpg_taint("java")
  → PathAnnotator.annotate("java")
    → CPGQuery.find_path("path_traversal", "path_traversal", taint_loader=..., language="java")
      → _find_taint_nodes(role="source") → 搜索 taint_source 属性
      → _find_taint_nodes(role="sink")   → 搜索 taint_sink 属性
      → _bfs_paths() → BFS 沿 DATA_FLOW + CALLS 边搜索路径
```

**关键发现**：`taint_rules.yaml` 中 Java path_traversal 配置完整（21 sources + 86 sinks），`TaintRuleLoader` 正确加载，但路径发现失败有三个根因。

### 2. 修复一：dangerous_calls.yaml 缺失 Java 文件操作规则

原有规则只有 Python（DANGER-010）和 JavaScript（DANGER-009）的文件操作检测。Java 完全没有路径遍历相关的 regex 规则。

新增六条规则：
- **DANGER-047**: `java.io.File/FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile` 构造器
- **DANGER-048**: `java.nio.file.Files.read/copy/write/move/...` 操作
- **DANGER-049**: `Paths.get()/.resolve()/.normalize()` 路径操作
- **DANGER-050**: `ClassLoader.getResource()/getResourceAsStream()` 类路径资源访问
- **DANGER-051**: `ServletContext.getResource()/MultipartFile.transferTo()` Web 资源操作
- **DANGER-052**: `ZipEntry/ZipFile/TarArchiveEntry` Zip Slip 攻击面

### 3. 修复二：NODE_PARAMETER 源过度标记

**问题**：`_label_taint_nodes` 中 NODE_PARAMETER 节点使用 `func_source_by_name` 查找所属函数的完整源码（含方法体，截断 200 字符）。当方法体前几行包含 `.getParameter()` 时，**所有参数**被标记为 17+ 个类别的 taint source。

例如：
```java
public void doGet(HttpServletRequest request, HttpServletResponse response) {
    String filePath = request.getParameter("file");  // ← body 第一行
    ...
```

函数 source 截断 200 字符包含 `request.getParameter("file")`，导致 `request` 和 `response` 参数都被错误标记为 `code_injection,command_injection,...,xss,xxe` 等 17 个类别。

**修复**：改用 `func_signature_by_name`，仅取函数签名部分（第一个 `{` 之前）。这样 `@RequestParam`、`@PathVariable` 等注解仍能被正确检测（注解在签名中），但方法体中的 `.getParameter()` 不会造成误标。

### 4. 修复三：参数→使用点数据流断裂

**问题**：`build_def_use_chains` 仅处理函数体内的赋值语句（`local_variable_declaration`、`assignment_expression`），不处理函数参数。参数名在函数体中的使用虽然被 `var_uses` 收集，但从不与任何定义关联，因此不生成 `NODE_VARIABLE_REF` 节点。

这意味着从 `NODE_PARAMETER(fileName)` 到 `new File(fileName)` 没有 DATA_FLOW 边，BFS 路径搜索失败。

**修复**：在 Phase 1.5 中提取函数参数声明（含注解文本），作为隐式赋值加入 `assignments` 列表。参数声明文本用于 taint 匹配（如 `@RequestParam String fileName` 匹配 source pattern `@RequestParam`），参数名用于关联使用点。

### 5. 验证模块诊断（未修复，记录供后续）

`Validator.validate_l1` 存在设计缺陷：它将 location 字符串（如 `file.java:10`）传给 `match_all_sources`/`match_sink` 做子串匹配。location 字符串不可能匹配代码模式（如 `.getParameter(`），因此 L1 始终返回 `"confirmed"`（空操作）。

两个验证路径分离：
- `_phase_finding_verification`：直接调用 LLM 验证 `Finding`，正确读取代码上下文
- `_phase_validation` → `Validator.validate()`：验证 LLM 生成的 `Hypothesis`，L1 空操作，L2 缺少 code_context

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `CPGGraphBuilder` 测试中节点无 taint 标记 | 测试未传 `taint_loader` 参数 | 确认 pipeline（orchestrator/cli）正确传递，测试补传 |
| `find_path` 对 `@RequestParam` 参数返回 0 条路径 | 参数→使用点无数据流边 | dataflow.py Phase 1.5：参数作为隐式赋值 |
| NODE_PARAMETER 误标 17 个 source 类别 | 函数体源码用于参数匹配 | graph.py：仅用函数签名（`{` 之前） |
| Java 路径遍历 regex 规则完全缺失 | 仅实现了 Python/JS 的文件操作规则 | 新增 DANGER-047~052 |

## 质量门禁

- **ruff**: 无新增错误（4 个 pre-existing warnings）
- **mypy**: 无新增错误（pre-existing networkx stubs 缺失）
- **pytest**: **1493 passed**, 2 skipped, 0 failed（与修改前一致）

## 设计反思

### 做得好
- 系统性地从数据流底层追踪问题，而不是草率加补丁
- 三个修复互相配合：规则补充 + 减少误标 + 完善数据流
- 所有变更通过 1493 个测试，零回归

### 可改进
- `taint_loader.match_all_sources` 的纯子串匹配导致 source 过度标记（`.getParameter(` 匹配 17+ 类别）。应该考虑更精确的匹配策略（如 AST 节点类型 + 模式匹配）
- 验证模块需要一次专注的修复 Session（L1 location→code、L2 code_context 管道）
- 参数数据流修复仅在函数内有效，跨函数参数传递仍需 `_add_cross_function_edges`

## 下步衔接
1. **测试验证**：在 CWE-Bench-Java CVE 目标上重新扫描，对比修复前后的检出率
2. **验证模块修复**：修复 `Validator.validate_l1` 的 location→code 映射，确保 L2 获取完整代码上下文
3. **Source 匹配精度**：将 `match_all_sources` 从纯子串匹配升级为更精确的匹配策略
4. **跨函数数据流**：验证 `_add_cross_function_edges` 在 Java 多方法调用场景下的表现
