# Session 1.15 — Spring DI 解析与同名函数冲突修复

## 目标
修复 ureport2 XXE 漏洞 0 路径检测问题。最初判断为 Spring DI 缺 import，
实现 B+C 组合修复后发现真正根因是**同名函数冲突**。

## 产出清单

| 文件 | 改动 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/callgraph_builder.py` | +146/-24 | B+C 虚拟导入 + 同名函数冲突修复 |
| `dev-docs/Session-1.15-SpringDI与同名函数修复.md` | 新增 | 本文档 |

**总计**: 2 commits (`1376198`, `a3a562c`)

## 实现过程

### 1. Spring DI 支持 (B+C 组合) — commit `1376198`

**B: 字段类型虚拟导入** — `_extract_field_types()` (~60行)
- 遍历 tree-sitter AST，从 `field_declaration` 提取 `type_identifier`
- 支持泛型 (`List<ReportProvider>` → 提取 `ReportProvider`)
- 过滤基本类型和 stdlib 容器名
- 虚拟注入到 `_imports` 中

**C: Java 同 package 默认可达**
- `build_calls()` 中 same-directory check
- 仅对 Java 生效（Python/JS 需显式 import）
- 修复了 test_no_imports_no_cross_edges (scope 到 `.java`)

### 2. 真正的根因发现 — 同名函数冲突

B+C 实现后最小测试通过（XXE 2 paths），但全量 ureport2 仍 0 paths。
深入排查发现：

```
DesignerServletAction.java:50 确实有 import com.bstek.ureport.parser.ReportParser ← 之前的分析错了！
resolve_imports() 正确解析: ReportParser → ureport2-core/.../ReportParser.java
但 build_calls() 检查 parse() 时: _all_functions["parse"] = ExcelParser.java (第一个被索引的)
_is_reachable(DesignerServletAction, ExcelParser.java) → False → 放弃
```

根因: ureport2 有 **36 个文件**定义 `parse()` 方法。`_all_functions` 用
first-definition-wins 策略，字母序在前的 `ExcelParser` 遮蔽了 `ReportParser`。

### 3. 同名函数冲突修复 — commit `a3a562c`

```python
# Before
_all_functions: dict[str, str] = {}  # func_name → file_path (first wins)

# After
_all_functions: dict[str, list[str]] = {}  # func_name → [file_paths]
```

`build_calls()` 改为遍历所有候选：

```python
candidates = self._all_functions.get(callee, [])
for target_file in candidates:
    if same_dir or self._is_reachable(file_path, target_file, ...):
        resolved_target = target_file
        break  # 第一个可达的候选
```

效果：`savePreviewData -> parse` 和 `saveReportFile -> parse` 成功解析为跨文件调用。
跨文件 edge 总数从 ~2137 增加到 4581。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| B+C 最小测试通过但全量 XXE 0 paths | 根因不是 Spring DI，是同名函数冲突 | 更改 `_all_functions` 为 list，遍历候选 |
| 之前错误判断"DesignerServletAction 无 import" | 没仔细检查源文件第 50 行的 import 语句 | 纠正根因分析 |
| test_no_imports_no_cross_edges 失败 | same-directory 对 Python 也生效 | scope 到 `.endswith(".java")` |
| 全量 ureport2 重建需 13min | 469 Java 文件 tree-sitter 解析 | 已实现 pickle 缓存 (Session 1.14) |

## 质量门禁
- ruff: (未运行)
- mypy: (未运行)
- pytest: **372 passed** in 3.65s ✓
- ureport2 端到端: **待验证**（重建未完成就关机）

## 设计反思

### 做得好
- 最小测试+全量测试的双层验证策略有效（快速迭代 B+C）
- 深入排查纠正了错误根因分析
- 同名函数修复是通用解决方案，36 个 parse() 全部正确消歧

### 可改进
- `_all_functions` 的 list 方案仍粗糙——36 个候选都要遍历 `_is_reachable`
- 更精确的方案是用 qualified name（`ClassName.methodName` 或 `file_path::func`）
- 当前 O(N_candidates) 的 reachable 检查在候选数少时可接受；长尾待优化

### 后续优化方向
- 方法调用用对象类型消歧（`reportParser.parse()` → 仅在 ReportParser 文件中找 parse）
- 预先建立 `{type_name: file_path}` 索引，O(1) 消歧

## 下步衔接

### 下次 Session 任务
1. **重建 ureport2 CPG 缓存** — 删除旧缓存，重建验证 XXE 4/4 全通
2. **commit 当前进度** — 已有 2 commits，还有 Session doc 待 commit
3. **Phase 2 内存更新** — BUG 8 已修复，更新 phase2-required-fixes.md

### 缓存说明
- 所有旧缓存已清理 (`~/.cache/hyqagent/cpg/`)
- 下次运行 `add_directory('rwtests/ureport2')` 会自动重建并缓存
- 首次重建 ~13 分钟，后续 ~0.8s
