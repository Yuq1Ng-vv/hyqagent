# Session 1.34 — Phase 5 Task 2: Scanner 层 Golden 测试 + CPG 基础设施修复

## 目标

在 Phase 5 Task 1（28 用例 Golden Dataset + L1-L4 确定性测试）的基础上：
1. 新增 **L5 Scanner-Level 集成测试**：对每个 golden 用例运行完整 `DeterministicScanner`，验证扫描器是否产生（或不产生）与 ground truth 一致的 Finding
2. **修复 3 个底层 CPG 基础设施问题**：Java 污点标记缺失、source/sink 标签混淆导致安全代码误报
3. 达成零误报（0 FP）的 scanner 层门禁

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `tests/eval/test_golden_dataset.py` | 修改 | 新增 `TestGoldenScannerIntegration` 类（5 个测试方法，140 条参数化用例） |
| `tests/eval/conftest.py` | 修改 | 新增 `build_labeled_graph_for_case`、`build_scanner_for_case` 辅助函数 |
| `src/hyqagent/cpg/graph.py` | 修改 | `_label_taint_nodes` 扩展：支持 NODE_CALL_SITE + NODE_PARAMETER，新增 `taint_source`/`taint_sink` 分离 |
| `src/hyqagent/cpg/query.py` | 修改 | `_find_taint_nodes` 新增 `role` 参数（source/sink 角色过滤），`find_path` 传递角色 |
| `src/hyqagent/scanner/rules/config_issues.yaml` | 修改 | CONFIG-009/010/016/017 添加 `category: csrf` |

**总计：5 files changed, +410/-97 lines**

## 实现过程

### L5 测试设计

```python
class TestGoldenScannerIntegration:
    test_scanner_constructs_and_runs  # 28 用例：构造 + scan_all() 无异常
    test_scanner_taint_labels_exist   # 25 用例：CPG 节点有污点标记
    test_config_scanner_finds_issue   # case-026：CSRF 配置检测端到端
    test_missing_auth_scanner         # case-027：缺失认证扫描器
    test_safe_code_produces_no_findings  # case-028：安全代码零 FP
```

- 跳过逻辑：非适用 detection_method 自动 `pytest.skip`（84 skipped）
- 内存预算：每个 fixture 单文件（~20 行），CPG 图 ~10-100 节点，峰值 ~300MB

### 基础设施修复 1：Java 污点标记缺失

**根因**：`_label_taint_nodes` 只处理 `NODE_ASSIGNMENT` 节点。Java Spring 使用 `@RequestParam("q") String keyword` 参数声明（产生 `NODE_PARAMETER` 节点，非 assignment），方法调用如 `jdbcTemplate.query(...)` 产生 `NODE_CALL_SITE` 节点（非 assignment）。

**修复**：扩展 `_label_taint_nodes` 三种节点类型解析：

| 节点类型 | 匹配文本来源 | 用途 |
|---------|-------------|------|
| NODE_ASSIGNMENT | `data["source"]`（RHS 表达式） | 已有，保持兼容 |
| NODE_CALL_SITE | `data["expression"]`（调用表达式） | 裸函数调用 sink（如 `cursor.execute(...)`） |
| NODE_PARAMETER | 外层函数 `data["source"]`（含 `@RequestParam` 等注解） | Java/Spring 参数源 |

### 基础设施修复 2：source/sink 标签混淆导致安全代码误报

**根因**：`_label_taint_nodes` 将所有匹配的节点统一写入 `taint_category` 属性，不区分 source 和 sink 角色。在安全参数化 SQL fixture（`parity_safe_sqli.py`）中：
- `conn = sqlite3.connect(":memory:")` → `.connect(` 匹配 SQLi **sink** 模式 → `taint_category = "sql_injection"`
- `cursor = conn.cursor()` → `.cursor(` 匹配 SQLi **sink** 模式 → `taint_category = "sql_injection"`
- BFS 以两个 sink 节点为"源→汇"找到 3 跳路径 → **误报 CONFIRMED_TAINT**

这四个 root cause 交织：
1. `.cursor(` 在 taint_rules.yaml 的 sink 列表中过于宽泛（匹配无害的 `conn.cursor()`）
2. `_find_taint_nodes` 不区分 source/sink 标签节点
3. sanitizer `connection.cursor()` 不匹配 `conn.cursor()`（变量名不同）
4. `cursor.execute("SELECT ... WHERE id = ?", (user_id,))` 是 expression_statement → 无 NODE_ASSIGNMENT 节点 → 不在图中 → 参数化查询的 sanitizer 无法生效

**修复**：在 `_label_taint_nodes` 中添加角色分离：
- `taint_source`：逗号分隔的 source 类别
- `taint_sink`：逗号分隔的 sink 类别
- `taint_category`：保留作为向后兼容（合并）

在 `_find_taint_nodes` 添加 `role` 参数：
- `role="source"`：只搜索 `taint_source` 属性
- `role="sink"`：只搜索 `taint_sink` 属性
- `role=None`（默认）：搜索 `taint_category`（向后兼容）

在 `find_path` 中传递角色给两次调用：
```python
sources = self._find_taint_nodes(source_pattern, ..., role="source")
sinks = self._find_taint_nodes(sink_pattern, ..., role="sink")
```

关键：当 `role` 非 None 且无匹配时，**不回退到子串匹配**（否则角色过滤失效）。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| case-003/017（Java SQLi/XSS）taint labels 0 | `_label_taint_nodes` 只处理 NODE_ASSIGNMENT，Java 使用 @RequestParam（参数节点）和方法调用（call_site 节点） | 扩展为三种节点类型：NODE_ASSIGNMENT + NODE_CALL_SITE + NODE_PARAMETER |
| case-028（safe SQLi）产生 1 个误报 TAINT-001 | `_find_taint_nodes` 不区分 source/sink，两个 sink 节点间找到伪路径 | 新增 `taint_source`/`taint_sink` 分离 + `role` 参数 + 禁止角色匹配回退子串搜索 |
| case-026（CSRF）category 不匹配 | config_issues.yaml CSRF 规则缺少 `category: csrf`，fallback 到 `default_category="config_issue"` | 在 4 条 CSRF 规则添加 `category: csrf`（CONFIG-009/010/016/017） |

## 质量门禁

```
ruff check  (modified files): 所有错误均为预存问题（D205, RUF003, RUF059, S301），无新增
ruff format (modified files): 4 files reformatted, 3 files already formatted
pytest     (full suite):      1891 passed, 131 skipped, 5 warnings (21.63s)
pytest     (golden L1-L5):    375 passed, 129 skipped (2.57s)
mypy       (tests/eval/):     10 import-untyped 错误（均为预存问题）
```

## 设计反思

### 做得好
- **Source/Sink 角色分离是正确抽象**：将单纯的 `taint_category` 拆分为 `taint_source`/`taint_sink`，从根本上解决了误报问题，而非 hack 式跳过
- **最小侵入**：`role=None` 保持向后兼容，所有现有测试无需修改
- **三种节点类型覆盖**：NODE_ASSIGNMENT（Python/JS）+ NODE_CALL_SITE（裸调用）+ NODE_PARAMETER（Java）覆盖了 fixture 中的所有代码模式
- **Scanner 层 FP 门禁达成**：case-028（安全参数化 SQL）的 scanner 层 FP 回归测试通过

### 可改进
- `@RequestParam` 被 taint rules 映射到 `code_injection` 而非 `sql_injection`（因为 `match_all_sources` 返回第一个匹配类别）。多类别匹配需要扩展到 `@RequestParam` 可以同时属于 SQLi/CMDi/XSS 等多种 source 类别
- `conn.cursor()` 本身不是危险的 —— cursor 只是对象分配，真正危险的是 `.execute(sql)`。`.cursor(` 作为 SQLi sink pattern 过于宽泛，应从 taint_rules.yaml 中移除或细化为 `.execute(` 级别的匹配
- Java 参数节点的 taint labeling 通过外层函数 `source` 文本间接匹配，不够精确 —— 理想情况下应直接检查 `@RequestParam` 注解的 source 文本
- NODE_CALL_SITE 节点目前只检查 sink 匹配 —— 如果 call_site 可以同时是 source（如 `graphql.ExecutionInput`），当前"source 优先"逻辑会在 source 检查后 skip sink

## 下步衔接

Session 1.33 的 L1-L4 与 Session 1.34 的 L5 共同构成了完整的 Golden Dataset 确定性测试体系。后续方向：

1. **扩展负面用例**：目前仅 case-028（SQLi），需要增加 XSS with escaping、SSRF with allowlist 等
2. **多类别 source 标记**：使 `match_all_sources` 返回所有匹配类别（非仅第一个），让 `@RequestParam` 同时被标记为 `sql_injection` + `command_injection` + `xss`
3. **CPG data-flow 增强**：expression_statement（如 `cursor.execute(sql)`）应产生可标记节点，使 sanitizer 匹配能正常工作
4. **Scanner 层 cpg_taint 端到端测试**：当前 CPG data-flow 在单文件 fixture 中无法追踪 variable_ref → call_site 的边（已知限制），完善后可对全部 25 个 cpg_taint 正例做全路径验证

**相关文件**:
- `src/hyqagent/cpg/graph.py` → `_label_taint_nodes`（三种节点类型 + source/sink 分离）
- `src/hyqagent/cpg/query.py` → `_find_taint_nodes`（role 参数）、`find_path`（传递 role）
- `tests/eval/test_golden_dataset.py` → `TestGoldenScannerIntegration`（L5 扫描器测试）
- `tests/eval/conftest.py` → `build_labeled_graph_for_case`、`build_scanner_for_case`
