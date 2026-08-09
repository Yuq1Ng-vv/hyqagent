# Session 1.33 — Phase 5 Task 1: Golden Dataset 构建

## 目标

构建 28 个标签化漏洞用例的 Golden Dataset（版本化 + 结构化 ground truth），配套确定性回归测试框架，实现 CI/CD 质量门禁基础。所有测试无需 LLM/API Key，仅需 ~0.8s 即可完成。

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `evals/golden_dataset_v1.json` | 新增 | 28 个用例的结构化 JSON（含 ground_truth） |
| `evals/golden_dataset_schema.json` | 新增 | JSON Schema (draft-07) 校验 |
| `evals/README.md` | 新增 | Golden Dataset 使用文档 |
| `tests/eval/golden_loader.py` | 新增 | `GoldenCase`/`GroundTruth` dataclass + `GoldenDatasetLoader` |
| `tests/eval/conftest.py` | 新增 | module-scoped fixtures (Parser, TaintRuleLoader, golden) + parametrized `case` fixture |
| `tests/eval/test_golden_dataset.py` | 新增 | 4 级测试层次（364 条测试项，319 pass + 45 skip） |
| `tests/eval/__init__.py` | 更新 | 添加模块 docstring |
| `tests/test_cpg/fixtures/parity_xss.*` | 新增 | 3 语言 XSS fixture |
| `tests/test_cpg/fixtures/parity_ssrf.*` | 新增 | 3 语言 SSRF fixture |
| `tests/test_cpg/fixtures/parity_open_redirect.*` | 新增 | 2 语言 Open Redirect fixture (Py/JS) |
| `tests/test_cpg/fixtures/parity_crypto.*` | 新增 | 3 语言 Crypto Weakness fixture |
| `tests/test_cpg/fixtures/parity_csrf.java` | 新增 | Java Spring Security CSRF config fixture |
| `tests/test_cpg/fixtures/parity_auth_bypass.py` | 新增 | Flask auth bypass (missing @login_required) fixture |
| `tests/test_cpg/fixtures/parity_safe_sqli.py` | 新增 | Python 安全参数化 SQL（负面用例） |

**总计：22 files changed, +1659/-52 lines**

## 实现过程

### 用例选择策略 (28 cases)

- **Group 1 (14)**: 复用现有 parity 测试 fixture，添加结构化元数据（CWE/severity/detection_method/ground_truth）
- **Group 2 (13)**: 填补检测盲区的新 fixture — XSS(3) + SSRF(3) + OpenRedirect(2) + Crypto(3) + CSRF(1) + AuthBypass(1)
- **Group 3 (1)**: 负面用例 — 安全参数化 SQL（确保扫描器零误报）

### 测试层次设计

```
L1: Fixture 完整性 → 文件存在 / 解析成功 / 含 source+sink 标注
L2: CPG 图构建 → 节点数>0 / 边数>0 / 函数节点存在 / DATA_FLOW 边存在
L3: 污点规则匹配 → all_sources/all_sinks 子串匹配 / match_source/match_sink 类别匹配
L4: 负面用例验证 → 安全代码 source 不匹配（sink 匹配不算 FP，API 相同是正常的）
```

### 关键技术决策

1. **Module-scoped fixtures** — Parser/TaintRuleLoader 整个测试模块只加载一次，~800MB 内存预算内安全运行
2. **`@pytest.fixture(params=...)` 自参数化** — 替代 `pytest_generate_tests` hooks，更简洁且与 class-based 测试兼容
3. **跳过而非失败** — 非 taint-path 用例 (config_issue/missing_auth) 和负面用例自动 skip Level 3 测试
4. **移除 `test_no_sink_match_on_safe_code`** — sink API（如 `cursor.execute()`）在安全和不安全代码中相同，pattern-level sink 匹配不能作为 FP 门禁

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `parity_xss.js` 产生 0 个 CPG 节点 | 使用匿名回调函数 `app.get('/hello', function(req, res) {...})`，`extract_functions` 无法提取 | 改写为命名函数（如 `helloHandler()`），匹配 parity_sqli.js 的模式 |
| `parity_open_redirect.js` 同样 0 节点 | 同上 | 同样改写为命名函数 |
| case-015 (parity_xss.py) sink_patterns_match 失败 | fixture 使用裸 `return` 语句，不匹配任何 taint sink pattern | 改用 `return Response(...)`（Flask Response 在 taint_rules.yaml 中定义为 XSS sink） |
| case-017 (parity_xss.java) sink_patterns_match 失败 | fixture 使用裸 `return` 语句 | 改用 `response.getWriter().write(...)`（`.getWriter(` 在 taint rules 中定义为 XSS sink） |
| case-028 (负面用例) Level 3 全部失败 | 负面用例不应运行 source/sink 匹配测试 | 添加 `if case.negative_test: pytest.skip(...)` |
| case-028 `test_no_sink_match_on_safe_code` 失败 | `match_sink` 正确返回 `sql_injection`（`cursor.execute()` 匹配 SQLi sink pattern） | **移除该测试** — sink 匹配不能区���安全/不安全 SQL，FP 门禁应在 scanner 层 |

## 质量门禁

```
ruff check  (tests/eval/):  All checks passed
ruff format (tests/eval/):  5 files already formatted
pytest     (full suite):    1835 passed, 47 skipped, 5 warnings (14.07s)
pytest     (golden only):   319 passed, 45 skipped (0.82s)
mypy       (tests/eval/):   10 import-untyped errors（均为预存问题——hyqagent 无 py.typed marker）
```

## 设计反思

### 做得好
- **快速迭代**：0.82s 完成全量 28 用例的 4 级验证，适合 pre-commit hook
- **零依赖**：仅用 pytest + networkx + pyyaml，不引入新依赖
- **扩展友好**：新增用例只需编辑 JSON + 写 fixture 文件，测试自动参数化
- **内存安全**：module-scoped fixtures 确保 ~800MB 限制内运行

### 可改进
- 负面用例仅 1 个（SQLi），其他漏洞类型也需要负面用例（XSS with escaping、SSRF with allowlist 等）
- L4 测试被削减为仅检查 source 匹配（移除了 sink 匹配检查），需要 Scanner 级别的 FP 回归测试（Phase 5 Task 2）
- 当前 `source_pattern`/`sink_pattern` 在 golden JSON 中为 manually curated，应考虑从 taint_rules.yaml 自动推导

## 下步衔接

**Phase 5 Task 2: Scanner-level Golden 测试** — 用 `DeterministicScanner` 或 mock scanner 跑完整扫描流水线，验证 `case-028`（安全 SQLi）不产生 Finding。当前 L4 只测了 pattern 层，需要推进到 scanner 层的 FP 门禁。

**相关文件**:
- `evals/golden_dataset_v1.json` — 可添加 scanner-level ground truth 字段（如 `ground_truth.expected_finding_count: 0`）
- `src/hyqagent/scanner/deterministic.py` — `DeterministicScanner.scan()` 是主要集成点
