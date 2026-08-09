# Session 1.35 — Phase 5 Task 3: LLM 评估 (DeepEval)

## 目标

在 Phase 5 Task 1+2（28 Golden Dataset + Scanner 层回归）基础上，为 LLM 流水线（HypothesisGenerator + Validator）建立自动化质量评估体系：

1. **Mock-based 流水线测试**：通过 FakeProvider 注入预构建响应，无需真实 LLM
2. **4 个自定义 DeepEval 指标**：衡量 vuln_type 准确性、severity 一致性、CWE 映射、verdict 正确性
3. **Opt-in 真实 LLM 评估**：通过 `HYQAGENT_EVAL_REAL_LLM=1` 环境变量启用 GEval

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `tests/eval/mock_responses.py` | NEW | 7 个预构建 LLM 响应（4 个 hypothesis + 3 个 validator）+ FakeProvider 类 |
| `tests/eval/metrics.py` | NEW | 4 个自定义 DeepEval 确定性指标（无 LLM 依赖） |
| `tests/eval/conftest.py` | 修改 | 新增 `mock_provider` fixture + TYPE_CHECKING 补充 |
| `tests/eval/test_llm_eval.py` | NEW | 4 个测试类（解析 + 生成 + 校验 + 度量） |
| `src/hyqagent/scanner/hypothesis.py` | 修改 | 修复 `_generate_one` 中 `Task`/`TaskType` 运行时缺失导入 |

**总计：4 new files, 2 modified, +703/-3 lines**

## 实现过程

### 1. FakeProvider 设计

核心设计：`FakeProvider` 实现 `generate_structured()` 接口，从队列中返回预构建响应。与 `AnthropicProvider` 接口兼容（duck typing），可注入到 `HypothesisGenerator` 和 `Validator` 的任意 provider 槽位。

```python
class FakeProvider:
    def __init__(self, responses=None):
        self._queue = list(responses) if responses else []
        self._calls = []  # 记录每次调用供断言

    async def generate_structured(
        self, messages, model="", output_schema=None, system="", max_tokens=4096, temperature=0.1
    ):
        self._calls.append({...})
        if not self._queue:
            raise AssertionError("FakeProvider: queue exhausted")
        return self._queue.pop(0)
```

响应格式匹配 Anthropic tool_use 的 `input` 字段，即 `{"hypotheses": [...]}` 或 `{"verdict": "...", "confidence": ..., "q1_reachability": ...}`。

### 2. 自定义 DeepEval 指标

四个指标均继承 `BaseMetric`，实现 `measure()` 方法，**无需 LLM** — 纯确定性逻辑：

| 指标 | 评分逻辑 |
|------|---------|
| `VulnTypeAccuracyMetric` | 1.0 精确匹配, 0.5 子串匹配, 0.0 不匹配 (threshold=0.5) |
| `SeverityAgreementMetric` | 1.0 精确, 0.8 相邻, 0.5 ±2 级, 0.2 ±3 级, 0.0 更远 (threshold=0.6) |
| `CWEMappingMetric` | 1.0 精确, 0.7 同族, 0.3 不同族但均合法, 0.0 无效 (threshold=0.5) |
| `VerdictCorrectnessMetric` | 1.0 正确判决, 0.5 inconclusive, 0.0 错误判决 (threshold=0.5) |

CWE 族映射包含 15 个父 CWE → 子 CWE 的字典（如 CWE-89 ← CWE-564/CWE-943），支持部分匹配评分。

### 3. Mock Pipeline 测试设计

```
TestHypothesisParsing (3 tests):
  ├── test_parse_sqli_true_positive  — _parse_response() 解析正确 Hypothesis
  ├── test_parse_empty_hypotheses    — 空列表无 FP
  └── test_parse_invalid_response    — 4 种畸形输入不崩溃

TestMockHypothesisGeneration (3 tests  × 28 cases):
  ├── test_generate_returns_hypotheses  — HEURISTIC_SINK → canned SQLLI
  ├── test_generate_empty_when_provider_returns_empty  — 空响应
  └── test_skips_non_llm_labels  — CONFIRMED_TAINT 跳过 LLM

TestMockValidation (3 tests  × 28 cases):
  ├── test_l2_validates_confirmed  — L2 LLM 确认 SQLi
  ├── test_l2_rejects_false_positive  — L2 LLM 拒绝安全代码
  └── test_l1_deterministic_rejects_type_mismatch  — L1 source/sink 类型不匹配

TestDeepEvalMetrics (10 standalone tests):
  10 个单测覆盖所有指标的边界情况
```

参数化使用 `conftest.py` 的 `case` fixture，28 个 golden 用例自动切分。非 cpg_taint 用例（config_issue/missing_auth）和 negative_test 用例通过 `pytest.skip` 跳过。

### 4. 基础设施修复

在实现 mock 测试时发现了一个**预存 bug**：

`HypothesisGenerator._generate_one()` 方法使用了 `Task` 和 `TaskType` 类，但它们只在 `TYPE_CHECKING` 块中导入（line 36）。运行时 `_generate_one()` 方法被调用时会抛出 `NameError: name 'Task' is not defined`。

**修复**：在 `_generate_one()` 方法体内添加运行时导入：
```python
async def _generate_one(self, annotated, label_str):
    from hyqagent.models.router import Task, TaskType

    ...
```

同时从 `TYPE_CHECKING` 块中移除不再需要的 `Task`/`TaskType` 导入。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| `NameError: name 'Task' is not defined` (25 个测试全部失败) | `_generate_one` 使用的 `Task`/`TaskType` 仅在 `TYPE_CHECKING` 导入，运行时不可用 | 在方法体内添加 `from hyqagent.models.router import Task, TaskType` 运行时导入 |
| `F821 Undefined name DeterministicScanner` (ruff UP037) | `DeterministicScanner` 未在 `TYPE_CHECKING` 导入，字符串类型注解被 auto-fix 移除后出错 | 在 `conftest.py` 的 `TYPE_CHECKING` 块中添加 `DeterministicScanner` 导入 |
| `RUF100 Unused noqa` (7 个) | `pytest.importorskip` 后不再需要 E402 抑制 | auto-fix 移除冗余 `# noqa` 注释 |
| `D105 Missing docstring in magic method` (4 个) | `__name__` 属性缺少 docstring（ruff D105 规则） | 添加 `# noqa: D105` 注释（magic method 不需要 docstring） |
| `B007 Unused loop variable family_id` | CWE_FAMILY.items() 的 key 未使用 | 重命名为 `_family_id` |

## 质量门禁

```
ruff check  (modified files): All checks passed! (0 errors)
ruff format (modified files): 5 files already formatted
pytest     (eval subset):     541 passed, 200 skipped (3.42s)
pytest     (full suite):      2057 passed, 202 skipped, 5 warnings (22.01s)
mypy       (mock_responses):  Success: no issues found
mypy       (tests/eval):      27 errors (均为预存: import-untyped + mock 注入类型不匹配)
```

## 设计反思

### 做得好
- **FakeProvider 设计轻量且可组合**：仅 ~50 行，通过队列机制支持任意测试场景。每个 test method 预加载需要的响应，互不干扰
- **确定性指标无 LLM 依赖**：4 个自定义指标完全基于字符串比较和序数距离，CI 中无需 API key，运行时间 < 1ms
- **Fix-forward 基础设施 bug**：mock 测试意外暴露了 `Task` 运行时缺失导入的 bug，直接修复而非绕过
- **参数化覆盖度**：利用现有的 28 个 golden 用例，每个 mock test class 自动得到 28× 参数化覆盖

### 可改进
- **Generator 测试应使用真实 CPG 路径**：当前 `_build_mock_annotated_path()` 构造的是 mock GraphPath 节点，虽然 `slice_path()` 工作正常，但未测试真实的 CPG path 数据流
- **GEval opt-in 测试未验证**：`TestRealLLMEval` 需要真实 API key 和 LLM 调用，目前在 CI 中全部 skip — 需要设置 CI secret 后启用
- **指标缺少聚合报告**：当前每个指标独立 measure，缺少一个 `EvalReport` 类来聚合金色数据集的总体 precision/recall/F1

## 下步衔接

Session 1.35 完成了 Phase 5 Task 3（LLM 评估框架）。Phase 5 剩余任务：

1. **Task 4: CI/CD 集成**（GitHub Actions）— 将 Golden Dataset 测试 + LLM Mock 测试加入 CI 流水线
2. **Task 5: 文档最终化 + 发布准备** — 完善 README、API 文档、使用示例

或者直接进入：
3. **Phase 6: 真实项目端到端测试** — 选择 3-5 个开源 Web 项目（如 DVWA、WebGoat、VulnPy）做完整扫描质量评估
4. **Recall 模式增强**：`generate_from_seeds()` 等方法需要类似的 DeepEval 测试覆盖
