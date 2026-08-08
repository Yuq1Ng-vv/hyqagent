# Session 1.19 — Phase 3 测试修复与质量门禁

## 目标

修复 Phase 3 模块的 3 个失败测试，通过全量质量门禁（971 测试 + ruff + mypy），并验证覆盖率盲区缓解方案的正确性。

## 产出清单

| 操作 | 文件 | 说明 |
|------|------|------|
| 修改 | `src/hyqagent/models/router.py` | `__init__` 创建实例级 ModelSpec 副本，避免类级可变状态跨测试泄漏 |
| 修改 | `tests/test_scanner/test_coverage_auditor.py` | 修复 reason 字符串匹配逻辑（"expose" 而非 "exposed"、"no vulnerability rule covers" 而非 "uncovered"）；移除未使用的 `pytest` import |
| 修改 | `tests/test_models/test_router.py` | 修复未使用变量命名（`provider` → `_provider`、`model` → `_model`）；拆分过长行 |
| 修改 | `tests/test_models/test_provider.py` | 修复未使用变量命名（`provider` → `_provider`） |
| 修改 | `tests/test_observability/test_cost_tracker.py` | 修复 import 排序（`PRICING` 排第一）、过长行拆分 |

## 实现过程

### 问题 1: Router 类属性变异导致测试隔离失败

**根因**: `ModelRouter.CHEAP_SPEC` / `MID_SPEC` / `STRONG_SPEC` 是类级 `ModelSpec` dataclass 实例。`__init__` 中 `self.CHEAP_SPEC.model_id = cheap_model` 直接修改了类属性，导致先运行的测试（`test_custom_model_names` 将 MID_SPEC.model_id 设为 `gpt-4o`）污染后续测试（`test_partial_custom_models` 期望 `claude-sonnet-5`）。

**修复**: 将 `__init__` 改为创建实例级副本：

```python
# Before: 直接修改类级可变属性
if cheap_model:
    self.CHEAP_SPEC.model_id = cheap_model

# After: 创建实例级副本，以类级为默认值
self.CHEAP_SPEC = ModelSpec(
    tier=ModelTier.CHEAP,
    model_id=cheap_model or ModelRouter.CHEAP_SPEC.model_id,
    provider_key=ModelRouter.CHEAP_SPEC.provider_key,
    cost_per_1k_input=ModelRouter.CHEAP_SPEC.cost_per_1k_input,
    cost_per_1k_output=ModelRouter.CHEAP_SPEC.cost_per_1k_output,
)
```

这是一种防御性设计——即使测试顺序改变或并行运行，不同 Router 实例间也不再互相干扰。

### 问题 2: Coverage Auditor 测试的 reason 字符串不匹配

- `exposed_no_source` 标签触发的 reason 实际为 `"3 endpoints expose user input but data flow tracing could not reach a sink..."`，测试搜索 `"exposed"` 失败。修复为搜索 `"expose"`。
- `uncovered_sink` 标签触发的 reason 实际为 `"1 sinks are reachable but no vulnerability rule covers this source→sink combination..."`，测试搜索 `"uncovered"` 失败。修复为搜索 `"no vulnerability rule covers"`。

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| `test_partial_custom_models` 断言 `MID_SPEC.model_id == "claude-sonnet-5"` 失败，得到 `"gpt-4o"` | 前一个测试 `test_custom_model_names` 设置了 `mid_model="gpt-4o"`，直接修改了类级 `ModelRouter.MID_SPEC.model_id` | `__init__` 创建实例级副本 |
| `test_multiple_exposed_no_source_creates_gap` 搜索 `"exposed"` 在 reason 中不命中 | 实际 reason 用词为 `"expose user input"` | 改为搜索 `"expose"` |
| `test_uncovered_sink_label_pattern` 搜索 `"uncovered"` 不命中 | 实际 reason 措辞为 `"no vulnerability rule covers"` | 改为搜索 `"no vulnerability rule covers"` |
| Ruff RUF059: 未使用变量 `provider`, `model` | 测试中解包返回值但未使用 | 加 `_` 前缀 |
| Ruff F401: 未使用 `pytest` import | coverage_auditor 测试不使用 `@pytest.fixture` 等装饰器 | 移除 import |
| Ruff I001: import 顺序 | `PRICING` 字母序应在 `CostEntry` 之前 | 调整顺序 |

## 质量门禁

| 检查项 | 结果 |
|--------|------|
| `uv run pytest` | **971 passed, 2 skipped, 0 failures** |
| `uv run ruff check` (修改文件) | **All checks passed** |
| `uv run mypy src/hyqagent/models/router.py` | **Success: no issues** |
| `uv run ruff format --check` (修改文件) | **1 file already formatted** (router.py) |

## 设计反思

### 做得好的
- **类属性可变状态问题发现及时** — 虽然在本次 Session 中才暴露，但这是一个真实的设计缺陷。实例级副本的修复既解决了测试隔离，也避免了生产环境中多 Router 实例共享可变状态的潜在问题。
- **测试作为规范** — 覆盖盲区缓解方案的测试验证了 CoverageAuditor._check_label_patterns() 对高风险标签模式的正确检测，这些测试本身就是文档。

### 可改进的
- 类属性用 `ModelSpec` 可变 dataclass 是不安全的——如果改用 frozen dataclass 或模块级常量，可以根本上防止此类变异。但当前修复的实例副本模式也足够健壮。
- Coverage Auditor 的 reason 字符串搜索测试比较脆弱（措辞微调就会失败）。未来可考虑用枚举或常量定义 reason 模板，测试引用同一常量。

## 下步衔接

Phase 3 代码和测试已全部就绪。当前 `/deep` 模式流程为：

```
Phase 2 扫描 → Phase 0 项目理解 → Phase 3 LLM 假设生成 → Coverage Audit → Completeness Critic
```

下一步可考虑：
1. **真实 LLM 集成测试** — 对 `rwtests/dvna` 跑 `hyqagent scan --deep`，验证 DeepSeek/Claude 的结构化输出
2. **Phase 4: Session 持久化** — SQLite 会话管理、信念系统、跨 Session 续扫
3. **Phase 1.5: PHP 规则扩展** — 按语言优先级（Java → PHP → Go）扩展 taint 规则
4. **Benchmark 基线** — 在 CWE/SARD 基准数据集上测量 Phase 2 vs Phase 3 的召回提升
