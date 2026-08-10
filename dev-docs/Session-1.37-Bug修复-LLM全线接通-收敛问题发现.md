# Session 1.37 — Bug 修复 + LLM 全线接通 + 收敛问题发现

## 目标

修复 `--deep` 扫描的 4 个串行 bug，确保 LLM 真正全线工作，并记录新发现的收敛循环问题。

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/hyqagent/session/checkpoint.py` | 修改 | Finding JSON 序列化修复（自定义 encoder） |
| `src/hyqagent/report/generator.py` | 修改 | 补充缺失的 `dynamic_verification_results` 参数 |
| `src/hyqagent/models/providers/anthropic_provider.py` | 修改 | 修复 callback 中 `suppress(Exception)` 吞掉错误 |
| `src/hyqagent/scanner/orchestrator.py` | 修改 | 给 provider 设置 `_current_phase` |
| `src/hyqagent/observability/cost_tracker.py` | 修改 | 修复 DeepSeek 缓存报告导致的负成本 |
| `src/hyqagent/observability/metrics.py` | 修改 | 修复 Prometheus 负值计数器 |
| `src/hyqagent/api/config.py` | 修改 | mid/strong 模型改为 deepseek-v4-flash |
| `src/hyqagent/scanner/hypothesis.py` | 修改 | 移除标签跳过列表，所有注释路径都走 LLM |
| `tests/test_api/test_config.py` | 修改 | 更新模型默认值断言 |
| `tests/test_observability/test_cost_tracker.py` | 修改 | 更新缓存读取成本计算测试 |
| `progress.md` | 修改 | 记录收敛循环问题 |
| `dev-docs/Session-1.37-Bug修复-LLM全线接通-收敛问题发现.md` | 新建 | 本文档 |

## 实现过程

### Bug 1: Finding JSON 序列化崩溃

**场景**: `PipelineState.phase_states` 存储了原始的 `Finding` dataclass 对象，checkpoint 序列化时 `json.dumps()` 不支持。

**修复**: 在 `checkpoint.py` 中添加 `_CheckpointEncoder`，对所有 dataclass 递归调用 `dataclasses.asdict()`：

```python
class _CheckpointEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if hasattr(o, "__dict__"):
            return {k: v for k, v in o.__dict__.items() if not k.startswith("_")}
        return super().default(o)
```

### Bug 2: generate() 缺失参数

CLI 层传了 `dynamic_verification_results` 但 `ReportGenerator.generate()` 签名里没有这个参数。补充参数声明和 `deep_ctx` 字典。

### Bug 3: LLM 成本始终为 $0.0000（三连环 bug）

**3a — Provider callback 吞异常**: `self._callback` 调用了 `suppress(Exception)`，当 callback 抛出 TypeError（缺少 phase 参数）时完全不可见。改为 `try/except logger.exception` + 手动注入 phase。

**3b — Orchestrator 未设置 phase**: `_run_phase()` 没有把当前 phase 传给 provider，callback 拿不到 phase 信息。添加 `_prov._current_phase = phase.value`。

**3c — 负成本**: DeepSeek API 的 cache_read 和 input 是分开报告的（同一个 request 里 cache 走单独计费）。原来的公式 `cost -= cache_k * (input - cache_read)` 会产生负值。改为 `cost += cache_k * cache_read_rate`。

### 核心变更: 移除标签跳过列表

用户要求所有 LLM 调用必须走 DeepSeek V4 Flash，且所有注释路径必须经过 LLM 验证。

**Before** (hypothesis.py):
```python
if label_str in (
    "confirmed_taint",
    "sanitized_taint",
    "missing_auth",
    "config_issue",
    "unreachable_sink",
    "trust_boundary_crossing",
):
    continue  # skip LLM
```

**After**: 每条注释路径都走 `_generate_one()`，由 LLM 进行具体的 CWE 分类和置信度评估。

**效果对比**:

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| LLM 调用 | 3 次 | 162 次 |
| LLM 假设 | 0 | 18 |
| LLM 验证 | 0 | 36 |
| LLM 成本 | $0.0000 | $0.0416 |
| 收敛轮次 | 3 (立即收敛) | 5 (强制停止) |
| 总耗时 | 69s | 1,027s |

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `TypeError: Object of type Finding is not JSON serializable` | checkpoint 中 `json.dumps()` 不支持 dataclass | 自定义 JSONEncoder 递归 asdict() |
| `generate() got unexpected keyword argument 'dynamic_verification_results'` | CLI 传了参数但函数签名没有 | 添加参数 |
| LLM 成本始终显示 $0.0000 | 三连环: callback 抛异常被 suppress 吞掉 / orchestrator 未设 phase / DeepSeek cache 计费公式错误 | 三处逐一修复 |
| 收敛循环 VDR 不降反升 (13→25→37→34→35) | LLM 每轮重新生成 hypothesis，跨轮不一致，C_hat=0 | 记入 progress.md 待修 |
| 收敛循环 token 浪费 (162 次调用 5 轮) | max_rounds=5 强制停止，每轮重跑全部 LLM 调用 | 短期缓解: 降 max_rounds 为 3；长期: 去重 + 跨轮上下文 |

## 质量门禁

- ruff: 392 pre-existing (no new issues)
- mypy: 82 pre-existing (no new issues)  
- pytest: 2,057 passed, 202 skipped, 0 failures

## 设计反思

**做得好的**:
- 移除标签跳过列表后，LLM 能正确将通用 `confirmed_taint` 分类到具体 CWE（CWE-89/470/502/22/918）
- DeepSeek V4 Flash 成本极低（162 次调用仅 $0.0416），证明廉价模型也能做有效分类
- 成本追踪 bug 链的根因分析清晰（从表现→三处串行 bug→逐一修复）

**可改进的**:
- 收敛循环的设计假设是 LLM 跨轮一致的，但现实中便宜模型的一致性很差。应该在收敛判断前做 finding 稳定性检查
- `suppress(Exception)` 这种无差别异常吞噬太危险，应该在关键路径上永远不用
- 收敛循环的理想设定应该是每轮只对新发现生成 hypothesis，而不是重跑全部

## 下步衔接

1. **收敛循环修复** — 最高优先级：同路径 hypothesis 去重 + 跨轮上下文传递 + finding 稳定性检查。长期方案已在 progress.md 记录
2. **max_rounds 短期调整** — 在修复前将默认 `max_rounds` 从 5 降为 3
3. **LLM 结果一致性评估** — 为 hypothesis_gen 和 validation 添加跨轮一致性指标
