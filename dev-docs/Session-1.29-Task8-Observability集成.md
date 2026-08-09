# Session 1.29 — Task 8 Observability 集成

## 目标
补齐 HyqAgent 可观测性三模块（Tracer、Metrics、AuditTrail）并完成与扫描管道的接线。此前仅有 CostTracker 独立存在且 `record()` 从未被调用——LLM 调用数据仅在 `_call_history` 和 structlog 中，不进入任何可观测性系统。

## 产出清单

| 操作 | 文件 | 行数 | 说明 |
|------|------|------|------|
| 新建 | `observability/tracer.py` | ~240 | ObservabilityManager: span 事件 + 协调 CostTracker/Metrics/AuditTrail |
| 新建 | `observability/metrics.py` | ~140 | PrometheusMetrics: 实现 MetricsCollector Protocol，6 个 Prometheus 指标 |
| 新建 | `observability/audit_trail.py` | ~185 | AuditTrail: ESAA SHA-256 链式决策审计 |
| 修改 | `observability/__init__.py` | +15 | 公共 API 导出 |
| 修改 | `models/providers/anthropic_provider.py` | +12 | 添加 `on_call_complete` 观察者回调 |
| 修改 | `scanner/orchestrator.py` | +30 | ObservabilityManager DI + Provider 回调注入 + budget gauge 更新 |
| 新建 | `tests/test_observability/test_tracer.py` | ~175 | 17 tests — SpanEvent + ObservabilityManager |
| 新建 | `tests/test_observability/test_metrics.py` | ~125 | 11 tests — 6 指标注册/记录/输出 |
| 新建 | `tests/test_observability/test_audit_trail.py` | ~130 | 12 tests — 条目/链验证/篡改检测/JSONL 导出 |
| 修改 | `tests/test_models/test_provider.py` | +55 | 3 tests — 回调调用/无回调正常/异常不崩溃 |
| **合计** | **3 新源文件 + 3 新测试文件 + 3 修改** | **~1100 行** | **43 tests** |

## 实现过程

### 1. `observability/tracer.py` — ObservabilityManager

**SpanEvent** — OTel 兼容的结构化 span：
- `trace_id` / `span_id` / `parent_span_id` — UUID 标识
- `start_time` / `end_time` — `time.monotonic()` 精度
- `duration_ms` — 计算属性
- `to_dict()` — OTel JSON 格式输出
- 通过 structlog 发射 `span_closed` 事件

**ObservabilityManager** — 中央协调器：
```
record_llm_call() → CostTracker.record() + PrometheusMetrics.record_llm_call() + AuditTrail.record()
record_finding()  → PrometheusMetrics.record_finding()
record_tool_call() → PrometheusMetrics.record_tool_call()
set_coverage()    → PrometheusMetrics.set_coverage()
```

所有 delegate 调用被独立 try/except 包裹 — 观察者子系统异常不传播。

### 2. `observability/metrics.py` — PrometheusMetrics

实现 `core.protocols.MetricsCollector` Protocol，注册 6 个 Prometheus 指标：

| 指标 | 类型 | Labels |
|------|------|--------|
| `hyqagent_llm_calls_total` | Counter | model, phase, status |
| `hyqagent_llm_cost_usd_total` | Counter | model |
| `hyqagent_llm_latency_seconds` | Histogram | model, phase (8 buckets: 0.1–60s) |
| `hyqagent_findings_total` | Counter | severity, cwe |
| `hyqagent_endpoint_coverage_ratio` | Gauge | — |
| `hyqagent_budget_spent_usd` | Gauge | — |

支持可选 `CollectorRegistry` 注入（测试隔离）。

### 3. `observability/audit_trail.py` — AuditTrail

**AuditEntry** — ESAA 决策记录（sequence, timestamp, phase, event, hypothesis_id, actor, decision, evidence_hash, chain_hash, metadata）。

**SHA-256 链**：
```
canonical_payload = f"{seq}|{ts}|{phase}|{event}|{h_id}|{actor}|{decision}|{ev_hash}|{metadata_json}|{prev_hash}"
chain_hash = sha256(canonical_payload)
```

**操作**：`record()` 追加、`verify_chain()` 重算验证、`export_jsonl()` 导出。

### 4. AnthropicProvider 观察者回调

```python
class AnthropicProvider:
    def __init__(self, config, ..., on_call_complete=None):
        self._on_call_complete = on_call_complete

    # In generate(), after structlog logging:
    if self._on_call_complete is not None:
        try:
            self._on_call_complete(model=..., input_tokens=..., ...)
        except Exception:
            pass  # 永不因指标失败中断审计
```

### 5. Orchestrator 接线

在 `_ensure_scanner_modules()` 末尾：
```python
# 创建 ObservabilityManager (共享 CostTracker + 新 PrometheusMetrics)
self._obs_manager = ObservabilityManager(
    cost_tracker=self._cost_tracker,
    metrics=PrometheusMetrics(),
)

# 注入回调到所有 LLM provider
for _prov in (self._cheap, self._mid, self._strong):
    if _prov is not None:
        _prov._on_call_complete = self._obs_manager.record_llm_call
```

在 `run()` / `resume()` 结束时更新 Prometheus budget gauge。

### 6. 测试 — 43 tests

| 测试文件 | 数量 | 覆盖 |
|----------|------|------|
| test_tracer.py | 17 | SpanEvent 创建/持续时间/to_dict/嵌套、OM 启停 span、record_llm_call 分发到三个子系统、metrics null safety |
| test_metrics.py | 11 | 6 指标注册、record_llm_call/finding/tool_call、get_metrics_text 输出、budget gauge |
| test_audit_trail.py | 12 | AuditEntry 默认值、record 返回条目、链验证、篡改检测、JSONL 导出、entries 不可变性 |
| test_provider.py | 3 | callback 被调用含正确 usage、无 callback 正常工作、callback 异常不崩溃 |

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| Prometheus `DuplicateTimeseries` — 多个测试创建 `PrometheusMetrics()` 时注册冲突 | 所有实例共享全局 `CollectorRegistry` | `PrometheusMetrics` 接受可选 `registry` 参数；测试用 `_new_metrics()` 工厂创建隔离 registry |
| `generate_latest()` 返回空输出 | 未传递自定义 registry，仍查全局 registry | 改为 `generate_latest(self._registry)` |
| `AuditEntry.test_defaults` — `missing 1 required argument: evidence_hash` | `evidence_hash: str` 无默认值 | 改为 `evidence_hash: str = ""` |
| ruff D413 — docstring Parameters section 缺少空行 | NumPy 风格要求 Parameters 后跟空行再 `"""` | 在 `"""` 前加空行 |
| ruff F841 — 未使用的测试变量 | `e2` 和 `entry` 赋值后未使用 | 移除变量赋值或用 `_` 前缀 |
| ruff S108 — `/tmp/logs` 硬编码路径 | 安全规则标记 `/tmp` 为"可能不安全" | 改为 `tempfile.TemporaryDirectory()` |
| mypy `[unused-ignore]` — tracer.py line 217 | `self._metrics` 类型声明为 `Any`，不需要 ignore | 移除 `# type: ignore[call-arg]` |
| mypy `Iterable[Metric]` not indexable — metrics.py line 125 | `Counter.collect()` 返回 `Iterable`，不可直接索引 | 改为 `list(self._llm_calls.collect())` |

## 质量门禁

### ruff
```
All checks passed! (0 errors on new/modified files)
```

### mypy
```
Success: no issues found in 5 source files (observability/)
AnthropicProvider + orchestrator: all errors pre-existing, 0 new
```

### pytest
```
1400 passed, 2 skipped, 5 warnings — 全量回归
新测试: 43 passed (17 tracer + 11 metrics + 12 audit_trail + 3 provider callback)
基线: 1356 → 1400 (+44)
```

## 设计反思

### 做得好
1. **观察者模式** — Provider 不需要知道 CostTracker/Prometheus 的存在，只接收一个简单 callback。依赖反转。
2. **三子系统独立 try/except** — 任何一个子系统失败不影响其他，不影响审计主流程
3. **零外部 SDK 依赖** — 不用 OTel/LangFuse SDK，span 通过 structlog 发射 OTel 兼容 JSON。Prometheus 已有。
4. **isolated registry for tests** — `PrometheusMetrics(registry=CollectorRegistry())` 避免全局状态泄漏
5. **SHA-256 链验证** — 不仅记录决策，还能检测事后篡改

### 可改进
1. **Span 持久化** — 当前 span 只通过 structlog 发射，不写文件。可加 JSONL span 持久化。
2. **Prometheus push gateway** — CLI 工具不适合 pull 模式（进程短命）。应加 push gateway 集成或用 `push_to_gateway()`。
3. **AuditTrail 未接入 orchestrator 决策点** — 当前只在 tracer 回调中写入（当 hypothesis_id 非空），orchestrator 的 Phase 方法未显式调用 `audit_trail.record()`（如 adversarial overturned 事件）。
4. **Finding/coverage 指标未在 Phase 方法中调用** — `record_finding()` / `set_coverage()` 已实现但 orchestator 未调用它们（可在后续 Session 中接入 `_phase_coverage_audit` 和 finding 生成点）。

## 下步衔接
- Task 8 核心完成 ✅ — 三模块已实现并接线
- **接线深化**（可选）：AuditTrail 接入 orchestrator 决策点、Finding 指标接入覆盖率审计
- **Prometheus push gateway**（可选）：适合 CLI 短命进程
- **Phase 5 — 动态验证沙箱**：用户表示"暂时不是很需要"
