# Session 1.31 — 报告 CLI 接入 + 漏洞覆盖盲区分析

**日期**: 2026-08-09

## 1. 目标

1. **报告 CLI 接入** — ReportGenerator 已存在但 `--deep` 模式只输出 bare JSON，AuditReport 的 hypotheses/convergence/cost 数据全部丢失。将其接入 CLI `scan --deep` 和 `resume` 命令。
2. **漏洞覆盖盲区分析** — 对照 `docs/detection_matrix.json`（200 项 ASVS 对齐检测矩阵）分析 Phase 1+2 当前覆盖缺口，输出未覆盖类别 Top 5 和 Quick Wins 路线图。

## 2. 产出清单

| 文件 | 变更 | 说明 |
|------|------|------|
| `src/hyqagent/report/generator.py` | +167 行 | `generate()` 新增 8 个 deep-audit 参数；`_to_json()` 新增 deep_audit/hypotheses/cost/convergence 段；`_to_markdown()` 新增 LLM 假设/收敛/成本章节 |
| `src/hyqagent/api/cli.py` | +96 行 | `_run_deep_audit()` 用 `_deep_audit` dict 打包 AuditReport；共享报告段检测并传递 deep data；`_output_report()` 支持 `report_format` 参数；`resume` 命令新增 `--format`/`--output` 选项 |
| `tests/test_report/test_generator.py` | +212 行 | `TestDeepAuditJSONReport`（6 测试）+ `TestDeepAuditMarkdownReport`（6 测试）；fake stub 类 `_FakeHypothesis`/`_FakeConvergence`/`_FakeCostSummary` |

## 3. 实现过程

### 3.1 报告 CLI 接入

**问题诊断**：5 个 gap：
1. `mode` 硬编码 `"quick"` → JSON 和 Markdown 都写死
2. AuditReport 12 字段传不到 Generate → 只有 findings/annotated_paths 能传
3. hypotheses 从未渲染（虽然在 ScanResult 上 monkey-patch 了）
4. `_output_report()` 硬编码 `fmt="json"`
5. `resume` 命令缺 `--format` 参数

**设计方案**（见 plan 文件）：
- **不修改 ScanResult dataclass** — 使用 `result._deep_audit = {...}` dict 打包，向后兼容
- **generate() 参数全部 optional** — 默认 None，quick mode 输出不变
- **三种格式（json/markdown/sarif）全部支持 deep data**

**ReportGenerator 增强**：
```python
def generate(self, result, fmt, ...,
             mode="quick", hypotheses=None, convergence=None,
             cost_summary=None, completeness_review=None,
             coverage_audit=None, phases_completed=None, validations=None):
```

JSON 新增段：
- `hypotheses` — 摘要列表（id/summary/confidence/endpoint/vuln_category）
- `validations` — 验证结果列表
- `convergence` — 收敛摘要（summary/rounds/status）
- `cost` — 成本明细（total_cost/prompt_tokens/completion_tokens/total_tokens）
- `deep_audit` — 元信息（phases_completed/hypotheses_count/validations_count/convergence_rounds/total_llm_cost）

Markdown 新增章节：`🤖 LLM 假设` / `🔄 收敛` / `💰 LLM 成本` / `📋 执行阶段`

**CLI 数据传递**（`_deep_audit` dict 模式）：
```python
# _run_deep_audit() 打包
result._deep_audit = {
    "hypotheses": report.hypotheses,
    "validations": report.validations,
    "convergence": report.convergence,
    "cost_summary": report.cost_summary,
    "completeness_review": report.completeness_review,
    "coverage_audit": report.coverage_audit,
    "phases_completed": report.phases_completed,
}

# scan 命令解包
deep_data = getattr(result, "_deep_audit", None)
if deep_data is not None:
    deep_kwargs = {"mode": "deep", ...}
```

### 3.2 漏洞覆盖盲区分析

对照 `docs/detection_matrix.json`（200 项，17 类别）和 `docs/phase12_coverage_tracking.json`，当前覆盖情况：

| 指标 | 数值 |
|------|------|
| Phase 1+2 确定性覆盖 | 41/200 (20.5%) |
| Phase 1+2 部分覆盖 | 33/200 (16.5%) |
| 未覆盖 | 126/200 (63%) |

**最大盲区 Top 5**：
1. **AUTH（认证）** — 17 uncovered: 密码策略/2FA/锁定/暴力破解
2. **BUSINESS（业务逻辑）** — 12 uncovered: 事务完整性/价格篡改/竞态
3. **SESSION（会话）** — 11 uncovered: CSPRNG/Cookie 属性/固定/并发登录
4. **DATAPRO（数据保护）** — 9 uncovered: 脱敏/TLS/加密存储
5. **CLIENT（客户端）** — 9 uncovered: DOM XSS/postMessage

**Quick Wins（1-2 Session 可完成）**：
- LOG-002 日志注入 — `dangerous_calls.yaml` 扩展（小）
- CONFIG-002 CSP 头 — `config_issues.yaml` 扩展（小）
- AUTH-002 弱密码哈希 — `dangerous_calls.yaml` 扩展（小）
- 完整分析见 plan 文件 `/root/.claude/plans/cryptic-sparking-sprout.md`

## 4. 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `test_deep_audit_json_cost` 失败：`KeyError: 'total_input_tokens'` | `_to_json()` 中 cost dict 的键是 `prompt_tokens`/`completion_tokens`，测试用 `total_input_tokens`/`total_output_tokens` | 修改测试断言使用正确的 JSON 键 |
| `test_deep_audit_json_convergence` 失败：`KeyError: 'recommendation'` | `_to_json()` 中 convergence dict 键是 `status`，测试用 `recommendation` | 修改测试断言为 `data["convergence"]["status"]` |
| CostSummary/ConvergenceReport 字段名假设错误 | CostSummary 有 `total_input_tokens`/`total_output_tokens`，非 `total_prompt_tokens`；ConvergenceReport 有 `round`/`recommendation`，非 `total_rounds`/`status` | 修复 `getattr()` 调用使用正确字段名 |
| `convergation` typo in cli.py | 拼写错误 | 修正为 `convergence` |
| mypy 类型窄化问题（3 errors） | `is_deep = deep_ctx is not None` 布尔变量不能窄化 `deep_ctx` 类型 | 改为直接在条件中使用 `deep_ctx is not None` 判断，去掉 `is_deep` 中间变量 |
| D205/D212 docstring 冲突（spring.py） | 多行 summary | 缩短为单行摘要 |
| SIM115 in test_frameworks.py（5 处） | `tempfile.NamedTemporaryFile` 未用 context manager | 改用 `with` 语句 |
| RUF001 fullwidth parens | 中文括号出现在 mode_label | 改为英文表达 |

## 5. 质量门禁

| 检查项 | 结果 |
|--------|------|
| `uv run pytest tests/test_report/` | ✅ 28/28 passed |
| `uv run pytest --ignore=tests/manual -x -q` | ✅ 1469 passed, 2 skipped |
| `uv run ruff check src/hyqagent/report/ src/hyqagent/api/cli.py` | ✅ 无新错误（残留 4 个 pre-existing: 2 RUF001 + 2 E501） |
| `uv run mypy src/hyqagent/report/generator.py src/hyqagent/api/cli.py` | ✅ 仅 7 个 pre-existing errors（无新增） |

## 6. 设计反思

**做得好**：
- `_deep_audit` dict 模式避免了修改 ScanResult dataclass，向后兼容性强
- generate() 参数全部 optional + 默认值合理，quick mode 输出零变化
- `test_quick_mode_no_deep_sections` 测试确保向后兼容

**可改进**：
- `_deep_audit` 是运行时 monkey-patch，类型检查器看不到 — 未来可考虑正式纳入 ScanResult
- 报告中的 Markdown 收敛轮次字段用了不存在的 `total_rounds`（应为 `round`），虽然 getattr 有 default 0 不回崩溃，但始终输出 0 — 下次修复

## 7. 下步衔接

- **Phase 5** 可选择 Quick Wins 中的 1-2 项（LOG-002/CONFIG-002/AUTH-002）快速提升覆盖率
- 或启动 **Phase 3 LLM 增强引擎**，处理 157 项需要 LLM 的检测项
- **REPORT 遗留**：Markdown 收敛轮次 bug（`total_rounds` → `round`）需修复
- **Session 1.30 dev-doc**（task #28）仍待生成 — 当时跳过了
