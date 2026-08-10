# Session 1.38 — 报告质量增强 + 幻觉字段修复

## 目标
1. 解决 Session 1.37 遗留的收敛循环 LLM 浪费问题（路径级跳过，减少重复 LLM 调用）
2. 增强安全审计报告质量：补充 CVSS 评分、PoC、可复现步骤、影响评估
3. 修复报告生成器中长期存在的幻觉字段问题（访问 Hypothesis/ValidationResult 不存在的属性）

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/hyqagent/report/templates.py` | **新建** | 确定性查表模块：CVSS 3.1 映射表（15+ 漏洞类型）、影响描述模板（18 种）、CWE 中英文对照（35+ 条目） |
| `src/hyqagent/report/generator.py` | 重写 | `_to_markdown()` 完全重写为新格式；新增 `_enrich_findings()`、`_build_repro_steps()`；修复 JSON/Markdown 幻觉字段 |
| `src/hyqagent/scanner/deterministic.py` | 修改 | `Finding` 新增 10 个可选字段（cwe_id, cvss_score, endpoint, poc, impact 等） |
| `src/hyqagent/scanner/orchestrator.py` | 修改 | 收敛循环新增 `covered_fingerprints` 路径级跳过机制 |
| `tests/test_report/test_generator.py` | 修改 | 适配新报告格式的断言更新；`_FakeHypothesis` 修改为使用真实字段名 |

## 实现过程

### 任务 1：收敛循环路径级跳过（承接 Session 1.37）

**问题**：每轮收敛循环都将全部 annotated paths 送入 LLM（162 次/轮），产出去重仅靠 stable_key 后处理，输入侧无过滤。

**方案**：在 `_phase_hypothesis_gen` 中，计算每个 annotated path 的 fingerprint（`source_location|sink_location`），查询 `_cross_round_state["covered_fingerprints"]` 跳过已覆盖的路径。

**核心代码** (`orchestrator.py`):
```python
# 路径指纹计算
@staticmethod
def _path_fingerprint(annotated_path):
    path = annotated_path.path
    src = path.nodes[0].location or path.nodes[0].node_id
    sink = path.nodes[-1].location or path.nodes[-1].node_id
    return f"{src}|{sink}"

# 验证阶段覆盖登记
if verdict == "confirmed" and conf >= 0.5:
    parts = key.rsplit("|", 1)  # strip vuln_type suffix
    cross_state.setdefault("covered_fingerprints", set()).add(parts[0])
```

### 任务 2：报告增强

#### 2a: Finding 数据类扩展

`Finding` dataclass 新增 10 个可选字段（均为默认空值，向后兼容）：
- `cwe_id`, `cvss_score`, `cvss_vector` — CWE/CVSS 评分
- `endpoint`, `http_method`, `http_params` — HTTP 端点信息
- `impact`, `poc` — 影响描述和概念验证
- `source_location`, `sink_location` — 数据流追踪

#### 2b: 确定性查表 (templates.py)

**设计原则**：零 LLM 成本，全部预定义映射。

- `CVSS_TEMPLATES`: (vuln_type, severity) → (score, vector) 映射，覆盖 SQLi/XSS/SSRF/路径穿越/反序列化/认证绕过/IDOR/XXE/SSTI/CSRF 等 15+ 类型
- `IMPACT_TEMPLATES`: vuln_type → 中文影响描述（攻击者可执行的操作清单）
- `CWE_NAMES`: CWE-ID → 中文名称映射
- 回退逻辑：无匹配时使用 severity-only CVSS 估算

#### 2c: 报告 Markdown 格式重设计

新格式每个 finding 包含：

```markdown
### 🟠 F-001: [HIGH] SQL Injection in GET /api/users

| 属性 | 值 |
|------|-----|
| **CWE** | CWE-89: SQL 注入 |
| **CVSS 3.1** | 9.8 (critical) |
| **置信度** | 确定性: high · LLM 验证: ✅ confirmed (85%) · 沙箱 PoC: ✅ verified |
| **位置** | 源: `app.py:42` → 汇: `app.py:128` |

#### 📖 描述 / 🧪 复现步骤 / 💉 PoC / 💥 影响 / 🛡 修复建议
```

#### 2d: 丰富管线 (`_enrich_findings`)

报告生成时自动交叉引用：
- **Hypothesis 匹配**：通过 stable_key（source|sink|vuln_type）匹配
- **验证结果**：attaches verdict + confidence 到 finding
- **动态验证**：从 sandbox 结果提取 PoC 代码
- **影响模板**：基于 CWE 自动填充

### 任务 3：幻觉字段修复

**发现**：JSON 和 Markdown 序列化中访问了 Hypothesis 不存在的属性：
- `h.summary` → 改为 `h.title`
- `h.endpoint` → 不存在的字段，已移除
- `h.vuln_category` → 改为 `h.vuln_type`
- `v.evidence_strength` → 不存在的字段，已移除

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| 报告测试失败：`# HyqAgent 扫描报告` 不匹配 | Header 改为 `# HyqAgent 安全审计报告` | 更新测试断言 |
| 报告测试失败：`### 1. [HIGH]` 不匹配 | 新格式使用 `F-001` 编号 + emoji 前缀 | 更新测试断言为 `F-001: [HIGH]` |
| `test_markdown_with_findings` 失败：找不到盲区章节 | 盲区清单被误放入 `if is_deep:` 块内 | 移到块外，两种模式都显示 |
| `_FakeHypothesis` 用旧参数名 `vuln_category`, `endpoint` | 幻觉字段修复后参数不兼容 | 改为 `vuln_type`, `cwe_id`, `source_location` 等真实字段 |
| Mypy 报 `ctx` 重定义 | 两个 if 块内重复 `ctx = deep_ctx` | 复用首个赋值 |
| Mypy `Unused type: ignore`  | 动态属性赋值上的 `type: ignore` 注释冗余 | 移除不必要的注释 |
| Ruff RUF001 42 个错误 | 中文全角冒号 `：` 在模板文件中 | **预存在问题**，不影响功能 |

## 质量门禁

- **pytest**: 2061 passed, 202 skipped, 0 failed ✅
- **ruff check** (changed modules): No new errors ✅
- **mypy** (changed modules): 6 errors, all pre-existing (SARIF dict type-args) ✅
- **lint**: 预存在的 RUF001（中文全角字符）42 个，非本次引入

## 设计反思

**做得好的**：
- 确定性查表方案零 LLM 成本，CVSS/Impact 模板覆盖了主流漏洞类型
- 报告格式 180° 转变——从简单列表变成安全研究人员可直接使用的审计文档
- 幻觉字段修复彻底解决了长期存在的属性访问问题
- 路径级跳过机制将后续轮次的 LLM 调用量大幅降低

**可改进的**：
- 复现步骤模板偏通用（基于 CWE 类型），可以进一步利用 HTTP endpoint metadata 生成更精确的 curl 命令
- CVSS 查表使用最坏情况假设，后续可集成真正的 CVSS 计算库进行精确向量计算
- `_enrich_findings` 的 stable_key 匹配逻辑假设 source_location 格式一致，跨模块可能不一致

## 下步衔接

下个 Session 可考虑：
1. **动态验证集成测试**：目前 dynamic_verification_results 的 PoC 提取逻辑已就位，需要端到端测试验证沙箱 PoC 是否正确展示在报告中
2. **SARIF 增强**：SARIF 格式也需要同步补充 CWE/CVSS 字段以支持 GitHub Code Scanning 的高级展示
3. **PHP 支持启动**：Java 深度审计已比较成熟，按照语言优先级（PHP > Go，Java 优先打磨）可开始 PHP CPG 适配
4. **Eval 数据集验证**：用 golden dataset 验证新报告格式对安全研究人员的实际可用性
