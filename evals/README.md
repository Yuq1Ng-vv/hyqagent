# HyqAgent Golden Dataset

版本化、标签化的漏洞用例集合，用于确定性回归测试。每次扫描器、污点规则或 CPG 管道变更时，必须通过全部 28 个用例。

## 快速开始

```bash
# 运行所有 golden dataset 测试 (无需 API Key)
uv run pytest tests/eval/test_golden_dataset.py -v

# 仅 taint-path 用例
uv run pytest tests/eval/test_golden_dataset.py -k "taint" -v

# 仅新增 gap-fill 用例
uv run pytest tests/eval/test_golden_dataset.py -k "gap-fill" -v

# 单个用例
uv run pytest tests/eval/test_golden_dataset.py -k "case-001" -v

# 所有 eval 测试 (含 ureport2)
uv run pytest -m eval -v
```

## 数据集结构

`golden_dataset_v1.json` 包含 28 个用例：

| 分组 | 数量 | 说明 |
|------|------|------|
| Group 1: Parity reuse | 14 | 复用现有 parity 测试用例，添加结构化元数据 |
| Group 2: Gap fill | 13 | 填补检测盲区的新用例 (XSS/SSRF/OpenRedirect/Crypto/CSRF/AuthBypass) |
| Group 3: Negative | 1 | 负面用例 — 确保扫描器不在安全代码上误报 |

## 用例字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 唯一标识 `case-NNN` |
| `language` | enum | `python` / `javascript` / `java` |
| `cwe` | string | CWE 编号 |
| `vulnerability_type` | string | 内部分类 (对应 `taint_rules.yaml`) |
| `detection_method` | enum | `cpg_taint` / `config_issue` / `missing_auth` / ... |
| `fixture_file` | string | 相对仓库根路径的 fixture 源文件 |
| `ground_truth.has_finding` | bool | 扫描器是否应检出 |
| `ground_truth.expected_category` | string | 预期的 Finding.category |
| `negative_test` | bool | 如果为 true，扫描器不应检出 (误报测试) |

## 测试层级

### Level 1 — Fixture 完整性
- 文件存在 → 解析成功 → 包含预期标注

### Level 2 — CPG 图构建
- 节点数 > 0 → 边数 > 0 → 函数节点存在 → DATA_FLOW 边存在

### Level 3 — 污点规则匹配
- TaintRuleLoader 匹配 source 模式 → 匹配 sink 模式
- `match_source()` / `match_sink()` 返回非 None

### Level 4 — 负面用例验证
- 安全代码不匹配任何 source/sink 模式 → 零误报

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0.0 | 2026-08-09 | 初始版本 — 28 个用例 (14 reuse + 13 gap-fill + 1 negative) |

## 添加新用例

1. 在 `tests/test_cpg/fixtures/` 中创建 fixture 源文件 (使用 `// $ source=category` / `// $ sink=category` 标注)
2. 在 `golden_dataset_v1.json` 中添加用例条目
3. 运行 `pytest tests/eval/test_golden_dataset.py -k "<new-case-id>" -v` 验证
4. 更新此 README

## 已知盲区

以下领域暂无规则覆盖，标记为 `known-gap` 标签：
- `case-027` — Auth Bypass (Flask `@login_required` 缺失检测依赖框架端点提取)
