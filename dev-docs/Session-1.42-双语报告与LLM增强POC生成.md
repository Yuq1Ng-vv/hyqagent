# Session 1.42 — 双语报告与 LLM 增强 PoC 生成

## 目标

1. **双语报告**：Markdown 报告同时生成中文（CN）和英文（EN）两个版本，CLI 层自动拆分为 `_cn.md` 和 `_en.md` 两个文件
2. **强制 PoC**：每个 Finding 都必须在报告中提供 PoC，动态验证不可用时生成基于代码分析的假设性 PoC
3. **LLM 增强 PoC**：在 deep audit 模式下，使用 LLM 分析实际代码上下文来生成更精准的 PoC（而非纯启发式生成）

## 产出清单

| 文件 | 改动类型 | 说明 |
|------|----------|------|
| `src/hyqagent/report/generator.py` | 重构 | 双语标签系统、PoC 生成模块、LLM 增强接口 |
| `src/hyqagent/api/cli.py` | 修改 | 双语文件拆分输出、LLM Provider 注入 |

### generator.py 关键改动

**双语标签系统**：
- 新增 `_L` 标签字典（~260 行），包含 CN/EN 键，覆盖所有 UI 字符串
- 新增 `BILINGUAL_SPLIT` 常量 `<!-- BILINGUAL_SPLIT -->` 作为中英文分隔符
- `_to_markdown()` 接受 `lang` 参数，所有 section label 通过 `_L[lang]` 查找
- `generate()` 在 Markdown 模式下生成两份报告并用分隔符拼接

**PoC 生成模块**：
- `_build_poc_section()` — 每个 Finding 强制渲染 PoC 段落
- `_generate_hypothetical_poc()` — 基于代码分析的 PoC 生成（提取变量名、推断端点、构造 curl）
- `_build_concrete_poc()` — 生成可直接复制粘贴的 curl/HTTPie 命令
- `_build_code_aware_poc_desc()` — 生成代码感知的 PoC 描述
- `_extract_variable_names()` — 从代码片段提取变量名
- `_infer_endpoint()` — 从文件路径推断 REST 端点
- `_infer_http_method()` — 从漏洞类型推断 HTTP 方法
- `_resolve_param_names()` — 解析 HTTP 参数名
- 按漏洞类型的解释函数：`_explain_sqli_cn()`, `_explain_xss_cn()`, `_explain_ssrf_cn()`, `_explain_cmdi_cn()`, `_explain_path_traversal_cn()`, `_explain_deser_cn()`, `_explain_ssti_cn()`, `_explain_generic_cn()` 及对应的 EN 版本

**LLM 增强 PoC**：
- `ReportGenerator.__init__(poc_llm=...)` — 接受可选的 LLM 调用接口
- `enrich_findings_pocs(findings, language)` — **异步**方法，对每个 Finding 调用 LLM 获取增强 PoC
- `_llm_enhance_poc(finding, language)` — 构造 prompt 并调用 LLM，返回特定于代码的 PoC
- 信号量限流（Semaphore(3)）避免并发调用过载
- LLM 调用失败时静默降级（best-effort，不影响报告生成）

### cli.py 关键改动

**双语文件拆分**：
- `_write_report_files()` — 检测 `BILINGUAL_SPLIT` 标记，拆分为 `report_cn.md` + `report_en.md`
- 非 Markdown 格式（JSON/SARIF）保持单文件输出

**LLM Provider 注入**：
- `_create_poc_llm(config)` — 从 `HyqAgentConfig` 创建 `poc_llm` 可调用对象
  - 支持 OpenAI 和 Anthropic 两种 provider
  - 返回 `async (system_prompt, user_prompt) -> str` 签名
  - API Key 不可用时返回 `None`（优雅降级）
- `scan --deep` 路径：创建 `poc_llm` → 注入 `ReportGenerator` → 调用 `enrich_findings_pocs()`
- `resume` 路径：同样注入 config 和 LLM PoC 增强

## 实现过程

### 1. 双语报告设计

**核心问题**：如何在不破坏现有 JSON/SARIF 格式的前提下支持双语 Markdown？

**方案**：分隔符模式
1. `_to_markdown(lang="cn")` 生成中文报告
2. `_to_markdown(lang="en")` 生成英文报告
3. `generate()` 中拼接：`cn + BILINGUAL_SPLIT + en`
4. CLI 层 `_write_report_files()` 检测分隔符并拆分写入

### 2. PoC 生成策略

**核心问题**：没有动态验证（`--verify`）时如何生成有意义的 PoC？

**方案**：代码分析驱动的启发式 PoC
1. 从 Finding 的 code_snippet 中提取变量名（正则匹配参数/变量模式）
2. 从 file_path 推断 REST 端点（如 `users.py` → `/api/users`）
3. 从漏洞类型推断 HTTP 方法（SQLi → POST, IDOR → GET）
4. 从 http_params 解析参数名
5. 构造具体的 curl 命令而非泛型模板

### 3. LLM 增强架构

**核心问题**：如何在不改变同步报告生成流程的前提下集成异步 LLM 调用？

**方案**：预增强（pre-enrichment）模式
1. 报告生成前，CLI 层调用 `await generator.enrich_findings_pocs()`
2. 该方法将 LLM 生成的 PoC 直接写入 `finding.poc` 字段
3. `_build_poc_section()` 检测到 `finding.poc` 已有值（来自 LLM），直接使用，跳过启发式生成

```
CLI scan --deep
  → asyncio.run(_run_deep_audit(...))     # 深度审计
  → _create_poc_llm(config)               # 创建 LLM callable
  → ReportGenerator(poc_llm=...)          # 注入
  → asyncio.run(generator.enrich_findings_pocs(...))  # 预增强
  → generator.generate(...)                # 生成报告（同步）
```

### 4. 变量名提取

`_extract_variable_names(code_snippet)` 使用多层正则：
1. Python f-string: `\{(\w+)\}`
2. Python %-formatting: `%\s*\(?\s*(\w+)`
3. 函数参数: `\((\w+)\)`
4. 赋值语句: `(\w+)\s*=` (排除关键字)
5. 通用标识符

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| ruff N806: Variable `L` should be lowercase | `L = _L[lang]` 在 20+ 方法中使用 | sed 批量替换 `L` → `labels` |
| ruff E501: 行过长（15 处） | 标签字符串和表格头超 100 字符 | 拆分 f-string / 多行字符串 |
| ruff SIM108: if-else 可用三元表达式 | `if endpoint: target = endpoint else: target = _infer_endpoint(...)` | 改为 `target_path = endpoint or _infer_endpoint(...)` |
| ruff D417: docstring 缺参数描述 | `_to_markdown()` 的 docstring 未列出所有参数 | 添加完整的 Args 段落 |
| ruff S110: try-except-pass | PoC 增强的异常处理使用裸 pass | 改为 `_log.debug("poc_llm_enrich_failed", exc_info=True)` |
| mypy: ProviderConfig 类型冲突 | openai 和 anthropic 分支 import 同名类 | 改用模块级 import：`_openai.ProviderConfig` / `_anthropic.ProviderConfig` |
| ruff I001: import 排序 | 别名 import 与非别名 import 同模块 | 改用模块级 import 避免同模块多行导入 |

## 质量门禁

```
ruff check src/hyqagent/report/generator.py src/hyqagent/api/cli.py
→ All checks passed!

mypy src/hyqagent/api/cli.py
→ Clean (generator.py 有 5 个预存错误，非本次引入)

pytest tests/ -x --ignore=tests/manual -q
→ 2061 passed, 202 skipped, 5 warnings in 24.44s
```

## 设计反思

### 做得好的
- **分隔符模式**简单可靠：CLI 层不需要知道报告内部结构，只检测一个标记字符串
- **pre-enrichment 模式**解决了同步/异步阻抗匹配问题，且保持报告生成器纯同步
- **优雅降级**：PoC 增强失败不影响报告生成，LLM 不可用时回退到启发式 PoC
- **信号量限流**避免了深检时大量 Finding 同时调用 LLM 导致的速率限制

### 可改进的
- `_L` 标签字典目前 ~260 行，未来模板内容增多后可考虑抽到独立 YAML 文件
- `_explain_*_cn()` 和 `_explain_*_en()` 函数代码重复度较高（CN/EN 成对出现），可考虑模板化
- PoC LLM prompt 当前硬编码在 `_llm_enhance_poc()` 中，应抽到 `prompts/` 目录的 YAML 模板
- `templates.py` 中的模板数据（impact 描述、prerequisites 等）目前仅中文，英文报告仍用中文模板内容

## 下步衔接

1. **模板英文化**：`templates.py` 的 impact/CVSS/prerequisites/proof_of_impact 需要英文版本，使英文报告完全英语化
2. **PoC Prompt 外部化**：将 `_llm_enhance_poc()` 的 system_prompt 和 user_prompt 模板移到 `prompts/` 目录
3. **报告质量评估**：对比 LLM 增强前后的 PoC 质量，建立评估基准
4. **性能优化**：当前对每个 Finding 逐一调用 LLM 增强 PoC，可考虑批量模式（一次 LLM 调用处理多个 Finding）
