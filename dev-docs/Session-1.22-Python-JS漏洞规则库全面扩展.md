# Session 1.22 — Python/JavaScript 漏洞规则库全面扩展

## 目标

将 Python 和 JavaScript 的 taint rules 从 9 类别扩展到 12 类别，与 Java 对齐，覆盖各自语言的企业级框架生态。

**量化目标**：
- Python: 9 → 12 类别（新增 xxe、ssti、crypto_weakness）
- JavaScript: 9 → 12 类别（新增 xxe、ssti、crypto_weakness）
- 规则量：Python ~226 → ~1077（~5x），JS ~150 → ~1440（~10x）
- 全量测试：883 passed ✅

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/taint_rules.yaml` | 修改 | Python/JS 段完全重写，从 1599 行扩至 2500+ 行 |
| `scripts/expand_py_js_rules.py` | 新增 | 数据驱动的 Python/JS 规则生成脚本，后续可复用 |
| `tests/test_cpg/test_taint_rules_coverage.py` | 修改 | PYTHON_EXPECTED/JS_EXPECTED 从 9→12 类别 |
| `tests/test_cpg/test_e2e_dvna.py` | 修改 | test_parse_xml_not_xxe 改为 test_js_has_xxe_category |

## 实现过程

### 1. 从手工扩展转向数据驱动生成

Session 1.20 的 Java 扩展是手工写 YAML，但 Python 和 JS 的规则量要求同样的规模（1000+ 模式每种语言），手工写太容易出错且不便于维护。

**新方案**：Python 脚本 `scripts/expand_py_js_rules.py` 维护结构化字典：
- `PY_SOURCES` / `PY_SINKS` / `PY_SANITIZERS` — 每个类别一个 list
- `JS_SOURCES` / `JS_SINKS` / `JS_SANITIZERS` — 同上
- `_generate_section()` — 生成完整语言段
- 自动去重、排序、YAML 安全引号

**优势**：
- 新增框架支持只需加条目到对应字典
- 自动处理 YAML 引号（`@`/`$`/`<`/包含引号的字符串）
- 后续 PHP/Go 扩展只需新增类似字典

### 2. YAML 引号处理

遇到三个引号问题：

| 问题 | 表现 | 修复 |
|------|------|------|
| `@` 开头字符串 | `@Query(` 被当作 YAML 锚点 | 所有特殊字符开头的字符串用单引号包裹 |
| 包含 `"` 和 `'` 的字符串 | `'<meta http-equiv="refresh"` 引号冲突 | 双引号包裹 + `\"` 转义 |
| 无引号 `<` 字符 | `<Navigate ` 被当作 YAML 流序列 | 统一引号策略，所有字符串强制引号 |

### 3. 新增类别覆盖

#### Python — 12 类别

| 类别 | Sources | Sinks | Sanitizers | 关键生态 |
|------|---------|-------|------------|---------|
| sql_injection | 40 | 66 | 24 | Django ORM/SQLAlchemy/asyncpg/psycopg2/Peewee/Redis |
| command_injection | 26 | 55 | 4 | subprocess/os/fabric/paramiko/Docker/sh |
| xss | 26 | 61 | 16 | Jinja2/Django/FastAPI/Mako/Tornado/Markdown |
| path_traversal | 28 | 56 | 13 | open/pathlib/shutil/zipfile/tarfile/send_file |
| ssrf | 28 | 94 | 12 | requests/httpx/aiohttp/urllib/socket/gRPC/AWS |
| deserialization | 23 | 83 | 12 | pickle/yaml/marshal/dill/torch/numpy/msgpack/Avro |
| open_redirect | 22 | 30 | 6 | Flask/Django/FastAPI/aiohttp/Tornado/Pyramid |
| code_injection | 26 | 54 | 4 | eval/exec/jinja2/Django template/mako |
| auth_bypass | 20 | 69 | 9 | Flask-Login/Django auth/FastAPI Security/JWT/OAuth |
| **xxe** ★ | 13 | 31 | 6 | lxml/xml.etree/minidom/sax/expat/xmltodict/defusedxml |
| **ssti** ★ | 24 | 21 | 8 | Jinja2/Django Templates/Mako/Tornado |
| **crypto_weakness** ★ | 0 | 24 | 12 | hashlib/cryptography/ssl/random — **纯静态检测** |

**总计**：290 sources, 644 sinks, 143 sanitizers = **1077 patterns**

#### JavaScript — 12 类别

| 类别 | Sources | Sinks | Sanitizers | 关键生态 |
|------|---------|-------|------------|---------|
| sql_injection | 52 | 107 | 22 | Sequelize/TypeORM/Prisma/Knex/Mongoose/MongoDB/pg/mysql2 |
| command_injection | 18 | 57 | 6 | child_process/execa/shelljs/zx/SSH/Docker/K8s/Puppeteer |
| xss | 38 | 89 | 19 | DOM/jQuery/React/Vue/Angular/Svelte/EJS/Handlebars/Pug |
| path_traversal | 17 | 95 | 12 | fs/path/express.static/zip-slip/S3/glob/fs-extra |
| ssrf | 22 | 96 | 16 | fetch/axios/got/superagent/needle/ky/DNS/socket/WebSocket |
| deserialization | 15 | 72 | 12 | node-serialize/serialize-javascript/js-yaml/prototype pollution |
| open_redirect | 17 | 42 | 8 | Express/Koa/Fastify/React/Vue/Angular Router |
| code_injection | 17 | 41 | 7 | eval/Function/vm/Worker/WebAssembly/Puppeteer/Babel |
| auth_bypass | 20 | 70 | 17 | Passport.js/JWT/jose/OAuth2/NextAuth/Supabase/Clerk |
| **xxe** ★ | 11 | 26 | 4 | libxmljs/xmldom/fast-xml-parser/xml2js/sax/jsdom |
| **ssti** ★ | 18 | 38 | 10 | EJS/Pug/Handlebars/Nunjucks/Lodash/Marko/Dust/Edge |
| **crypto_weakness** ★ | 0 | 15 | 13 | crypto.createHash/createCipher/Math.random/tls — **纯静态检测** |

**总计**：282 sources, 993 sinks, 165 sanitizers = **1440 patterns**

### 4. 测试更新

- `PYTHON_EXPECTED`/`JS_EXPECTED` 从 9→12 类别（新增 xxe/ssti/crypto_weakness）
- `test_parse_xml_not_xxe_category` 改为 `test_js_has_xxe_category`（JS 现在有 XXE 类别）
- 添加 `os.environ` 和 `process.env` 到 path_traversal sources（修复 cross-language parity 测试）
- 添加 `.query`/`.body`/`.params`/`.cookies`/`.headers` 到 JS sources（保持 dot-prefixed 兼容）

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| YAML ScannerError: `@` cannot start token | `@Query(` 等未引号 YAML 值 | `_yaml_str()` 强制引号所有值，`@`/`$`/`{`/`<` 等特殊字符统一处理 |
| YAML ParserError: expected block end | `"'<meta http-equiv="refresh""` 引号冲突 | 含 `"` 的字符串用双引号包裹 + `\"` 转义 |
| `$queryRaw` `/` `$executeRaw` 反引号 SyntaxError | Python 字符串中含反引号被解析为未终止字符串 | 切换到单引号 Python 字符串或单引号包裹 |
| `test_source_category_match[js-.query]` 失败 | 新规则只有 `req.query` 不含 `.query` 模式 | 添加 `.query`/`.body`/`.params` 到 JS sources |
| `test_parse_xml_not_xxe_category` 失败 | JS 新增 XXE 类别后测试预期过时 | 改为 `test_js_has_xxe_category` |
| `test_source_category_match[py-os.environ]` 失败 | `os.environ` 不在新的 path_traversal sources | 添加 `os.environ` + `process.env` 到 sources |

## 质量门禁

```
uv run pytest -x --tb=short
  → 883 passed, 2 skipped, 5 warnings in 9.61s ✅

uv run ruff check src/hyqagent/cpg/taint_rules.yaml
  → (YAML file, not Python) ✅

YAML 解析验证：
  - taint_rules.yaml: TaintRuleLoader 成功加载 ✅
  - Python: 12 categories ✅
  - JavaScript: 12 categories ✅
  - Java: 13 categories (unchanged) ✅
```

## 三语言规则规模对比

| | Python | JavaScript | Java |
|---|--------|-----------|------|
| 类别数 | 12 | 12 | 13 |
| Sources | 290 | 282 | 176 |
| Sinks | 644 | 993 | 504 |
| Sanitizers | 143 | 165 | 153 |
| **总计** | **1077** | **1440** | **833** |

Java 因更精确的模式选择（避免 `.print(`/`.write(` 等泛化模式），sinks 数量反而低于 JS/Python。但 Java 的 dangerous_calls（46 条）和 config_issues（41 条）补充了检测能力。

## 设计反思

### 做得好

1. **数据驱动生成脚本**：`expand_py_js_rules.py` 把规则定义与 YAML 输出分离，后续 PHP/Go 扩展只需新增类似字典
2. **YAML 安全引号**：统一处理所有特殊字符，避免手工写 YAML 时的引号地狱
3. **自动化去重排序**：每条规则确保 unique + sorted，便于 diff 和审查
4. **向后兼容**：保留 `.query`/`.body` 等 dot-prefixed 模式，适配 `pat in text` 匹配逻辑

### 可改进

1. **规则验证缺乏**：没有检查 Python source 是否包含至少一个 Django 框架模式（如果目标项目是 Django）
2. **规则性能**：Python 644 sinks + JS 993 sinks 可能显著增加 CPG 扫描时间，需要基准测试
3. **规则质量**：部分 sink 模式可能过于泛化（如 `.query(` 同时是 source 和 sink）
4. **覆盖 JSON 未更新**：`phase12_coverage_tracking.json` 仍以 Java 为准，需要重跑 `generate_phase12_coverage.py` 反映 Python/JS 的新覆盖能力

## 下步衔接

1. **重跑覆盖 JSON**：`uv run python scripts/generate_phase12_coverage.py` 更新覆盖数据
2. **PHP 规则启动**：基于 `expand_py_js_rules.py` 的数据驱动模式，快速添加 PHP (Laravel/Symfony) 规则
3. **Go 规则启动**：Go (net/http/gin/echo/GORM) 规则
4. **规则性能基准**：benchmark `analyze_taint` 三种语言的耗时变化
5. **Phase 3 准备**：Python/JS 规则补齐后，Phase 3 LLM 的输入上下文可以更聚焦
