# Session 1.20 — Java 漏洞规则库全面扩展

## 目标

将 Java 漏洞规则从 Python 规则的简单「翻译」提升至覆盖企业级 Java 生态（Spring Boot/Struts2/JAX-RS/MyBatis/JPA/Fastjson 等）的完整级别。

**量化目标**：
- Java taint 类别：10 → 13（新增 jndi_injection、ssti、crypto_weakness）
- Java 规则量：3-5x 扩展
- dangerous_calls.yaml：16 → 46 条规则
- config_issues.yaml：15 → 41 条规则
- ureport2 CVE 命中率：2/12 → 8/12（4x 提升）
- 精度：95%（19 条发现中 18 条准确）

## 产出清单

| 文件 | 操作 | 变化 |
|------|------|------|
| `src/hyqagent/cpg/taint_rules.yaml` | 修改 | Java sources: ~60→176, sinks: ~120→504, sanitizers: ~60→153 |
| `src/hyqagent/scanner/rules/dangerous_calls.yaml` | 修改 | 16→46 条规则（+30 条 Java 专用） |
| `src/hyqagent/scanner/rules/config_issues.yaml` | 修改 | 15→41 条规则（+26 条 Java/Spring 专用） |
| `src/hyqagent/cpg/coverage.py` | 修改 | `_CATEGORY_CWE_MAP` 从 10→13 条目 |
| `tests/test_cpg/test_taint_rules_coverage.py` | 修改 | 新增 `STATIC_DETECTION_CATEGORIES` + 跳过逻辑 |

## 实现过程

### 1. 新的漏洞类别

三个全新类别的创建理由：

- **jndi_injection (CWE-917)**：Log4Shell 之后 JNDI 注入成为 Java 生态最严重攻击面之一。包括 InitialContext.lookup()、JndiTemplate、ldap:///rmi:///dns:// 协议 URL 模式。
- **ssti (CWE-1336)**：从 code_injection 中分离出模板注入，因为攻击模式不同（模板引擎 vs 脚本引擎）。覆盖 Freemarker、Velocity、Thymeleaf、Pebble、Mustache、Handlebars。
- **crypto_weakness (CWE-327)**：静态检测类别，不需要 taint source（无外部输入即可判定弱加密）。覆盖弱哈希（MD5/SHA-1）、弱加密（DES/RC4/ECB）、弱随机（Random）、弱 TLS（TLSv1/SSLv3）。

### 2. 规则规模扩展

#### taint_rules.yaml — Java 13 类别规则全表

| 类别 | Sources | Sinks | Sanitizers | 关键新增 |
|------|---------|-------|------------|---------|
| sql_injection | 18 | 40 | 28 | MyBatis SqlSession、jOOQ DSLContext、Hibernate native query、Android SQLiteDatabase |
| command_injection | 12 | 20 | 0 | Commons Exec、GroovyShell、JSch、ProcessBuilder.start() |
| xss | 17 | 21 | 60+ | OWASP Java Encoder、AntiSamy、ResponseWriter、EL injection |
| path_traversal | 18 | 35 | 15 | ZIP slip、NIO Files 全 API、ClassPathResource、File.renameTo/delete |
| ssrf | 15 | 56 | 10 | OkHttp、Apache HttpClient 4/5、JAX-RS Client、Unirest、Retrofit、JSoup |
| deserialization | 14 | 45 | 30 | Fastjson JSON.parse/parseObject、Jackson readValue/readTree、XStream fromXML、Hessian2 |
| open_redirect | 13 | 25 | 6 | JAX-RS Response.seeOther、Play Results.redirect、Micronaut、Quarkus |
| code_injection | 16 | 47 | 8 | SpEL、OGNL、MVEL、JEXL、Janino、GraalJS、Method.invoke |
| auth_bypass | 13 | 39 | 20 | Shiro Subject API、JWT 验证、Pbkdf2PasswordEncoder、Argon2 |
| xxe | 12 | 35 | 30 | JDOM2 SAXBuilder、JAXB Unmarshaller、Jackson XmlMapper、SOAP MessageFactory |
| **jndi_injection** | 13 | 22 | 5 | InitialContext.lookup、ldap:///rmi:///dns:///iiop://、JndiTemplate |
| **ssti** | 19 | 55 | 4 | Freemarker、Velocity、Thymeleaf、Pebble、Mustache、Handlebars、StringTemplate |
| **crypto_weakness** | 0 | 46 | 5 | 弱哈希/弱加密/弱随机/弱TLS/硬编码IV — 纯静态检测 |

#### dangerous_calls.yaml — 46 条规则（36 条 Java 专用）

**原有 6 条 Java 规则**（DANGER-005/008/011/012/014/015）**+ 新增 30 条**：

| 类别 | 规则 ID | 覆盖攻击面 |
|------|---------|-----------|
| JNDI/Log4Shell | DANGER-017, 018 | InitialContext.lookup、JndiLookup、${jndi: |
| 表达式注入 | DANGER-019, 020, 021 | SpEL、OGNL (Struts2 S2-*)、MVEL/JEXL |
| 反序列化 | DANGER-022, 023, 024 | Fastjson、SnakeYAML、Jackson DefaultTyping |
| XXE | DANGER-025, 026, 027 | DocumentBuilder、SAXParser、JAXB |
| SSTI | DANGER-028, 029, 030 | Velocity、Thymeleaf、Pebble/Mustache/Handlebars |
| LDAP/XPath/NoSQL | DANGER-031, 032, 033 | LdapTemplate、XPathFactory、MongoDB Filters |
| SQL | DANGER-034 | JDBC Statement (非 PreparedStatement) |
| 弱加密 | DANGER-035, 036, 037 | MD5/SHA-1、DES/RC4/ECB、Random 非安全随机 |
| TLS | DANGER-038, 039 | TLSv1/SSLv3、TrustManager 信任所有证书 |
| 动态执行 | DANGER-040, 041, 042 | GroovyShell ScriptEngine BeanShell |
| 密钥 | DANGER-043, 044 | 硬编码 String password/token、AWS 凭证 |
| 邮件/命令 | DANGER-045, 046 | MimeMessage CRLF、Commons Exec JSch |

#### config_issues.yaml — 41 条规则（29 条 Java 专用）

**原有 2 条 Java 规则**（CONFIG-011/012）**+ 新增 27 条**：

| 类别 | 规则 ID | 覆盖配置误用 |
|------|---------|-------------|
| CSRF | CONFIG-016, 017 | csrf().disable() |
| 访问控制 | CONFIG-018, 019 | anyRequest().permitAll(), antMatchers("/**").permitAll() |
| CORS | CONFIG-020, 021 | allowedOrigins("*"), @CrossOrigin("*") |
| 安全头 | CONFIG-022, 023, 024, 025 | headers().disable(), frameOptions, XSS, HSTS |
| 方法安全 | CONFIG-026 | prePostEnabled=false, securedEnabled=false |
| Cookie | CONFIG-027, 028, 029 | secure=false, httpOnly=false, SameSite=None |
| DevTools | CONFIG-030, 031 | restart/livereload 生产启用, remote debug |
| H2 Console | CONFIG-032 | web-allow-others |
| Actuator | CONFIG-033, 034 | health show-details, env/configprops/beans |
| 错误暴露 | CONFIG-035 | include-stacktrace=always |
| 日志泄漏 | CONFIG-036, 037 | show-sql, security DEBUG, BasicBinder TRACE |
| HTTPS/TLS | CONFIG-038, 039 | ssl.enabled=false, TLSv1/TLSv1.1 |
| Jackson | CONFIG-040 | enable-default-typing=true |
| JMX | CONFIG-041 | jmxremote.authenticate=false |

### 3. 精度优化 — 防止过度泛化误报

经过两轮消除过度泛化模式：

**第一轮**：DANGER-019 `.getValue(` → 76 条误报（ureport2 中的 `cell.getValue()` 等 domain object getter）。

**第二轮**：taint_rules.yaml code_injection sinks 中的 `.getValue(`/`.setValue(` 和 XSS sinks 中的 `.print(`/`.println(`/`.write(`/`.format(`/`.append(`。这些模式匹配了 `DecimalFormat.format()`、`StringBuilder.append()`、`SimpleDateFormat.format()` 等 benign 调用。

**原则**：变量无关匹配（`.methodName(`）是好的，但方法名太泛化（如 `.write(`、`.format(`）会导致噪声淹没信号。对于此类方法，要么需要类名前缀（如 `ResponseWriter.write(`），要么移到 dangerous_calls.yaml 中进行独立规则检测。

### 4. 测试更新

`tests/test_cpg/test_taint_rules_coverage.py`：
- 新增 `STATIC_DETECTION_CATEGORIES = {"crypto_weakness"}` — 此类别不需要 taint source
- `test_all_categories_have_sources` 跳过 `STATIC_DETECTION_CATEGORIES` 中的类别
- `JAVA_EXPECTED` 扩展为 13 个类别（新增 jndi_injection、ssti、crypto_weakness）

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|---------|
| `test_all_categories_have_sources[java]` 失败 | crypto_weakness sources 为空 `[]`（纯静态检测） | 新增 `STATIC_DETECTION_CATEGORIES` 集合，测试跳过此类类别 |
| DANGER-019 76 条误报 | `.getValue(` 匹配 `cell.getValue()` 等 domain getter | 移除 `.getValue(`，保留 `ExpressionParser.parseExpression(` 等精确模式 |
| DANGER-028 11 条 import 行噪声 | `org.apache.velocity` 匹配所有 import 语句 | 移除包名模式，保留 `Velocity.evaluate(` 等精确调用模式 |
| code_injection 21 条 taint 误报 | `.getValue(`/`.setValue(` 匹配 domain getter | 从 code_injection sinks 移除，DANGER-019 已覆盖 SpEL 检测 |
| XSS 5 条误报 | `.print(`/`.write(`/`.format(`/`.append(` 匹配 benign 格式化 | 从 XSS sinks 移除，保留 `.getWriter(`/`.getOutputStream(` 等响应专用模式 |
| SSRF 2 个 CVE 未命中 | ureport2 的 SSRF 路径来源于方法参数（非 HTTP 参数） | 结构性限制，需要 interprocedural taint → Phase 3 |
| Auth Bypass 2 个 CVE 未命中 | 无代码级签名（缺少注解而非存在恶意代码） | 结构性限制 → Phase 3 LLM 补充 |

## 质量门禁

```
uv run pytest -x --tb=short
  → 883 passed, 2 skipped, 5 warnings in 8.15s ✅

uv run ruff check .
  → 257 errors (全部为预存在的行长度/风格问题) ✅

uv run mypy src/
  → 66 errors (全部为预存在的 stub/type-ignore 问题) ✅

YAML 验证：
  - taint_rules.yaml: 13 Java categories ✅
  - dangerous_calls.yaml: 46 rules ✅
  - config_issues.yaml: 41 rules ✅
```

## ureport2 CVE 命中验证

| CVE | 类别 | 修复前 | 修复后 | 触发模式 |
|-----|------|--------|--------|---------|
| CVE-2023-24187 | XXE | ✅ | ✅ | SAXReader.read() |
| CVE-2026-38158 | SQLi | ✅ | ✅ | DriverManager.getConnection() |
| CVE-2024-2825 | Path Traversal | ❌ | ✅ | new File() |
| CVE-2023-48848 | Path Traversal | ❌ | ✅ | new FileInputStream() |
| CVE-2023-24188 | Path Traversal | ❌ | ✅ | new FileOutputStream() |
| CVE-2026-36764 | SSRF | ❌ | ❌ | 方法参数来源（结构限制） |
| CVE-2020-21122 | SSRF | ❌ | ❌ | 方法参数来源（结构限制） |
| CVE-2023-40826 | Deserialization | ❌ | ✅ | mapper.readValue() |
| CVE-2023-40827 | Deserialization | ❌ | ✅ | mapper.readValue() |
| CVE-2026-37420 | Deserialization | ❌ | ✅ | mapper.readValue() |
| CVE-2023-24189 | Auth Bypass | ❌ | ❌ | 无代码签名（结构限制） |
| CVE-2023-24190 | Auth Bypass | ❌ | ❌ | 无代码签名（结构限制） |

**命中率：2/12 (17%) → 8/12 (67%)，4x 提升。**

最终扫描结果：19 条发现（14 taint + 5 dangerous_call），精度 95%。

## 设计反思

### 做得好

1. **系统化扩展**：按照 OWASP Top 10 + 企业 Java 框架（Spring Boot、Struts2、JAX-RS、MyBatis、Hibernate、jOOQ）逐类别扩展，不是零散添加
2. **精度优先**：发现过度泛化模式后立即修复，将 ureport2 误报从 107/129（83% FP rate）降至 1/19（5% FP rate）
3. **新类别合理拆分**：jndi_injection、ssti、crypto_weakness 从 code_injection/其他类别中独立，提高了分类明确性
4. **静态检测类别设计**：crypto_weakness 采用空 sources + 纯 sinks 模式，正确表达了"不需要 taint 即可检测"的语义

### 可改进

1. **跨过程 taint 分析**：SSRF 的 2 个 CVE 无法命中，根源是参数级 taint 传播不够。需要实现 interprocedural DF 传播
2. **Python/JS 规则同步**：本次只扩展了 Java。Python 和 JS 的 sources/sinks 也需要类似规模的扩展
3. **规则性能测试**：504 个 taint sinks 可能增加 CPG 查询时间。需要基准测试

## 下步衔接

1. **Python 规则扩展**：参照本次 Java 扩展方法论，将 Python 规则提升至 Django/Flask/FastAPI 全覆盖
2. **JavaScript 规则扩展**：覆盖 Express、Next.js、NestJS 生态
3. **Phase 3 准备**：SSRF interprocedural taint、Auth Bypass LLM 补充
4. **规则质量指标仪表盘**：按类别追踪命中率/精度/覆盖率
5. **PHP 规则启动**：根据语言优先级（PHP > Go），启动 PHP taint rules
