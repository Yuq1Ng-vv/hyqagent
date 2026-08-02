# HyqAgent Web漏洞全量覆盖矩阵

> 编制时间：2026年8月2日
> 研究方法：4个专业Agent并行研究 + 12+次WebSearch + 多维度交叉验证
> 参考标准：OWASP Top 10 / ASVS V5.0 / WSTG V5 / MITRE CWE Top 25 / CISA KEV / WASC V2 / Bugcrowd VRT / HackerOne / NIST SP 800-30 / CVSS v4.0

---

## 目录

1. [总览：180+漏洞类型 × 五级危害 × 四级检测可行性](#一总览)
2. [CRITICAL级漏洞——穷举挖掘策略](#二critical级漏洞穷举挖掘策略)
3. [HIGH级漏洞——深度挖掘策略](#三high级漏洞深度挖掘策略)
4. [MEDIUM级漏洞——标准挖掘策略](#四medium级漏洞标准挖掘策略)
5. [LOW/INFO级漏洞——自动扫描策略](#五lowinfo级漏洞自动扫描策略)
6. [200项检测能力对照表](#六200项检测能力对照表)
7. [预算与时间分配总表](#七预算与时间分配总表)
8. [输出物清单](#八输出物清单)

---

## 一、总览

### 1.1 研究产出汇总

| Agent | 产出 | 规模 |
|:------|:-----|:-----|
| Agent 1: 漏洞类型全量枚举 | 22大类 180+ 子类型 | 完整枚举 |
| Agent 2: 危害分级框架 | 五级分类 + 七层挖掘阶梯 | 完整框架 |
| Agent 3: 检测策略评估 | 35种漏洞的A→E可行性矩阵 | 矩阵分析 |
| Agent 4: 检测项枚举 | 200项ASVS对齐检测项 | 结构化JSON |

### 1.2 核心统计数据

| 维度 | 数据 |
|:-----|:-----|
| 漏洞类型总数 | **180+** (22大类的所有子类型) |
| CRITICAL级漏洞 | **~35** 种子类型 (占~19%) |
| HIGH级漏洞 | **~45** 种子类型 (占~25%) |
| MEDIUM级漏洞 | **~55** 种子类型 (占~31%) |
| LOW/INFO级 | **~45** 种子类型 (占~25%) |
| 确定性可检测 (A级) | **134** 项 (67%) |
| LLM辅助检测 (B级) | **~43** 项 (21.5%) |
| 需动态验证 (D级) | **~23** 项 (11.5%) |
| 无法自动化 (E级) | **~6** 种漏洞类别 |
| 总检测项 | **200** 项 (17大类) |

### 1.3 检测能力矩阵

```
检测可行性
    A级(确定性) ████████████████████████████████████████ 67%
    B级(LLM辅助) ████████████████ 21.5%
    D级(动态验证) ████████ 11.5%
    E级(无法自动化) ██ <1%
```

### 1.4 危害分级总表

| 级别 | CVSS | 漏洞数量 | 挖掘深度 | 预算占比 | 最低验收标准 |
|:-----|:-----|:--------|:--------|:--------|:----------|
| **CRITICAL** | 9.0-10.0 | ~35 | L1-L7全量 | **40%** | 100% L7人工签字 |
| **HIGH** | 7.0-8.9 | ~45 | L1-L5必选 | **30%** | 95% L4强模型验证率 |
| **MEDIUM** | 4.0-6.9 | ~55 | L1+L3必选 | **20%** | L1规则覆盖率100% |
| **LOW** | 0.1-3.9 | ~30 | L1扫描 | **7%** | L1全量 + 盲区清单 |
| **INFO** | 0 | ~15 | L1自动 | **3%** | 自动汇总 |

---

## 二、CRITICAL级漏洞——穷举挖掘策略

> **原则：宁可多花10倍时间，不能漏掉1个CRITICAL。**
> 遗漏代价：MOVEit单漏洞→$9.2B损失；Log4Shell→全球范围影响。
> 挖掘深度：**7层全量 (L1-L7)**

### 2.1 CRITICAL级漏洞完整清单

#### A类：远程代码执行 (RCE)

| # | 漏洞类型 | CWE | 检测方法 | 检测深度 | 语言 |
|:--|:--------|:----|:--------|:--------|:----|
| C1 | OS命令注入 | CWE-78 | CPG污点: HTTP输入→system/exec/popen | L1-L6 | py/js/java |
| C2 | 代码注入(eval/exec) | CWE-94 | CPG模式: eval/exec/Function() | L1-L6 | py/js |
| C3 | 反序列化RCE(Java) | CWE-502 | CPG污点: 网络输入→readObject() + LLM gadget分析 | L1-L6 | java |
| C4 | 反序列化RCE(Python pickle) | CWE-502 | 确定性: pickle.loads()检测 + CPG数据流 | L1-L6 | py |
| C5 | 反序列化RCE(Node.js) | CWE-502 | 确定性: node-serialize检测 | L1-L3 | js |
| C6 | SSTI RCE (Jinja2/Freemarker/Velocity) | CWE-1336 | CPG污点: 用户输入→render_template_string() | L1-L6 | py/java/js |
| C7 | 表达式语言注入 (Spring EL/OGNL) | CWE-917 | CPG污点: 表达式解析器+用户输入 | L1-L5 | java |
| C8 | 任意文件上传→Webshell | CWE-434 | CPG: 文件上传+可执行扩展名+Web可访问路径 | L1-L6 | py/js/java |
| C9 | XXE→RCE (通过expect://等) | CWE-611 | CPG: XML解析器配置+LLM | L1-L4 | java/py |

#### B类：认证完全绕过

| # | 漏洞类型 | CWE | 检测方法 | 检测深度 | 语言 |
|:--|:--------|:----|:--------|:--------|:----|
| C10 | 关键功能无认证 | CWE-306 | CPG: 敏感操作无auth装饰器 + 多端点交叉验证 | L1-L7 | py/js/java |
| C11 | JWT alg:none | CWE-345 | 确定性: jwt.verify()配置检查 | L1-L3 | js/java/py |
| C12 | JWT密钥混淆(RS256→HS256) | CWE-327 | LLM: 密钥用途分析 | L3-L5 | js/java/py |
| C13 | OAuth账户接管(redirect_uri绕过) | CWE-287 | LLM: OAuth流程分析 + 动态验证 | L3-L7 | js/java/py |
| C14 | SAML签名绕过 | CWE-347 | LLM + 动态 | L3-L6 | java |

#### C类：全量数据泄露

| # | 漏洞类型 | CWE | 检测方法 | 检测深度 | 语言 |
|:--|:--------|:----|:--------|:--------|:----|
| C15 | SQL注入(数据泄露) | CWE-89 | CPG污点: 请求参数→未参数化SQL | L1-L6 | py/js/java |
| C16 | NoSQL注入(数据泄露) | CWE-943 | CPG污点: 请求→$where/$regex操作符 | L1-L4 | js/py |
| C17 | GraphQL内省+全量数据 | CWE-200 | 确定性: GraphQL endpoint+内省开启 | L1-L2 | js/java/py |
| C18 | SSRF→云元数据(IMDS) | CWE-918 | CPG污点: URL参数→HTTP客户端 + 动态OOB | L1-L6 | py/js/java |

#### D类：供应链/基础设施

| # | 漏洞类型 | CWE | 检测方法 | 检测深度 | 语言 |
|:--|:--------|:----|:--------|:--------|:----|
| C19 | 依赖混淆 | CWE-427 | SCA扫描 | L1-L2 | py/js/java |
| C20 | 已知CVE依赖(如Log4Shell) | CWE-1104 | SCA扫描 | L1-L2 | py/js/java |
| C21 | CI/CD管道注入(PPE) | CICD-SEC-4 | 确定性: CI配置分析 | L3-L5 | — |
| C22 | 硬编码生产凭据 | CWE-798 | 正则扫描 + 熵检测 | L1-L2 | py/js/java |

#### CRITICAL挖掘要求

```
每项CRITICAL漏洞的最低挖掘要求：

L1 确定性规则 .......... ✅ 必选 — 运行全部CRITICAL规则集
L2 CPG反向分析 ........ ✅ 必选 — sink→source全量回溯
L3 LLM假设生成 ........ ✅ 必选 — Sonnet+扩展上下文
L4 LLM深度验证 ........ ✅ 必选 — Opus/GPT-5.2全量验证
L5 对抗性审查 ......... ✅ 必选 — 攻击者视角审视"安全"路径
L6 动态PoC验证 ........ ✅ 必选(如可行) — 沙箱构造PoC
L7 人工签字 ........... ✅ 必选 — 安全专家独立审查

验收标准：
- Sink覆盖率: 100% CRITICAL sink经过L2反向分析
- 攻击假设: 每个受污染sink至少3个独立假设
- L4验证率: 100%
- L7审查率: 100%
- 误报率: <10%
```

---

## 三、HIGH级漏洞——深度挖掘策略

> 挖掘深度：**L1-L5必选 (L6可选)**

### 3.1 HIGH级漏洞清单

#### A类：用户账户/会话劫持

| # | 漏洞类型 | CWE | 检测方法 | 语言 |
|:--|:--------|:----|:--------|:----|
| H1 | 存储型XSS | CWE-79 | CPG污点: 输入→存储→HTML渲染(跨请求) | py/js/java |
| H2 | DOM XSS(高危source→sink) | CWE-79 | CPG+LLM: JS data flow | js |
| H3 | CSRF(敏感操作) | CWE-352 | CPG: 状态变更端点无CSRF token | py/js/java |
| H4 | 会话固定 | CWE-384 | 动态: 登录前后session对比 | py/js/java |
| H5 | 会话劫持(Cookie窃取) | CWE-732 | 确定性: Cookie属性检查 | py/js/java |
| H6 | JWT伪造(弱密钥/未验证) | CWE-347 | CPG+LLM: jwt.verify逻辑分析 | js/java/py |
| H7 | OAuth state缺失(登录CSRF) | — | LLM: OAuth流程完整性 | js/java/py |
| H8 | 多因素认证绕过 | CWE-288 | 动态+LLM | py/js/java |

#### B类：敏感数据/内部网络访问

| # | 漏洞类型 | CWE | 检测方法 | 语言 |
|:--|:--------|:----|:--------|:----|
| H9 | SSRF(可访问内部服务) | CWE-918 | CPG污点: URL→HTTP客户端 + LLM验证 | py/js/java |
| H10 | IDOR/水平越权 | CWE-639 | CPG: 资源ID无所有权验证 + 多端点交叉 | py/js/java |
| H11 | 垂直越权 | CWE-269 | CPG: 角色检查不一致 + 多端点交叉 | py/js/java |
| H12 | XXE(文件读取/SSRF) | CWE-611 | CPG: XML解析器配置 | java/py |
| H13 | LFI(敏感文件读取) | CWE-98 | CPG: include/require+用户输入 | py/js/java |
| H14 | Mass Assignment(权限提升) | CWE-915 | CPG: ORM bind()+req.body + LLM | py/js/java |

#### C类：认证/授权逻辑缺陷

| # | 漏洞类型 | CWE | 检测方法 | 语言 |
|:--|:--------|:----|:--------|:----|
| H15 | 密码重置流程缺陷 | CWE-640 | LLM: 业务逻辑分析 | py/js/java |
| H16 | 功能级访问控制缺失 | CWE-862 | CPG: 端点无auth → 多端点交叉验证 | py/js/java |
| H17 | CORS+凭证泄露 | CWE-942 | 确定性: ACA-Origin:* + ACA-Credentials:true | js/py/java |
| H18 | 路径遍历(系统文件) | CWE-22 | CPG: 文件路径←用户输入 | py/js/java |
| H19 | 二阶SQL注入 | CWE-89 | CPG: DB写→DB读→SQL concat(跨请求) | py/js/java |
| H20 | HTTP请求走私 | CWE-444 | 动态验证 | py/js/java |
| H21 | Host头注入(密码重置投毒) | CWE-644 | CPG: Host头→URL生成 | py/js/java |
| H22 | GraphQL字段级授权缺失 | CWE-862 | LLM: Resolver授权逻辑 | js/java/py |

#### HIGH挖掘要求

```
每项HIGH漏洞的挖掘要求：

L1 确定性规则 .......... ✅ 必选
L2 CPG反向分析 ........ ✅ 必选 (重点: XSS/SSRF/IDOR/LFI/认证)
L3 LLM假设生成 ........ ✅ 必选 (Sonnet, 函数+调用链上下文)
L4 LLM深度验证 ........ ✅ 必选 (Opus/GPT-5.2)
L5 对抗性审查 ......... ✅ 必选 (认证/授权逻辑100%审查)
L6 动态PoC验证 ........ ⚠️ 可选 (高置信度发现)

验收标准：
- Sink覆盖率: ≥95%
- L4验证率: ≥90%
- 认证/授权逻辑: 100%经过L5审查
- IDOR/越权覆盖: 所有授权端点都检查了水平/垂直越权
```

---

## 四、MEDIUM级漏洞——标准挖掘策略

> 挖掘深度：**L1+L3必选 (L2+L4按需)**

### 4.1 MEDIUM级漏洞清单

| # | 漏洞类型 | CWE | 检测方法 | 触发L4条件 |
|:--|:--------|:----|:--------|:---------|
| M1 | 反射型XSS | CWE-79 | CPG污点+上下文分析 | 置信度>70% |
| M2 | DOM XSS(低危) | CWE-79 | CPG数据流(JS) | 置信度>70% |
| M3 | CSRF(非敏感操作) | CWE-352 | CPG: 无CSRF保护 | 涉及资金操作 |
| M4 | 业务逻辑(价格/数量/优惠券) | CWE-841 | LLM语义理解 | 财务影响>阈值 |
| M5 | 任意文件上传(非Web目录) | CWE-434 | CPG: 文件类型验证缺失 | 存在路径遍历组合 |
| M6 | CRLF注入(响应头) | CWE-93 | CPG: 响应头←用户输入 | 可链接到XSS |
| M7 | 竞争条件(TOCTOU) | CWE-367 | CPG+LLM: check-then-act模式 | 涉及关键操作 |
| M8 | WebSocket劫持(CSWSH) | CWE-1385 | 动态: Origin验证 | — |
| M9 | Prototype Pollution(无RCE) | CWE-1321 | CPG: merge+__proto__ | 有可行gadget |
| M10 | 缓存投毒 | CWE-644 | 动态验证 | — |
| M11 | 加密弱点(可解密) | CWE-327 | 确定性: 弱算法名匹配 | — |
| M12 | 开放重定向(可用于钓鱼) | CWE-601 | CPG: redirect参数 | 结合OAuth |
| M13 | 模板注入(SSTI低危) | CWE-1336 | CPG: 模板引擎+用户数据 | 模板可被用户控制 |
| M14 | LDAP注入 | CWE-90 | CPG: LDAP筛选器+用户输入 | — |
| M15 | XPath注入 | CWE-643 | CPG: XPath+用户输入 | — |

#### MEDIUM挖掘要求

```
L1 确定性规则 .......... ✅ 必选
L2 CPG反向分析 ........ ⚠️ 仅高发类型(XSS输出点)
L3 LLM假设生成 ........ ✅ 必选 (Sonnet, 函数级)
L4 LLM验证 ........... ⚠️ L3置信度>70%时触发 (Opus)

安全检查：
- 检查MEDIUM漏洞是否可链式组合提升为HIGH
- 对可疑组合进行L4深度分析
```

---

## 五、LOW/INFO级漏洞——自动扫描策略

> 挖掘深度：**L1全量 (L2标注，不强制LLM)**

### 5.1 LOW级漏洞

| # | 漏洞类型 | CWE | 检测方法 |
|:--|:--------|:----|:--------|
| L1 | 详细错误消息泄露 | CWE-209 | 正则: 堆栈跟踪/DB错误输出 |
| L2 | 调试端点暴露 | CWE-489 | URL模式: /debug /actuator /swagger |
| L3 | 版本信息泄露 | CWE-200 | 响应头: Server/X-Powered-By |
| L4 | 目录遍历(无敏感文件) | CWE-548 | 响应: Index of / |
| L5 | 缺失安全头 | CWE-693 | 响应头检查: CSP/HSTS/XFO等 |
| L6 | 默认凭据(非生产) | CWE-1392 | 配置扫描 |
| L7 | Self-XSS | CWE-79 | 报告标注 |
| L8 | 速率限制缺失 | CWE-307 | 端点+无rate-limit中间件 |
| L9 | 开放重定向(无token) | CWE-601 | redirect参数+无白名单 |
| L10 | Cookie缺少SameSite | CWE-1004 | Set-Cookie头检查 |

### 5.2 INFO级

| # | 问题类型 | 检测方法 |
|:--|:--------|:--------|
| I1 | 不安全的默认配置 | 配置基线检查 |
| I2 | DEBUG模式(非生产) | 配置扫描 |
| I3 | HTTP(非HTTPS)公开页面 | URL协议检查 |
| I4 | 不安全的加密模式(理论风险) | 算法名匹配 |
| I5 | 点击劫持(无敏感操作) | 响应头检查 |

---

## 六、200项检测能力对照表

完整的200项检测能力矩阵已保存到 `detection_matrix.json`，包含17大类：

| 大类 | 项目数 | 核心覆盖 |
|:-----|:------|:--------|
| **INPUT** (输入验证) | 27 | 类型/长度/格式/编码/文件上传/XXE/ReDoS |
| **AUTH** (认证) | 20 | 密码策略/多因素/JWT/OAuth/SAML/暴力破解 |
| **CONFIG** (配置) | 13 | DEBUG/CSP/HSTS/CORS/安全头/默认凭据 |
| **CRYPTO** (密码学) | 13 | 算法/AEAD/PRNG/IV/密钥管理/TLS |
| **OUTPUT** (输出编码) | 12 | HTML/JS/CSS/URL编码+JSON/XML序列化 |
| **BUSINESS** (业务逻辑) | 12 | 工作流/金额验证/竞态/幂等/限速 |
| **AUTHZ** (授权) | 12 | 水平/垂直越权/CORS/Mass Assignment/多租户 |
| **SESSION** (会话) | 11 | 令牌生成/Cookie属性/固定/超时/CSRF |
| **DATAPRO** (数据保护) | 11 | 日志脱敏/传输加密/静态加密/最小化 |
| **NETWORK** (网络) | 11 | SSRF/DNS Rebinding/Host头/请求走私/WebSocket |
| **SQL** (数据库) | 10 | 参数化/ORM安全/动态列名/NoSQL/二阶注入 |
| **FILE** (文件系统) | 10 | 路径穿越/符号链接/Zip Slip/临时文件 |
| **MISC** (其他) | 10 | eval/SSTI/CMD注入/LDAP/XPath/整数溢出 |
| **CLIENT** (客户端) | 9 | DOM XSS/postMessage/CSP in SPA/第三方脚本 |
| **LOGGING** (日志) | 7 | 安全事件/注入防护/脱敏/审计链 |
| **DESERIALIZE** (反序列化) | 6 | ObjectInputStream/pickle/Jackson/YAML |
| **SUPPLY** (供应链) | 6 | CVE扫描/EOL/锁文件/SRI/SBOM |

---

## 七、预算与时间分配总表

### 7.1 三级模式对比

| 模式 | 预算 | CRITICAL | HIGH | MEDIUM | LOW/INFO | 估计时间(10万行) | 估计召回率 |
|:-----|:-----|:---------|:-----|:--------|:--------|:---------------|:----------|
| `--quick` | ~$1 | L1-L2 | L1-L2 | L1 | L1 | ~2h | ~25-35% |
| `--standard` | ~$5 | L1-L5 | L1-L5 | L1+L3 | L1+L2 | ~8h | **~50-60%** |
| `--deep` | ~$25 | L1-L7 | L1-L6 | L1-L4 | L1+L3 | ~20h | **~65-75%** |

### 7.2 预算分配可视化

```
CRITICAL (40%)    ████████████████████████████████████████  $2.00/项目 (standard)
HIGH (30%)        ██████████████████████████████            $1.50/项目
MEDIUM (20%)      ████████████████████                      $1.00/项目
LOW (7%)          ███████                                     $0.35/项目
INFO (3%)         ███                                         $0.15/项目
```

### 7.3 CRITICAL级内部细分

```
L1 规则+CPG污点 ...... 10%    ████          $0.20
L2 CPG反向分析 ....... 15%    ██████         $0.30
L3 LLM假设生成 ....... 15%    ██████         $0.30
L4 LLM深度验证 ....... 20%    ████████       $0.40
L5 对抗性审查 ........ 15%    ██████         $0.30
L6 动态PoC验证 ....... 15%    ██████         $0.30
L7 人工审查 .......... 10%    ████           $0.20
```

### 7.4 动态优先级调整

| 信号 | 调整动作 |
|:-----|:--------|
| L1/L2发现≥5个CRITICAL sink受污染 | CRITICAL预算 40%→50% |
| 使用已知高危框架版本(Struts/旧版Spring) | 增加L2反向分析深度 |
| 发现1个已验证的CRITICAL | 启动全量L5对抗性审查 |
| 认证/授权逻辑复杂(多角色/多租户) | HIGH预算 30%→35% |
| 发现eval/exec/system调用 | 立即触发L4强模型 |
| 主要是静态页面/无用户输入 | 降低CRITICAL，增加MEDIUM/LOW |
| 项目有第三方依赖注入 | 增加CRITICAL(供应链) |

---

## 八、输出物清单

| 文件 | 大小 | 内容 |
|:-----|:-----|:-----|
| `RESEARCH.md` | 25KB | 原始研究：20+论文、15+系统对比 |
| `PLAN.md` | 35KB | 完整设计方案：架构+路线图 |
| `COVERAGE-GAP-ANALYSIS.md` | 33KB | 覆盖盲区深度分析（首次研究） |
| `severity_based_vulnerability_mining_framework.md` | 27KB | 五级危害+七层挖掘阶梯框架 |
| `detection_matrix.json` | 142KB | 200项ASVS对齐的结构化检测项 |
| `WEB-VULN-FULL-MATRIX.md` | 本文档 | 全量漏洞覆盖矩阵（最终综合） |

---

> **核心原则重申**：
> 1. **宁可多花时间，不能遗漏CRITICAL/HIGH漏洞**
> 2. **不同危害等级 = 不同挖掘深度，不是"挖不挖"的区别**
> 3. **CRITICAL级必须穷举到L7（人工签字），HIGH级到L5（对抗性审查）**
> 4. **预算向高危倾斜 — CRITICAL+HIGH占70%预算**
> 5. **"我们漏了什么"必须是主动机制，不是被动声明**
