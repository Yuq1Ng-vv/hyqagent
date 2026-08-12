"""report/templates.py — Deterministic lookup tables for security report enrichment.

Zero-LLM: all templates are pre-defined mappings from vuln_type + severity
to CVSS scores, business impact descriptions, and CWE names.

Used by :class:`ReportGenerator` and :class:`Orchestrator` to enrich findings
without additional LLM cost.
"""

from __future__ import annotations

# ── CVSS 3.1 Base Scores ─────────────────────────────────────────────────────
# Format: (vuln_type, severity) → (base_score, vector_string)
# Based on CVSS v3.1 specification with typical worst-case assumptions.

CVSS_TEMPLATES: dict[tuple[str, str], tuple[float, str]] = {
    # ── Injection ──
    ("sql_injection", "critical"): (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    ("sql_injection", "high"): (
        8.6,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    ("sql_injection", "medium"): (
        6.3,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    ),
    ("command_injection", "critical"): (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    ("command_injection", "high"): (
        8.4,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    ("code_injection", "critical"): (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    ("code_injection", "high"): (
        8.4,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    ("ssti", "critical"): (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    ("ssti", "high"): (
        8.4,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    # ── XSS ──
    ("xss", "high"): (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    ),
    ("xss", "medium"): (
        5.4,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ),
    ("xss", "critical"): (
        8.2,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    ),
    # ── SSRF ──
    ("ssrf", "critical"): (
        9.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    ("ssrf", "high"): (
        8.6,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    ),
    ("ssrf", "medium"): (
        6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ),
    # ── Path Traversal ──
    ("path_traversal", "high"): (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    ("path_traversal", "critical"): (
        9.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    # ── Deserialization ──
    ("deserialization", "critical"): (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    ("deserialization", "high"): (
        8.1,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    # ── Auth / IDOR ──
    ("auth_bypass", "critical"): (
        9.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    ("auth_bypass", "high"): (
        8.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ),
    ("idor", "high"): (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    ("idor", "medium"): (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    # ── XXE ──
    ("xxe", "critical"): (
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    ("xxe", "high"): (
        8.6,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    ),
    # ── Crypto ──
    ("crypto_weakness", "high"): (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    ("crypto_weakness", "medium"): (
        5.9,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    # ── CSRF ──
    ("csrf", "high"): (
        8.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    ),
    ("csrf", "medium"): (
        6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    ),
    # ── Info Disclosure ──
    ("info_disclosure", "medium"): (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ),
    ("info_disclosure", "high"): (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ),
    # ── Open Redirect ──
    ("open_redirect", "medium"): (
        6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    ),
    ("open_redirect", "low"): (
        4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    ),
    # ── Race Condition ──
    ("race_condition", "high"): (
        7.0,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ),
    # ── Business Logic ──
    ("business_logic", "high"): (
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    ),
    ("business_logic", "medium"): (
        5.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    ),
}

# ── Impact Descriptions ──────────────────────────────────────────────────────
# Business impact descriptions per vulnerability type, written for security
# researchers and engineering leads.  Each entry is a concise bullet list
# of concrete attacker capabilities.

IMPACT_TEMPLATES: dict[str, str] = {
    "sql_injection": (
        "攻击者可以：\n"
        "- 读取/修改/删除数据库中的任意数据\n"
        "- 提取用户密码哈希、PII、会话令牌等敏感信息\n"
        "- 通过 UNION 注入跨表读取\n"
        "- 在支持堆叠查询时执行任意 SQL（如 DROP TABLE）\n"
        "- 在特定配置下通过 INTO OUTFILE 写入 webshell"
    ),
    "command_injection": (
        "攻击者可以：\n"
        "- 在服务器上执行任意系统命令\n"
        "- 读取文件系统中的任意文件\n"
        "- 下载并执行恶意程序\n"
        "- 横向移动到内网其他主机\n"
        "- 建立持久化后门"
    ),
    "xss": (
        "攻击者可以：\n"
        "- 在受害者浏览器中执行任意 JavaScript\n"
        "- 窃取会话 Cookie 并劫持用户会话\n"
        "- 重定向用户到钓鱼页面\n"
        "- 篡改页面内容进行社会工程攻击\n"
        "- 配合 CSRF 执行敏感操作"
    ),
    "ssrf": (
        "攻击者可以：\n"
        "- 使服务器向内部网络发起请求\n"
        "- 访问云元数据服务（AWS IMDSv1/GCP metadata）获取凭据\n"
        "- 扫描内网拓扑和开放端口\n"
        "- 攻击内网中未加固的服务\n"
        "- 绕过防火墙和 ACL 限制"
    ),
    "path_traversal": (
        "攻击者可以：\n"
        "- 读取服务器上的任意文件（/etc/passwd、源码、配置文件）\n"
        "- 获取数据库凭据、API 密钥等敏感配置\n"
        "- 在特定条件下写入文件（日志投毒 → RCE）\n"
        "- 读取应用源码以发现更多漏洞"
    ),
    "code_injection": (
        "攻击者可以：\n"
        "- 在服务器上执行任意代码\n"
        "- 完全控制应用服务器\n"
        "- 读取/修改/删除文件系统中的任意数据\n"
        "- 以应用进程身份执行系统命令"
    ),
    "ssti": (
        "攻击者可以：\n"
        "- 在服务器端模板上下文中执行任意代码\n"
        "- 读取服务器文件系统中的敏感文件\n"
        "- 远程代码执行（RCE）\n"
        "- 完全控制应用服务器"
    ),
    "deserialization": (
        "攻击者可以：\n"
        "- 通过构造恶意序列化数据实现远程代码执行\n"
        "- 实例化任意类并触发 gadget chain\n"
        "- 完全控制应用服务器\n"
        "- 绕过所有应用层安全控制"
    ),
    "xxe": (
        "攻击者可以：\n"
        "- 读取服务器上的本地文件（/etc/passwd、配置等）\n"
        "- 发起 SSRF 攻击访问内部服务\n"
        "- 通过 Billion Laughs 攻击导致拒绝服务\n"
        "- 在极少数情况下实现远程代码执行"
    ),
    "auth_bypass": (
        "攻击者可以：\n"
        "- 绕过身份验证机制\n"
        "- 以任意用户身份访问受保护的功能\n"
        "- 访问管理员接口和敏感操作\n"
        "- 在未授权的情况下执行特权操作"
    ),
    "idor": (
        "攻击者可以：\n"
        "- 通过修改资源 ID 访问其他用户的数据\n"
        "- 查看/修改/删除不属于自己的资源\n"
        "- 枚举所有用户数据（水平越权）\n"
        "- 访问管理员专属功能（垂直越权）"
    ),
    "csrf": (
        "攻击者可以：\n"
        "- 诱导已登录用户执行非预期的操作\n"
        "- 修改用户密码/邮箱/安全设置\n"
        "- 发起转账、下单等金融操作\n"
        "- 以受害者身份执行任意应用功能"
    ),
    "open_redirect": (
        "攻击者可以：\n"
        "- 将用户重定向到钓鱼网站\n"
        "- 窃取 OAuth 授权码或访问令牌\n"
        "- 绕过链接白名单检查\n"
        "- 结合 XSS 进行更复杂的攻击"
    ),
    "crypto_weakness": (
        "攻击者可以：\n"
        "- 暴力破解弱哈希（如 MD5/SHA1 在 GPU 上秒级破解）\n"
        "- 解密弱加密算法保护的数据\n"
        "- 伪造数字签名\n"
        "- 推测硬编码密钥并解密敏感通信"
    ),
    "info_disclosure": (
        "攻击者可以：\n"
        "- 获取应用内部实现细节（错误堆栈、调试信息）\n"
        "- 枚举用户/资源（通过不同响应差异）\n"
        "- 发现隐藏的 API 端点\n"
        "- 为更严重的攻击收集情报"
    ),
    "race_condition": (
        "攻击者可以：\n"
        "- 在高并发场景下绕过业务限制\n"
        "- 多次使用同一优惠券/代金券\n"
        "- 超额提现或转账\n"
        "- 绕过速率限制和验证码"
    ),
    "business_logic": (
        "攻击者可以：\n"
        "- 利用业务流程中的设计缺陷\n"
        "- 操纵价格/数量/折扣等参数\n"
        "- 绕过支付流程\n"
        "- 获取不应得的权限或资源"
    ),
}

# ── English impact descriptions ──
IMPACT_TEMPLATES_EN: dict[str, str] = {
    "sql_injection": (
        "An attacker can:\n"
        "- Read/modify/delete arbitrary data in the database\n"
        "- Extract password hashes, PII, session tokens, and other sensitive data\n"
        "- Cross-table read via UNION injection\n"
        "- Execute arbitrary SQL (e.g., DROP TABLE) when stacked queries are supported\n"
        "- Write a webshell via INTO OUTFILE under specific configurations"
    ),
    "command_injection": (
        "An attacker can:\n"
        "- Execute arbitrary system commands on the server\n"
        "- Read arbitrary files from the filesystem\n"
        "- Download and execute malicious programs\n"
        "- Pivot laterally to other hosts on the internal network\n"
        "- Establish persistent backdoors"
    ),
    "xss": (
        "An attacker can:\n"
        "- Execute arbitrary JavaScript in the victim's browser\n"
        "- Steal session cookies and hijack user sessions\n"
        "- Redirect users to phishing pages\n"
        "- Deface page content for social engineering attacks\n"
        "- Chain with CSRF to perform sensitive operations"
    ),
    "ssrf": (
        "An attacker can:\n"
        "- Force the server to make requests to the internal network\n"
        "- Access cloud metadata services (AWS IMDSv1/GCP metadata) to steal credentials\n"
        "- Scan internal network topology and open ports\n"
        "- Attack unhardened internal services\n"
        "- Bypass firewall and ACL restrictions"
    ),
    "path_traversal": (
        "An attacker can:\n"
        "- Read arbitrary files on the server (/etc/passwd, source code, config files)\n"
        "- Obtain database credentials, API keys, and other sensitive configuration\n"
        "- Write files under specific conditions (log poisoning → RCE)\n"
        "- Read application source code to discover further vulnerabilities"
    ),
    "code_injection": (
        "An attacker can:\n"
        "- Execute arbitrary code on the server\n"
        "- Gain full control of the application server\n"
        "- Read/modify/delete arbitrary data on the filesystem\n"
        "- Execute system commands with the application process privileges"
    ),
    "ssti": (
        "An attacker can:\n"
        "- Execute arbitrary code in the server-side template context\n"
        "- Read sensitive files from the server filesystem\n"
        "- Achieve Remote Code Execution (RCE)\n"
        "- Gain full control of the application server"
    ),
    "deserialization": (
        "An attacker can:\n"
        "- Achieve remote code execution via crafted serialized payloads\n"
        "- Instantiate arbitrary classes and trigger gadget chains\n"
        "- Gain full control of the application server\n"
        "- Bypass all application-layer security controls"
    ),
    "xxe": (
        "An attacker can:\n"
        "- Read local files on the server (/etc/passwd, configuration, etc.)\n"
        "- Launch SSRF attacks to access internal services\n"
        "- Cause denial of service via Billion Laughs attack\n"
        "- Achieve remote code execution in rare cases"
    ),
    "auth_bypass": (
        "An attacker can:\n"
        "- Bypass authentication mechanisms\n"
        "- Access protected functionality as any user\n"
        "- Reach administrative interfaces and sensitive operations\n"
        "- Perform privileged operations without authorization"
    ),
    "idor": (
        "An attacker can:\n"
        "- Access other users' data by modifying resource IDs\n"
        "- View/modify/delete resources not owned by the attacker\n"
        "- Enumerate all user data (horizontal privilege escalation)\n"
        "- Access admin-only functionality (vertical privilege escalation)"
    ),
    "csrf": (
        "An attacker can:\n"
        "- Trick authenticated users into performing unintended actions\n"
        "- Change user passwords/email/security settings\n"
        "- Initiate financial operations (transfers, orders)\n"
        "- Execute arbitrary application functions as the victim"
    ),
    "open_redirect": (
        "An attacker can:\n"
        "- Redirect users to phishing sites\n"
        "- Steal OAuth authorization codes or access tokens\n"
        "- Bypass link whitelist checks\n"
        "- Chain with XSS for more sophisticated attacks"
    ),
    "crypto_weakness": (
        "An attacker can:\n"
        "- Brute-force weak hashes (e.g., MD5/SHA1 cracked in seconds on GPU)\n"
        "- Decrypt data protected by weak encryption algorithms\n"
        "- Forge digital signatures\n"
        "- Derive hardcoded keys and decrypt sensitive communications"
    ),
    "info_disclosure": (
        "An attacker can:\n"
        "- Obtain internal implementation details (stack traces, debug info)\n"
        "- Enumerate users/resources via differential response analysis\n"
        "- Discover hidden API endpoints\n"
        "- Gather intelligence for more severe attacks"
    ),
    "race_condition": (
        "An attacker can:\n"
        "- Bypass business limits under high-concurrency scenarios\n"
        "- Redeem the same coupon/voucher multiple times\n"
        "- Overdraw or double-transfer funds\n"
        "- Bypass rate limiting and CAPTCHA"
    ),
    "business_logic": (
        "An attacker can:\n"
        "- Exploit design flaws in business processes\n"
        "- Manipulate price/quantity/discount parameters\n"
        "- Bypass payment flows\n"
        "- Obtain unauthorized privileges or resources"
    ),
}

# ── Default fallback ──
_DEFAULT_IMPACT = (
    "攻击者可利用此漏洞绕过安全控制，对应用系统的"
    "机密性、完整性或可用性造成损害。"
)
_DEFAULT_IMPACT_EN = (
    "An attacker can exploit this vulnerability to bypass security controls, "
    "compromising the confidentiality, integrity, or availability of the "
    "application system."
)


# ── CWE Descriptions ─────────────────────────────────────────────────────────
# CWE ID → Chinese name mapping for report display.

CWE_NAMES: dict[str, str] = {
    "CWE-89": "SQL 注入",
    "CWE-79": "跨站脚本 (XSS)",
    "CWE-78": "命令注入",
    "CWE-918": "服务端请求伪造 (SSRF)",
    "CWE-22": "路径遍历",
    "CWE-94": "代码注入",
    "CWE-1336": "服务端模板注入 (SSTI)",
    "CWE-502": "不安全的反序列化",
    "CWE-611": "XML 外部实体注入 (XXE)",
    "CWE-287": "认证绕过",
    "CWE-639": "不安全的直接对象引用 (IDOR)",
    "CWE-352": "跨站请求伪造 (CSRF)",
    "CWE-601": "开放重定向",
    "CWE-200": "信息泄露",
    "CWE-327": "弱加密算法",
    "CWE-916": "弱密码哈希",
    "CWE-798": "硬编码凭据",
    "CWE-862": "缺少授权检查",
    "CWE-434": "无限制文件上传",
    "CWE-400": "未控制的资源消耗",
    "CWE-362": "竞态条件",
    "CWE-470": "不安全的反射",
    "CWE-95": "eval 注入",
    "CWE-77": "命令注入（通用）",
    "CWE-209": "信息通过错误消息泄露",
    "CWE-732": "不正确的权限分配",
    "CWE-284": "不当的访问控制",
    "CWE-840": "业务逻辑错误",
    "CWE-269": "不当的权限管理",
    "CWE-306": "关键功能缺少认证",
    "CWE-384": "会话固定",
    "CWE-613": "会话未过期",
    "CWE-614": "未设置 Secure Cookie 标志",
}

# ── English CWE names ──
CWE_NAMES_EN: dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-78": "Command Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-22": "Path Traversal",
    "CWE-94": "Code Injection",
    "CWE-1336": "Server-Side Template Injection (SSTI)",
    "CWE-502": "Insecure Deserialization",
    "CWE-611": "XML External Entity Injection (XXE)",
    "CWE-287": "Authentication Bypass",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-601": "Open Redirect",
    "CWE-200": "Information Disclosure",
    "CWE-327": "Weak Encryption Algorithm",
    "CWE-916": "Weak Password Hashing",
    "CWE-798": "Hardcoded Credentials",
    "CWE-862": "Missing Authorization Check",
    "CWE-434": "Unrestricted File Upload",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-362": "Race Condition",
    "CWE-470": "Unsafe Reflection",
    "CWE-95": "Eval Injection",
    "CWE-77": "Command Injection (Generic)",
    "CWE-209": "Information Exposure Through Error Messages",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-284": "Improper Access Control",
    "CWE-840": "Business Logic Error",
    "CWE-269": "Improper Privilege Management",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-384": "Session Fixation",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Missing Secure Cookie Flag",
}


# ── Vuln Type → CWE Mapping ────────────────────────────────────────────────────
# Used by the deterministic scanner to attach CWE IDs to findings at creation
# time, before any LLM involvement.

VULN_TYPE_TO_CWE: dict[str, str] = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78",
    "code_injection": "CWE-94",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "ssti": "CWE-1336",
    "path_traversal": "CWE-22",
    "file_inclusion": "CWE-98",
    "open_redirect": "CWE-601",
    "deserialization": "CWE-502",
    "xxe": "CWE-611",
    "auth_bypass": "CWE-287",
    "idor": "CWE-639",
    "csrf": "CWE-352",
    "crypto_weakness": "CWE-327",
    "info_disclosure": "CWE-200",
    "header_injection": "CWE-113",
    "injection_general": "CWE-74",
    "format_string": "CWE-134",
    "log_injection": "CWE-117",
    "nosql_injection": "CWE-943",
    "jndi_injection": "CWE-917",
    "ldap_injection": "CWE-90",
    "xpath_injection": "CWE-643",
    "cleartext_transmission": "CWE-319",
    "config_issue": "CWE-16",
    "missing_auth": "CWE-306",
    "dangerous_call": "CWE-676",
    "business_logic": "CWE-840",
    "secret": "CWE-798",
}


# ── OWASP Category Grouping ─────────────────────────────────────────────────────
# Maps vuln_type → (section_name, prefix, display_name)
# Used by the report generator to group findings by vulnerability class and
# generate category-scoped vulnerability IDs (e.g. INJ-001, XSS-001).

VULN_TYPE_TO_OWASP_CATEGORY: dict[str, tuple[str, str, str]] = {
    # ── Injection ──
    "sql_injection":     ("Injection Vulnerabilities", "INJ", "SQL Injection"),
    "command_injection":  ("Injection Vulnerabilities", "INJ", "Command Injection"),
    "code_injection":     ("Injection Vulnerabilities", "INJ", "Code Injection"),
    "ssti":               ("Injection Vulnerabilities", "INJ", "Server-Side Template Injection"),
    "nosql_injection":    ("Injection Vulnerabilities", "INJ", "NoSQL Injection"),
    "jndi_injection":     ("Injection Vulnerabilities", "INJ", "JNDI Injection"),
    "ldap_injection":     ("Injection Vulnerabilities", "INJ", "LDAP Injection"),
    "xpath_injection":    ("Injection Vulnerabilities", "INJ", "XPath Injection"),
    "injection_general":  ("Injection Vulnerabilities", "INJ", "General Injection"),
    "format_string":      ("Injection Vulnerabilities", "INJ", "Format String"),
    "log_injection":      ("Injection Vulnerabilities", "INJ", "Log Injection"),
    "header_injection":   ("Injection Vulnerabilities", "INJ", "Header Injection"),
    # ── Cross-Site Scripting ──
    "xss": ("Cross-Site Scripting (XSS)", "XSS", "Cross-Site Scripting"),
    # ── SSRF ──
    "ssrf": ("Server-Side Request Forgery (SSRF)", "SSRF", "Server-Side Request Forgery"),
    # ── Authentication & Access Control ──
    "auth_bypass": ("Broken Authentication & Access Control", "AUTH", "Authentication Bypass"),
    "missing_auth": ("Broken Authentication & Access Control", "AUTH", "Missing Authentication"),
    "idor": ("Broken Authentication & Access Control", "AUTH",
             "Insecure Direct Object Reference"),
    "csrf": ("Broken Authentication & Access Control", "AUTH",
             "Cross-Site Request Forgery"),
    # ── Path Traversal ──
    "path_traversal":  ("Path Traversal", "PATH", "Path Traversal"),
    "file_inclusion":  ("Path Traversal", "PATH", "File Inclusion"),
    # ── Deserialization ──
    "deserialization": ("Insecure Deserialization", "DESER", "Insecure Deserialization"),
    # ── XXE ──
    "xxe": ("XML External Entity (XXE)", "XXE", "XML External Entity"),
    # ── Security Misconfiguration ──
    "config_issue":         ("Security Misconfiguration", "CONFIG", "Configuration Issue"),
    "crypto_weakness":      ("Security Misconfiguration", "CONFIG", "Cryptographic Weakness"),
    "cleartext_transmission": ("Security Misconfiguration", "CONFIG", "Cleartext Transmission"),
    "dangerous_call":       ("Security Misconfiguration", "CONFIG", "Dangerous Function Call"),
    "secret":               ("Security Misconfiguration", "CONFIG", "Hardcoded Secret"),
    "info_disclosure":      ("Security Misconfiguration", "CONFIG", "Information Disclosure"),
    # ── Business Logic ──
    "business_logic": ("Business Logic Errors", "BIZ", "Business Logic Error"),
    # ── Open Redirect ──
    "open_redirect":  ("Open Redirect", "REDIR", "Open Redirect"),
}

# Category ordering for report generation (deterministic section order).
OWASP_CATEGORY_ORDER: list[str] = [
    "Injection Vulnerabilities",
    "Cross-Site Scripting (XSS)",
    "Server-Side Request Forgery (SSRF)",
    "Broken Authentication & Access Control",
    "Path Traversal",
    "Insecure Deserialization",
    "XML External Entity (XXE)",
    "Security Misconfiguration",
    "Business Logic Errors",
    "Open Redirect",
    "Other",
]

# ── Prerequisites Templates ─────────────────────────────────────────────────────
# Auto-generated per vulnerability type.  Each entry describes the conditions
# that must be met for the vulnerability to be exploitable.

PREREQUISITES_TEMPLATES: dict[str, str] = {
    "sql_injection": (
        "- 应用程序使用字符串拼接或模板方式构建 SQL 查询\n"
        "- 用户可控的输入未经过滤或参数化即被传入 SQL 语句\n"
        "- 攻击者能够访问受影响的功能端点"
    ),
    "command_injection": (
        "- 应用程序调用系统命令或外部程序时使用了用户可控的参数\n"
        "- 输入未经过滤或转义，允许注入命令分隔符（`;`、`|`、`&&`）\n"
        "- 应用进程有足够的系统权限执行注入的命令"
    ),
    "code_injection": (
        "- 应用程序动态执行代码（如 eval、exec）时使用了用户可控的输入\n"
        "- 输入未经过滤或沙箱隔离\n"
        "- 攻击者能够访问受影响的功能端点"
    ),
    "xss": (
        "- 应用程序将用户输入直接嵌入到 HTML 页面中，未做输出编码\n"
        "- 受害者需要访问包含恶意输入的页面或点击恶意链接\n"
        "- 应用未设置有效的 Content-Security-Policy (CSP) 头"
    ),
    "ssrf": (
        "- 应用程序接受用户提供的 URL 并发起服务器端请求\n"
        "- 未对目标地址进行有效的白名单验证或 DNS 解析限制\n"
        "- 应用服务器能够访问内部网络或云元数据服务"
    ),
    "ssti": (
        "- 应用程序使用模板引擎渲染用户可控的输入\n"
        "- 模板引擎未启用沙箱模式或输入未经过滤\n"
        "- 攻击者能够访问受影响的功能端点"
    ),
    "path_traversal": (
        "- 应用程序使用用户输入构造文件系统路径\n"
        "- 未对路径进行规范化或限制在允许的目录范围内\n"
        "- 应用进程有权限读取目标文件"
    ),
    "file_inclusion": (
        "- 应用程序动态包含文件时使用了用户可控的路径\n"
        "- 未限制可包含的文件范围（如白名单）\n"
        "- 攻击者能够上传或控制远程文件内容"
    ),
    "open_redirect": (
        "- 应用程序使用用户提供的 URL 进行重定向\n"
        "- 未对重定向目标进行白名单验证\n"
        "- 受害者需要点击包含恶意重定向的链接"
    ),
    "deserialization": (
        "- 应用程序反序列化来自不可信来源的数据\n"
        "- classpath 中存在可利用的 gadget chain\n"
        "- 攻击者能够向反序列化入口提交恶意数据"
    ),
    "xxe": (
        "- 应用程序解析用户提供的 XML 文档\n"
        "- XML 解析器未禁用外部实体（DTD）处理\n"
        "- 攻击者能够向 XML 解析端点提交恶意 XML"
    ),
    "auth_bypass": (
        "- 应用程序的身份验证逻辑存在缺陷\n"
        "- 认证检查可以被参数篡改或请求头操作绕过\n"
        "- 攻击者能够访问受保护的功能端点"
    ),
    "idor": (
        "- 应用程序使用可预测的资源标识符（如数字 ID）\n"
        "- 未验证当前用户是否有权访问请求的资源\n"
        "- 攻击者拥有有效的用户会话"
    ),
    "csrf": (
        "- 应用程序的关键操作（修改密码、转账等）未要求 CSRF Token\n"
        "- Cookie 未设置 SameSite 属性或设置为 None\n"
        "- 受害者需要访问攻击者控制的恶意页面"
    ),
    "crypto_weakness": (
        "- 应用程序使用已知不安全的加密算法（MD5/SHA1/DES/RC4）\n"
        "- 攻击者能够获取到加密或哈希处理的数据\n"
        "- 密钥空间不足以抵抗暴力破解"
    ),
    "info_disclosure": (
        "- 应用程序在错误消息或响应中暴露内部实现细节\n"
        "- 调试模式、堆栈跟踪或配置信息对外可见\n"
        "- 攻击者能够访问触发错误的端点"
    ),
    "business_logic": (
        "- 应用程序的业务流程设计存在逻辑缺陷\n"
        "- 缺少服务端的状态验证或事务控制\n"
        "- 攻击者能够通过正常的功能交互利用流程缺陷"
    ),
}

# ── English prerequisites ──
PREREQUISITES_TEMPLATES_EN: dict[str, str] = {
    "sql_injection": (
        "- The application builds SQL queries using string concatenation or templating\n"
        "- User-controllable input reaches SQL statements without filtering or parameterization\n"
        "- The attacker can reach the affected functional endpoint"
    ),
    "command_injection": (
        "- The application passes user-controllable parameters to system commands\n"
        "- Input is not filtered or escaped, allowing command separators (`;`, `|`, `&&`)\n"
        "- The application process has sufficient privileges to execute injected commands"
    ),
    "code_injection": (
        "- The application dynamically executes code (eval, exec) with user input\n"
        "- Input is not filtered or sandboxed\n"
        "- The attacker can reach the affected functional endpoint"
    ),
    "xss": (
        "- The application embeds user input directly into HTML without output encoding\n"
        "- The victim visits a page containing malicious input or clicks a malicious link\n"
        "- The application does not set an effective Content-Security-Policy (CSP) header"
    ),
    "ssrf": (
        "- The application accepts user-supplied URLs and makes server-side requests\n"
        "- Target addresses are not validated against a whitelist or DNS resolution\n"
        "- The application server can reach internal networks or cloud metadata services"
    ),
    "ssti": (
        "- The application renders user-controllable input through a template engine\n"
        "- The template engine does not use sandbox mode or input is unfiltered\n"
        "- The attacker can reach the affected functional endpoint"
    ),
    "path_traversal": (
        "- The application constructs filesystem paths from user input\n"
        "- Paths are not normalized or restricted to allowed directory boundaries\n"
        "- The application process has permissions to read the target file"
    ),
    "file_inclusion": (
        "- The application dynamically includes files using a user-controllable path\n"
        "- The set of includable files is not restricted (e.g., via whitelist)\n"
        "- The attacker can upload or control the content of a remote file"
    ),
    "open_redirect": (
        "- The application uses a user-supplied URL for redirection\n"
        "- The redirect target is not validated against a whitelist\n"
        "- The victim must click a link containing the malicious redirect"
    ),
    "deserialization": (
        "- The application deserializes data from an untrusted source\n"
        "- An exploitable gadget chain exists on the classpath\n"
        "- The attacker can submit malicious data to the deserialization entry point"
    ),
    "xxe": (
        "- The application parses user-supplied XML documents\n"
        "- The XML parser has not disabled external entity (DTD) processing\n"
        "- The attacker can submit malicious XML to the XML parsing endpoint"
    ),
    "auth_bypass": (
        "- The application's authentication logic contains flaws\n"
        "- Authentication checks can be bypassed via parameter tampering or header manipulation\n"
        "- The attacker can reach protected functional endpoints"
    ),
    "idor": (
        "- The application uses predictable resource identifiers (e.g., numeric IDs)\n"
        "- No check verifies whether the current user is authorized to access the resource\n"
        "- The attacker holds a valid user session"
    ),
    "csrf": (
        "- Critical operations (password changes, transfers) do not require a CSRF token\n"
        "- Cookies lack a SameSite attribute or it is set to None\n"
        "- The victim must visit a malicious page controlled by the attacker"
    ),
    "crypto_weakness": (
        "- The application uses known-weak cryptographic algorithms (MD5/SHA1/DES/RC4)\n"
        "- The attacker can obtain encrypted or hashed data\n"
        "- The key space is insufficient to resist brute-force attacks"
    ),
    "info_disclosure": (
        "- The application exposes internal implementation details in errors or responses\n"
        "- Debug mode, stack traces, or configuration information are publicly visible\n"
        "- The attacker can reach endpoints that trigger errors"
    ),
    "business_logic": (
        "- The application's business process design contains logic flaws\n"
        "- Server-side state validation or transaction controls are missing\n"
        "- The attacker can exploit process flaws through normal functional interactions"
    ),
}

# Default fallback prerequisites
_DEFAULT_PREREQUISITES = (
    "- 攻击者可以访问受影响的功能端点\n"
    "- 应用未对用户输入进行充分的验证和过滤\n"
    "- 相关安全控制机制缺失或配置不当"
)
_DEFAULT_PREREQUISITES_EN = (
    "- The attacker can reach the affected functional endpoint\n"
    "- The application does not sufficiently validate and filter user input\n"
    "- Relevant security controls are missing or misconfigured"
)


# ── Proof of Impact Templates ───────────────────────────────────────────────────
# Scenario-based impact statements that describe what an attacker actually achieves.

PROOF_OF_IMPACT_TEMPLATES: dict[str, str] = {
    "sql_injection": (
        "成功利用此漏洞后，攻击者无需任何身份验证即可读取数据库中所有用户的"
        "密码哈希、邮箱地址和个人信息。通过 UNION 注入技术，攻击者能够跨表"
        "提取敏感数据。如果数据库用户拥有 FILE 权限，攻击者还可以写入 webshell"
        "获得服务器完全控制权。"
    ),
    "command_injection": (
        "成功利用此漏洞后，攻击者可以在服务器上以应用进程身份执行任意系统命令。"
        "攻击者可以读取 `/etc/passwd`、下载恶意程序、建立反向 shell，并横向"
        "移动至内网其他主机。此漏洞可导致服务器完全沦陷。"
    ),
    "code_injection": (
        "成功利用此漏洞后，攻击者可以在应用服务器上执行任意代码。攻击者可以"
        "读取配置文件中的数据库凭据和 API 密钥、修改或删除业务数据、植入"
        "持久化后门。最严重的情况下，攻击者可获取服务器的完全控制权。"
    ),
    "xss": (
        "成功利用此漏洞后，攻击者可以窃取已登录用户的会话 Cookie，从而以受害者"
        "身份执行任意操作。攻击者还可以重定向用户到钓鱼页面窃取凭据，或篡改页面"
        "内容进行社会工程攻击。在配合其他漏洞的情况下，XSS 可导致账户完全接管。"
    ),
    "ssrf": (
        "成功利用此漏洞后，攻击者可以让服务器向 AWS 元数据服务（169.254.169.254）"
        "发起请求，获取 IAM 临时凭据。攻击者还可以扫描内网拓扑、攻击未加固的内部"
        "服务、绕过防火墙和 ACL 限制。如果获取到云凭据，攻击者可进一步控制云资源。"
    ),
    "ssti": (
        "成功利用此漏洞后，攻击者可以在服务器端模板上下文中执行任意代码，进而"
        "读取服务器上的任意文件、获取环境变量中的敏感凭据、建立反向 shell。"
        "此漏洞通常可导致应用服务器完全沦陷。"
    ),
    "path_traversal": (
        "成功利用此漏洞后，攻击者可以读取服务器上的任意文件，包括 `/etc/passwd`、"
        "应用配置文件中的数据库凭据、源代码中的硬编码密钥等。在特定条件下（如"
        "日志投毒），路径遍历可升级为远程代码执行。"
    ),
    "deserialization": (
        "成功利用此漏洞后，攻击者可以通过构造恶意序列化数据触发 gadget chain，"
        "在服务器上实现远程代码执行。攻击者可以完全控制应用服务器，包括读取、"
        "修改和删除任意数据，以及建立持久化后门。"
    ),
    "xxe": (
        "成功利用此漏洞后，攻击者可以读取服务器上的敏感文件（如 `/etc/passwd`、"
        "配置文件），发起 SSRF 攻击访问内部服务，或通过 Billion Laughs 攻击导致"
        "服务拒绝。此漏洞可导致严重的数据泄露和服务器沦陷。"
    ),
    "auth_bypass": (
        "成功利用此漏洞后，攻击者无需任何身份验证即可访问管理后台接口。攻击者"
        "可以查看所有用户数据、修改系统配置、删除业务数据，以管理员权限执行任意"
        "操作。此漏洞可导致整个应用的数据完整性和机密性完全丧失。"
    ),
    "idor": (
        "成功利用此漏洞后，攻击者可以通过遍历资源 ID（如 user_id=1,2,3...）"
        "批量获取所有用户的个人信息、订单记录和私密数据。攻击者还可以修改或删除"
        "其他用户的资源，造成严重的数据泄露和业务损失。"
    ),
    "open_redirect": (
        "成功利用此漏洞后，攻击者可以构造看似指向合法域名的链接，实际将用户"
        "重定向到精心准备的钓鱼页面。在 OAuth 流程中，开放重定向可被用于窃取"
        "授权码和访问令牌，进而接管用户账户。"
    ),
    "crypto_weakness": (
        "成功利用此漏洞后，攻击者可以通过彩虹表或 GPU 暴力破解在秒级内恢复弱哈希"
        "算法的原始输入。如果加密密钥被派生，攻击者可以解密所有历史加密通信数据。"
        "敏感凭据和用户数据的机密性完全丧失。"
    ),
    "info_disclosure": (
        "成功利用此漏洞后，攻击者可以获取应用的技术栈信息、内部路径结构、框架"
        "版本号等情报。虽然此漏洞本身风险较低，但这些信息可被用于策划更精确的"
        "攻击，大幅降低其他严重漏洞的利用门槛。"
    ),
    "csrf": (
        "成功利用此漏洞后，攻击者可以诱导已登录用户执行非预期操作（如修改密码、"
        "转账、更改邮箱）。CSRF 攻击可以在受害者完全不知情的情况下以受害者身份"
        "执行任意应用功能，导致账户接管和资金损失。"
    ),
    "business_logic": (
        "成功利用此漏洞后，攻击者可以绕过正常的业务流程限制，例如重复使用优惠券、"
        "以负价格下单、绕过支付验证等。此类漏洞直接损害业务收入和数据完整性，"
        "且传统安全工具难以检测。"
    ),
}

# ── English proof of impact ──
PROOF_OF_IMPACT_TEMPLATES_EN: dict[str, str] = {
    "sql_injection": (
        "Upon successful exploitation, an attacker can read password hashes, "
        "email addresses, and personal information for all users in the database "
        "without any authentication. Using UNION injection techniques, the attacker "
        "can extract sensitive data across tables. If the database user holds FILE "
        "privileges, the attacker can also write a webshell and gain full server control."
    ),
    "command_injection": (
        "Upon successful exploitation, an attacker can execute arbitrary system "
        "commands as the application process. The attacker can read /etc/passwd, "
        "download malicious programs, establish a reverse shell, and pivot laterally "
        "to other hosts on the internal network. This vulnerability can lead to "
        "complete server compromise."
    ),
    "code_injection": (
        "Upon successful exploitation, an attacker can execute arbitrary code on "
        "the application server. The attacker can read database credentials and API "
        "keys from configuration files, modify or delete business data, and implant "
        "persistent backdoors. In the worst case, the attacker gains full control "
        "of the server."
    ),
    "xss": (
        "Upon successful exploitation, an attacker can steal session cookies from "
        "authenticated users and perform arbitrary actions as the victim. The attacker "
        "can also redirect users to phishing pages to harvest credentials, or deface "
        "page content for social engineering attacks. When chained with other "
        "vulnerabilities, XSS can lead to full account takeover."
    ),
    "ssrf": (
        "Upon successful exploitation, an attacker can force the server to make "
        "requests to the AWS metadata service (169.254.169.254) and obtain IAM "
        "temporary credentials. The attacker can also scan internal network topology, "
        "attack unhardened internal services, and bypass firewall and ACL restrictions. "
        "If cloud credentials are obtained, the attacker can further control cloud resources."
    ),
    "ssti": (
        "Upon successful exploitation, an attacker can execute arbitrary code in "
        "the server-side template context, read arbitrary files on the server, obtain "
        "sensitive credentials from environment variables, and establish a reverse "
        "shell. This vulnerability typically leads to full application server compromise."
    ),
    "path_traversal": (
        "Upon successful exploitation, an attacker can read arbitrary files on the "
        "server, including /etc/passwd, database credentials in application config "
        "files, and hardcoded keys in source code. Under specific conditions (e.g., "
        "log poisoning), path traversal can be escalated to remote code execution."
    ),
    "deserialization": (
        "Upon successful exploitation, an attacker can trigger a gadget chain via "
        "crafted serialized data, achieving remote code execution on the server. "
        "The attacker can fully control the application server, including reading, "
        "modifying, and deleting arbitrary data, and establishing persistent backdoors."
    ),
    "xxe": (
        "Upon successful exploitation, an attacker can read sensitive files on the "
        "server (e.g., /etc/passwd, configuration files), launch SSRF attacks against "
        "internal services, or cause denial of service via Billion Laughs attack. "
        "This vulnerability can lead to severe data exposure and server compromise."
    ),
    "auth_bypass": (
        "Upon successful exploitation, an attacker can access administrative panels "
        "without any authentication. The attacker can view all user data, modify "
        "system configuration, delete business data, and perform arbitrary operations "
        "with administrator privileges. This vulnerability can lead to complete loss "
        "of data integrity and confidentiality across the application."
    ),
    "idor": (
        "Upon successful exploitation, an attacker can enumerate resource IDs "
        "(e.g., user_id=1,2,3...) to batch-retrieve personal information, order "
        "records, and private data for all users. The attacker can also modify or "
        "delete other users' resources, causing severe data breaches and business loss."
    ),
    "open_redirect": (
        "Upon successful exploitation, an attacker can craft links that appear to "
        "point to the legitimate domain but actually redirect users to a carefully "
        "prepared phishing page. In OAuth flows, open redirects can be used to steal "
        "authorization codes and access tokens, leading to account takeover."
    ),
    "crypto_weakness": (
        "Upon successful exploitation, an attacker can recover the original input "
        "of weak hash algorithms in seconds using rainbow tables or GPU brute-force. "
        "If an encryption key is derived, the attacker can decrypt all historical "
        "encrypted communications. The confidentiality of sensitive credentials and "
        "user data is completely lost."
    ),
    "info_disclosure": (
        "Upon successful exploitation, an attacker can gather intelligence about the "
        "application's technology stack, internal path structure, and framework "
        "versions. While the direct risk is lower, this information can be used to "
        "plan more precise attacks, significantly lowering the barrier to exploit "
        "other, more severe vulnerabilities."
    ),
    "csrf": (
        "Upon successful exploitation, an attacker can trick authenticated users "
        "into performing unintended actions (password changes, fund transfers, email "
        "modifications). CSRF attacks execute arbitrary application functions as the "
        "victim without their knowledge, leading to account takeover and financial loss."
    ),
    "business_logic": (
        "Upon successful exploitation, an attacker can bypass normal business process "
        "restrictions — for example, reusing coupons, placing orders at negative "
        "prices, or bypassing payment verification. Such flaws directly harm business "
        "revenue and data integrity, and are difficult for traditional security "
        "tools to detect."
    ),
}

_DEFAULT_PROOF_OF_IMPACT = (
    "成功利用此漏洞后，攻击者可以绕过安全控制机制，对应用系统的机密性、完整性"
    "或可用性造成不同程度的损害。具体影响取决于漏洞所处上下文和攻击者的利用能力。"
)
_DEFAULT_PROOF_OF_IMPACT_EN = (
    "Upon successful exploitation, an attacker can bypass security controls, "
    "causing varying degrees of damage to the confidentiality, integrity, or "
    "availability of the application. The exact impact depends on the "
    "vulnerability's context and the attacker's exploit capability."
)

# ── Public API ────────────────────────────────────────────────────────────────


def lookup_cwe_from_vuln_type(vuln_type: str) -> str:
    """Map a vulnerability type string to its primary CWE ID.

    Returns the empty string if *vuln_type* is not recognised.
    """
    return VULN_TYPE_TO_CWE.get(vuln_type, "")


def lookup_cvss(vuln_type: str, severity: str) -> tuple[float, str]:
    """Look up CVSS 3.1 base score and vector for a vulnerability.

    Args:
        vuln_type: e.g. ``"sql_injection"``, ``"xss"``.
        severity: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.

    Returns:
        ``(base_score, vector_string)``.  Falls back to a severity-based
        estimate when no exact template matches.

    """
    key = (vuln_type, severity)
    if key in CVSS_TEMPLATES:
        return CVSS_TEMPLATES[key]

    # Try with different severities
    for sev in ("critical", "high", "medium", "low"):
        candidate = (vuln_type, sev)
        if candidate in CVSS_TEMPLATES:
            return CVSS_TEMPLATES[candidate]

    # Severity-only fallback
    return _severity_fallback_cvss(severity)


def _severity_fallback_cvss(severity: str) -> tuple[float, str]:
    """Return a conservative CVSS estimate based on severity alone."""
    return {
        "critical": (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        "high": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
        "low": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    }.get(severity, (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"))


def lookup_impact(vuln_type: str, lang: str = "cn") -> str:
    """Look up business impact description for a vulnerability type.

    Args:
        vuln_type: e.g. ``"sql_injection"``.
        lang: ``"cn"`` for Chinese, ``"en"`` for English.

    Returns:
        Human readable impact description with bullet points.

    """
    if lang == "en":
        return IMPACT_TEMPLATES_EN.get(vuln_type, _DEFAULT_IMPACT_EN)
    return IMPACT_TEMPLATES.get(vuln_type, _DEFAULT_IMPACT)


def lookup_cwe_name(cwe_id: str, lang: str = "cn") -> str:
    """Look up a human-readable CWE name.

    Args:
        cwe_id: e.g. ``"CWE-89"``.
        lang: ``"cn"`` for Chinese, ``"en"`` for English.

    Returns:
        CWE name in the requested language, or empty string if not found.

    """
    if lang == "en":
        return CWE_NAMES_EN.get(cwe_id, "")
    return CWE_NAMES.get(cwe_id, "")


def cvss_severity_label(score: float) -> str:
    """Map a CVSS base score to a severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def cvss_severity_emoji(score: float) -> str:
    """Map a CVSS base score to an emoji."""
    if score >= 9.0:
        return "🔴"
    if score >= 7.0:
        return "🟠"
    if score >= 4.0:
        return "🟡"
    return "🟢"


def lookup_owasp_category(vuln_type: str) -> tuple[str, str, str]:
    """Map a vuln_type to its OWASP category info.

    Args:
        vuln_type: e.g. ``"sql_injection"``.

    Returns:
        ``(section_name, prefix, display_name)``.  Falls back to
        ``("Other", "OTHER", vuln_type)`` when unrecognised.

    """
    return VULN_TYPE_TO_OWASP_CATEGORY.get(
        vuln_type,
        ("Other", "OTHER", vuln_type.replace("_", " ").title()),
    )


def lookup_prerequisites(vuln_type: str, lang: str = "cn") -> str:
    """Look up exploitability prerequisites for a vulnerability type.

    Args:
        vuln_type: e.g. ``"sql_injection"``.
        lang: ``"cn"`` for Chinese, ``"en"`` for English.

    Returns:
        Human-readable prerequisites description, or a default fallback.

    """
    if lang == "en":
        return PREREQUISITES_TEMPLATES_EN.get(vuln_type, _DEFAULT_PREREQUISITES_EN)
    return PREREQUISITES_TEMPLATES.get(vuln_type, _DEFAULT_PREREQUISITES)


def lookup_proof_of_impact(vuln_type: str, lang: str = "cn") -> str:
    """Look up a scenario-based proof of impact for a vulnerability type.

    Args:
        vuln_type: e.g. ``"sql_injection"``.
        lang: ``"cn"`` for Chinese, ``"en"`` for English.

    Returns:
        Human-readable proof-of-impact narrative, or a default fallback.

    """
    if lang == "en":
        return PROOF_OF_IMPACT_TEMPLATES_EN.get(vuln_type, _DEFAULT_PROOF_OF_IMPACT_EN)
    return PROOF_OF_IMPACT_TEMPLATES.get(vuln_type, _DEFAULT_PROOF_OF_IMPACT)


def get_category_order() -> list[str]:
    """Return the canonical OWASP category display order for report sections."""
    return list(OWASP_CATEGORY_ORDER)
