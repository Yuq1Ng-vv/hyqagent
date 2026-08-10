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

# ── Default fallback ──
_DEFAULT_IMPACT = (
    "攻击者可利用此漏洞绕过安全控制，对应用系统的"
    "机密性、完整性或可用性造成损害。"
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


# ── Public API ────────────────────────────────────────────────────────────────


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


def lookup_impact(vuln_type: str) -> str:
    """Look up business impact description for a vulnerability type.

    Args:
        vuln_type: e.g. ``"sql_injection"``.

    Returns:
        Human readable impact description with bullet points.

    """
    return IMPACT_TEMPLATES.get(vuln_type, _DEFAULT_IMPACT)


def lookup_cwe_name(cwe_id: str) -> str:
    """Look up a human-readable CWE name.

    Args:
        cwe_id: e.g. ``"CWE-89"``.

    Returns:
        Chinese CWE name, or empty string if not found.

    """
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
