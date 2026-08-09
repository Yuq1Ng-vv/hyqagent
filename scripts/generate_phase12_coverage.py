#!/usr/bin/env python3
"""Generate Phase 1+2 coverage tracking JSON for all 200 detection items.

Reads docs/detection_matrix.json, annotates each item with current
Phase 1+2 deterministic scanner coverage, and writes the annotated
result to docs/phase12_coverage_tracking.json.

This is the authoritative reference for:
1. Which items are fully covered by Phase 2 deterministic rules
2. Which items are partially covered (detectable but incomplete)
3. Which items are uncovered and need Phase 3 LLM / dynamic testing
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ── Per-item coverage mapping ─────────────────────────────────────────────
# Each entry maps an item ID to its Phase 1+2 coverage details.
# Items NOT in this map fall through to the default classifier below.

COVERAGE_MAP: dict[str, dict[str, Any]] = {
    # ══════════════════════════════════════════════════════════════════
    # INPUT — 输入验证层 (27 items)
    # ══════════════════════════════════════════════════════════════════
    "INPUT-001": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "CPG taint 追踪 SQL 注入的 source→sink 路径，但无法判断输入验证本身是否缺失",
        "limitations": "仅检测已发生的 taint flow，不检测'应该有验证但没写'的情况",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "输入验证缺失属于负空间检测——需要理解代码意图",
            "llm_approach": "LLM 审查每个端点参数是否执行了与类型/长度/范围匹配的验证",
        },
    },
    "INPUT-002": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["command_injection"],
        "detail": "CPG taint 追踪命令注入 source→sink，覆盖 ProcessBuilder/Runtime.exec 等",
        "limitations": "同 INPUT-001，无法检测验证缺失",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "验证缺失是负空间问题",
            "llm_approach": "LLM 审查是否对命令参数做了白名单/转义验证",
        },
    },
    "INPUT-003": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["xss"],
        "detail": "XSS sanitizer 检测 (DOMPurify/bleach/OWASP Java Encoder 等 60+ 模式)",
        "limitations": "sanitizer 存在 ≠ 正确配置；无法评估 sanitizer 策略是否充分",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "sanitizer 质量评估需要语义理解",
            "llm_approach": "LLM 审查 sanitizer 配置是否覆盖所有输出上下文",
        },
    },
    "INPUT-004": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["path_traversal"],
        "detail": "完整 path traversal taint 追踪 + FilenameUtils.normalize/getCanonicalPath 等 sanitizer",
        "limitations": None,
        "needs_phase3": None,
    },
    "INPUT-005": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["ssrf"],
        "detail": "SSRF taint 追踪覆盖 56 个 sink (OkHttp/Apache HttpClient/JAX-RS Client/Unirest 等)",
        "limitations": "检测到 SSRF sink 但无法验证是否有 URL 白名单/IP 过滤",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "白名单/IP 过滤验证需要理解防御逻辑",
            "llm_approach": "LLM 审查 SSRF 防护措施：协议限制、域名白名单、内网 IP 过滤",
        },
    },
    "INPUT-006": {
        "phase12_status": "partial",
        "scanners": ["scan_dangerous_calls", "scan_cpg_taint"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-031"],
        "detail": "DANGER-031 检测 LdapTemplate/LdapQueryBuilder/DirContext.search 等 LDAP 查询",
        "limitations": "仅标记 LDAP 调用，需要 taint 分析确定输入是否用户可控",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LDAP 参数化/转义的正确性需要语义理解",
            "llm_approach": "LLM 审查 LDAP 查询是否使用参数化过滤或特殊字符转义",
        },
    },
    "INPUT-007": {
        "phase12_status": "partial",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-011", "DANGER-032"],
        "detail": "DANGER-011 (XPath.evaluate/compile) + DANGER-032 (XPathFactory/XPathExpression.evaluate)",
        "limitations": "仅标记 XPath API 调用，无参数化检测",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "XPath 参数化检测需要理解查询构造方式",
            "llm_approach": "LLM 审查 XPath 是否使用参数化查询或转义特殊字符",
        },
    },
    "INPUT-008": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["ssti"],
        "rule_ids": ["DANGER-013", "DANGER-028", "DANGER-029", "DANGER-030"],
        "detail": "SSTI 专用 taint 类别 (55 sinks) + 6 条 dangerous_call 规则覆盖 Freemarker/Velocity/Thymeleaf/Pebble/Mustache/Jinja2",
        "limitations": "Python/JS 的 SSTI 规则尚不如 Java 完善",
        "needs_phase3": None,
    },
    "INPUT-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "ReDoS 检测需要正则复杂度分析 (NFA/回溯)，当前无此能力",
        "limitations": "需要专门的 ReDoS 分析引擎或 LLM 辅助识别危险正则模式",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "正则回溯复杂度分析是专门领域",
            "llm_approach": "LLM 审查正则表达式中的嵌套量词/交替/反向引用模式",
        },
    },
    "INPUT-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "JSON 注入检测需要在 JSON 构造点追踪用户输入，当前无专门规则",
        "limitations": "JSON 注入不是传统 SAST 高优先级项",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "JSON 注入模式多样 (注入字段/注释/Unicode 逃逸)",
            "llm_approach": "LLM 审查 JSON 序列化是否使用安全库 (Jackson/Gson/json.dumps)",
        },
    },
    "INPUT-011": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["xxe"],
        "rule_ids": ["DANGER-025", "DANGER-026", "DANGER-027"],
        "detail": "XXE taint 追踪 (35 sinks) + 3 条 DANGER 规则检测 XML 解析器工厂的不安全创建",
        "limitations": "无法确定解析器是否在运行时启用了 FEATURE_SECURE_PROCESSING",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "XXE 防护配置是否完整需要理解全局安全策略",
            "llm_approach": "LLM 审查 XML 解析器是否设置 DTD/外部实体禁用",
        },
    },
    "INPUT-012": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "CSV/公式注入 (CSV Injection) 检测无专门规则",
        "limitations": "需要检测以 =/+/@/- 开头的 CSV 输出",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "CSV 注入是特定场景 (Excel/Google Sheets 公式执行)",
            "llm_approach": "LLM 审查 CSV 输出中是否对 =/+/@/- 前缀做了转义",
        },
    },
    "INPUT-013": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "GraphQL 注入/批量查询攻击无专门规则",
        "limitations": "需要 GraphQL schema 分析和查询复杂度检测",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "GraphQL 安全需要理解 schema 和 resolver 逻辑",
            "llm_approach": "LLM 审查 GraphQL resolver 中的深度限制/查询复杂度限制/授权检查",
        },
    },
    "INPUT-014": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "HTTP Verb Tampering 需要检测路由配置中的 HTTP 方法覆盖",
        "limitations": "框架路由配置检测需要解析注解/配置",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "方法覆盖检测需要理解路由配置和中间件",
            "llm_approach": "LLM 审查路由定义是否对敏感操作限定了 HTTP 方法",
        },
    },
    "INPUT-015": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "参数污染 (HPP) 需要检测同一参数多次出现的处理方式",
        "limitations": "大部分框架默认处理 HPP，但自定义解析可能有风险",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "HPP 检测需要理解参数绑定和处理逻辑",
            "llm_approach": "LLM 审查自定义参数解析逻辑",
        },
    },
    "INPUT-016": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Mass Assignment/自动绑定检测：Spring @ModelAttribute 自动绑定、Django ModelForm、Express body-parser",
        "limitations": "需要理解 ORM 字段声明和客户端可提交字段的差异",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Mass Assignment 需要理解 DTO 字段安全性",
            "llm_approach": "LLM 审查 DTO/Form 对象中是否有敏感字段暴露给客户端绑定",
        },
    },
    "INPUT-017": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["code_injection"],
        "rule_ids": ["DANGER-019", "DANGER-020", "DANGER-021"],
        "detail": "SpEL/OGNL/MVEL/JEXL 表达式注入检测，code_injection 47 sinks + 3 DANGER rules",
        "limitations": "部分表达式引擎（如 Janino/GraalJS）覆盖较弱",
        "needs_phase3": None,
    },
    "INPUT-018": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["command_injection"],
        "detail": "命令注入 taint 追踪 (ProcessBuilder/Runtime.exec/Commons Exec/JSch)",
        "limitations": "无法检测 shell 解释器特性利用 (通配符展开/命令替换)",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Shell 元字符过滤质量需要语义审查",
            "llm_approach": "LLM 审查 shell 命令是否用了参数数组形式而非字符串拼接",
        },
    },
    "INPUT-019": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["jndi_injection"],
        "rule_ids": ["DANGER-017", "DANGER-018"],
        "detail": "JNDI 注入专用 taint 类别 (22 sinks) + Log4Shell 特征检测",
        "limitations": None,
        "needs_phase3": None,
    },
    "INPUT-020": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "SQL 注入 taint 追踪 (MyBatis/MyBatis-Spring/JPA/Hibernate/SqlSession/jOOQ 等 40 sinks)",
        "limitations": "无法判断 ORM Criteria API 的动态字段拼接是否来自用户输入",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "ORM 动态查询的安全性需要语义理解",
            "llm_approach": "LLM 审查 ORM 动态查询中是否对字段名/操作符使用了白名单",
        },
    },
    "INPUT-021": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["code_injection"],
        "detail": "code_injection 覆盖 ScriptEngine.eval/GroovyShell/GraalJS 等脚本引擎",
        "limitations": "脚本沙箱逃逸检测需要理解沙箱配置",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "沙箱配置是否充分需要深度语义分析",
            "llm_approach": "LLM 审查脚本引擎沙箱是否限制了类加载/文件系统/网络访问",
        },
    },
    "INPUT-022": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection", "command_injection", "xss", "path_traversal", "ssrf"],
        "detail": "各注入类的 sanitizer 规则检测（PreparedStatement/htmlspecialchars/ESAPI 等）",
        "limitations": "sanitizer 白名单可以由多类别 taint 粗粒度覆盖，但精确度不高",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "sanitizer 白名单的精确配置需要语义理解",
            "llm_approach": "LLM 审查是否使用了正确的编码/过滤库及配置",
        },
    },
    "INPUT-023": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "文件类型魔数验证需要检测上传后是否检查实际文件类型，纯静态分析难以实现",
        "limitations": "运行时行为（读取文件头 + 比较）很难通过 CPG 静态分析判断",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "文件类型验证逻辑需要上下文追踪",
            "llm_approach": "LLM 审查文件上传处理中是否读取并验证了文件魔数/Content-Type",
        },
    },
    "INPUT-024": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["xss"],
        "detail": "XSS taint 追踪 (21 sinks, 60+ sanitizers) 覆盖 Servlet/JSP/Spring MVC/JSF 输出方法",
        "limitations": None,
        "needs_phase3": None,
    },
    "INPUT-025": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["xss"],
        "detail": "XSS sanitizer 检测覆盖 OWASP Java Encoder/AntiSamy/DOMPurify/Bleach 等",
        "limitations": "sanitizer 是否覆盖了所有输出上下文需要 LLM 判断",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "输出上下文适配需要理解 HTML/JS/CSS/URL 四种上下文",
            "llm_approach": "LLM 审查每个输出点是否使用了对应上下文的编码函数",
        },
    },
    "INPUT-026": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["xxe"],
        "rule_ids": ["DANGER-025", "DANGER-026", "DANGER-027"],
        "detail": "XXE taint 追踪 (35 sinks: SAXReader/DocumentBuilder/SAXParser/JAXB/XMLInputFactory 等) + 3 DANGER rules",
        "limitations": None,
        "needs_phase3": None,
    },
    "INPUT-027": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["ssrf"],
        "detail": "SSRF taint 已经检测到 sink 调用，但 URL 构建是否绕过验证需要深度分析",
        "limitations": "间接 URL 构造 (从数据库读取 URL 再请求) 无法追踪",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "间接 URL 构造跨越了 CPG 分析边界",
            "llm_approach": "LLM 审查 URL 构建链是否完全来自用户输入",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # OUTPUT — 输出编码层 (12 items)
    # ══════════════════════════════════════════════════════════════════
    "OUTPUT-001": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["xss"],
        "detail": "XSS taint 追踪覆盖 .getWriter()/.getOutputStream() 等响应输出 sink",
        "limitations": "编码函数的正确性评估需要 LLM",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "编码函数选择是否正确需要上下文判断",
            "llm_approach": "LLM 审查输出编码是否匹配输出上下文 (HTML body/attribute/JS/CSS/URL)",
        },
    },
    "OUTPUT-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "JS 输出上下文的编码函数选择需要 JS 前端代码分析，当前 CPG 不支持前端 JS",
        "limitations": "前端 JS 分析不在 Phase 1-2 范围内",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "需要前端 JS AST 分析",
            "llm_approach": "LLM 审查前端 JS 中的输出编码函数选择",
        },
    },
    "OUTPUT-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "CSS 上下文编码在大多数 SAST 中不支持，需要专门的 CSS 解析",
        "limitations": "CSS 解析和注入检测不在当前能力范围",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "CSS 注入检测需要 CSS 解析器",
            "llm_approach": "LLM 审查 CSS 构造是否允许用户注入任意属性/选择器",
        },
    },
    "OUTPUT-004": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["xss"],
        "detail": "XSS taint 追踪 + HTML 编码 sanitizer (HtmlUtils.htmlEscape/ESAPI.encoder/OWASP Encoder)",
        "limitations": None,
        "needs_phase3": None,
    },
    "OUTPUT-005": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["xss"],
        "detail": "XSS taint 追踪 (ResponseWriter.write/StreamingOutput 等 JSF/JAX-RS sink)",
        "limitations": None,
        "needs_phase3": None,
    },
    "OUTPUT-006": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["open_redirect"],
        "detail": "Open Redirect taint 追踪 (sendRedirect/setHeader Location/ModelAndView redirect)",
        "limitations": "URL 白名单验证是否充分需要 LLM 判断",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "白名单策略需要语义理解",
            "llm_approach": "LLM 审查重定向目标是否使用了白名单/URL 解析后验证",
        },
    },
    "OUTPUT-007": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-005", "CONFIG-020", "CONFIG-021"],
        "detail": "CORS 配置检测 (Access-Control-Allow-Origin: *, CORS_ORIGIN_ALLOW_ALL, @CrossOrigin(*))",
        "limitations": "仅检测配置文件/注解中的 CORS 通配符，不检测代码中动态设置的 CORS 头",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "动态 CORS 头设置需要流分析",
            "llm_approach": "LLM 审查代码中动态设置 CORS 头的逻辑",
        },
    },
    "OUTPUT-008": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-022", "CONFIG-023", "CONFIG-024", "CONFIG-025"],
        "detail": "安全头配置检测: headers().disable()/frameOptions/XSS/HSTS",
        "limitations": "仅检测 Spring Security Java 配置，不覆盖其他框架",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Python/JS 框架的安全头检测需要扩展",
            "llm_approach": "LLM 审查 Python/JS 项目的安全头中间件配置",
        },
    },
    "OUTPUT-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Cache-Control 头检测无专门规则 (需要检测 no-store/no-cache 缺失)",
        "limitations": "安全缓存头检测未实现",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "检测缺失比检测存在更难",
            "llm_approach": "LLM 审查敏感响应中是否设置了 Cache-Control: no-store",
        },
    },
    "OUTPUT-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "P3P 头已过时，现代浏览器不再支持",
        "limitations": "历史遗留项，优先级低",
        "needs_phase3": None,
    },
    "OUTPUT-011": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Clear-Site-Data 头检测无专门规则",
        "limitations": "这是一个较新的 HTTP 头，实现较少",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查登出端点是否设置了此头",
            "llm_approach": "LLM 审查登出响应中是否设置了 Clear-Site-Data",
        },
    },
    "OUTPUT-012": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Content-Type 字符集声明需要检测每个响应的 charset 设置",
        "limitations": "需要 HTTP 响应级别的分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "charset 声明分析需要审查所有响应写入路径",
            "llm_approach": "LLM 审查响应是否设置了明确的 Content-Type charset",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # AUTH — 认证层 (20 items)
    # ══════════════════════════════════════════════════════════════════
    "AUTH-001": {
        "phase12_status": "partial",
        "scanners": ["scan_missing_auth"],
        "rule_files": [],
        "detail": "scan_missing_auth 检测端点是否缺少认证注解/装饰器",
        "limitations": "仅检测注解缺失，不评估认证实现的正确性",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "认证实现质量 (密码存储/多因素/暴力保护) 需要深度审查",
            "llm_approach": "LLM 审查认证流程的完整性",
        },
    },
    "AUTH-002": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["auth_bypass"],
        "detail": "auth_bypass taint 追踪 (SecurityContext.getAuthentication/isAuthenticated/hasRole 等)",
        "limitations": "仅检测认证状态检查点的存在，不评估密码策略/锁定策略",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "密码策略/账户锁定是配置+逻辑的综合问题",
            "llm_approach": "LLM 审查密码强度策略和暴力破解防护",
        },
    },
    "AUTH-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "密码长度/复杂度规则是业务逻辑配置，无代码签名可检测",
        "limitations": "需要审查密码验证逻辑和配置",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "密码策略在代码中以验证规则形式出现",
            "llm_approach": "LLM 审查注册/修改密码的验证逻辑",
        },
    },
    "AUTH-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "重置token过期/单次使用是时序逻辑问题",
        "limitations": "需要理解 token 生命周期管理",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Token 生命周期是状态机问题",
            "llm_approach": "LLM 审查密码重置 token 的生成/存储/验证/失效逻辑",
        },
    },
    "AUTH-005": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["crypto_weakness"],
        "detail": "crypto_weakness 检测弱哈希 (MD5/SHA-1) 使用",
        "limitations": "无法判断是否使用了专门的密码哈希函数 (bcrypt/scrypt/argon2)",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "需要区分一般哈希和密码哈希上下文",
            "llm_approach": "LLM 审查密码存储是否使用了 bcrypt/argon2/PBKDF2",
        },
    },
    "AUTH-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "错误消息的用户枚举 (「用户不存在」vs「密码错误」) 无代码签名",
        "limitations": "需要语义理解错误消息的差异性",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "差异错误消息是业务逻辑意图问题",
            "llm_approach": "LLM 审查登录失败时是否返回统一的模糊错误消息",
        },
    },
    "AUTH-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "验证码强度/类型 (reCAPTCHA/hCaptcha/自研) 无代码签名",
        "limitations": "CAPTCHA 检测需要识别特定库调用",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以识别 CAPTCHA 集成模式",
            "llm_approach": "LLM 审查登录/注册端点是否有 CAPTCHA 验证",
        },
    },
    "AUTH-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "多因素认证流程的完整性和绕过检查",
        "limitations": "MFA 是复杂的业务流程，需要完整理解认证链",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "MFA 绕过检测需要理解整个认证状态机",
            "llm_approach": "LLM 审查 MFA 流程是否可以跳过第二步验证",
        },
    },
    "AUTH-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "注销/退出时服务器端 token 失效",
        "limitations": "Token 黑名单/白名单管理是业务逻辑问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Token 失效策略在代码中以业务逻辑形式出现",
            "llm_approach": "LLM 审查登出端点是否使 JWT/session 在服务端失效",
        },
    },
    "AUTH-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "OAuth 流程中的 state 参数验证和 CSRF 防护",
        "limitations": "OAuth 实现审查需要理解重定向和回调流程",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "OAuth state 参数验证是流程完整性问题",
            "llm_approach": "LLM 审查 OAuth 回调是否验证了 state 参数",
        },
    },
    "AUTH-011": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "OAuth access token 的存储和传输安全",
        "limitations": "Token 存储位置 (Cookie/localStorage/memory) 需要 JS 代码分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Token 存储安全需要分析前端代码",
            "llm_approach": "LLM 审查 Token 存储位置和传输方式",
        },
    },
    "AUTH-012": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "JWT 签名算法验证 (none/HS256混淆/弱密钥)",
        "limitations": "JWT 安全需要分析 JWT 库的使用方式",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "JWT 验证逻辑需要语义理解",
            "llm_approach": "LLM 审查 JWT 验证是否指定了算法白名单 (拒绝 none)",
        },
    },
    "AUTH-013": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "JWT 密钥管理 (弱签名密钥/密钥硬编码/对称密钥泄露)",
        "limitations": "JWT 密钥管理是配置+代码问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "密钥强度检测需要审查密钥来源",
            "llm_approach": "LLM 审查 JWT 签名密钥是否从安全存储加载",
        },
    },
    "AUTH-014": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Remember-me token 的安全存储和失效",
        "limitations": "token 安全是业务逻辑问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Remember-me 实现审查需要完整分析",
            "llm_approach": "LLM 审查 Remember-me token 的生成/存储/失效机制",
        },
    },
    "AUTH-015": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "SAML 断言的签名验证和重放防护",
        "limitations": "SAML 安全需要专业的协议理解",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "SAML 是复杂的企业协议",
            "llm_approach": "LLM 审查 SAML 响应验证是否检查了签名/条件/NotOnOrAfter",
        },
    },
    "AUTH-016": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "API Key 的生成质量 (熵和长度)",
        "limitations": "密钥生成熵检测是专门的密码学审查",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "密钥随机性需要审查生成函数",
            "llm_approach": "LLM 审查 API Key 是否使用 SecureRandom/UUID.randomUUID 生成",
        },
    },
    "AUTH-017": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "两步验证中的 backup code 安全性",
        "limitations": "业务逻辑审查",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Backup code 管理是专门的业务逻辑",
            "llm_approach": "LLM 审查备份码的生成/存储/使用次数限制",
        },
    },
    "AUTH-018": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "用户注册时的邮箱/手机验证流程",
        "limitations": "业务逻辑审查",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "验证流程完整性需要语义理解",
            "llm_approach": "LLM 审查注册流程是否必须先验证邮箱/手机才能激活",
        },
    },
    "AUTH-019": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "OAuth scope 越权 (用户授权的 scope vs 实际使用的 scope)",
        "limitations": "OAuth scope 审查需要理解授权流程",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Scope 验证需要理解 OAuth 授权流程",
            "llm_approach": "LLM 审查 OAuth 回调中是否验证了返回的 scope",
        },
    },
    "AUTH-020": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "OpenID Connect 的 nonce 参数验证防护 CSRF",
        "limitations": "OIDC 是特定协议问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "OIDC nonce 验证是协议安全性",
            "llm_approach": "LLM 审查 OIDC 认证请求中是否使用了 nonce 参数",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # SESSION — 会话管理层 (11 items)
    # ══════════════════════════════════════════════════════════════════
    "SESSION-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Session ID 生成使用的随机源 (SecureRandom vs Random) 可由 crypto_weakness 部分覆盖",
        "limitations": "Session ID 生成通常使用框架默认，不易在应用代码中检测",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Session ID 生成通常在框架内部",
            "llm_approach": "LLM 审查自定义 Session ID 生成逻辑",
        },
    },
    "SESSION-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Session 固定防护 (登录后重新生成 Session ID)",
        "limitations": "需要审查登录流程是否调用了 session.invalidate()/session.regenerateId()",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Session 固定防护是流程完整性问题",
            "llm_approach": "LLM 审查登录成功处理中是否重新生成了 Session ID",
        },
    },
    "SESSION-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Session 超时配置检测",
        "limitations": "超时配置在框架配置文件中，或代码中的 setMaxInactiveInterval 调用",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "检测超时设置是否合理需要审查配置",
            "llm_approach": "LLM 审查 session 超时配置是否合理 (15-30分钟)",
        },
    },
    "SESSION-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Session ID 仅通过 Cookie 传输 (禁止 URL 重写)",
        "limitations": "URL 重写启用是框架配置问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Session URL 重写是框架配置问题",
            "llm_approach": "LLM 审查是否启用了 URL session 追踪 (jsessionid)",
        },
    },
    "SESSION-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "并发 Session 控制 (同一用户允许的最大并发 Session 数)",
        "limitations": "业务逻辑安全",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "并发控制是业务策略问题",
            "llm_approach": "LLM 审查是否有并发 session 限制配置",
        },
    },
    "SESSION-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Session 数据存储安全 (是否加密/存储位置/访问控制)",
        "limitations": "Session 存储后端选择是部署配置问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Session 存储是部署/配置问题",
            "llm_approach": "LLM 审查 Session 存储配置 (Redis/JDBC/Memcached 的加密和访问控制)",
        },
    },
    "SESSION-007": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-016", "CONFIG-017"],
        "detail": "CSRF Token 配置检测 (csrf().disable()/enable-csrf=false)",
        "limitations": "仅检测配置关闭，不检测 CSRF token 验证逻辑的正确性",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "CSRF Token 验证的正确性 (如 token 绑定/单次使用) 需要语义审查",
            "llm_approach": "LLM 审查 CSRF token 的绑定/验证/失效逻辑",
        },
    },
    "SESSION-008": {
        "phase12_status": "covered",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-007", "CONFIG-027"],
        "detail": "Cookie Secure 标志检测 (SESSION_COOKIE_SECURE=False/cookie.secure=false/setUseSecureCookie(false))",
        "limitations": None,
        "needs_phase3": None,
    },
    "SESSION-009": {
        "phase12_status": "covered",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-008", "CONFIG-028"],
        "detail": "Cookie HttpOnly 标志检测 (SESSION_COOKIE_HTTPONLY=False/cookie.http-only=false)",
        "limitations": None,
        "needs_phase3": None,
    },
    "SESSION-010": {
        "phase12_status": "covered",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-010", "CONFIG-029"],
        "detail": "Cookie SameSite 标志检测 (SameSite=None/cookie.same-site=None)",
        "limitations": None,
        "needs_phase3": None,
    },
    "SESSION-011": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-007", "CONFIG-027"],
        "detail": "Cookie Prefix 检测 (__Host-/__Secure- 前缀使用) 未实现",
        "limitations": "Cookie 命名前缀是相对较新的最佳实践",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Cookie 前缀是命名约定，不是代码签名",
            "llm_approach": "LLM 审查敏感 Cookie 是否使用了 __Host-/__Secure- 前缀",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # AUTHZ — 授权/访问控制层 (12 items)
    # ══════════════════════════════════════════════════════════════════
    "AUTHZ-001": {
        "phase12_status": "partial",
        "scanners": ["scan_missing_auth", "scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["auth_bypass"],
        "detail": "端点认证检查 (scan_missing_auth) + auth_bypass taint 追踪",
        "limitations": "授权粒度 (角色/权限层级) 的充分性无法确定",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "授权逻辑的质量评估需要理解业务角色模型",
            "llm_approach": "LLM 审查每个端点的授权注解/逻辑是否与操作敏感度匹配",
        },
    },
    "AUTHZ-002": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["auth_bypass"],
        "detail": "Spring Security hasRole/hasAuthority/@PreAuthorize 使用检测",
        "limitations": "权限注解的存在不等于权限模型的正确性",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "权限模型的充分性需要理解业务需求",
            "llm_approach": "LLM 审查 RBAC 模型是否与业务角色一致",
        },
    },
    "AUTHZ-003": {
        "phase12_status": "partial",
        "scanners": ["scan_missing_auth"],
        "rule_files": [],
        "detail": "敏感操作 (管理端点/数据导出/配置修改) 的授权要求检测",
        "limitations": "敏感操作识别需要语义理解",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "敏感操作分类是语义问题",
            "llm_approach": "LLM 审查管理类端点是否有适当的授权检查",
        },
    },
    "AUTHZ-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "IDOR — 对象级访问控制缺失，无结构性签名",
        "limitations": "IDOR 需要理解对象所有权检查逻辑",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "IDOR 检测需要理解对象所有权查询 (WHERE user_id = ?)",
            "llm_approach": "LLM 审查每个端点是否验证了当前用户对目标资源的所有权",
        },
    },
    "AUTHZ-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "横向/纵向越权 — 功能级访问控制缺失",
        "limitations": "需要理解用户角色和功能对应关系",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "功能级访问控制审查需要完整的角色-功能映射",
            "llm_approach": "LLM 审查不同角色的可用功能是否有适当的隔离",
        },
    },
    "AUTHZ-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "CORS 源验证是否使用了 startsWith/endsWith 而非精确匹配",
        "limitations": "CORS 源验证是字符串比较问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "CORS 源匹配逻辑的正确性需要代码审查",
            "llm_approach": "LLM 审查 CORS Origin 验证是否使用精确匹配而非后缀/前缀匹配",
        },
    },
    "AUTHZ-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "JWT claim 验证是否完整 (exp/nbf/aud/iss)",
        "limitations": "JWT 验证完整性是专门的审查领域",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "JWT claim 验证需要审查 JWT 验证代码",
            "llm_approach": "LLM 审查 JWT 验证是否检查了 exp/nbf/aud/iss 等关键声明",
        },
    },
    "AUTHZ-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "JWT 签名密钥混淆攻击 (使用公钥算法但密钥可控)",
        "limitations": "需要理解 JWT 算法和密钥来源",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "JWT 算法混淆是专门的高级攻击",
            "llm_approach": "LLM 审查 JWT 验证是否限制了允许的算法列表",
        },
    },
    "AUTHZ-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "API 网关层面的访问控制配置",
        "limitations": "API 网关配置通常不在应用代码仓库中",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "网关配置可能在单独的仓库中",
            "llm_approach": "LLM 审查是否有 API 网关配置的引用",
        },
    },
    "AUTHZ-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "GraphQL 字段级/类型级的访问控制",
        "limitations": "GraphQL 授权分析需要 schema 和 resolver 级别的审查",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "GraphQL 字段级授权是特有的授权模型",
            "llm_approach": "LLM 审查 GraphQL resolver 中的字段级授权",
        },
    },
    "AUTHZ-011": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-026"],
        "detail": "Spring Security 方法安全检测 (prePostEnabled=false/securedEnabled=false)",
        "limitations": "仅检测全局配置关闭，不检测单个方法的安全注解",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "每个方法的授权正确性需要逐个审查",
            "llm_approach": "LLM 审查关键业务方法是否有 @PreAuthorize/@PostAuthorize",
        },
    },
    "AUTHZ-012": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-018", "CONFIG-019"],
        "detail": 'Spring Security 全通配配置检测 (anyRequest().permitAll()/antMatchers("/**").permitAll())',
        "limitations": "仅检测 Java/Spring 框架",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Python/JS 框架的同等问题需要扩展",
            "llm_approach": "LLM 审查 Python/JS 项目的路由访问控制配置",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # DATAPRO — 数据保护层 (11 items)
    # ══════════════════════════════════════════════════════════════════
    "DATAPRO-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "客户端-服务端数据传输加密 (HTTPS 使用) 可通过 CONFIG-038 部分覆盖",
        "limitations": "无法检测是否所有敏感数据传输都使用了 HTTPS",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "需要审查所有网络通信点",
            "llm_approach": "LLM 审查 HTTP 客户端调用是否使用 HTTPS",
        },
    },
    "DATAPRO-002": {
        "phase12_status": "covered",
        "scanners": ["scan_secrets", "scan_dangerous_calls"],
        "rule_files": ["secrets.yaml", "dangerous_calls.yaml"],
        "rule_ids": ["DANGER-043", "DANGER-044"],
        "detail": "硬编码密钥检测 (secrets.yaml 基础模式 + DANGER-043/044 Java 专用模式)",
        "limitations": "secrets.yaml 规则需要扩展更多密钥格式",
        "needs_phase3": None,
    },
    "DATAPRO-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "数据脱敏/掩码 (如日志中的信用卡号/身份证号) 无专门规则",
        "limitations": "日志脱敏检测需要匹配敏感数据模式 + 日志输出追踪",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "脱敏检测是数据流 + 语义理解问题",
            "llm_approach": "LLM 审查日志/输出中是否对敏感字段做了脱敏处理",
        },
    },
    "DATAPRO-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "数据库存储加密 (透明加密/TDE) 是数据库层面配置",
        "limitations": "数据库加密通常在 DBA 层面，不在应用代码中",
        "needs_phase3": None,  # 需要 dynamic/infra 检测
    },
    "DATAPRO-005": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["crypto_weakness"],
        "detail": "crypto_weakness 检测弱加密算法",
        "limitations": "仅检测已知弱算法，不检测实现错误 (如 IV 复用/密钥管理)",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "加密实现的正确性需要深度审查",
            "llm_approach": "LLM 审查加密实现中的 IV 管理/密钥派生/认证加密使用",
        },
    },
    "DATAPRO-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "RAM 中的敏感数据清零 (如密码使用后 Arrays.fill(password, '\\0'))",
        "limitations": "内存清零是代码习惯问题，静态分析很难全面覆盖",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "敏感数据清理需要在所有使用点审查",
            "llm_approach": "LLM 审查敏感数据 (密码/密钥) 使用后是否做了清理",
        },
    },
    "DATAPRO-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "安全删除/文件粉碎 (覆写后删除而非直接 delete)",
        "limitations": "安全删除是专门的实现细节",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查是否使用了安全删除方法",
            "llm_approach": "LLM 审查敏感文件删除前是否覆写了内容",
        },
    },
    "DATAPRO-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "数据备份的加密和访问控制",
        "limitations": "备份策略是运维层面的问题",
        "needs_phase3": None,  # 运维层面
    },
    "DATAPRO-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "敏感数据在不同环境 (dev/staging/prod) 的隔离",
        "limitations": "环境隔离是运维配置问题",
        "needs_phase3": None,  # 运维层面
    },
    "DATAPRO-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "数据库连接字符串中的密码文件保护",
        "limitations": "连接字符串通常来自环境变量/配置中心",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查连接字符串的来源",
            "llm_approach": "LLM 审查数据库密码是否从安全配置源加载而非硬编码",
        },
    },
    "DATAPRO-011": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "GDPR/CCPA 数据主体权利的实现 (数据导出/删除)",
        "limitations": "合规需求是业务流程问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "合规功能是业务逻辑审查",
            "llm_approach": "LLM 审查是否有用户数据导出/删除的 API 端点",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # CRYPTO — 密码学层 (13 items)
    # ══════════════════════════════════════════════════════════════════
    "CRYPTO-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "加密库选择 (使用经过认证的库如 libsodium/Tink，而非自研算法)",
        "limitations": "自研加密算法检测是语义问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "自研加密需要代码审查判断",
            "llm_approach": "LLM 审查是否使用了非标准加密实现",
        },
    },
    "CRYPTO-002": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["crypto_weakness"],
        "rule_ids": ["DANGER-035", "DANGER-036", "DANGER-037", "DANGER-038"],
        "detail": "弱哈希/加密/随机/TLS 全面覆盖 (MD5/SHA-1/DES/RC4/ECB/Random/TLSv1/SSLv3)",
        "limitations": None,
        "needs_phase3": None,
    },
    "CRYPTO-003": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-037"],
        "detail": "不安全随机数检测 (new Random()/SecureRandom.setSeed)",
        "limitations": None,
        "needs_phase3": None,
    },
    "CRYPTO-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "密钥管理体系 (KMS/HSM 集成) 是否规范",
        "limitations": "KMS 集成是架构问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "KMS 集成检测需要识别特定 SDK 调用",
            "llm_approach": "LLM 审查密钥管理是否使用了 AWS KMS/Azure Key Vault/HashiCorp Vault",
        },
    },
    "CRYPTO-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "数字签名的正确实现 (算法选择/密钥管理/签名验证)",
        "limitations": "签名实现正确性是密码学专门领域",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "需要专门的密码学审查",
            "llm_approach": "LLM 审查签名实现中的算法选择和验证流程",
        },
    },
    "CRYPTO-006": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls", "scan_config_issues"],
        "rule_files": ["dangerous_calls.yaml", "config_issues.yaml"],
        "rule_ids": ["DANGER-038", "CONFIG-039"],
        "detail": "TLS 版本检测 (SSLv3/TLSv1 弃用版本检测)",
        "limitations": "仅检测代码中硬编码的 TLS 版本，框架配置层面的 TLS 设置",
        "needs_phase3": None,
    },
    "CRYPTO-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "证书固定 (Certificate Pinning) 的实现",
        "limitations": "证书固定在移动端更常见，服务端较少",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以检测 OkHttp CertificatePinner 等实现",
            "llm_approach": "LLM 审查 HTTP 客户端是否实现了证书固定",
        },
    },
    "CRYPTO-008": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-039"],
        "detail": "TrustManager 信任所有证书检测 (X509TrustManager 空实现)",
        "limitations": "仅检测 Java TrustManager 模式，Python/JS 需要扩展",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Python/JS 的证书验证禁用需要补充",
            "llm_approach": "LLM 审查 Python requests(verify=False)/JS NODE_TLS_REJECT_UNAUTHORIZED",
        },
    },
    "CRYPTO-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "密码学协议 (如安全多方计算/同态加密) 的正确使用",
        "limitations": "高级密码学协议是研究级问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "高级密码学需要专门的知识",
            "llm_approach": "LLM 审查高级密码学原语的使用是否遵循最佳实践",
        },
    },
    "CRYPTO-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "HMAC 的密钥长度和哈希算法选择",
        "limitations": "HMAC 实现审查需要理解密钥管理",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "HMAC 安全性需要审查密钥和算法",
            "llm_approach": "LLM 审查 HMAC 使用的密钥长度 (>=256 bits) 和哈希算法 (SHA-256+)",
        },
    },
    "CRYPTO-011": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["crypto_weakness"],
        "rule_ids": ["DANGER-036"],
        "detail": 'AES-ECB 检测 (Cipher.getInstance("AES/ECB") 等)',
        "limitations": None,
        "needs_phase3": None,
    },
    "CRYPTO-012": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-036"],
        "detail": "DES/RC4/Blowfish 检测",
        "limitations": None,
        "needs_phase3": None,
    },
    "CRYPTO-013": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "RSA 密钥长度和填充方案 (PKCS#1 v1.5 vs OAEP)",
        "limitations": "密钥长度和填充方案在代码中很难提取",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "RSA 参数需要审查密钥生成代码",
            "llm_approach": "LLM 审查 RSA 密钥长度 (>=2048) 和填充方案 (OAEP)",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # SQL — SQL/数据库层 (10 items)
    # ══════════════════════════════════════════════════════════════════
    "SQL-001": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "SQL 注入 taint 追踪：40 sinks (JdbcTemplate/MyBatis SqlSession/JPA createNativeQuery/jOOQ DSLContext 等)",
        "limitations": None,
        "needs_phase3": None,
    },
    "SQL-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "存储过程中的动态 SQL 执行，存储过程源码通常不在应用代码库中",
        "limitations": "存储过程在数据库中，超出 SAST 范围",
        "needs_phase3": None,  # 需要数据库层面审查
    },
    "SQL-003": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["sql_injection"],
        "rule_ids": ["DANGER-034"],
        "detail": "PreparedStatement 使用检测 + JDBC Statement (非 PreparedStatement) 标记",
        "limitations": None,
        "needs_phase3": None,
    },
    "SQL-004": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "Hibernate/MyBatis/JPA/jOOQ 动态查询中的参数绑定检测 (sanitizer: .setParameter/#{param}/DSL.param)",
        "limitations": "MyBatis ${} vs #{} 检测需要区分，目前 #{} 是 sanitizer",
        "needs_phase3": None,
    },
    "SQL-005": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "LIKE/IN 子句的参数化检测通过 PreparedStatement setString 等 sanitizer 覆盖",
        "limitations": "动态 ORDER BY/GROUP BY 字段名参数化需要额外检测",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "ORDER BY 字段名白名单需要语义理解",
            "llm_approach": "LLM 审查动态 ORDER BY/GROUP BY 是否使用了字段白名单",
        },
    },
    "SQL-006": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "ORM Criteria API 的动态查询通过 taint 追踪覆盖",
        "limitations": "复杂 Criteria 构造的安全性可能依赖 LLM 判断",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Criteria 安全边界需要语义分析",
            "llm_approach": "LLM 审查 JPA Criteria API 是否允许用户指定任意字段名",
        },
    },
    "SQL-007": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-036", "CONFIG-037"],
        "detail": "SQL 日志输出检测 (spring.jpa.show-sql/logging.level 配置)",
        "limitations": "仅覆盖 Java/Spring，Python/JS 的 SQL 日志需要扩展",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "非 Java 框架的 SQL 日志检测需要 LLM 补充",
            "llm_approach": "LLM 审查数据库查询日志是否记录了敏感数据",
        },
    },
    "SQL-008": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-033"],
        "detail": "NoSQL 注入检测 (MongoDB BasicDBObject/Document.parse/Filters.regex/Filters.where)",
        "limitations": "仅覆盖 Java MongoDB driver，Python/JS 的 PyMongo/Mongoose 需要扩展",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "非 Java NoSQL 注入需要 LLM 补充",
            "llm_approach": "LLM 审查 MongoDB/Redis/Cassandra 查询是否使用了用户输入构造条件",
        },
    },
    "SQL-009": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["sql_injection"],
        "detail": "JDBC 连接 URL 的 SQL 注入 taint 追踪 (注: SQL-009 是连接字符串注入，DriverManager.getConnection 是 sink)",
        "limitations": "连接字符串通常来自配置文件而非用户输入",
        "needs_phase3": None,
    },
    "SQL-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Second-Order SQL 注入 — 污染跨越持久化边界，单请求 CPG 无法追踪",
        "limitations": "需要跨请求的数据流追踪 — 这需要 Phase 3 LLM 理解数据生命周期",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "跨请求数据流追踪超出 CPG 单请求模型",
            "llm_approach": "LLM 审查存储数据在后续查询中是否未做参数化",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # FILE — 文件系统层 (10 items)
    # ══════════════════════════════════════════════════════════════════
    "FILE-001": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["path_traversal"],
        "detail": "Path traversal taint: 35 sinks (Files.readAllBytes/Files.delete/ZipInputStream/getNextEntry 等) + 15 sanitizers (FilenameUtils.normalize/getCanonicalPath 等)",
        "limitations": None,
        "needs_phase3": None,
    },
    "FILE-002": {
        "phase12_status": "partial",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["path_traversal"],
        "detail": "getCanonicalPath/getAbsolutePath/realpath 使用检测通过 sanitizer 模式覆盖",
        "limitations": "仅检测使用，不检测缺失（应该 normalize 但没 normalize）",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "缺失检测是负空间问题",
            "llm_approach": "LLM 审查文件操作前是否调用了路径规范化",
        },
    },
    "FILE-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "符号链接检测需要检查 Files.isSymbolicLink()/lstat() 等调用的存在",
        "limitations": "当前规则库无此模式",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "可以添加 DANGER rule 检测符号链接处理缺失",
            "llm_approach": "LLM 审查文件操作前是否检测了符号链接",
        },
    },
    "FILE-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "临时文件安全 (createTempFile/tempfile.NamedTemporaryFile) 需要检测随机性和权限",
        "limitations": "当前规则库无此模式",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "可以添加 CONFIG rule 检测不安全的临时文件创建",
            "llm_approach": "LLM 审查临时文件创建是否使用了安全 API 和 600 权限",
        },
    },
    "FILE-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "文件权限 (umask/POSIX file permissions) 的静态检测",
        "limitations": "umask/Files.setPosixFilePermissions 使用检测",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以检测权限设置是否遵循最小权限原则",
            "llm_approach": "LLM 审查文件创建后的权限设置",
        },
    },
    "FILE-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "上传目录执行权限配置检测",
        "limitations": "这是 Web 服务器配置 (Nginx/Apache) 问题",
        "needs_phase3": None,  # 基础设施配置问题
    },
    "FILE-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "上传文件名安全处理的代码检测",
        "limitations": "文件名处理是否安全需要审查 sanitize 逻辑",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查文件名清理逻辑",
            "llm_approach": "LLM 审查是否对上传文件名做了重命名/特殊字符清理",
        },
    },
    "FILE-008": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["path_traversal"],
        "detail": "ZIP Slip 检测 (ZipInputStream.getNextEntry/ZipEntry.getName 模式)",
        "limitations": None,
        "needs_phase3": None,
    },
    "FILE-009": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["path_traversal"],
        "detail": "文件下载的用户输入路径验证通过 path_traversal taint 追踪覆盖",
        "limitations": None,
        "needs_phase3": None,
    },
    "FILE-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "TOCTOU 竞态条件 — CPG 无线程交错模型",
        "limitations": "TOCTOU 检测需要时序分析，超出静态分析能力",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "CPG 无法建模线程交错，LLM 可以识别 check-then-use 模式",
            "llm_approach": "LLM 审查文件操作中的 check-then-use 模式",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # NETWORK — 网络/HTTP层 (11 items)
    # ══════════════════════════════════════════════════════════════════
    "NET-001": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["ssrf"],
        "detail": "SSRF taint 追踪: 56 sinks (URL.openConnection/OkHttp/Apache HttpClient/RestTemplate/WebClient/JAX-RS Client 等)",
        "limitations": "内网 IP 过滤/协议白名单的验证需要 LLM",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "SSRF 防护的充分性需要语义审查",
            "llm_approach": "LLM 审查是否有内网 IP 过滤/协议限制/域名白名单",
        },
    },
    "NET-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "DNS Rebinding 防护 — 需要检测 HTTP 客户端是否验证了每次 DNS 解析结果",
        "limitations": "DNS 层面的攻击防护很少在应用代码中显式处理",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "DNS Rebinding 需要在网络层 + 应用层协同防护",
            "llm_approach": "LLM 审查是否有 Host 头验证/DNS 缓存固定",
        },
    },
    "NET-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "HTTP 超时设置需要通过检测 RestTemplate/HttpClient/OkHttp 的 timeout 配置",
        "limitations": "当前规则库无超时检测模式",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "可以添加 CONFIG rule 或 LLM 检测",
            "llm_approach": "LLM 审查 HTTP 客户端是否设置了 connectTimeout/readTimeout",
        },
    },
    "NET-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "HTTP 重定向跟随控制 (allow_redirects=False/maxRedirects:0)",
        "limitations": "当前规则库无此模式",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "可以添加 CONFIG rule 检测",
            "llm_approach": "LLM 审查 HTTP 客户端是否禁用了自动重定向跟随",
        },
    },
    "NET-005": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["open_redirect"],
        "detail": "Open Redirect taint: 25 sinks (sendRedirect/Response.seeOther/Play redirect/ModelAndView redirect)",
        "limitations": "仅检测到重定向 sink，白名单验证需要 LLM 补充",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "白名单验证的充分性需要语义理解",
            "llm_approach": "LLM 审查重定向目标是否使用了 URL 白名单",
        },
    },
    "NET-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Host Header 验证检测 (密码重置/邮箱验证 URL 是否依赖 Host 头)",
        "limitations": "Host 头依赖检测需要数据流分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Host 头验证缺失需要 LLM 审查",
            "llm_approach": "LLM 审查 URL 构造是否使用了 Host 头而非配置的 base URL",
        },
    },
    "NET-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "X-Forwarded-For 头处理 (IP 获取/速率限制基于代理头)",
        "limitations": "代理头处理逻辑没有明确的代码签名",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "代理头处理需要审查 IP 获取逻辑",
            "llm_approach": "LLM 审查是否使用了 X-Forwarded-For 作为信任的客户端 IP",
        },
    },
    "NET-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "HTTP Request Smuggling — 需要 Content-Length/Transfer-Encoding 解析一致性分析",
        "limitations": "走私攻击是协议层面问题，需要基础设施分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "HTTP 走私需要分析代理和应用服务器的一致性",
            "llm_approach": "LLM 审查是否有 CL.TE/TE.CL 走私风险的安全配置",
        },
    },
    "NET-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "WebSocket Origin 验证 — 需要检测 WebSocket 服务器端的 Origin 检查",
        "limitations": "WebSocket 代码中的 Origin 验证检测未实现",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 WebSocket 握手处理中的 Origin 验证",
            "llm_approach": "LLM 审查 WebSocket 服务器端是否验证了 Origin 头",
        },
    },
    "NET-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "请求大小限制 (max-request-size/body-parser limit/nginx client_max_body_size)",
        "limitations": "请求大小限制是框架/服务器配置问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查是否有请求体大小限制",
            "llm_approach": "LLM 审查是否配置了请求体大小限制",
        },
    },
    "NET-011": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "连接池/并发数限制 (maxPoolSize/maxConnections/maxConcurrentStreams)",
        "limitations": "连接池配置检测未实现",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查连接池配置",
            "llm_approach": "LLM 审查数据库/HTTP 连接池的最大连接数配置",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # CONFIG — 配置/部署层 (13 items)
    # ══════════════════════════════════════════════════════════════════
    "CONFIG-001": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-001"],
        "detail": "DEBUG 模式检测 (Django DEBUG=True/NODE_ENV=production 反模式)",
        "limitations": "仅覆盖 Python/JS，Java 的 debug:false 检测需要补充",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "各框架 DEBUG 模式标志不同",
            "llm_approach": "LLM 审查生产环境配置中是否关闭了调试模式",
        },
    },
    "CONFIG-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "CSP 头配置 (Content-Security-Policy) 检测需要审查安全头设置",
        "limitations": "CSP 是 HTTP 头层面的配置，通常在 Nginx/代码中的中间件",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "CSP 配置通常在框架/网关层面",
            "llm_approach": "LLM 审查是否设置了 CSP 头及策略是否合理",
        },
    },
    "CONFIG-003": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-023"],
        "detail": "X-Frame-Options 检测 (Spring Security frameOptions().disable())",
        "limitations": "仅覆盖 Java Spring Security，非 Java 框架需要扩展",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Python/JS 的 X-Frame-Options 设置需要 LLM 审查",
            "llm_approach": "LLM 审查是否设置了 X-Frame-Options 或 CSP frame-ancestors",
        },
    },
    "CONFIG-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "X-Content-Type-Options 头检测未实现",
        "limitations": "需要检测 HTTP 头中间件/Filter 配置",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 审查安全头配置",
            "llm_approach": "LLM 审查是否设置了 X-Content-Type-Options: nosniff",
        },
    },
    "CONFIG-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Referrer-Policy 头检测未实现",
        "limitations": "需要检测 HTTP 头中间件/Filter 配置",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 审查安全头配置",
            "llm_approach": "LLM 审查是否设置了 Referrer-Policy",
        },
    },
    "CONFIG-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Permissions-Policy 头检测未实现",
        "limitations": "需要检测 HTTP 头中间件/Filter 配置",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 审查安全头配置",
            "llm_approach": "LLM 审查是否设置了 Permissions-Policy",
        },
    },
    "CONFIG-007": {
        "phase12_status": "covered",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-038", "CONFIG-025"],
        "detail": "HTTPS 强制检测 (server.ssl.enabled=false/security.require-ssl=false/HSTS disabled)",
        "limitations": "仅覆盖 Java/Spring，Python/JS 的 HTTPS 强制需要扩展",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "非 Java 框架的 HTTPS 配置需要 LLM 补充",
            "llm_approach": "LLM 审查 HTTP 到 HTTPS 的重定向配置和 HSTS 头",
        },
    },
    "CONFIG-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "默认账户/密码的检测需要审查配置文件中的默认凭据",
        "limitations": "默认凭据检测需要已知默认值库",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以识别硬编码的默认密码 (admin/admin 等)",
            "llm_approach": "LLM 审查是否使用了框架/平台默认账户和密码",
        },
    },
    "CONFIG-009": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-030", "CONFIG-031", "CONFIG-032", "CONFIG-033", "CONFIG-034"],
        "detail": "测试后门/调试接口检测 (DevTools remote/H2 Console/Actuator env/configprops)",
        "limitations": "仅覆盖 Java Spring 生态，Python/JS 的调试接口需要 LLM 补充",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "非 Java 框架的调试接口检测需要 LLM",
            "llm_approach": "LLM 审查是否暴露了调试/管理端点",
        },
    },
    "CONFIG-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "不必要的 HTTP 方法禁用检测 (TRACE/OPTIONS/PUT/DELETE)",
        "limitations": "HTTP 方法限制通常在 Web 服务器/框架路由配置层",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查路由定义中使用了哪些 HTTP 方法",
            "llm_approach": "LLM 审查是否禁用了不安全的 HTTP 方法",
        },
    },
    "CONFIG-011": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-012"],
        "detail": "管理接口的访问控制检测 (Actuator 全暴露 management.endpoints.web.exposure.include=*)",
        "limitations": "仅 Java Spring Actuator，其他框架的管理端点需要 LLM",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "Python/JS 的管理接口检测需要 LLM",
            "llm_approach": "LLM 审查管理/内部接口是否有 IP 白名单或认证要求",
        },
    },
    "CONFIG-012": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "COOP/COEP 头设置检测未实现 (跨域隔离)",
        "limitations": "相对较新的安全头",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 审查安全头配置",
            "llm_approach": "LLM 审查是否设置了 COOP/COEP 头",
        },
    },
    "CONFIG-013": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "CORP 头设置检测未实现",
        "limitations": "相对较新的安全头",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 审查安全头配置",
            "llm_approach": "LLM 审查是否设置了 CORP 头",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # BUSINESS — 业务逻辑层 (12 items)
    # ══════════════════════════════════════════════════════════════════
    "BUS-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "多步骤操作的事务完整性 — 无代码签名",
        "limitations": "步骤完整性需要理解业务流程状态机",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "业务流程完整性是 LLM + 动态测试的典型场景",
            "llm_approach": "LLM 审查多步流程是否有服务端状态机控制步骤顺序",
        },
    },
    "BUS-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "价格/数量参数服务端验证 — 需要审查客户端提交的敏感参数是否在服务端重新验证",
        "limitations": "纯业务逻辑，无代码签名",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "价格服务端验证是业务逻辑审查",
            "llm_approach": "LLM 审查支付/订单流程中价格/数量是否来自服务端计算",
        },
    },
    "BUS-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "优惠券/折扣的服务端验证 — 纯业务逻辑",
        "limitations": "无代码签名",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "优惠券验证逻辑的完整性需要 LLM 审查",
            "llm_approach": "LLM 审查优惠券折扣金额/使用次数/适用范围的验证",
        },
    },
    "BUS-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "负数/零值输入的验证 — 需要检测数值参数是否有下限检查",
        "limitations": "当前规则库无此检测，但可以通过简单的 @Min/@Positive 注解检测实现部分覆盖",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "数值下限检测可以通过注解分析 + LLM 补充",
            "llm_approach": "LLM 审查金额/数量参数是否有 @Min/@Positive 或手动下限检查",
        },
    },
    "BUS-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "竞态条件防护 — CPG 无线程交错模型",
        "limitations": "需要审查 SELECT FOR UPDATE/乐观锁/@Version 使用",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "并发控制需要代码审查 + 动态测试",
            "llm_approach": "LLM 审查库存/余额的并发控制 (悲观锁/乐观锁/原子操作)",
        },
    },
    "BUS-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "幂等性/重复提交防护 — 需要审查 Idempotency Key 或去重 Token 机制",
        "limitations": "无代码签名",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "幂等性检测是业务逻辑审查",
            "llm_approach": "LLM 审查支付/下单等关键操作是否有重复提交防护",
        },
    },
    "BUS-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "操作频率限制 — 需要审查是否有 @RateLimiter/rate limit 中间件",
        "limitations": "可以通过检测限流库 (bucket4j/express-rate-limit/flask-limiter) 部分检测",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "频率限制检测可以通过库识别 + LLM 审查",
            "llm_approach": "LLM 审查关键操作 (投票/抽奖/验证码) 是否有频率限制",
        },
    },
    "BUS-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "API 限速 — 需要审查 RateLimiter/Throttling 配置",
        "limitations": "限流通常在网关/中间件层",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "限速配置审查",
            "llm_approach": "LLM 审查 API 层是否有全局/端点级/用户级限速",
        },
    },
    "BUS-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "批量操作的原子性 — 需要审查 @Transactional 覆盖范围",
        "limitations": "事务注解检测未实现",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查批量操作的事务管理",
            "llm_approach": "LLM 审查批量操作是否有事务回滚和失败状态追踪",
        },
    },
    "BUS-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "用户账户生命周期安全 — 注册/激活/冻结/注销流程完整性",
        "limitations": "纯业务逻辑，无代码签名",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "账户生命周期是业务逻辑审查",
            "llm_approach": "LLM 审查注册是否有验证、注销后数据是否删除、冻结是否可绕过",
        },
    },
    "BUS-011": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "业务约束条件验证 — 最低金额/最大数量/库存等",
        "limitations": "纯业务逻辑",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "业务约束验证是 LLM + 动态测试的典型场景",
            "llm_approach": "LLM 审查业务规则 (金额/数量/库存) 是否在服务端强制验证",
        },
    },
    "BUS-012": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "工作流步骤绕过检测 — 需要审查多步流程的强制步骤顺序",
        "limitations": "需要状态机分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "步骤完整性是业务逻辑安全问题",
            "llm_approach": "LLM 审查多步流程是否有服务端强制步骤顺序",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # LOGGING — 日志/监控层 (7 items)
    # ══════════════════════════════════════════════════════════════════
    "LOG-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "安全事件日志记录 — 需要审查是否记录了登录/认证/授权/敏感操作事件",
        "limitations": "日志记录缺失是负空间问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "日志缺失检测需要理解代码意图",
            "llm_approach": "LLM 审查敏感操作 (登录/权限变更/数据导出) 是否有日志记录",
        },
    },
    "LOG-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "日志注入防护 — 可以检测 log.info(user_input)/logger.debug(request.getParameter)",
        "limitations": "CPG taint 可以追踪用户输入到日志调用的路径，但当前无专门的 log_injection 类别",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "可以添加 log_injection taint 类别，或 LLM 审查",
            "llm_approach": "LLM 审查日志调用是否使用了参数化接口而非字符串拼接",
        },
    },
    "LOG-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "日志中敏感信息泄漏 — 需要审查日志内容是否包含密码/Token/信用卡号",
        "limitations": "需要理解日志输出的数据流",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "敏感信息识别需要语义理解",
            "llm_approach": "LLM 审查日志输出中是否包含密码/Token/PII 字段",
        },
    },
    "LOG-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "日志完整性保护 — 需要审查日志存储策略 (append-only/集中式日志系统)",
        "limitations": "日志基础设施配置，超出代码分析范围",
        "needs_phase3": None,  # 基础设施问题
    },
    "LOG-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "审计追踪 — 需要审查关键操作是否有完整审计日志",
        "limitations": "审计追踪完整性是业务需求问题",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "审计日志完整性需要理解业务合规需求",
            "llm_approach": "LLM 审查关键操作是否有用户/时间/IP/资源/操作五要素",
        },
    },
    "LOG-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "日志存储访问控制和加密",
        "limitations": "日志文件权限是部署配置问题",
        "needs_phase3": None,  # 基础设施配置问题
    },
    "LOG-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "分布式追踪 ID 集成 (OpenTelemetry/Jaeger/Zipkin)",
        "limitations": "基础设施/可观测性问题，非安全漏洞",
        "needs_phase3": None,  # 可观测性优化，非安全检测
    },
    # ══════════════════════════════════════════════════════════════════
    # DESERIALIZE — 反序列化安全 (6 items)
    # ══════════════════════════════════════════════════════════════════
    "DESER-001": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["deserialization"],
        "rule_ids": ["DANGER-008", "DANGER-022", "DANGER-023", "DANGER-024"],
        "detail": "Java 反序列化 taint (45 sinks: ObjectInputStream/Fastjson/Jackson/Gson/XStream/Hessian/SnakeYAML) + 4 DANGER rules",
        "limitations": "ObjectInputStream 反序列化是 sink 标记，但需要 taint 分析确定输入来源",
        "needs_phase3": None,
    },
    "DESER-002": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["deserialization"],
        "rule_ids": ["DANGER-007"],
        "detail": "Python pickle.load/loads/yaml.load/unsafe_load 检测",
        "limitations": None,
        "needs_phase3": None,
    },
    "DESER-003": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint"],
        "rule_files": ["taint_rules.yaml"],
        "taint_categories": ["deserialization"],
        "detail": "JS deserialization taint (node-serialize/js-yaml 等) 检测",
        "limitations": "JS 反序列化规则可能不如 Java 完善",
        "needs_phase3": None,
    },
    "DESER-004": {
        "phase12_status": "covered",
        "scanners": ["scan_config_issues", "scan_dangerous_calls"],
        "rule_files": ["config_issues.yaml", "dangerous_calls.yaml"],
        "rule_ids": ["CONFIG-040", "DANGER-024"],
        "detail": "Jackson DefaultTyping 检测 (enableDefaultTyping/activateDefaultTyping) + 配置 enable-default-typing=true",
        "limitations": None,
        "needs_phase3": None,
    },
    "DESER-005": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["deserialization", "xxe"],
        "rule_ids": ["DANGER-023"],
        "detail": "YAML 反序列化 (safe_load/safeLoad vs load/loadAll) 检测",
        "limitations": None,
        "needs_phase3": None,
    },
    "DESER-006": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["deserialization"],
        "rule_ids": ["DANGER-025", "DANGER-026"],
        "detail": "XMLDecoder/XStream 不安全 (XMLDecoder.readObject/XStream.fromXML) 检测",
        "limitations": None,
        "needs_phase3": None,
    },
    # ══════════════════════════════════════════════════════════════════
    # SUPPLY — 依赖/供应链层 (6 items)
    # ══════════════════════════════════════════════════════════════════
    "SUPPLY-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "依赖 CVE 扫描 — 需要集成 OWASP Dependency-Check/Snyk/Trivy 等外部工具",
        "limitations": "供应链安全不在 SAST 引擎范围内，应作为 CI/CD 步骤集成",
        "needs_phase3": None,  # 外部工具 (pip-audit/npm audit/Trivy)
    },
    "SUPPLY-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "过期依赖检测 — 需要外部依赖数据库",
        "limitations": "EOL 检测需要依赖元数据",
        "needs_phase3": None,  # 外部工具
    },
    "SUPPLY-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "依赖最小化/依赖混淆 — 需要审查私有包名与公共注册表的冲突",
        "limitations": "依赖混淆检测需要包管理器元数据分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 package.json/requirements.txt 中的依赖来源",
            "llm_approach": "LLM 审查是否有私有包可能在公共注册表上被抢注",
        },
    },
    "SUPPLY-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "锁文件完整性 — 检测 lock 文件是否在版本控制中",
        "limitations": "文件存在性检查，可以通过简单的文件扫描实现",
        "needs_phase3": None,  # 可添加简单的文件检查规则
    },
    "SUPPLY-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "CDN SRI 完整性 — 需要检测 HTML/模板中的 script/link 标签是否有 integrity 属性",
        "limitations": "SRI 检测需要解析前端模板/HTML",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查前端模板中是否使用了 integrity 属性",
            "llm_approach": "LLM 审查 script/link 标签是否包含 integrity 属性",
        },
    },
    "SUPPLY-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "SBOM 生成 — 需要 CI/CD 集成 CycloneDX/SPDX",
        "limitations": "CI/CD 配置问题，非代码分析",
        "needs_phase3": None,  # CI/CD 配置
    },
    # ══════════════════════════════════════════════════════════════════
    # CLIENT — 客户端安全层 (9 items)
    # ══════════════════════════════════════════════════════════════════
    "CLIENT-001": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "DOM XSS source→sink 检查 — 需要前端 JS AST 分析，当前 CPG 不支持",
        "limitations": "前端 JS 分析不在 Phase 1-2 CPG 范围内",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "DOM XSS 需要前端 JS Semgrep/ESLint + LLM 分析",
            "llm_approach": "LLM 审查前端 JS 中 location.hash→innerHTML 的 DOM XSS sink",
        },
    },
    "CLIENT-002": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "postMessage 安全 — 需要检测 event.origin 的精确匹配验证",
        "limitations": "前端 JS 分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 postMessage 处理中是否使用了精确 origin 匹配",
            "llm_approach": "LLM 审查 addEventListener('message') 中的 event.origin 验证",
        },
    },
    "CLIENT-003": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "客户端 URL 重定向 — 需要检测 location.href/location.replace/window.open 的源",
        "limitations": "前端 JS 分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查客户端路由跳转是否对目标做了白名单验证",
            "llm_approach": "LLM 审查 location.href/window.open 是否使用了用户可控的 URL",
        },
    },
    "CLIENT-004": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "客户端存储敏感数据 — 需要检测 Cookie vs localStorage vs sessionStorage 的使用",
        "limitations": "前端 JS 分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 Token 存储位置",
            "llm_approach": "LLM 审查 JWT/Token 是否存储在 HTTPOnly Cookie 而非 localStorage",
        },
    },
    "CLIENT-005": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "SPA CSP script-src 配置 — 需要审查 CSP 头中是否有 unsafe-inline/unsafe-eval",
        "limitations": "CSP 配置通常在 index.html 或服务器配置中",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 CSP meta 标签或服务器配置",
            "llm_approach": "LLM 审查 CSP 配置中的 script-src 是否避免了 unsafe-inline/unsafe-eval",
        },
    },
    "CLIENT-006": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "第三方 JS 脚本供应链安全 — 需要审查第三方脚本的来源和 SRI",
        "limitations": "前端资源审查",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查模板中的第三方脚本引用",
            "llm_approach": "LLM 审查模板中引用的第三方 CDN 脚本是否有 SRI hash",
        },
    },
    "CLIENT-007": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "前端输入验证双重防护 — 需要审查是否有对应的服务端验证",
        "limitations": "服务端验证的检测已经通过各 taint 类别覆盖",
        "needs_phase3": {
            "llm": True,
            "dynamic": True,
            "reason": "前端验证 ≠ 服务端验证的判断需要 LLM",
            "llm_approach": "LLM 审查前端验证是否有对应的服务端验证逻辑",
        },
    },
    "CLIENT-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Web Worker 安全数据传递 — 需要审查 postMessage 中的数据内容",
        "limitations": "前端 JS 分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 Web Worker 通信中是否传递了敏感数据",
            "llm_approach": "LLM 审查 Worker postMessage 中是否包含 Token/密码",
        },
    },
    "CLIENT-009": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "Service Worker 缓存清理 — 需要审查 SW 缓存的敏感数据",
        "limitations": "前端 SW 代码分析",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查 Service Worker 的缓存策略",
            "llm_approach": "LLM 审查 SW 缓存中是否包含认证响应/敏感数据",
        },
    },
    # ══════════════════════════════════════════════════════════════════
    # MISC — 其他/纵深防御 (10 items)
    # ══════════════════════════════════════════════════════════════════
    "MISC-001": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["code_injection"],
        "rule_ids": ["DANGER-001", "DANGER-040", "DANGER-041", "DANGER-042"],
        "detail": "代码执行 (eval/exec/Function/ScriptEngine/GroovyShell/BeanShell) 全面覆盖",
        "limitations": None,
        "needs_phase3": None,
    },
    "MISC-002": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-035"],
        "detail": "常量时间比较检测 (MessageDigest.isEqual) — 虽然有危险调用检测，但需要额外规则",
        "limitations": "当前规则检测弱哈希 (MD5/SHA-1)，但未直接检测常时比较的使用",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "常量时间比较的缺失检测需要 LLM (正检测使用 == 比较 hash)",
            "llm_approach": "LLM 审查 Token/密码比较是否使用了常时比较函数",
        },
    },
    "MISC-003": {
        "phase12_status": "partial",
        "scanners": ["scan_config_issues"],
        "rule_files": ["config_issues.yaml"],
        "rule_ids": ["CONFIG-035"],
        "detail": "错误暴露堆栈 (server.error.include-stacktrace=always) 检测",
        "limitations": "仅检测 Spring Boot 配置，try-catch 中区分内部/用户错误的逻辑需要 LLM",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "异常处理中的信息泄漏需要语义理解",
            "llm_approach": "LLM 审查 try-catch 中是否区分了内部异常和业务异常",
        },
    },
    "MISC-004": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["command_injection"],
        "rule_ids": ["DANGER-003", "DANGER-004", "DANGER-005", "DANGER-006", "DANGER-046"],
        "detail": "命令注入 taint (ProcessBuilder/Runtime.exec/subprocess/child_process/Commons Exec) + 6 DANGER rules",
        "limitations": None,
        "needs_phase3": None,
    },
    "MISC-005": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["ssti"],
        "rule_ids": ["DANGER-013", "DANGER-028", "DANGER-029", "DANGER-030"],
        "detail": "SSTI 全面覆盖 (Jinja2/Freemarker/Velocity/Thymeleaf/Pebble/Mustache/Handlebars)",
        "limitations": None,
        "needs_phase3": None,
    },
    "MISC-006": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-012", "DANGER-031"],
        "detail": "LDAP 注入检测 (LdapTemplate/LdapQueryBuilder/DirContext.search/ldap.search)",
        "limitations": "仅检测 LDAP API 调用，参数化/转义的充分性需要 LLM",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LDAP 参数化/特殊字符转义的正确性需要语义审查",
            "llm_approach": "LLM 审查 LDAP 查询是否使用参数化过滤或特殊字符转义",
        },
    },
    "MISC-007": {
        "phase12_status": "covered",
        "scanners": ["scan_dangerous_calls"],
        "rule_files": ["dangerous_calls.yaml"],
        "rule_ids": ["DANGER-011", "DANGER-032"],
        "detail": "XPath 注入检测 (XPathFactory/XPathExpression.evaluate/DocumentHelper.selectNodes)",
        "limitations": "仅检测 XPath API 调用，参数化的充分性需要 LLM",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "XPath 参数化的正确性需要语义审查",
            "llm_approach": "LLM 审查 XPath 查询是否使用了参数化或特殊字符转义",
        },
    },
    "MISC-008": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "线程安全/同步控制 — CPG 无线程交错模型",
        "limitations": "线程安全分析需要并发模型，超出 CPG 静态分析能力",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "LLM 可以审查共享资源访问是否有同步控制",
            "llm_approach": "LLM 审查 synchronized/lock/threading.Lock 的使用",
        },
    },
    "MISC-009": {
        "phase12_status": "covered",
        "scanners": ["scan_cpg_taint", "scan_dangerous_calls"],
        "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml"],
        "taint_categories": ["code_injection"],
        "rule_ids": ["DANGER-015", "DANGER-016"],
        "detail": "反射/动态类加载 (Class.forName/Method.invoke/getattr/__import__) 检测",
        "limitations": "仅标记反射调用，输入白名单验证需要 LLM 判断",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "反射调用的输入白名单验证需要语义审查",
            "llm_approach": "LLM 审查动态类加载/反射的类名是否来自白名单",
        },
    },
    "MISC-010": {
        "phase12_status": "uncovered",
        "scanners": [],
        "rule_files": [],
        "detail": "整数溢出安全检查 — 需要数值范围分析和上下文判断",
        "limitations": "整数溢出在 Java/Python 中较少成为安全漏洞 (Python 大整数自动扩展)",
        "needs_phase3": {
            "llm": True,
            "dynamic": False,
            "reason": "整数溢出在 Web 应用中较少见，LLM 可以审查数值边界检查",
            "llm_approach": "LLM 审查数组索引/金额计算的溢出风险",
        },
    },
}


# ── Default classifier for items not in COVERAGE_MAP ─────────────────────

DEFAULT_UNCOVERED: dict[str, Any] = {
    "phase12_status": "uncovered",
    "scanners": [],
    "rule_files": [],
    "detail": "未实现专门的检测规则——Phase 2 未覆盖",
    "limitations": "需要 Phase 3 LLM 或动态测试补充",
    "needs_phase3": {
        "llm": True,
        "dynamic": False,
        "reason": "Phase 2 确定性规则无法覆盖此项",
        "llm_approach": "LLM 基于语义审查",
    },
}


# ── Main generator ────────────────────────────────────────────────────────


def generate_coverage_json() -> dict[str, Any]:
    """Read detection_matrix.json and annotate with Phase 1+2 coverage."""
    matrix_path = PROJECT_ROOT / "docs" / "detection_matrix.json"
    with open(matrix_path, encoding="utf-8") as f:
        matrix = json.load(f)

    total_covered = 0
    total_partial = 0
    total_uncovered = 0
    total_llm_needed = 0
    total_dynamic_needed = 0

    enhanced_categories = []
    for cat in matrix["categories"]:
        enhanced_items = []
        for item in cat["items"]:
            item_id = item["id"]
            coverage = COVERAGE_MAP.get(item_id)
            if coverage is None:
                # Items not explicitly mapped — try fallback classification
                if item.get("deterministic") and not item.get("llm"):
                    # Marked deterministic in matrix but not in our coverage map
                    # → we should eventually cover it but haven't yet
                    coverage = dict(DEFAULT_UNCOVERED)
                else:
                    coverage = dict(DEFAULT_UNCOVERED)

            item["phase12_coverage"] = {
                "status": coverage["phase12_status"],
                "scanners": coverage["scanners"],
                "rule_files": coverage["rule_files"],
                "rule_ids": coverage.get("rule_ids", []),
                "taint_categories": coverage.get("taint_categories", []),
                "detail": coverage["detail"],
                "limitations": coverage.get("limitations"),
            }

            ns = coverage.get("needs_phase3")
            if ns:
                item["phase3_needed"] = ns
                total_llm_needed += 1
                if ns.get("dynamic"):
                    total_dynamic_needed += 1

            # Tally
            if coverage["phase12_status"] == "covered":
                total_covered += 1
            elif coverage["phase12_status"] == "partial":
                total_partial += 1
            else:
                total_uncovered += 1

            enhanced_items.append(item)

        cat_copy = dict(cat)
        cat_copy["items"] = enhanced_items
        enhanced_categories.append(cat_copy)

    # Update summary
    summary = {
        "total_items": total_covered + total_partial + total_uncovered,
        "phase12_summary": {
            "covered": total_covered,
            "partial": total_partial,
            "uncovered": total_uncovered,
            "coverage_rate": round(total_covered / 200 * 100, 1),
            "partial_coverage_rate": round((total_covered + total_partial) / 200 * 100, 1),
        },
        "phase3_needed": {
            "items_requiring_llm": total_llm_needed,
            "items_requiring_dynamic_testing": total_dynamic_needed,
            "note": "LLM 和动态测试有重叠：部分项同时需要 LLM + 动态测试",
        },
        "architectural_note": (
            "当前 CoverageTracker._STRUCTURAL_BLIND_SPOTS 仅硬编码 5 个结构性盲区 "
            "(idor/business_logic/race_condition/second_order/prototype_pollution)，"
            f"但实际有 {total_llm_needed} 个检测项需要 Phase 3 LLM 补充。"
            "Phase 3 启动前必须将盲区清单扩充为此 JSON 中所有 phase3_needed=true 的项，"
            "否则 LLM 通道无法获知需要分析的检测维度。"
        ),
    }

    result = {
        "meta": {
            "generated_by": "scripts/generate_phase12_coverage.py",
            "generated_at": "2026-08-08",
            "source": "docs/detection_matrix.json",
            "description": (
                "Phase 1+2 确定性扫描器对 200 项 ASVS 对齐检测矩阵的覆盖追踪。"
                "每个检测项标注了当前覆盖状态 (covered/partial/uncovered)、"
                "负责的扫描器和规则文件、以及 Phase 3 是否需要 LLM/动态测试补充。"
            ),
            "phase12_scanners": {
                "scan_cpg_taint": "CPG taint 追踪 (taint_rules.yaml) — 13 个漏洞类别",
                "scan_dangerous_calls": "危险调用检测 (dangerous_calls.yaml) — 46 条规则",
                "scan_config_issues": "配置问题检测 (config_issues.yaml) — 41 条规则",
                "scan_secrets": "密钥检测 (secrets.yaml)",
                "scan_missing_auth": "缺失认证检测 — 端点注解审查",
            },
        },
        "categories": enhanced_categories,
        "summary": summary,
    }

    return result


def main() -> None:
    result = generate_coverage_json()
    output_path = PROJECT_ROOT / "docs" / "phase12_coverage_tracking.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"✅ Written {output_path}")
    s = result["summary"]["phase12_summary"]
    print(f"   Covered: {s['covered']}/200 ({s['coverage_rate']}%)")
    print(f"   Partial: {s['partial']}/200 ({s['partial_coverage_rate']}% with partial)")
    print(f"   Uncovered: {s['uncovered']}/200")
    print(f"   Phase 3 LLM needed: {result['summary']['phase3_needed']['items_requiring_llm']}")
    print(
        f"   Dynamic testing needed: {result['summary']['phase3_needed']['items_requiring_dynamic_testing']}"
    )


if __name__ == "__main__":
    main()
