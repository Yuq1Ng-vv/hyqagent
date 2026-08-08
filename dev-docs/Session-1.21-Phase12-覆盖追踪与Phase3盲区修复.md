# Session 1.21 — Phase 1+2 覆盖追踪与 Phase 3 盲区修复

## 目标

1. 对 `detection_matrix.json` 的 200 条 ASVS 对齐检测项做逐项 Phase 1+2 覆盖标注
2. 修复 CoverageTracker 盲区清单的结构性遗漏——确保 Phase 3 LLM 通道不会跳过需要分析的检测维度
3. 确定哪些漏洞类型纯靠 Phase 1+2 确定性规则覆盖、哪些需要 Phase 3 LLM、哪些需要动态测试

## 产出清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `docs/phase12_coverage_tracking.json` | 新增 | 200 条检测项的 Phase 1+2 覆盖追踪 JSON（最终产出） |
| `scripts/generate_phase12_coverage.py` | 新增 | 覆盖 JSON 生成脚本（后续规则更新后可重跑） |
| `src/hyqagent/cpg/coverage.py` | 修改 | 结构性盲区从 5→22 条 + `load_phase3_manifest()` + 整合到 `generate_blind_spot_manifest()` |
| `dev-docs/Session-1.21-*.md` | 新增 | 本文档 |

## 实现过程

### 1. 覆盖追踪 JSON 的设计

对 200 条检测项的每条，添加两个顶层字段：

```json
{
  "phase12_coverage": {
    "status": "covered|partial|uncovered",
    "scanners": ["scan_cpg_taint", "scan_dangerous_calls", ...],
    "rule_files": ["taint_rules.yaml", "dangerous_calls.yaml", ...],
    "rule_ids": ["DANGER-017", "CONFIG-016"],
    "taint_categories": ["sql_injection", "xss"],
    "detail": "具体检测机制",
    "limitations": "当前局限性"
  },
  "phase3_needed": {
    "llm": true|false,
    "dynamic": true|false,
    "reason": "Phase 2 无法覆盖的原因",
    "llm_approach": "LLM 应以什么方式补充检测"
  }
}
```

生成脚本 (`scripts/generate_phase12_coverage.py`) 维护了一个 200 条的 `COVERAGE_MAP` 字典，逐条手工标注。这样做而非自动推断的原因是：

- 同一个 CWE（如 CWE-89 SQL 注入）下有多个检测维度（如参数化、输入验证、二阶注入），覆盖状态不同
- taint 检测的存在 ≠ 检测维度的完整覆盖（如检测到了 SQL sink 但不代表验证了参数化是否正确）
- 精度需要：`partial` vs `covered` vs `uncovered` 的判断需要理解每条检测项的语义

### 2. 覆盖度全局统计

| 指标 | 数量 | 占比 |
|------|------|------|
| 完全覆盖 (covered) | 41 | 20.5% |
| 部分覆盖 (partial) | 33 | 16.5% |
| 未覆盖 (uncovered) | 126 | 63.0% |
| 含部分覆盖总计 | 74 | 37.0% |

**每个分类的覆盖明细**（C=covered, P=partial, U=uncovered）：

```
INPUT     (27):  6C + 13P +  8U — 检测 taint flow，但验证缺失需 LLM
OUTPUT    (12):  2C +  4P +  6U — XSS 好，安全头/CORS 需扩展
AUTH      (20):  0C +  3P + 17U — 几乎全部依赖 LLM
SESSION   (11):  0C +  0P + 11U — 仅 Cookie 标志配置有检测
AUTHZ     (12):  0C +  5P +  7U — 注解缺失+通配配置，授权粒度需 LLM
DATAPRO   (11):  1C +  1P +  9U — 仅硬编码密钥+弱加密算法
CRYPTO    (13):  6C +  0P +  7U — 弱算法全检测，实现正确性需 LLM
SQL       (10):  7C +  1P +  2U — 强的 taint 覆盖，二阶注入需 LLM
FILE      (10):  3C +  1P +  6U — 路径穿越/ZIP Slip 全，权限/TOCTOU 需扩展
NETWORK   (11):  2C +  0P +  9U — SSRF+OpenRedirect，8 项防御配置需 LLM
CONFIG    (13):  1C +  4P +  8U — 仅 Java/Spring 生态，跨框架差距大
BUSINESS  (12):  0C +  0P + 12U — 纯业务逻辑，0% 确定性覆盖
LOGGING   ( 7):  0C +  0P +  7U — 未实现
DESERIALIZE(6):  6C +  0P +  0U — ✅ 唯一 100% 覆盖的类别
SUPPLY    ( 6):  0C +  0P +  6U — 供应链需外部工具
CLIENT    ( 9):  0C +  0P +  9U — 前端 JS，CPG 不支持
MISC      (10):  7C +  1P +  2U — 74% 覆盖
```

### 3. 架构修复：CoverageTracker 盲区清单大修补

**问题诊断**：

`_STRUCTURAL_BLIND_SPOTS` 原来只有 5 条硬编码盲区：
```python
# 原来只有这 5 条：
- idor_no_structural_signature
- business_logic_no_sink
- race_condition_not_modeled
- second_order_not_modeled
- prototype_pollution_not_modeled
```

Phase 3 LLM 如果仅依赖此清单作为"需要分析的检测维度"，会遗漏：
- 认证实现质量（JWT 安全、OAuth/OIDC、密码策略、MFA……）
- 授权粒度（横向/纵向越权、CORS 源验证、GraphQL 字段授权……）
- 数据保护全生命周期（脱敏、内存清理、合规……）
- HTTP 安全头（CSP/CORS/COOP/COEP/CORP……）
- …等共 ~140 个检测项

**修复方案**：

1. **`_STRUCTURAL_BLIND_SPOTS`** 从 5 条扩展到 22 条，按 Phase 3 检测维度分组：

```python
_STRUCTURAL_BLIND_SPOTS = [
    # 原有的 5 条（保留，增加 matrix_ids 字段）
    {"reason": "idor_no_structural_signature", ..., "matrix_ids": "AUTHZ-004"},
    {"reason": "business_logic_no_sink", ..., "matrix_ids": "BUS-001,BUS-002,..."},
    {"reason": "race_condition_not_modeled", ..., "matrix_ids": "BUS-005,FILE-010,MISC-008"},
    {"reason": "second_order_not_modeled", ..., "matrix_ids": "SQL-010"},
    {"reason": "prototype_pollution_not_modeled", ..., "matrix_ids": "MISC-JS-PROTO-POLLUTION"},
    
    # 新增 17 条 Phase 3 必备维度（每条标注涉及的 matrix_ids）
    {"reason": "negative_space_validation", ..., "matrix_ids": "INPUT-001,INPUT-002,..."},
    {"reason": "auth_implementation_quality", ..., "matrix_ids": "AUTH-001...AUTH-020,..."},
    {"reason": "authorization_granularity", ..., "matrix_ids": "AUTHZ-001...AUTHZ-012"},
    {"reason": "data_protection_lifecycle", ..., "matrix_ids": "DATAPRO-001...DATAPRO-011"},
    {"reason": "crypto_implementation_correctness", ..., "matrix_ids": "CRYPTO-001,CRYPTO-004,..."},
    {"reason": "http_security_headers", ..., "matrix_ids": "OUTPUT-007,OUTPUT-008,..."},
    {"reason": "network_defense_config", ..., "matrix_ids": "NET-002,NET-003,..."},
    {"reason": "deploy_config_gaps", ..., "matrix_ids": "CONFIG-001,CONFIG-008,..."},
    {"reason": "logging_security", ..., "matrix_ids": "LOG-001,LOG-002,LOG-003,LOG-005"},
    {"reason": "client_side_js_security", ..., "matrix_ids": "CLIENT-001...CLIENT-009"},
    {"reason": "injection_edge_cases", ..., "matrix_ids": "INPUT-009,INPUT-010,..."},
    {"reason": "sql_advanced", ..., "matrix_ids": "SQL-002,SQL-005,SQL-006,..."},
    {"reason": "file_security_gaps", ..., "matrix_ids": "FILE-002,FILE-003,..."},
    {"reason": "ssrf_defense_depth", ..., "matrix_ids": "INPUT-005,INPUT-027,NET-001,NET-002"},
    {"reason": "ssti_xss_defense_depth", ..., "matrix_ids": "INPUT-003,INPUT-025,..."},
    {"reason": "misc_security_gaps", ..., "matrix_ids": "MISC-002,MISC-003,MISC-008,MISC-010"},
    {"reason": "supply_chain_gaps", ..., "matrix_ids": "SUPPLY-001,SUPPLY-002,..."},
]
```

2. **新增 `load_phase3_manifest()` 方法**：从 `docs/phase12_coverage_tracking.json` 动态加载所有 `phase3_needed.llm=true` 的检测项，生成 146 条 BlindSpot 条目供 Phase 3 使用。

3. **`generate_blind_spot_manifest(include_phase3=True)`**：整合三层盲区——
   - 22 条结构性盲区（总是存在）
   - 动态类别缺口（本扫描未触发的 taint 类别）
   - 146 条 Phase 3 清单（来自覆盖 JSON）
   
   **总计：179 条盲区条目，确保 Phase 3 LLM 不会遗漏任何检测维度。**

### 4. Phase 3 LLM 输入保证

现在的盲区清单生成流程：

```
CoverageTracker.generate_blind_spot_manifest(include_phase3=True)
    │
    ├── 1. 端点无 source 覆盖（per-scan）
    ├── 2. 端点缺认证注解（per-scan）
    ├── 3. 22 条结构性盲区（always）     ← 从 5 条扩展到 22 条
    ├── 4. 未触发 taint 类别（per-scan）
    └── 5. load_phase3_manifest()       ← 新增：146 条来自覆盖 JSON
```

Phase 3 启动时，LLM 通道读取此清单即可获知全部需要分析的检测维度，结合每条的 `matrix_ids` 可以反查 `detection_matrix.json` 获取完整的检测标准文本（`detail` 字段），形成结构化的审计 Prompt。

## 质量门禁

```
uv run pytest -x --tb=short
  → 883 passed, 2 skipped, 5 warnings in 8.22s ✅

uv run ruff check src/hyqagent/cpg/coverage.py
  → 无新增错误 ✅

JSON 验证：
  - phase12_coverage_tracking.json: 200 items, valid JSON ✅
  - 覆盖数据一致性：全部分类 item 总数 = 200 ✅
```

## 设计反思

### 做得好

1. **逐条手工标注而非自动推断**：200 条全手工标注虽然耗时，但避免了自动推断的三种典型错误：
   - 同 CWE 不同检测维度的混淆（如 SQL-001 参数化 vs SQL-010 二阶注入）
   - taint 存在 ≠ 完整覆盖（如检测到 SSRF sink ≠ 覆盖了 IP 过滤验证）
   - sanitizer 检测 ≠ 质量检测（如检测到 sanitizer ≠ sanitizer 配置正确）
2. **架构问题在 Phase 3 启动前修复**：如果等到 Phase 3 开发时才发现盲区清单不完整，返工成本会高很多
3. **覆盖 JSON 作为权威数据源**：`_STRUCTURAL_BLIND_SPOTS` 引用 `matrix_ids`，`load_phase3_manifest()` 从 JSON 动态加载，单一数据源避免不一致

### 可改进

1. **覆盖 JSON 维护成本**：新增/修改 Phase 2 规则后需要同步更新覆盖标注。可以通过 CI 检查确保 JSON 同步
2. **Python/JS 覆盖度低于 Java**：当前覆盖标注以 Java 规则库为准，Python/JS 的覆盖状态可能更差
3. **63% 未覆盖是现实但也是警示**：Phase 3 LLM 承担了绝大部分检测工作，LLM Prompt 质量和上下文管理将是 Phase 3 成功的关键

### 后续开发中需持续跟踪的未覆盖项

Phase 3 及后续版本的开发必须考虑以下检测维度（按优先级排列）：

**P0 — Phase 3 启动时必须覆盖：**
- 认证实现质量（AUTH-001 ~ AUTH-020，20 项）—— 密码策略/JWT/OAuth/OIDC/MFA/暴力保护
- 授权粒度（AUTHZ-004 ~ AUTHZ-010）—— IDOR/横向越权/纵向越权/功能级访问控制
- 会话管理（SESSION-001 ~ SESSION-007）—— Session 固定/超时/并发/存储安全

**P1 — Phase 3 重点：**
- 业务逻辑（BUS-001 ~ BUS-012，12 项全未覆盖）—— 多步流程/价格验证/竞态条件/幂等性
- 输入验证缺失（negative_space_validation）—— "应该有但没写"的负空间问题
- SSRF 防御纵深（INPUT-005, NET-001, NET-002）—— IP 过滤/协议白名单/DNS Rebinding
- 安全头配置（CONFIG-002 ~ CONFIG-006, OUTPUT-007 ~ OUTPUT-012）—— CSP/CORS/COOP/COEP

**P2 — 后续迭代：**
- 日志安全（LOG-001 ~ LOG-007）—— 安全事件记录/日志注入/敏感信息泄漏
- 文件安全缺口（FILE-003 ~ FILE-007, FILE-010）—— 符号链接/临时文件/权限/TOCTOU
- 网络防御配置（NET-002 ~ NET-011）—— 超时/重定向控制/Host 验证/HTTP 走私

**P3 — 低优先级/需外部工具：**
- 客户端 JS（CLIENT-001 ~ CLIENT-009）—— 需要前端 AST 分析
- 供应链（SUPPLY-001 ~ SUPPLY-006）—— 需集成 Trivy/npm audit/pip-audit
- 高级密码学（CRYPTO-004/005/007/009/010/013）—— 需专门的密码学审查

## 下步衔接

1. **Phase 3 LLM 通道开发**：基于本 Session 的盲区清单（179 条），设计 LLM Prompt 模板和上下文管理策略
2. **Python 规则扩展**：参照 Session 1.20 的 Java 扩展方法论，提升 Python 覆盖度
3. **JavaScript 规则扩展**：覆盖 Express/Next.js/NestJS 生态
4. **CI 检查**：添加检查确保 `phase12_coverage_tracking.json` 与 `detection_matrix.json` 的 item 数量一致
5. **规则更新后重跑**：每次修改 taint_rules/dangerous_calls/config_issues 后执行 `uv run python scripts/generate_phase12_coverage.py` 更新覆盖数据
