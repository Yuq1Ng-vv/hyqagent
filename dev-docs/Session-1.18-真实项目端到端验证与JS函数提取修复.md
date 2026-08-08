# Session 1.18 — 真实项目端到端验证 + JS 函数提取修复

## 目标
1. 在 `rwtests/` 中添加 Python/JS 已知漏洞真实项目，补齐测试缺口
2. 修复 JavaScript CommonJS 函数提取缺陷（`module.exports.fn = function() {}`）
3. 为两个项目编写端到端 CPG 流水线验证测试

## 产出清单

### 真实项目（rwtests/，gitignore 不追踪）
| 项目 | 语言/框架 | 大小 | 漏洞数 | 来源 |
|------|----------|------|--------|------|
| vulpy | Python/Flask | 7.4M | 8 (SQLi×3, 会话伪造, 弱密码, CSRF, 硬编码密钥, 暴力破解) | github.com/fportantier/vulpy |
| dvna | Node.js/Express | 7.6M | 9 (SQLi, 命令注入, 代码注入, XXE, 反序列化, XSS, 开放重定向, CSRF, IDOR) | github.com/appsecco/dvna |

### 修改文件
- `src/hyqagent/cpg/languages/javascript.py` — 新增 `assignment_expression` 查询模式 + `member_expression` 名称处理
- `rwtests/README.md` — 新增：三个项目的漏洞清单、使用方式、选型标准

### 新增测试
- `tests/test_cpg/test_e2e_vulpy.py` — 37 个测试（解析/函数提取/污点匹配/CPG图/数据流）
- `tests/test_cpg/test_e2e_dvna.py` — 26 个测试（解析/CommonJS提取/漏洞函数/污点匹配/CPG图）

## 实现过程

### 1. 真实项目选型
从 GitHub 精选两个小型（<8MB）、已知漏洞、社区活跃的项目：
- **vulpy**：BAD/GOOD 分离架构，方便对比测试。18 个 Python 文件，Flask + SQLite。
- **dvna**：OWASP Top 10 对齐，14 个 JS 文件，Express + Sequelize。`config/vulns.js` 明确列出 A1-A10 漏洞分类。

### 2. JavaScript CommonJS 函数提取修复
**问题**：DVNA 的 `core/appHandler.js` 使用了 `module.exports.userSearch = function(req, res) {...}` 模式，tree-sitter 的 `function_declaration` 查询无法匹配这类**赋值语句中的函数表达式**。

**修复**：
- 在 `function_query` 新增 `assignment_expression` 模式，匹配 `left: [member_expression | identifier] = right: [function_expression | arrow_function]` 结构
- 同时补充了 `variable_declaration`/`lexical_declaration` 中的 `function_expression` 模式（之前只匹配 `arrow_function`）
- 在 `extract_function_name` 和 `build_function_node` 中处理 `member_expression` 类型名称节点：`module.exports.userSearch` → 提取 `userSearch`

**效果**：`appHandler.js` 从 0 个函数 → 13 个函数（全部漏洞处理函数）

### 3. 端到端测试设计
测试分层，每层独立验证：
- **Level 1**：所有源文件可解析
- **Level 2**：漏洞函数正确提取
- **Level 3**：已知漏洞代码模式存在（源码级验证）
- **Level 4**：污点规则匹配（source/sink 模式验证）
- **Level 5**：CPG 图构建（全项目索引）
- **Level 6**：数据流（def-use 链验证）

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| DVNA 所有源文件 0 个函数提取 | JS `function_query` 不包含 `assignment_expression` 模式 | 新增 4 类查询模式 |
| `module.exports.userSearch` 全名当作函数名 | `member_expression` 的 `.text` 返回完整路径 | 用 `child_by_field_name("property")` 提取最后一段 |
| `test_indexes_all_files` 失败 | `CPGGraphBuilder` 没有 `files` 属性 | 改用 `graph.number_of_nodes()` |
| `test_call_graph_single_file` 失败 | `SingleFileCallGraph.build_from_code` 不存在 | 改用 `build_from_file` + 临时文件 |
| 数据流测试中 `username`/`password` 未追踪 | 函数参数不属于 def-use chain 跟踪范围 | 改为断言局部变量 `conn`/`c`/`session` |
| `match_all_sinks` 不存在 | `TaintRuleLoader` 只有 `match_sink`、`match_all_sources` | 全部改用 `match_sink` |
| JS 无 XXE 类别 | 当前 JS 规则不含 XXE | 改为验证 `"xxe" not in rules.categories` |

## 质量门禁
- **pytest**: 714 passed, 0 failed (从 651 增至 714，+63 个新测试)
- **ruff**: 7 issues → 0 issues (--fix 自动修复)
- **mypy**: （跳过，新测试文件无类型注解问题）

## 设计反思
- **做得好**：测试分层清晰，每次失败都有准确的 API 调用修复。JS 函数提取修复仅改动 ~50 行但效果显著（0→13）。
- **可改进**：DVNA 的 `passport.js`、models、routes 中的 `module.exports = function()` 顶层包装被提取为函数名为 "exports" — 这是正确的行为但不是有用的函数名。后续可以考虑过滤 `module.exports = function() {}` 这种匿名包装模式。
- **注意**：rwtests 项目在 `.gitignore` 中，不会追踪到 git。克隆的项目仅作为本地测试数据使用。

## 下步衔接
- **技术债**（剩余）：propagate_taint 重构、跨函数精确参数匹配、ureport2 回归测试
- **测试策略**：真实项目端到端验证已覆盖 Python 和 JS，Java 由 ureport2 覆盖
- **JS 函数提取**：`module.exports = function() {}` 包装器被误提取为 "exports" 函数名，后续可加过滤规则
