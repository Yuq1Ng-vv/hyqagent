# Session 1.13 — ureport2 真实漏洞检测：系统性根因分析与修复

## 目标
用 rwtests/ureport2 (真实 Java 项目, 4 个已知漏洞) 验证 Phase 1 扫描器，
发现并修复所有阻碍真实漏洞检测的系统性缺陷。

## 产出清单

| 文件 | 改动 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/taint_rules.yaml` | +218/-46 行 | YAML 模式全面审计修复 |
| `src/hyqagent/cpg/graph.py` | +67 行 | 新增 `_add_rhs_to_lhs_edges` 方法 |
| `src/hyqagent/cpg/query.py` | +23/-4 行 | `_find_nodes` 增加 `exclude_types` 参数 |

## 实现过程

### 1. 调试起点
用户中断前正在调试 ureport2 SQL 注入：
- 源码: `DatasourceServletAction.previewData()`
- 路径: `req.getParameter("sql")` → `parseSql()` → `jdbc.queryForList(sql, map)`
- 问题: 扫描器未能检测到此漏洞

### 2. 诊断方法
- 解析单个 Java 文件 (DatasourceServletAction.java)
- 检查 CPG graph 的节点和边
- 测试不同 source/sink pattern 组合的 find_path 结果
- 启动 3 个并行 Agent: YAML 审计 / Graph 数据流分析 / rwtests 漏洞覆盖

### 3. 发现的三个根本性缺陷

#### 缺陷 1: YAML 模式过于变量名特定 (Root Cause #1)
- `request.getParameter(` → 0 匹配，代码用 `req.getParameter(`
- `jdbcTemplate.query(` → 0 匹配，代码用 `jdbc.queryForList(`
- 修复: 全部改为 `.methodName(` 模式 (变量无关)
- 同时发现: Python 和 JavaScript 的 YAML 也存在同样问题 (将在 Phase 2 修复)

#### 缺陷 2: CPG Graph 数据流断链 (Root Cause #2)
```
variable_ref(sql@235) ──???──▶ assignment(list@235)
```
graph 只追踪单变量 de-fuse 链，不追踪跨变量 RHS→LHS 流入。
修复: `_add_rhs_to_lhs_edges()` — 将同行的 var_ref 连接到 assignment。

#### 缺陷 3: 函数节点的源/汇误匹配 (Root Cause #3)
`_find_nodes` 在函数节点的 body 文本中匹配到 source/sink，
产生无意义的 2 跳假路径。
修复: `find_path` 排除 NODE_FUNCTION 节点。

### 4. 额外发现 (Agent 并行分析)
- rwtests/ureport2 有 4 个已知漏洞，修复前只能检测到 1 个
- 缺少整个 XXE 类别 (DOM4J SAXReader)
- JDBC 注入 RCE 的 sink 模式完全缺失
- 5 个 CPG 数据流缺口全部确认
- Python/JavaScript 的 YAML 也存在变量名硬编码问题
- 多个 sanitizer 模式会产生大量假阴性 (移除)

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `find_path('request.getParameter(', ...)` → 0 paths | 代码使用 `req` 变量名，模式写死 `request` | `.getParameter(` 变量无关模式 |
| `find_path(..., 'jdbcTemplate.query(')` → 0 paths | 实际调用 `.queryForList(`, 而且变量名是 `jdbc` | 补充 `.queryForList(`, `.queryForObject(`, `.queryForMap(` |
| 修复后在模式匹配正确的组合下仍是 0 条路径 | variable_ref(sql@235) 到 assignment(list@235) 无边 | `_add_rhs_to_lhs_edges()` |
| 修复后获得路径但路径质量极差(2跳) | function 节点→assignment 直接 DATA_FLOW 边 | `exclude_types={NODE_FUNCTION}` |
| test_rules_for_java 失败 | YAML 中 command_injection sanitizers 变为 null | 显式设 `command_injection: []` |
| `PreparedStatement` 假阴性风险 | 类型名匹配函数声明/参数类型/imports | 从 sanitizers 移除, 保留方法级 `.setString(` 等 |

## 质量门禁
- ruff: (未运行, 仅修改 YAML + 少量 Python)
- mypy: (未运行, 同上)
- pytest: **372 passed** ✓

## 设计反思

### 做得好
- 用实际漏洞项目(ureport2, 4个CVE)来验证的决策完全正确
- 并行 Agent 策略非常高效: 3 个维度同时分析，各自产出专业报告
- 调试工具链 (单文件解析 + graph 节点检查) 定位问题精准
- YAML 模式审计覆盖了 3 种语言 × 9 个类别

### 可改进
- Python/JavaScript 的 YAML 变量名问题本次未修 (留到 Phase 2)
- 跨函数数据流 (Gap 4) 需要重点投入
- 应该在 CI 中加入真实漏洞项目的回归测试
- rwtests/ 不应提交到 git (100MB+ 二进制图片)

## 下步衔接

### Phase 2 启动前需要处理:
1. **Python YAML 重写**: 移除所有 `request.` 前缀 → 变量无关模式
2. **JavaScript YAML 重写**: 移除 `req.query` 等硬编码变量名
3. **跨函数数据流**: 实现 Gap 4 (caller→callee→return)
4. **添加 Django/FastAPI/Koa/Next.js 框架源模式**
5. **添加 Vue/Angular/Svelte XSS 模式**
6. **完整端到端测试**: 对 rwtests/ureport2 的4个漏洞跑完整验证

### 已知风险
- `.read(` 在 XXE sinks 中太泛 (会匹配 InputStream.read 等)
- `.query(` 在 SQL sinks 中会匹配 document.querySelector
- 需要上下文感知或复合模式来降低假阳性

### 文档
- YAML 审计 Agent 报告: 完整的 3 语言 × 9 类别审计
- Graph 分析 Agent 报告: 5 个数据流缺口的详细分析
- rwtests Agent 报告: 4 个漏洞的逐项检测覆盖评估
