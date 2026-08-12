# Session 1.45 计划 — CPG 污点精度提升

## 当前状态

Session 1.44 打通了 CPG 跨文件污点追踪管道（0→450 TAINT-001），但有效率仅 ~5%。
三个根本问题需要解决。

## 具体任务

### 1. NODE_PARAMETER 过度标记修复

**文件**：`src/hyqagent/cpg/graph.py` `_label_taint_nodes` 方法

**改法**：
- NODE_PARAMETER 分支的 `source_text` 从 `func_signature_by_name.get(encl_func, "")` 改为只提取函数签名中的 Spring 注解部分
- 注解→类别精确映射表：`@RequestParam`→`injection_general`、`@PathVariable`→`path_traversal`、`@RequestBody`→`injection_general` 等
- 不再用函数体代码做参数 source 判断

### 2. Sink 排除白名单

**文件**：`src/hyqagent/cpg/graph.py` `_label_taint_nodes` 或 `src/hyqagent/cpg/taint_rules.yaml`

**改法**：
- `taint_rules.yaml` 的 sink rules 添加 `exclude_pattern` 字段
- 白名单：`I18nUtil\.getString`、`\.toString\(\)`、`Exception.*getResponseBodyAsString`、`MessageFormat\.format\(.*getString`
- 在 `_label_taint_nodes` 匹配 sink 后做排除检查

### 3. 非污点 CVE 规则补充

**文件**：
- `src/hyqagent/cpg/rules/dangerous_calls.yaml` — 添加 StringSubstitutor 相关规则
- `src/hyqagent/cpg/rules/hardcoded_rules.yaml` — 添加 JWT secret 模式

**commons-text CVE-2022-42889**：
- 检测 `StringSubstitutor.replace()` / `StringSubstitutor.substitute()` 调用
- 检测 `ScriptStringLookup` / `ScriptEngine` 组合使用

**xxl-job CVE-2020-29204**：
- 检测 `XxlJobAdminConfig` 中硬编码的 `accessToken`
- 检测 `@Value("${xxl.job.accessToken}")` 模式（如果默认值硬编码）

### 4. 回归验证

- 5 个 CVE 目标重新扫描
- 目标：≥3 个真实命中，有效率 ≥20%

## 预期产出

- `src/hyqagent/cpg/graph.py` — NODE_PARAMETER source 标记精度修复
- `src/hyqagent/cpg/rules/taint_rules.yaml` — sink 排除模式
- `src/hyqagent/cpg/rules/dangerous_calls.yaml` — StringSubstitutor 规则
- `src/hyqagent/cpg/rules/hardcoded_rules.yaml` — JWT secret 规则
