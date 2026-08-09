# Session 1.30 — Java 深: 注解提取 + 框架深化 + 配置扫描

## 目标

深化 Java 语言支持（"先做 Java 深"），在添加 PHP/Go 支持之前补齐 Java 侧的短板：
- 实现 tree-sitter Java 注解提取（`extract_decorators()` 之前返回 `[]`）
- 新增 JAX-RS / Jakarta REST 框架提取器
- 深化 Spring 提取器（控制器验证、FeignClient、Actuator）
- 新增 Java 部署描述符扫描器（pom.xml / properties / web.xml）
- 扩展 Java 漏洞测试覆盖（反序列化/JNDI/SpEL/XXE/SSTI）

## 产出清单

| 操作 | 文件 | 说明 |
|------|------|------|
| **新增** | `src/hyqagent/cpg/frameworks/jaxrs.py` | JAX-RS / Jakarta REST 框架提取器 (~250 lines) |
| **新增** | `src/hyqagent/scanner/java_config.py` | Java 项目配置扫描器 (~380 lines) |
| **新增** | `tests/test_cpg/test_java_annotations.py` | Java 注解提取测试 (8 tests) |
| **新增** | `tests/test_scanner/test_java_config.py` | 配置扫描器测试 (12 tests) |
| **新增** | `tests/test_cpg/fixtures/jaxrs_sample.java` | JAX-RS 示例控制器 (8 endpoints) |
| **新增** | `tests/test_cpg/fixtures/parity_deser.java` | 反序列化漏洞 fixture |
| **新增** | `tests/test_cpg/fixtures/parity_jndi.java` | JNDI 注入 fixture |
| **新增** | `tests/test_cpg/fixtures/parity_spel.java` | SpEL 注入 fixture |
| **新增** | `tests/test_cpg/fixtures/parity_xxe.java` | XXE 漏洞 fixture |
| **新增** | `tests/test_cpg/fixtures/parity_ssti.java` | SSTI (FreeMarker) fixture |
| **修改** | `src/hyqagent/cpg/languages/java.py` | 实现 `extract_decorators()` + 接入 `build_function_node/build_class_node` |
| **修改** | `src/hyqagent/cpg/frameworks/spring.py` | 控制器验证 + FeignClient + Actuator + 类型注解修复 |
| **修改** | `src/hyqagent/scanner/orchestrator.py` | 接线 JaxRsExtractor |
| **修改** | `tests/test_cpg/test_frameworks.py` | +15 测试 (JAX-RS 10 + Spring 深化 5) |
| **修改** | `tests/test_cpg/test_cross_language_parity.py` | +5 Java 漏洞 fixture + 参数化 |

## 实现过程

### Step 1: JavaAdapter 注解提取

tree-sitter Java AST 中，注解位于 `modifiers` 节点的 `annotation`（带参数）和 `marker_annotation`（无参数）子节点中。实现方式：

```python
def extract_decorators(self, node: Node) -> list[str]:
    for child in node.children:
        if child.type == "modifiers":
            for modifier in child.children:
                if modifier.type in ("marker_annotation", "annotation"):
                    text = modifier.text.decode("utf-8") if modifier.text else ""
                    if text:
                        decorators.append(text)
            break
    return decorators
```

此方法现在是 `build_function_node()` 和 `build_class_node()` 的注解来源。注解包含完整文本（如 `@GetMapping("/users/{id}")`），供框架提取器使用。

### Step 2: JAX-RS 框架提取器

遵循 `BaseFrameworkExtractor` 接口，支持以下注解：
- **类级/方法级** `@Path` — 路由前缀与子路由合并
- **HTTP 方法**: `@GET/@POST/@PUT/@DELETE/@PATCH/@HEAD/@OPTIONS`
- **参数**: `@PathParam/@QueryParam/@FormParam/@HeaderParam/@CookieParam/@MatrixParam/@BeanParam`
- **安全**: `@RolesAllowed/@PermitAll/@DenyAll`

`detect()` 检查 `javax.ws.rs` 或 `jakarta.ws.rs` 导入 + `@Path` 注解存在。

### Step 3: Spring 提取器深化

三个主要增强：
1. **`_is_controller_class()`**: 验证包围类是否为 `@RestController/@Controller/@RequestMapping` — 非控制器类（如 `@Service`）的映射注解方法被跳过，降低误报
2. **`_find_feign_client()`**: 检测 `@FeignClient(name, url)` 声明式 HTTP 客户端接口
3. **`_find_actuator_endpoint()`**: 检测 `@Endpoint/@WebEndpoint` + `@ReadOperation/@WriteOperation/@DeleteOperation`

### Step 4: Java 配置扫描器

纯确定性模块，零 LLM 调用：
- **pom.xml**: Maven 命名空间感知解析，提取依赖 + 版本对比（`_compare_versions()`）
- **危险依赖检测**: log4j-core/fastjson/commons-collections/struts2-core/commons-text/xstream/snakeyaml 共 8 种
- **application.properties/yml**: 键值提取（含缩进嵌套 YAML）
- **web.xml**: 命名空间感知的 servlet-mapping/filter-mapping/security-constraint 提取
- **危险配置检测**: Actuator 全暴露/DevTools 启用/Security 禁用

### Step 5: Orchestrator 接线

`orchestrator.py` 中 Java 框架列表从 `[SpringExtractor]` 扩展为 `[SpringExtractor, JaxRsExtractor]`。

### Step 6: 测试

新增 35 个测试，全部通过：
- `test_java_annotations.py`: 8 tests (方法注解/标记注解/无注解/类注解/参数注解/FunctionNode.Node 装饰器填充)
- `test_frameworks.py`: +15 tests (JAX-RS: detect/routes/methods/patterns/params/auth; Spring: controller 验证 ×3/FeignClient/Actuator ×2)
- `test_java_config.py`: 12 tests (版本比较 ×4/pom 解析/dangerous deps ×3/properties/yml/config/web.xml)
- `test_cross_language_parity.py`: +5 Java fixture 参数化 (deser/jndi/spel/xxe/ssti)

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| `extract_decorators()` 返回 `[]` | tree-sitter Java 注解在 `modifiers` 下，需特殊遍历 | 直接遍历 `node.children` 找 `modifiers` 再提取注解文本 |
| `_extract_element_value()` 返回 None | `element_value_pair` 的 key 不是 named field，是第一个 named child | 用 `named_children[0]` 获取 key text |
| 仍返回 None | `element_value_pair` 嵌套在 `annotation_argument_list` 中，`ann_node.children` 不直接包含 | 改用 `_walk_subtree(ann_node)` 递归遍历 |
| Actuator 检测 0 routes | 是上述两个 bug 的组合效果 | 两个 bug 修复后自动解决 |
| web.xml 解析 0 servlet mappings | XML 默认命名空间 `xmlns.jcp.org` 未被 `root.iter("servlet-mapping")` 匹配 | 用 `_local_tag()` 辅助函数剥离命名空间 |
| 配置警告重复 | `_check_dangerous_config()` 在每个文件解析时被调用 | 移到 `scan()` 末尾，所有文件解析后统一调用一次 |
| ruff D205 vs D212 冲突 | 多行 docstring summary 格式：`"""` 与 summary 同行时 D205 要求后面空行，但多行 summary 让 D212 认为不标准 | 缩短 summary 到单行，满足两个规则 |
| mypy: `provider` 无类型注解 | `_extract_method_params` 参数缺少类型 | 添加 `LanguageProvider` 类型注解并导入 |

## 质量门禁

| 检查 | 结果 |
|------|------|
| ruff (changed files) | ✅ All checks passed |
| mypy (changed files) | ✅ No issues (pre-existing 67 errors on other files) |
| pytest --ignore=tests/manual | ✅ 1457 passed, 2 skipped, 0 failed |

## 设计反思

**做得好:**
- 注解提取打通了 Java CPG → 框架发现的关键链路，之前返回 `[]` 是重大盲区
- JAX-RS 提取器补上了污染规则中已有大量 JAX-RS source/sink 但端点发现缺失的缺口
- Spring `_is_controller_class()` 验证大幅降低误报（`@Service` 类中 `@Scheduled` 方法不会被误判）
- JavaConfigScanner 完全确定性，零 LLM 开销，适合作为扫描第一阶段
- tree-sitter Java 注解的嵌套结构（modifiers → annotation → argument_list → element_value_pair）是开发的核心难点，文档化后后续维护者不会踩坑

**可改进:**
- `_extract_element_value()` 通过 `_walk_subtree` 遍历所有后代节点，大型注解可能有效率问题——可考虑限制遍历深度
- JavaConfigScanner 目前只处理 pom.xml 单模块，多模块 Maven 项目（aggregator pom）未处理
- 危险依赖列表硬编码在代码中，后续应考虑移到 YAML 配置文件（类似 `dangerous_calls.yaml`）

## 下步衔接

Java 深化第一轮完成。接下来可能的 Java 深化方向：
1. **多模块 Maven/Gradle 支持** — 当前只解析单 pom.xml，实际项目常有父子模块
2. **Spring 拦截器/过滤器** — `HandlerInterceptor`/`OncePerRequestFilter` 可能引入安全逻辑
3. **Java 反序列化 gadget 检测** — 基于依赖列表 + 已知 gadget chain 的静态匹配
4. **PHP/Go 语言支持** — 按语言优先级计划，Java 打磨后开始新语言

也可以按原路线继续推进 scanner 流水线的剩余阶段（Phase 4 后续）。
