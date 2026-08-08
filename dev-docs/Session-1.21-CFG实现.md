# Session 1.21 — CPG Control Flow Graph 实现

## 目标
完成为 Python/JavaScript/Java 三种语言实现 Basic Block 级别的 CFG，集成到 CPG 图（NODE_BASIC_BLOCK + EDGE_CTRL_FLOW），并提供查询接口（可达性/支配性）。

同时回答"PDG/SSA/别名分析什么时候做"的路线图问题。

## 产出清单

| 文件 | 变化 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/cfg.py` | +650 行 | CFG 核心算法：CFGBuilder、CFGEdge |
| `src/hyqagent/cpg/types.py` | 修改 | BasicBlock dataclass + post_init 验证 |
| `src/hyqagent/cpg/languages/base.py` | +50 行 | CFG 抽象接口（control_flow_node_types 等） |
| `src/hyqagent/cpg/languages/python.py` | +65 行 | Python CFG 适配方法 |
| `src/hyqagent/cpg/languages/javascript.py` | +65 行 | JavaScript CFG 适配方法 |
| `src/hyqagent/cpg/languages/java.py` | +65 行 | Java CFG 适配方法 |
| `src/hyqagent/cpg/graph.py` | +90 行 | NODE_BASIC_BLOCK/EDGE_CTRL_FLOW 常量 + _build_cfg 集成 |
| `src/hyqagent/cpg/query.py` | +140 行 | get_cfg_for_function/is_reachable/dominates 查询 |
| `tests/test_cpg/fixtures/cfg_samples.py` | +86 行 | 14 个 Python CFG 模式函数 |
| `tests/test_cpg/test_cfg.py` | +650 行 | 45 个测试（7 个测试类） |

## 实现过程

### 1. CFG 核心算法设计

采用**递归 basic block 构建**算法，不同于传统的 leader-based approach：

- **入口**：`build_cfg(tree, func_node, file_path)` → 创建 entry/exit 虚拟块
- **递归**：`_process_stmt_sequence(block_node, ...)` 处理语句序列
  - 控制流语句（if/for/while/try/switch）→ 委派给专门的 handler
  - 终止语句（return/break/continue）→ 解析跳转目标（loop stack）
  - 普通语句 → 累积到当前 basic block
- **边类型**：fallthrough, branch_true, branch_false, loop_back, exception, return
- **break/continue 解决**：`_loop_stack` 维护嵌套循环上下文

### 2. entry_edge_kind 重构

初版使用 `create_entry_edge: bool` 参数，配合 `_wire_first_edge_from()` 对边类型做后置修改。发现三个问题：
1. 当 `create_entry_edge=False` 时，`_process_stmt_sequence` 不创建任何入口边
2. `_wire_first_edge_from` 找不到可重标记的边（因为没有边）
3. 多处调用遗漏了 `entry_edge_kind` 参数

**修复**：重构为 `entry_edge_kind: str | None` 参数，在边创建的瞬间就使用正确的类型。

### 3. _is_terminator 优先检查

`return_statement` 同时属于 `control_flow_node_types` 和 terminator 集合。旧代码先检查 `control_flow_node_types` → dispatch 到 `_process_ctrl_stmt` → 落入 else 分支 → "Unhandled CF node" debug log → 边不创建。

**修复**：在 `_process_stmt_sequence` 中优先检查 `_is_terminator`，再检查 `control_flow_node_types`。

### 4. 测试设计 — 7 类 45 个测试

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| TestBasicBlock | 5 | dataclass 验证 |
| TestCFGBuilderPython | 16 | 14 种控制流模式 + entry/exit 约束 |
| TestCFGBuilderJavaScript | 2 | JS 函数构建 + if/else |
| TestCFGBuilderJava | 2 | Java 函数构建 + 循环 |
| TestCFGGraphIntegration | 7 | 节点/边存在性 + pickle 往返 |
| TestCFGQuery | 11 | 块查询、可达性、支配性 |
| TestCFGEdgeCases | 2 | 边界情况 |

### 5. PDG/SSA/别名分析路线图

分析结果（完整分析见 Session 对话）：

| 技术 | 决定 | 时间点 |
|------|------|--------|
| Control Dependence | ✅ 立即做（~100行） | CFG 完成后下一个 Session |
| Full PDG | ❌ 不需要（CPG 已覆盖） | — |
| SSA | ⚠️ Phase 3 按需 | 当前 def-use 精度不够时 |
| 别名分析 | ❌ 不做完整版 | 可做轻量 field-tracking |

## 遇到的问题与修复

| 现象 | 原因 | 修复方案 |
|------|------|----------|
| BasicBlock start_line=0 触发 ValueError | 虚拟块（entry/exit）没有真实源码行 | 放宽验证：允许 start_line=0 |
| `return_statement` 被当作"Unhandled CF node" | `_process_stmt_sequence` 先检查 control_flow_node_types 再检查 _is_terminator | 交换检查顺序：terminator 优先 |
| if/else 无 branch_true/false 边 | `_process_stmt_sequence` 的 create_entry_edge=False 不创建入口边 | 重构为 entry_edge_kind 参数 |
| JS/Java 适配器实例化失败 | 新增 3 个抽象方法未实现 | 为 JS/Java 添加 control_flow_node_types/statement_types/get_branch_targets |

## 质量门禁
- **pytest**: 788 passed, 2 skipped, 0 failures (+43 CFG tests)
- **ruff**: 仅预存问题 + cfg.py 的 11 个 docstring style（非阻塞）
- **全部已有测试无回归** ✅

## 设计反思
- **做得好**：entry_edge_kind 重构后，边的创建逻辑从"创建→后修改"变为"创建时指定正确类型"，大幅减少了 edge case
- **可改进**：_process_stmt_sequence 的 "live" accumulator 语义还可以更清晰；merge block 的创建时机（总是提前创建）会导致一些孤立的 merge 块
- **技术债务**：for-else/while-else 的 else clause 控制流建模不精确（标记为 fallthrough）；switch fallthrough 未建模；异常精确路径未建模

## 下步衔接
- **Control Dependence**（CFG 后立即做）：post-dominator tree + dominance frontier，用于 sanitizer 有效性检查
- **Phase 2**：确定性扫描器开始——规则引擎 + CPG taint tracking + CLI v0
