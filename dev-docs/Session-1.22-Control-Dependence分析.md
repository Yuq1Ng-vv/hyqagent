# Session 1.22 — Control Dependence 分析

## 目标
在 CFG 基础上实现 post-dominance tree + control dependence graph (CDG)，为 Phase 2 确定性扫描器提供控制依赖查询能力（sanitizer 是否必然执行）。

## 产出清单

| 文件 | 变化 | 说明 |
|------|------|------|
| `src/hyqagent/cpg/cfg.py` | +150 行 | `DominanceAnalyzer` 静态工具类 |
| `src/hyqagent/cpg/query.py` | +110 行 | post_dominates / get_control_dependents / is_control_dependent_on |
| `tests/test_cpg/test_cfg.py` | +120 行 | TestDominanceAnalyzer + TestCDGQuery (13 tests) |
| `progress.md` | 更新 | 801 tests total |

## 实现过程

### 1. DominanceAnalyzer 设计

完全独立的静态工具类，操作 `set[str]` 和 `dict[str, set[str]]`，不依赖 NetworkX/tree-sitter 或任何 CPG 组件：

```python
class DominanceAnalyzer:
    @staticmethod
    def compute_dominators(block_ids, preds, entry_id) -> dict[str, set[str]]
    @staticmethod
    def compute_post_dominators(block_ids, succs, exit_ids) -> dict[str, set[str]]
    @staticmethod
    def _build_ipd_tree(dom) -> dict[str, str | None]
    @staticmethod
    def compute_control_dependence(block_ids, succs, post_dom) -> dict[str, set[str]]
```

- `compute_post_dominators`: 在反转 CFG 上运行 dominator 算法，引入虚拟 EXIT 节点连接所有真实 exit blocks
- `compute_control_dependence`: 对每条 CFG 边 A→B，沿 post-dominator tree 从 B 向上走到 IPD[A]，标记路径上每个节点为 CD on A

### 2. 关键设计决策

**仅分支节点产生控制依赖**：`len(successors) < 2` 的节点（单 fallthrough edge）被跳过。这避免了单后继节点的不必要 CD 标记。

### 3. Query 集成

- `_collect_cfg_data_for_function(func_name)`: 从 NetworkX 图中提取该函数的 (block_ids, preds, succs, entry, exits)，桥接 graph ↔ DominanceAnalyzer
- `post_dominates(A, B, func_name)`: 调 DominanceAnalyzer.compute_post_dominators
- `get_control_dependents(B, func_name)`: 返回哪些 block 的执行取决于 B 的决策
- `is_control_dependent_on(A, B, func_name)`: A 是否依赖于 B 的决策

### 4. API 语义修正

初版 `is_control_dependent_on(A, B)` 参数顺序搞反（内部调 `B in get_control_dependents(A)` 应为 `A in get_control_dependents(B)` — A depends on B = A ∈ blocks controlled by B）。修复后测试通过。

## 测试覆盖

| 测试类 | 数量 | 覆盖范围 |
|--------|------|----------|
| TestDominanceAnalyzer | 7 | diamond CFG（支配/后支配/CD） + linear CFG + empty |
| TestCDGQuery | 6 | 真实 Python fixture 上的后支配/CDG/is-control-dependent |

关键验证点：
- diamond 中 entry 支配所有节点 ✓
- 兄弟分支不互相支配 ✓
- exit block 后支配所有节点 ✓
- diamond 中分支体 CD on 条件块 ✓
- diamond 中 merge 块 NOT CD on 条件块 ✓
- 直线代码无控制依赖 ✓

## 质量门禁
- **pytest**: 801 passed, 2 skipped, 0 failures (+13 tests)
- **ruff**: 仅预存问题
- **全量回归通过** ✅

## 设计反思
- **做得好**：DominanceAnalyzer 作为纯集合运算类，测试无需构建 CPG 图，极致解耦
- **后支配算法**：虚拟 EXIT 节点方案简洁有效，避免了多 exit 节点的复杂性
- **下步**：Phase 2 确定性扫描器——利用 `is_control_dependent_on` 判断 sanitizer 是否必然在 sink 前执行
