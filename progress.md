# HyqAgent 开发进度

> 上次更新: Session 1.3 完成后

## Phase 1: CPG Foundation — 进行中
- [x] **Session 1.1** — 项目骨架初始化 (commit: 4ba65f7)
  - pyproject.toml, src-layout, .env, pre-commit
  - CLAUDE.md, AGENTS.md, README.md, progress.md
  - core/protocols.py (6个核心协议), core/state.py, core/events.py (12种事件类型)
  - docs/ 目录整理 (10份参考文档移入，docs/README.md 索引)
- [x] **Session 1.2** — tree-sitter 安装和单文件解析 (cpg/parser.py)
  - 安装 tree-sitter 0.26.0 + Python/JS/Java 语法包
  - 实现 `cpg/parser.py` — Parser 类支持 parse_file/parse_code
  - 支持 extract_functions/extract_classes/extract_imports（三种语言）
  - 44 个 pytest 测试全部通过
  - ruff/mypy 零错误
- [x] **Session 1.3** — AST 遍历器 (cpg/traversal.py + 59 tests)
  - Traverser 类: TreeCursor 实现的 DFS 前序/后序遍历
  - 节点类型过滤、named_only 模式、子树遍历
  - 导航工具: get_children/parent/ancestors/ancestor_of_type
  - 工具方法: find_first/find_all/count/node_type_path
  - 103 个 pytest 测试全部通过，ruff/mypy 零错误
- [ ] Session 1.4 — 单文件调用图
- [ ] Session 1.5 — 跨文件调用图（⚠️ P0 风险：反射/DI/动态import）
- [ ] Session 1.6 — 数据流图构建
- [ ] Session 1.7 — CPG 查询接口 (cpg/query.py)
- [ ] Session 1.8 — Flask 框架提取器
- [ ] Session 1.9 — 端到端 CPG 测试（用已知 CVE 项目验证）
- [ ] Session 1.10-1.12 — 边界情况修复

## Phase 2-5: 待开始

## 当前阻塞
- 无

## 下次 Session 目标
- **Session 1.4**: 实现单文件调用图 `cpg/callgraph.py`
- 产出标准: 基于 Traverser 遍历 AST，识别函数内调用表达式，构建 caller→callee 关系图，支持三种语言
