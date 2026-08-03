# CLAUDE.md — HyqAgent 项目开发指南

## 项目概述
HyqAgent 是一个基于 CPG + 多模型级联的白盒代码审计 CLI 工具。
优先支持 Python/JavaScript/Java 的 Web 应用漏洞检测（SQL 注入、XSS、SSRF、IDOR 等）。

核心设计哲学：
- **确定性先行，LLM 后行** — 正则/CPG 能确定的事不用 LLM
- **提出者 ≠ 裁决者** — 生成假设和验证假设用不同模型/上下文
- **单 Agent + 丰富工具 > 多 Agent + 协调开销**

## 构建与测试
- 安装依赖: `uv sync --dev`
- 运行所有测试: `uv run pytest`
- 仅单元测试(快): `uv run pytest tests/unit/ -x`
- 仅 Eval 测试: `uv run pytest tests/eval/ -m eval`
- Lint: `uv run ruff check . && uv run ruff format --check .`
- 类型检查: `uv run mypy src/`
- 安全审计: `uv run pip-audit`

## 架构
```
src/hyqagent/
├── core/protocols.py      ← ⭐ 核心抽象接口（最重要文件）
├── cpg/                   ← CPG Engine (tree-sitter/Joern)
├── scanner/               ← 五阶段扫描流水线
├── models/                ← 模型路由 + 预算管理
├── session/               ← SQLite 持久化 + 信念系统
├── memory/                ← 上下文管理 + 代码检索
├── observability/         ← 日志/追踪/指标/审计链
├── prompts/               ← Prompt 模板 (YAML+Jinja2, 语义版本)
├── api/                   ← CLI 入口 + 配置
└── report/                ← 报告生成
```

## 代码风格
- Python 3.12+, 严格 Type Hints (`mypy --strict`)
- 配置: `pydantic-settings` + `.env`
- 日志: `structlog`, 事件名用 snake_case
- 异步: I/O 操作用 async, CPU 密集型用 sync + `asyncio.to_thread()`
- 工具统一返回 `ToolResult`: `ToolResult.ok(name, result)` / `ToolResult.fail(name, error)`

## 安全约束
- API Key 从环境变量读取，永不硬编码 — `pydantic-settings.SecretStr`
- 日志不输出完整源码
- 被审计代码只读取分析，不执行
- 审计报告的密钥值脱敏

## 文档导航

### 开发过程文档（`dev-docs/`）⭐ 每次 Session 必写

**每次开发 Session 结束后，必须在 `dev-docs/` 目录下生成一个中文命名的 Markdown 文档**，用于项目学习与开发过程回顾。此目录与 `docs/`（深度参考文档）和根目录（项目说明文档）严格区分。

文档命名格式：`Session-X.Y-简短中文描述.md`

每个 Session 文档必须包含以下章节：
1. **目标** — 本次 Session 要达成的产出标准
2. **产出清单** — 新增/修改的文件列表及说明
3. **实现过程** — 关键技术决策、探索过程、核心代码片段
4. **遇到的问题与修复** — 表格形式记录：现象 → 原因 → 修复方案
5. **质量门禁** — ruff/mypy/pytest 最终结果
6. **设计反思** — 做得好和可改进的地方
7. **下步衔接** — 下个 Session 的上下文铺垫

> **注意**：这个规则是强制性的，不需要用户提醒。每次 Session 完成后自动生成。

### 根目录（日常开发必读）
- `ARCHITECTURE_OVERVIEW.md` — 项目白皮书，架构全景，**推荐首次阅读**
- `DESIGN-IMPLEMENTATION.md` — 12 章实现蓝图（接口/数据流/阶段划分），**开发时最常用**
- `AGENTS.md` — AI Agent 项目文档标准
- `progress.md` — 开发进度追踪，**每次 Session 开始必读**

### docs/ 目录（深度参考，按需查阅）
- `docs/RESEARCH.md` — 原始研究：20+论文、15+系统对比
- `docs/PLAN.md` — 原始设计方案（CPG/扫描流水线/Model Router）
- `docs/COVERAGE-GAP-ANALYSIS.md` — 覆盖盲区分析 + 七种缓解方案
- `docs/severity_based_vulnerability_mining_framework.md` — 五级危害 × 七层挖掘阶梯
- `docs/detection_matrix.json` — 200 项 ASVS 对齐的结构化检测项
- `docs/WEB-VULN-FULL-MATRIX.md` — 180+ 漏洞类型全量覆盖矩阵
- `docs/LONG-RUNNING-AGENT-ARCHITECTURE.md` — 长任务持续运行架构
- `docs/IMPLEMENTATION-GUIDE.md` — 实现前必读（关键风险 + 多 Agent 决策）
- `docs/DEVELOPMENT-STANDARDS.md` — 生产级开发规范
- `docs/CLAUDE-CODE-DEVELOPMENT-GUIDE.md` — 用 Claude Code 开发的实操指南
- `docs/README.md` — 文档目录索引
