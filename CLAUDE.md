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

## 关键设计文档
- `DESIGN-IMPLEMENTATION.md` — 12 章实现蓝图（接口/数据流/阶段划分）
- `DEVELOPMENT-STANDARDS.md` — 生产级规范（测试/可观测性/Prompt 管理）
- `PLAN.md` — 原始设计方案（CPG/扫描流水线/Model Router）
- `ARCHITECTURE_OVERVIEW.md` — 项目白皮书
