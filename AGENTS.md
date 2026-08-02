# AGENTS.md — HyqAgent AI Agent 项目文档

## 项目概述
HyqAgent 是一个基于 CPG+多模型级联的白盒代码审计 CLI 工具，用 Python 3.12+ 开发。
检测 Python/JavaScript/Java Web 应用的安全漏洞（SQL 注入、XSS、SSRF、IDOR 等）。

## 核心架构原则
1. **确定性先行，LLM 后行** — 能用正则/CPG 确定的事，不调用 LLM
2. **提出者 ≠ 裁决者** — 生成漏洞假设和验证假设必须用不同的模型/上下文
3. **全部工具统一返回 `ToolResult`** — `ToolResult.ok(name, result)` 或 `ToolResult.fail(name, error, code)`
4. **依赖倒置** — 高层模块依赖 `core/protocols.py` 中的协议，不依赖具体实现
5. **异步 I/O** — LLM 调用和子进程用 async，CPU 密集用 sync + `asyncio.to_thread()`

## 构建和测试
```bash
uv sync --dev                          # 安装依赖
uv run pytest                          # 全部测试
uv run pytest tests/unit/ -x -v        # 仅单元测试
uv run ruff check . && uv run ruff format --check .  # Lint
uv run mypy src/                       # 类型检查
```

## 目录结构关键点
- `src/hyqagent/core/protocols.py` — 所有抽象接口（ToolResult, BaseTool, CpgAnalyzer, LlmProvider, AuditRepository）
- `src/hyqagent/cpg/` — CPG Engine（parser, call_graph, data_flow, query, taint_rules.yaml, frameworks/）
- `src/hyqagent/scanner/` — 五阶段流水线（deterministic → mapper → hypothesis → validator → orchestrator）
- `src/hyqagent/session/` — SQLite 持久化（schema.sql, manager, belief, checkpoint）
- `src/hyqagent/observability/` — 日志/追踪/指标（structlog, OTel, CostTracker, Prometheus metrics）

## 安全约束
- API Key 用 `pydantic-settings.SecretStr`，从环境变量读取，永不硬编码
- 日志不输出完整源码 — 只记录文件路径和行号
- 审计代码只读不执行 — 工具权限 deny-by-default
- 审计报告中密钥值脱敏

## 开发约定
- Python 3.12+, `mypy --strict`
- 日志事件名用 snake_case（`hypothesis_confirmed`, `phase_completed`）
- 每个新模块首先定义其协议（在 `core/protocols.py`），然后实现
- 新增工具实现 `BaseTool`，在 `ToolRegistry` 中注册
- Pre-commit: ruff → ruff-format → mypy → detect-private-key

## 常见陷阱
- `py-tree-sitter` v0.23.1 有 segfault 风险 — 查询外围加重试
- SQLite WAL checkpoint 饥饿会导致文件无限增长 — 定期 `PRAGMA wal_checkpoint`
- 不要按 sink 生成子 Agent — 业界无系统这样做，成本灾难
- 跨文件调用图是 CPG 最难点 — 反射/DI/动态 import 需要特殊处理
