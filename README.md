# HyqAgent — 白盒代码审计智能体

## 项目状态

🚧 **Phase 1: CPG Foundation** — 项目骨架已初始化，核心抽象层已定义。

## 是什么

HyqAgent 是一个基于 **CPG（代码属性图）+ 多模型级联** 的白盒代码审计 CLI 工具。它用确定性分析处理可模式化的漏洞，用 LLM 语义推理处理逻辑漏洞——两者互补，达到接近多 Agent 的检出率，同时保持单 Agent 的成本优势。

## 快速开始

```bash
# 安装依赖
uv sync --dev

# 配置 API 密钥
cp .env.example .env
# 编辑 .env 填入 ANTHROPIC_API_KEY

# 运行（开发中）
uv run hyqagent --help
```

## 核心文档

| 文档 | 说明 |
|:-----|:-----|
| `ARCHITECTURE_OVERVIEW.md` | 项目白皮书 — 推荐首次阅读 |
| `DESIGN-IMPLEMENTATION.md` | 详细实现蓝图 — 开发时参考 |
| `CLAUDE.md` | Claude Code 开发指南 — Agent 最早阅读 |
| `DEVELOPMENT-STANDARDS.md` | 生产级开发规范 |
| `IMPLEMENTATION-GUIDE.md` | 实现前必读 — 关键风险和决策 |

## 技术栈

Python 3.12+ | tree-sitter | Joern | LangGraph | Anthropic API | SQLite | structlog | pytest | Ruff
