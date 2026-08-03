# Session 1.1 — 项目骨架初始化

> **日期**: 2026-08-02  
> **提交**: `4ba65f7` — init: HyqAgent项目骨架初始化  
> **Phase**: Phase 1 — CPG Foundation

---

## 一、目标

从零搭建 HyqAgent 项目的完整工程骨架，包含目录结构、依赖管理、核心抽象接口、配置文件、文档体系。

---

## 二、产出清单

### 2.1 项目构建配置

| 文件 | 说明 |
|------|------|
| `pyproject.toml` | uv 构建系统，Python 3.12+，依赖声明（tree-sitter/networkx/langgraph/anthropic/structlog 等），Ruff+mypy+pytest 配置 |
| `.env.example` | 环境变量模板（API Key/模型配置/存储路径/可观测性） |
| `.pre-commit-config.yaml` | pre-commit hooks（ruff/mypy/gitleaks 等） |
| `.gitignore` | Python 项目标准忽略规则 |

### 2.2 源码目录结构（src-layout）

```
src/hyqagent/
├── core/          ← 已实现：protocols.py, state.py, events.py
├── cpg/           ← 空骨架
├── scanner/       ← 空骨架
├── models/        ← 空骨架
├── session/       ← 空骨架
├── memory/        ← 空骨架
├── observability/ ← 空骨架
├── prompts/       ← 空骨架
├── api/           ← 空骨架
└── report/        ← 空骨架
```

### 2.3 核心抽象接口 — `core/protocols.py`

这是项目最重要的文件，全部模块通过接口通信。定义了：

| 接口 | 类型 | 职责 |
|------|------|------|
| `ToolResult[T]` | dataclass | 统一返回类型（success/error 二分） |
| `FindingSeverity` | Enum | 五级严重度（CRITICAL→INFO） |
| `HypothesisStatus` | Enum | 假设生命周期状态机 |
| `CodeLocation` | dataclass | 代码位置（文件/行号/函数） |
| `DataFlowStep` | dataclass | 数据流路径步骤 |
| `VulnerabilityHypothesis` | dataclass | 漏洞假设完整模型 |
| `BaseTool` | ABC | 工具接口（name/description/parameters/execute） |
| `CpgAnalyzer` | Protocol | CPG分析器协议（Joern/tree-sitter 可互换） |
| `AuditRepository` | ABC | 存储抽象（SQLite/PostgreSQL 透明切换） |
| `LlmProvider` | ABC | LLM Provider 抽象（Anthropic/OpenAI 实现） |
| `MetricsCollector` | Protocol | 指标采集器协议 |

### 2.4 状态与事件 — `core/state.py`, `core/events.py`

- **state.py**: Agent 运行状态类型定义
- **events.py**: 12 种事件类型（ESAA 模式的事件溯源基础）

### 2.5 项目文档

| 文件 | 说明 |
|------|------|
| `CLAUDE.md` | AI 开发指南（构建/测试/架构/代码风格/安全约束） |
| `AGENTS.md` | AI Agent 项目文档标准 |
| `README.md` | 项目说明 |
| `progress.md` | 开发进度追踪 |

### 2.6 参考文档整理（docs/ 目录）

将 10 份原始研究/设计/规划文档移入 `docs/`，创建 `docs/README.md` 索引。

---

## 三、关键决策

1. **构建系统选 uv**：比 Poetry 快 10-100 倍，Rust 实现，CI 中 2 秒 sync
2. **src-layout**：PEP 517 标准，`src/hyqagent/` 而非 `hyqagent/`
3. **协议驱动架构**：所有模块通过 `protocols.py` 中的抽象接口通信，符合 DIP（依赖倒置原则）
4. **Python 3.12+**：使用新语法特性（`X | None` 联合类型、`@runtime_checkable` 等）

---

## 四、质量门禁

| 检查项 | 状态 |
|--------|------|
| ruff check | ✅（仅项目配置，无源码产出） |
| mypy --strict | ✅ |
| pytest | N/A（无测试代码） |

---

## 五、遇到的问题

无。本次为纯项目初始化，未涉及技术难点。

---

## 六、下步衔接

Session 1.2 将基于此骨架安装 tree-sitter 并实现 `cpg/parser.py`——Phase 1 的第一个实质性组件。
