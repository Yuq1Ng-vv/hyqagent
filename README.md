# HyqAgent — 白盒代码审计智能体

[![CI](https://github.com/hyqagent/hyqagent/actions/workflows/ci.yml/badge.svg)](https://github.com/hyqagent/hyqagent/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-2267-brightgreen.svg)](https://github.com/hyqagent/hyqagent)

**基于 CPG + 多模型级联的白盒代码审计 CLI 工具。** 确定性分析处理可模式化的漏洞，LLM 语义推理处理逻辑漏洞——两者互补，接近多 Agent 检出率，同时保持单 Agent 的成本优势。

## 项目状态

✅ **Phase 5: Quality & Release** — 2,267 tests, 0 failures, 84 source files, ~23,000 lines.

| Phase | 内容 | 状态 |
|:------|:-----|:----:|
| 1 | CPG Engine（解析/调用图/数据流/污点传播/框架提取） | ✅ |
| 2 | Deterministic Scanner（五阶段扫描/路径标注/覆盖追踪） | ✅ |
| 3 | LLM Integration（假设生成/验证/成本追踪/Nudge/收敛检测） | ✅ |
| 4 | Long-Running Agent（上下文结晶/代码检索/饱和扫描/盲扫/反向Sink） | ✅ |
| 5 | Quality & Release（Golden Dataset/DeepEval/CI/CD/文档） | 🔵 |

## 快速开始

```bash
# 安装依赖
git clone https://github.com/hyqagent/hyqagent.git
cd hyqagent
uv sync --dev

# 配置 API 密钥（仅 --deep 模式需要）
cp .env.example .env
# 编辑 .env 填入 ANTHROPIC_API_KEY / DEEPSEEK_API_KEY

# 快速扫描（零 LLM，纯确定性）
uv run hyqagent scan ./myapp

# 深度审计（LLM 增强，假设生成 + 多轮验证）
uv run hyqagent scan ./myapp --deep

# 断点续扫
uv run hyqagent resume <SESSION_ID>

# 查看历史会话
uv run hyqagent sessions list
```

## 核心能力

### 确定性分析（Phase 1-2，零 LLM 成本）

| 能力 | 说明 |
|:-----|:-----|
| **多语言 CPG** | Python / JavaScript / Java 的 AST → 调用图 → 数据流 → 污点传播 |
| **框架感知** | Flask / Django / FastAPI / Express / Spring / JAX-RS 自动端点发现 |
| **污点规则** | 3 语言 × 10 类别 YAML 规则（SQLi / XSS / SSRF / XXE / RCE …） |
| **覆盖追踪** | ~179 盲点自动检测，反向 Sink 分析 |
| **大规模验证** | ureport2 (469 Java 文件)：76K 节点 / 240K 边，缓存 0.3s 加载 |

### LLM 增强（Phase 3-4）

| 能力 | 说明 |
|:-----|:-----|
| **双模式策略** | `precision` 模式（速度优先）vs `recall` 模式（覆盖优先，ReAct 代码探索） |
| **假设-验证流水线** | CPG 切片 → LLM 假设生成 → L1 确定性 + L2 LLM 五问验证 |
| **多证据融合** | 贝叶斯信念更新，7 种 EvidenceStrength 预设 |
| **收敛检测** | VDR / EC / RWC / VCC / C_hat 五维收敛指标 |
| **补充通道** | 盲扫 LLM 通道 + 反向 Sink 分析 + 饱和扫描 |
| **成本控制** | 按 Phase 归因的成本追踪 + 预算上限 |

### 工程质量

| 能力 | 说明 |
|:-----|:-----|
| **Golden Dataset** | 28 个标签化漏洞用例，4 级确定性回归（L1-L5） |
| **DeepEval 集成** | VulnTypeAccuracy / SeverityAgreement / CWEMapping / VerdictCorrectness |
| **会话持久化** | SQLite + 检查点管理，支持中断续扫 |
| **可观测性** | structlog 结构化日志 + Prometheus 指标 + SHA-256 审计链 |
| **CI/CD** | GitHub Actions：lint + typecheck + unit tests + eval tests |

## 架构

```
src/hyqagent/
├── core/protocols.py       ← 核心抽象接口（8 协议）
├── cpg/                    ← CPG Engine（tree-sitter 解析 + 图构建）
│   ├── parser.py           # 多语言解析器
│   ├── callgraph.py        # 调用图构建
│   ├── dataflow.py         # 数据流分析 + 污点传播
│   ├── graph.py            # MultiDiGraph 统一 CPG
│   ├── query.py            # 图查询接口
│   ├── frameworks/         # 6 种框架提取器
│   └── languages/          # Python/JS/Java Adaptor
├── scanner/                ← 确定性 + LLM 扫描流水线
│   ├── deterministic.py    # 五阶段确定性扫描
│   ├── hypothesis.py       # LLM 假设生成
│   ├── validator.py        # L1 确定性 + L2 LLM 验证
│   └── orchestrator.py     # 收敛循环编排
├── models/                 ← 模型路由 + 预算管理
├── session/                ← SQLite 持久化 + 信念系统
├── memory/                 ← 上下文管理 + 代码检索
├── observability/          ← 日志/追踪/指标/审计链
├── prompts/                ← Prompt 模板（YAML+Jinja2）
├── api/                    ← CLI 入口 + 配置
└── report/                 ← 报告生成（JSON/Markdown）
```

详见 [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) 和 [DESIGN-IMPLEMENTATION.md](DESIGN-IMPLEMENTATION.md)。

## 文档导航

| 文档 | 说明 |
|:-----|:-----|
| [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) | 项目白皮书，架构全景 — **推荐首次阅读** |
| [DESIGN-IMPLEMENTATION.md](DESIGN-IMPLEMENTATION.md) | 12 章实现蓝图 — **开发时最常用** |
| [progress.md](progress.md) | 开发进度追踪 — **每次 Session 开始必读** |
| [AGENTS.md](AGENTS.md) | AI Agent 项目文档标准 |
| [docs/新手友好-HyqAgent架构详解.md](docs/新手友好-HyqAgent架构详解.md) | 零基础可读的架构讲解 |
| [docs/README.md](docs/README.md) | 文档目录总索引 |

## 开发

```bash
# 安装开发依赖
uv sync --dev

# 运行测试
uv run pytest                          # 全部测试 (~2,267)
uv run pytest tests/unit/ -x           # 仅单元测试（快）
uv run pytest tests/eval/ -m eval      # 仅 Golden Eval 测试

# 代码质量
uv run ruff check .                    # Lint
uv run ruff format --check .           # 格式检查
uv run mypy src/                       # 类型检查
uv run pip-audit                       # 依赖安全审计
```

## 技术栈

Python 3.12+ | tree-sitter | NetworkX | LangGraph | Anthropic SDK | DeepSeek | SQLite | structlog | pytest | Ruff | Click | Rich | Prometheus

## License

[MIT](LICENSE) © 2025 HyqAgent Team
