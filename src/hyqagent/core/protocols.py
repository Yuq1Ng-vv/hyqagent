"""core/protocols.py — HyqAgent 核心抽象接口

这是整个项目最重要的文件。所有具体实现依赖这些协议，协议不依赖任何具体实现。
这是依赖倒置原则（DIP）在代码层面的体现。

详见 DEVELOPMENT-STANDARDS.md 第1.4节。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

# ─── 统一返回类型（每个工具都返回这个结构）───


T = TypeVar("T")


class FindingSeverity(str, Enum):
    """漏洞严重度 — 与 severity_based_vulnerability_mining_framework.md 五级对齐"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HypothesisStatus(str, Enum):
    """假设生命周期状态"""

    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    SUPPORTING = "supporting_evidence"
    REFUTING = "refuting_evidence"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ToolResult(Generic[T]):
    """每个工具调用返回的统一结构 — 核心契约"""

    success: bool
    tool_name: str
    result: T | None = None
    error: str | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls, tool_name: str, result: T, **metadata: Any) -> ToolResult[T]:
        return cls(success=True, tool_name=tool_name, result=result, metadata=metadata)

    @classmethod
    def fail(cls, tool_name: str, error: str, error_code: str = "UNKNOWN") -> ToolResult[T]:
        return cls(success=False, tool_name=tool_name, error=error, error_code=error_code)


@dataclass
class CodeLocation:
    """代码位置 — 文件+行号+函数名"""

    file_path: str
    start_line: int
    end_line: int | None = None
    function_name: str | None = None


@dataclass
class DataFlowStep:
    """数据流路径上的一个步骤"""

    step: int
    location: CodeLocation
    code_snippet: str
    role: str  # "source" | "propagation" | "sanitizer" | "sink"


@dataclass
class VulnerabilityHypothesis:
    """一个漏洞假设"""

    id: str
    title: str
    vuln_type: str  # CWE-89, CWE-79 等
    severity: FindingSeverity
    confidence: float  # 0.0 - 1.0，贝叶斯更新
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    source: CodeLocation | None = None
    sink: CodeLocation | None = None
    data_flow_path: list[DataFlowStep] = field(default_factory=list)
    evidence_chain: list[dict[str, Any]] = field(default_factory=list)
    cwe_id: str | None = None
    description: str = ""
    remediation: str = ""


# ─── 工具接口（ISP：Agent循环需要的且仅需要的）───


class BaseTool(ABC):
    """每个工具必须实现的接口

    BaseTool只暴露(name, description, parameters, execute)。
    不暴露存储、日志、UI — 那是其他模块的职责。
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def parameters(self) -> dict[str, Any]: ...

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult[Any]: ...

    def to_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# ─── CPG 分析器协议（LSP：Joern和tree-sitter可互换）───


@runtime_checkable
class CpgAnalyzer(Protocol):
    """代码属性图分析器协议"""

    async def build_cpg(self, code: str, file_path: str) -> ToolResult[Any]: ...

    async def find_path(
        self, source: CodeLocation, sink: CodeLocation
    ) -> ToolResult[list[DataFlowStep]]: ...

    async def find_sources(self, sink: CodeLocation) -> ToolResult[list[CodeLocation]]: ...

    async def find_sinks(self, source: CodeLocation) -> ToolResult[list[CodeLocation]]: ...

    async def get_sanitizers(
        self, source: CodeLocation, sink: CodeLocation
    ) -> ToolResult[list[CodeLocation]]: ...

    async def get_call_chain(self, func_a: str, func_b: str) -> ToolResult[list[CodeLocation]]: ...

    async def slice_path(
        self, source: CodeLocation, sink: CodeLocation, context_lines: int = 3
    ) -> ToolResult[list[str]]: ...


# ─── 存储协议（DIP：高层代码依赖这个，不依赖SQLite）───


class AuditRepository(ABC):
    """审计发现和运行元数据的抽象存储"""

    @abstractmethod
    async def save_session(self, session: dict[str, Any]) -> str: ...

    @abstractmethod
    async def get_session(self, session_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    async def save_finding(self, session_id: str, hypothesis: VulnerabilityHypothesis) -> str: ...

    @abstractmethod
    async def get_findings(
        self, session_id: str, severity: FindingSeverity | None = None
    ) -> list[VulnerabilityHypothesis]: ...

    @abstractmethod
    async def update_hypothesis_status(
        self, hypothesis_id: str, status: HypothesisStatus, confidence: float
    ) -> None: ...


# ─── LLM Provider 协议（OCP：新 Provider 是扩展，不改编排器）───


class LlmProvider(ABC):
    """LLM Provider — Anthropic/OpenAI 或任何兼容 API 实现此接口。

    每个方法返回规范化的内部格式（content blocks / usage / stop_reason），
    与具体 SDK 无关。调用方不感知底层走的是 Anthropic 还是 OpenAI 协议。

    工具定义统一使用 OpenAI function-calling 格式
    ``{"type":"function","function":{"name":...,"description":...,"parameters":...}}``
    — Anthropic SDK 也接受此格式，无需转换。
    """

    # ── 核心生成接口 ─────────────────────────────────────────────────

    @abstractmethod
    async def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """单轮 LLM 调用。

        Returns:
            dict with keys:
            - ``content``: list of content-block dicts.
              每个 block 至少包含 ``type``（``"text"`` / ``"tool_use"``）,
              ``text``, ``input``, ``name``.
            - ``model``: 实际使用的模型 ID.
            - ``usage``: ``{"input_tokens": N, "output_tokens": N,
              "cache_read_input_tokens": N}``.
            - ``stop_reason``: 停止原因字符串.
        """
        ...

    @abstractmethod
    async def generate_structured(
        self,
        messages: list[dict[str, Any]],
        output_schema: dict[str, Any],
        *,
        model: str,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """生成结构化 JSON 输出（通过 tool_use / function-calling）。

        *output_schema* 格式::

            {
                "name": "output_tool_name",
                "description": "...",
                "input_schema": { ... JSON Schema ... }
            }

        Returns:
            解析后的 JSON dict（tool_use 的 input / function-call 的 arguments）。
            如果解析失败返回 ``{}``。
        """
        ...

    @abstractmethod
    async def generate_with_tools(
        self,
        messages: list[dict[str, Any]],
        model: str,
        output_schema: dict[str, Any],
        audit_tools: list[dict[str, Any]],
        *,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """带审计工具的 ReAct 风格生成。

        模型可以调用审计工具（代码检索等）之后再用 output tool 输出。
        调用方负责检查返回的 ``content`` 并决定是否继续循环。

        Returns:
            同 :meth:`generate` — 规范化的 content / model / usage / stop_reason dict.
        """
        ...

    # ── 工具方法 ─────────────────────────────────────────────────────

    @abstractmethod
    def count_tokens(
        self,
        messages: list[dict[str, Any]],
        model: str,
        *,
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
    ) -> int:
        """估算 *messages* 的 token 数。提供商 API 不可用时降级为字符估算。"""
        ...

    @property
    @abstractmethod
    def call_history(self) -> list[dict[str, Any]]:
        """返回 LLM 调用历史的只读副本（用于成本追踪和审计）。"""
        ...


# ─── 可观测性协议 ───


class MetricsCollector(Protocol):
    """指标采集器协议"""

    def record_llm_call(
        self,
        model: str,
        phase: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int,
        cost_usd: float,
        latency_seconds: float,
        status: str = "success",
    ) -> None: ...

    def record_finding(self, severity: FindingSeverity, cwe: str) -> None: ...

    def record_tool_call(self, tool_name: str, success: bool, latency_seconds: float) -> None: ...

    def set_coverage(self, session_id: str, endpoint: float, risk_weighted: float) -> None: ...
