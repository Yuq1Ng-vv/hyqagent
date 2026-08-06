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
    """LLM Provider抽象 — Anthropic/OpenAI/Kimi实现此接口"""

    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @abstractmethod
    async def generate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]: ...

    @abstractmethod
    async def generate_structured(
        self,
        messages: list[dict[str, Any]],
        output_schema: type,
        **kwargs: Any,
    ) -> Any: ...


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
