"""core/events.py — 事件类型定义

ESAA（事件溯源自治Agent）模式下，所有Agent动作记录为不可变事件。
事件类型定义遵循六条审计不变量（详见 LONG-RUNNING-AGENT-ARCHITECTURE.md）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class AuditEvent:
    """所有审计事件的基类"""

    event_type: str
    session_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PhaseStarted(AuditEvent):
    phase: str = ""
    files_total: int = 0


@dataclass
class PhaseCompleted(AuditEvent):
    phase: str = ""
    duration_ms: float = 0.0
    findings_count: int = 0


@dataclass
class HypothesisCreated(AuditEvent):
    hypothesis_id: str = ""
    vuln_type: str = ""
    file_path: str = ""
    line_start: int = 0
    severity: str = ""
    initial_confidence: float = 0.0


@dataclass
class HypothesisStatusChanged(AuditEvent):
    hypothesis_id: str = ""
    old_status: str = ""
    new_status: str = ""
    old_confidence: float = 0.0
    new_confidence: float = 0.0
    reason: str = ""


@dataclass
class FindingConfirmed(AuditEvent):
    hypothesis_id: str = ""
    severity: str = ""
    cwe_id: str = ""
    final_confidence: float = 0.0
    evidence_count: int = 0


@dataclass
class FileSkipped(AuditEvent):
    file_path: str = ""
    reason: str = ""
    skip_category: str = ""  # test_file | generated_code | low_priority


@dataclass
class CheckpointSaved(AuditEvent):
    trigger: str = ""  # phase_end | time_driven | signal | threshold
    checkpoint_id: str = ""
    items_processed: int = 0


@dataclass
class CheckpointRestored(AuditEvent):
    checkpoint_id: str = ""
    restore_time_ms: float = 0.0
    items_remaining: int = 0


@dataclass
class LlmCallCompleted(AuditEvent):
    model: str = ""
    phase: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    status: str = "success"  # success | error | budget_exceeded


@dataclass
class ToolCallCompleted(AuditEvent):
    tool_name: str = ""
    success: bool = True
    duration_ms: float = 0.0
    error: str = ""


@dataclass
class ConvergenceChecked(AuditEvent):
    vuln_type: str = ""
    rounds_without_findings: int = 0
    endpoint_coverage: float = 0.0
    risk_weighted_coverage: float = 0.0
    chao2_estimate: float = 0.0


@dataclass
class ErrorOccurred(AuditEvent):
    error_type: str = ""
    phase: str = ""
    error_message: str = ""
    recoverable: bool = True
