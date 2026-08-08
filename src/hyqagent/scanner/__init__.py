"""HyqAgent scanner package — deterministic scanning + LLM hypothesis generation."""

from hyqagent.scanner.nudge import (
    NudgeConfig,
    NudgeLoop,
    NudgeResult,
    NudgeType,
    stop_on_empty,
    stop_on_low_confidence,
    stop_on_missing_verdict,
)

__all__ = [
    "NudgeConfig",
    "NudgeLoop",
    "NudgeResult",
    "NudgeType",
    "stop_on_empty",
    "stop_on_low_confidence",
    "stop_on_missing_verdict",
]
