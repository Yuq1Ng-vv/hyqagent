"""memory/ — Context management, crystallization, and hybrid code retrieval.

Three-zone context model (LONG-RUNNING-AGENT-ARCHITECTURE.md §2):
- Fixed zone (~5K tokens): system prompt, rules, vuln types — Prompt Cache break 1
- Long-term M(t) (~30K tokens): crystallized phase summaries — Prompt Cache break 2
- Working I(k)(t) (~60K tokens): recent N turns, sliding window — not cached
"""

from hyqagent.memory.context import ContextManager, TurnRecord, ZoneBudget
from hyqagent.memory.crystallizer import (
    ContextCrystallizer,
    CrystalSummary,
    should_crystallize_on_phase_change,
)
from hyqagent.memory.retriever import CodeChunk, CodeRetriever, SearchResult

__all__ = [
    "CodeChunk",
    "CodeRetriever",
    "ContextCrystallizer",
    "ContextManager",
    "CrystalSummary",
    "SearchResult",
    "TurnRecord",
    "ZoneBudget",
    "should_crystallize_on_phase_change",
]
