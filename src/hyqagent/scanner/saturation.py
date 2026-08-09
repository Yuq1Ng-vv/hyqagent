"""scanner/saturation.py — Iterative attack-surface expansion from confirmed vulns.

Saturation scanning (饱和扫描) is a --deep mode mechanism that uses confirmed
vulnerabilities as seeds to discover adjacent attack surface.  When a sink
function is confirmed vulnerable, the scanner finds:

1. **Callers** — who else calls this sink?  (upstream expansion)
2. **Callees** — what does this sink call?   (downstream expansion)

Each discovered function becomes a new seed for the next expansion round,
up to *max_rounds*.  The process is purely graph-based (no LLM) and
naturally converges as the seed frontier is exhausted.

See docs/COVERAGE-MINIMIZATION-ARCHITECTURE.md §3.8.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hyqagent.cpg.query import CPGQuery


# ── Data model ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SeedPoint:
    """A code function discovered through saturation expansion."""

    function_name: str
    file_path: str
    reason: str = ""  # "caller_of_sink" | "callee_of_sink"
    source_finding_id: str = ""  # which confirmed finding spawned this seed
    source_sink: str = ""  # the confirmed sink function name


@dataclass
class SaturationResult:
    """Aggregate result of a saturation scanning session."""

    rounds_completed: int = 0
    total_seeds_generated: int = 0  # cumulative unique seeds across all rounds
    seeds_per_round: list[int] = field(default_factory=list)
    seed_functions: list[str] = field(default_factory=list)  # deduplicated function names
    reasoning: str = ""


# ── Graph traversal helpers ─────────────────────────────────────────────────

# Node types used in function-call traversal
_NODE_FUNCTION = "function"
_NODE_CALL_SITE = "_call_site"


def _resolve_function_at(
    graph: Any,  # nx.MultiDiGraph
    file_path: str,
    line: int,
) -> str | None:
    """Resolve ``file:line`` to a function name via the CPG graph.

    Scans all ``NODE_FUNCTION`` nodes for one whose *file_path* matches
    and whose *start_line* … *end_line* contains *line*.
    """
    for _nid, data in graph.nodes(data=True):
        if data.get("node_type") != _NODE_FUNCTION:
            continue
        if data.get("file_path") != file_path:
            continue
        start = data.get("start_line", 0)
        end = data.get("end_line", 0)
        if start <= line <= end:
            name = data.get("name")
            if isinstance(name, str):
                return name
    return None


def _find_callers(graph: Any, func_name: str) -> list[tuple[str, str]]:
    """Find all functions that **call** *func_name*.

    Returns ``[(caller_name, caller_file), …]``.
    """
    results: list[tuple[str, str]] = []
    for node_id, data in graph.nodes(data=True):
        if data.get("node_type") != _NODE_FUNCTION:
            continue
        if data.get("name") != func_name:
            continue
        # Walk: caller → call_site → this_func
        for pred in graph.predecessors(node_id):
            pred_data = graph.nodes.get(pred, {})
            if pred_data.get("node_type") == _NODE_CALL_SITE:
                for caller_id in graph.predecessors(pred):
                    caller_data = graph.nodes.get(caller_id, {})
                    if caller_data.get("node_type") == _NODE_FUNCTION:
                        results.append((
                            caller_data.get("name", caller_id),
                            caller_data.get("file_path", ""),
                        ))
    return results


def _find_callees(graph: Any, func_name: str) -> list[tuple[str, str]]:
    """Find all functions that *func_name* **calls**.

    Returns ``[(callee_name, callee_file), …]``.
    """
    results: list[tuple[str, str]] = []
    for node_id, data in graph.nodes(data=True):
        if data.get("node_type") != _NODE_FUNCTION:
            continue
        if data.get("name") != func_name:
            continue
        # Walk: this_func → call_site → callee
        for succ in graph.successors(node_id):
            succ_data = graph.nodes.get(succ, {})
            if succ_data.get("node_type") == _NODE_CALL_SITE:
                for callee_id in graph.successors(succ):
                    callee_data = graph.nodes.get(callee_id, {})
                    if callee_data.get("node_type") == _NODE_FUNCTION:
                        results.append((
                            callee_data.get("name", callee_id),
                            callee_data.get("file_path", ""),
                        ))
    return results


# ── Scanner ─────────────────────────────────────────────────────────────────


class SaturationScanner:
    """Iterative attack-surface expansion driven by confirmed vulnerabilities.

    Each confirmed finding becomes a seed — its sink function's callers
    and callees are added to the frontier.  The process repeats across
    rounds until no new functions are discovered or *max_rounds* is hit.

    This is **zero-LLM** — it operates purely on the CPG call graph.
    The orchestrator feeds discovered seeds back into the hypothesis
    pipeline in the next convergence round.

    Usage::

        scanner = SaturationScanner(cpg_query, max_rounds=4)
        result = await scanner.scan(confirmed_findings)
    """

    def __init__(
        self,
        cpg_query: CPGQuery,
        max_rounds: int = 4,
    ) -> None:
        self._query = cpg_query
        self._max_rounds = max_rounds
        self._seen: set[str] = set()  # "file::func" dedup keys

    # ── Public API ──────────────────────────────────────────────────────

    async def scan(
        self,
        confirmed: list[tuple[Any, Any]],  # (Hypothesis, ValidationResult)
    ) -> SaturationResult:
        """Run saturation scanning from a batch of confirmed findings.

        Args:
            confirmed: List of ``(hypothesis, validation_result)`` tuples
                       where ``validation_result.verdict == "confirmed"``.

        Returns:
            Aggregated ``SaturationResult`` covering all rounds.
        """
        if not confirmed:
            return SaturationResult(reasoning="No confirmed findings to seed saturation.")

        graph = getattr(self._query, "_graph", None)
        if graph is None:
            return SaturationResult(reasoning="CPG graph not available — cannot expand.")

        # Round 0: extract initial seeds from confirmed findings
        current_seeds = self._extract_seeds(confirmed, graph)
        all_seed_counts: list[int] = [len(current_seeds)]
        all_functions: list[str] = sorted({s.function_name for s in current_seeds})
        round_num = 0

        while round_num < self._max_rounds and current_seeds:
            round_num += 1

            next_seeds: set[SeedPoint] = set()
            for seed in current_seeds:
                expanded = self._expand_one(seed, graph)
                for s in expanded:
                    key = f"{s.file_path}::{s.function_name}"
                    if key not in self._seen:
                        self._seen.add(key)
                        next_seeds.add(s)

            all_functions = sorted(
                {f for s in next_seeds for f in [s.function_name]} | set(all_functions)
            )
            all_seed_counts.append(len(next_seeds))
            current_seeds = next_seeds

        return SaturationResult(
            rounds_completed=round_num,
            total_seeds_generated=sum(all_seed_counts),
            seeds_per_round=all_seed_counts,
            seed_functions=all_functions,
            reasoning=(
                f"Saturation scanning completed {round_num} round(s). "
                f"Discovered {sum(all_seed_counts[1:]) if len(all_seed_counts) > 1 else 0} "
                f"new function(s) across {len(all_functions)} unique functions."
            ),
        )

    # ── Internals ───────────────────────────────────────────────────────

    def _extract_seeds(
        self,
        confirmed: list[tuple[Any, Any]],
        graph: Any,
    ) -> set[SeedPoint]:
        """Extract initial seeds from confirmed findings.

        For each confirmed sink function, discover its callers and callees.
        """
        seeds: set[SeedPoint] = set()
        confirmed_sinks: set[str] = set()  # prevent re-seeding confirmed sinks

        for hyp, _val in confirmed:
            sink_loc = getattr(hyp, "sink_location", "") or ""
            hid = getattr(hyp, "id", "")

            # Parse "file.py:line"
            func_name = self._func_from_location(sink_loc, graph)
            if not func_name:
                continue

            confirmed_sinks.add(func_name)

            # Callers — who calls this vulnerable sink?
            for caller_name, caller_file in _find_callers(graph, func_name):
                if caller_name not in confirmed_sinks:
                    seeds.add(SeedPoint(
                        function_name=caller_name,
                        file_path=caller_file,
                        reason="caller_of_sink",
                        source_finding_id=hid,
                        source_sink=func_name,
                    ))

            # Callees — what does this sink call?
            for callee_name, callee_file in _find_callees(graph, func_name):
                if callee_name not in confirmed_sinks:
                    seeds.add(SeedPoint(
                        function_name=callee_name,
                        file_path=callee_file,
                        reason="callee_of_sink",
                        source_finding_id=hid,
                        source_sink=func_name,
                    ))

        # Register initial seeds as seen
        for s in seeds:
            self._seen.add(f"{s.file_path}::{s.function_name}")

        return seeds

    def _expand_one(self, seed: SeedPoint, graph: Any) -> set[SeedPoint]:
        """Expand a single seed — find **its** callers and callees."""
        expanded: set[SeedPoint] = set()

        for caller_name, caller_file in _find_callers(graph, seed.function_name):
            expanded.add(SeedPoint(
                function_name=caller_name,
                file_path=caller_file,
                reason="caller_of_sink",
                source_sink=seed.function_name,
            ))

        for callee_name, callee_file in _find_callees(graph, seed.function_name):
            expanded.add(SeedPoint(
                function_name=callee_name,
                file_path=callee_file,
                reason="callee_of_sink",
                source_sink=seed.function_name,
            ))

        return expanded

    @staticmethod
    def _func_from_location(location: str, graph: Any) -> str | None:
        """Parse ``"file.py:128"`` and resolve to a function name via CPG."""
        if ":" not in location:
            return None
        parts = location.rsplit(":", 1)
        file_path = parts[0]
        try:
            line = int(parts[1])
        except ValueError:
            return None

        return _resolve_function_at(graph, file_path, line)


# ── Public helpers ──────────────────────────────────────────────────────────


def confirmed_from_state(
    state: Any,  # PipelineState
) -> list[tuple[Any, Any]]:
    """Extract confirmed (hypothesis, validation) pairs from pipeline state.

    A finding is "confirmed" when:
    - validation.verdict == "confirmed" (regular validation)
    - validation.verdict == "confirmed" AND validation.validation_type ==
      "adversarial_review" (overturned rejections)
    """
    hypotheses: list[Any] = state.phase_states.get("hypotheses", [])
    validations: list[Any] = state.phase_states.get("validations", [])

    hyp_map: dict[str, Any] = {}
    for h in hypotheses:
        hid = getattr(h, "id", "")
        if hid:
            hyp_map[hid] = h

    confirmed: list[tuple[Any, Any]] = []
    seen: set[str] = set()
    for v in validations:
        vid = getattr(v, "hypothesis_id", "")
        if getattr(v, "verdict", "") == "confirmed" and vid in hyp_map:
            if vid not in seen:
                seen.add(vid)
                confirmed.append((hyp_map[vid], v))

    return confirmed
