"""scanner/reverse_sink.py — Reverse sink analysis (通道3).

Finds sinks that have paths to unrecognised sources — sources the forward
taint rules missed.  Pure CPG graph analysis, zero LLM cost.

Algorithm:
1. Enumerate all sink candidates (labelled + unlabelled-but-dangerous).
2. For each sink, reverse-BFS through DATA_FLOW + CALLS edges looking
   for upstream nodes that look like user input but aren't tagged as
   known sources.
3. Deduplicate against already-annotated paths from forward analysis.
4. Return novel discoveries as structured results.

See docs/COVERAGE-IMPROVEMENT-PLAN.md §Phase B — B3.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hyqagent.cpg.query import CPGQuery


# ── Node-type constants ─────────────────────────────────────────────────────

_NODE_FUNCTION = "function"
_NODE_ASSIGNMENT = "assignment"
_NODE_SOURCE = "source"
_NODE_PARAMETER = "parameter"

# ── Data model ──────────────────────────────────────────────────────────────


@dataclass
class ReverseSinkDiscovery:
    """A single sink↔source path discovered by reverse analysis."""

    sink_name: str  # enclosing function or call expression
    sink_file: str
    sink_line: int
    sink_source: str  # the actual call expression, e.g. "mysql_query($x)"
    source_names: list[str] = field(default_factory=list)  # upstream source function names
    source_files: list[str] = field(default_factory=list)
    taint_category: str = ""  # if labelled, which category
    confidence: str = "medium"  # high | medium | low — based on graph distance


@dataclass
class ReverseSinkResult:
    """Aggregate result of a reverse-sink analysis session."""

    total_sinks_checked: int = 0
    total_labeled: int = 0  # sinks with known taint_category
    total_unlabeled: int = 0  # sinks without taint labels
    discoveries: list[ReverseSinkDiscovery] = field(default_factory=list)
    previously_covered: int = 0  # sinks already in annotated_paths
    reasoning: str = ""


# ── Heuristic source detection ──────────────────────────────────────────────


# Patterns that suggest a node is a user-input source, even if not tagged.
_SOURCE_HEURISTICS: list[str] = [
    "request",
    "params",
    "query",
    "body",
    "input",
    "get_arg",
    "get_param",
    "form",
    "cookie",
    "header",
    "session",
    "argv",
    "stdin",
    "environ",
    "post",
    "get",
    "files",
    "readline",
    "get_json",
    "get_data",
    "get_query",
    "InputStream",
    "Reader",
    "readUTF",
    "args",
    "kwargs",
    "payload",
    "upload",
]


def _looks_like_source(node_data: dict[str, Any]) -> bool:
    """Heuristic: does this node look like a user-input source."""
    name = str(node_data.get("name", "")).lower()
    source = str(node_data.get("source", "")).lower()
    taint = str(node_data.get("taint_category", ""))
    ntype = str(node_data.get("node_type", ""))

    # Already tagged as source → skip (it's known)
    if taint:
        return False
    if ntype == _NODE_SOURCE:
        return True

    # NODE_PARAMETER nodes: function parameters — these are the "entry
    # points" through which untrusted data enters a function.  If the
    # enclosing function is called from a source-like context, treat
    # the parameter as a source proxy.
    if ntype == _NODE_PARAMETER:
        return True

    combined = f"{name} {source}"
    return any(h in combined for h in _SOURCE_HEURISTICS)


# ── Reverse BFS ─────────────────────────────────────────────────────────────


def _reverse_bfs_from_node(
    graph: Any,  # nx.MultiDiGraph
    start_node_id: str,
    max_depth: int = 15,
) -> list[dict[str, Any]]:
    """Reverse BFS from *start_node_id*, following DATA_FLOW + CALLS edges.

    Returns list of source-like nodes found upstream.
    """
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_node_id, 0)])
    sources: list[dict[str, Any]] = []

    # Guard: missing node → empty result
    if start_node_id not in graph:
        return sources

    while queue:
        node_id, depth = queue.popleft()
        if depth > max_depth or node_id in visited:
            continue
        visited.add(node_id)

        node_data: dict[str, Any] = dict(graph.nodes.get(node_id, {}))
        if _looks_like_source(node_data):
            sources.append(node_data)
            continue  # don't traverse past a source

        for pred in graph.predecessors(node_id):
            if pred not in visited:
                # Only follow DATA_FLOW and CALLS edges
                for _key, edge_data in graph.get_edge_data(pred, node_id, default={}).items():
                    if edge_data.get("edge_type") in ("DATA_FLOW", "CALLS"):
                        queue.append((pred, depth + 1))
                        break

    return sources


# ── Analyzer class ──────────────────────────────────────────────────────────


class ReverseSinkAnalyzer:
    """Reverse sink analysis — discovers sinks connected to unrecognised sources.

    Forward taint analysis (PathAnnotator) traces from known sources.
    This analyser does the opposite: start from every sink and trace
    backwards.  Any sink that reaches something that *looks like* user
    input but isn't a tagged source is a discovery.

    Usage::

        analyser = ReverseSinkAnalyzer(cpg_query, max_depth=15)
        result = await analyser.analyse(annotated_paths=paths)
    """

    def __init__(self, cpg_query: CPGQuery, max_depth: int = 15) -> None:
        self._query = cpg_query
        self._max_depth = max_depth

    # ── Public API ──────────────────────────────────────────────────────

    async def analyse(
        self,
        annotated_paths: list[Any] | None = None,
        language: str = "",
    ) -> ReverseSinkResult:
        """Run reverse-sink analysis.

        Args:
            annotated_paths: Forward-annotated paths from PathAnnotator.
                             Used to deduplicate — sinks already covered
                             by forward analysis are skipped.
            language: Target language hint (unused currently).

        Returns:
            Aggregated result with discoveries.

        """
        graph = getattr(self._query, "_graph", None)
        if graph is None:
            return ReverseSinkResult(reasoning="CPG graph not available.")

        # ── Collect all sink candidates ─────────────────────────────────
        all_sinks = self._query.get_all_sink_candidates(language)
        _labeled_ids: set[str] = set(self._query.get_labeled_sinks())

        if not all_sinks:
            return ReverseSinkResult(reasoning="No sink candidates found in CPG.")

        # ── Determine already-covered sinks ─────────────────────────────
        covered_sinks: set[str] = set()
        if annotated_paths:
            for ap in annotated_paths:
                path = getattr(ap, "path", None)
                if path is None:
                    continue
                for node in getattr(path, "nodes", []) or []:
                    ntype = getattr(node, "node_type", "")
                    if ntype == _NODE_ASSIGNMENT:
                        covered_sinks.add(getattr(node, "node_id", ""))

        # ── Analyse each un-covered sink ────────────────────────────────
        discoveries: list[ReverseSinkDiscovery] = []
        total_labeled = 0
        total_unlabeled = 0
        previously_covered = 0

        for sink in all_sinks:
            sid = sink["node_id"]
            tainted = sink["taint_category"]

            if tainted:
                total_labeled += 1
            else:
                total_unlabeled += 1

            if sid in covered_sinks:
                previously_covered += 1
                continue

            # Reverse BFS from this sink
            sources = _reverse_bfs_from_node(graph, sid, self._max_depth)
            if not sources:
                continue

            source_names = [s.get("name") or s.get("node_id", "?") for s in sources]
            source_files = [s.get("file_path", "") for s in sources]

            # Confidence: closer sources → higher confidence
            depths = [s.get("_depth", self._max_depth) for s in sources]
            min_depth = min(depths) if depths else self._max_depth
            if min_depth <= 3:
                confidence = "high"
            elif min_depth <= 8:
                confidence = "medium"
            else:
                confidence = "low"

            discoveries.append(
                ReverseSinkDiscovery(
                    sink_name=sink.get("enclosing_function", "") or sink.get("source", "?")[:60],
                    sink_file=sink["file_path"],
                    sink_line=sink["start_line"],
                    sink_source=sink["source"],
                    source_names=source_names,
                    source_files=source_files,
                    taint_category=tainted,
                    confidence=confidence,
                )
            )

        # Sort: unlabelled sinks are more interesting (new discoveries)
        discoveries.sort(key=lambda d: (1 if d.taint_category else 0, d.sink_file, d.sink_line))

        return ReverseSinkResult(
            total_sinks_checked=len(all_sinks),
            total_labeled=total_labeled,
            total_unlabeled=total_unlabeled,
            discoveries=discoveries,
            previously_covered=previously_covered,
            reasoning=(
                f"Reverse analysis checked {len(all_sinks)} sink(s). "
                f"{previously_covered} already covered by forward analysis, "
                f"{len(discoveries)} new discovery/ies found."
            ),
        )
