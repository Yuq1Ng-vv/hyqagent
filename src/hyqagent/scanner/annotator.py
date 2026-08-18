"""scanner/annotator.py — Path annotator with CDG-based sanitizer verification.

Converts Phase 1 from a **lossy filter** into a **lossless annotator**.
Every code path receives one of 10 labels; no path is silently discarded.

The key FP-reduction technique is :meth:`PathAnnotator._verify_sanitizer_dominance`,
which uses the Control Dependence Graph (Session 1.22) to distinguish:

* **MUST_EXECUTE** — the sanitizer is in a block that post-dominates the sink;
  it always runs before the sink on every path.
* **CONDITIONAL** — the sanitizer is control-dependent on a branch; the
  attacker may be able to bypass it.
* **DEAD_CODE** — the sanitizer block is unreachable from the entry.

See ``COVERAGE-IMPROVEMENT-PLAN.md`` Section 3 for the full 10-label taxonomy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hyqagent.cpg.discovery import SinkDiscoverer, SourceCompletenessChecker
    from hyqagent.cpg.query import CPGQuery, GraphPath
    from hyqagent.cpg.taint_loader import TaintRuleLoader


# ── Enums ────────────────────────────────────────────────────────────────────


class PathLabel(str, Enum):
    """The 10-path-label taxonomy (see COVERAGE-IMPROVEMENT-PLAN.md Sec 3)."""

    CONFIRMED_TAINT = "confirmed_taint"
    """Source and sink both in YAML rules; full data-flow path exists."""

    SANITIZED_TAINT = "sanitized_taint"
    """Tainted path has a sanitizer that MUST execute (CDG-verified)."""

    CONDITIONAL_SANITIZED = "conditional_sanitized"
    """Tainted path has a sanitizer, but it is control-dependent on a branch --
    the sanitizer may NOT execute in all scenarios."""

    HEURISTIC_SINK = "heuristic_sink"
    """Sink discovered by heuristic scoring (not in YAML rules)."""

    EXPOSED_NO_SOURCE = "exposed_no_source"
    """HTTP endpoint has no known taint source coverage."""

    MISSING_AUTH = "missing_auth"
    """Endpoint lacks an authentication decorator/annotation."""

    UNREACHABLE_SINK = "unreachable_sink"
    """Sink exists but no known source can reach it via CPG edges."""

    TRUST_BOUNDARY = "trust_boundary_crossing"
    """Data flow crosses a trust boundary (e.g. public→internal)."""

    UNCOVERED_SINK = "uncovered_but_reachable"
    """Sink is reachable from a source but no YAML rule covers this category."""

    CONFIG_ISSUE = "config_issue"
    """Configuration problem (DEBUG=True, hardcoded keys, etc.)."""


class SanitizerStatus(str, Enum):
    """Result of CDG-based sanitizer dominance verification."""

    MUST_EXECUTE = "must_execute"
    """Sanitizer block is NOT control-dependent on any branch
    and post-dominates the source → always runs before the sink."""

    CONDITIONAL = "conditional"
    """Sanitizer block is control-dependent on a branch →
    attacker may bypass the sanitizer by controlling the branch condition."""

    DEAD_CODE = "dead_code"
    """Sanitizer block is unreachable from the function entry."""

    UNKNOWN = "unknown"
    """Could not determine (no CFG data, or sanitizer block not found)."""


# ── Dataclass ────────────────────────────────────────────────────────────────


@dataclass
class AnnotatedPath:
    """A CPG data-flow path with its label and sanitizer status.

    This is the output of :class:`PathAnnotator.annotate` — the exact
    same path that :meth:`CPGQuery.find_path` returns, enriched with
    classification metadata.
    """

    path: GraphPath
    label: PathLabel
    sanitizer_status: SanitizerStatus | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ── PathAnnotator ────────────────────────────────────────────────────────────


class PathAnnotator:
    """Annotate every CPG taint path with a :class:`PathLabel`.

    Does NOT discard any path.  Later stages (Phase 3 LLM, Phase 4 deep
    scan) consume the full annotated output and decide budget allocation
    per label.

    Usage::

        annotator = PathAnnotator(query, taint_loader, sink_discoverer, source_checker)
        annotated = annotator.annotate("python")
        for ap in annotated:
            if ap.label == PathLabel.CONFIRMED_TAINT:
                print(f"  HIGH confidence: {ap.path}")
    """

    def __init__(
        self,
        query: CPGQuery,
        taint_loader: TaintRuleLoader,
        sink_discoverer: SinkDiscoverer,
        source_checker: SourceCompletenessChecker,
    ) -> None:
        self._query = query
        self._taint_loader = taint_loader
        self._sink_discoverer = sink_discoverer
        self._source_checker = source_checker

    # ── Public API ──────────────────────────────────────────────────────

    def annotate(self, language: str) -> list[AnnotatedPath]:
        """Run full annotation pipeline for *language*.

        Steps:
        1. Find confirmed-taint paths (source + sink in YAML)
        2. Check sanitizer status with CDG for each path
        3. Discover heuristic sinks (not in YAML, scored as dangerous)
        4. Find exposed endpoints (no source coverage)
        """
        annotated: list[AnnotatedPath] = []

        # 1. Confirmed-taint paths — source 不限类别, 漏洞类型由 sink 决定.
        #    (对齐 Session 1.45 参数标记语义: @RequestParam 等参数保守标记为
        #    injection_general, 精确类别由 sink 决定. 若仍按 find_path(cat,cat)
        #    把源/sink 绑死同一类别, injection_general 源永远匹配不到具体 sink.)
        for path in self._query.find_taint_paths(max_depth=20):
            label = self._label_path(path, language)
            annotated.append(
                AnnotatedPath(
                    path=path,
                    label=label,
                    sanitizer_status=self._verify_sanitizer_dominance(path, language),
                )
            )

        # 2. Heuristic sinks
        heuristic = self._sink_discoverer.discover_heuristic_sinks(language)
        for hs in heuristic:
            # Create a minimal single-node "path" for annotation
            from hyqagent.cpg.query import GraphNode, GraphPath

            node = GraphNode(
                node_id=hs.node_id,
                node_type="assignment",
                location=f"{hs.file_path}:{hs.line}",
                source=hs.expression,
            )
            path = GraphPath(nodes=[node], edges=[])
            annotated.append(
                AnnotatedPath(
                    path=path,
                    label=PathLabel.HEURISTIC_SINK,
                    metadata={
                        "score": hs.score,
                        "keywords": hs.matched_keywords,
                        "reachable": hs.reachable_from_source,
                    },
                )
            )

        # 3. Exposed endpoints (no source)
        exposed = self._source_checker.find_exposed_no_source()
        for ep in exposed:
            from hyqagent.cpg.query import GraphNode, GraphPath

            node = GraphNode(
                node_id=f"ep:{ep.handler_func}",
                node_type="function",
                location=f"{ep.file_path}:{ep.line}",
                name=ep.handler_func,
            )
            path = GraphPath(nodes=[node], edges=[])
            annotated.append(
                AnnotatedPath(
                    path=path,
                    label=PathLabel.EXPOSED_NO_SOURCE,
                    metadata={"endpoint": ep.endpoint},
                )
            )

        return annotated

    # ── Label logic ─────────────────────────────────────────────────────

    def _label_path(self, path: GraphPath, language: str) -> PathLabel:
        """Determine the label for a single data-flow path.

        Checks (in order):
        1. Empty path → UNREACHABLE_SINK
        2. Has sanitizer → CDG verification (SANITIZED_TAINT or CONDITIONAL_SANITIZED)
        3. No sanitizer → CONFIRMED_TAINT (deterministic finding)
        """
        if not path or not path.nodes:
            return PathLabel.UNREACHABLE_SINK

        # Check for sanitizers along the path
        sanitizers = self._query.get_sanitizers(path, taint_loader=self._taint_loader)

        if sanitizers:
            # Has sanitizer — need CDG to determine if it's safe
            status = self._verify_sanitizer_dominance(path, language)
            if status == SanitizerStatus.MUST_EXECUTE:
                return PathLabel.SANITIZED_TAINT
            elif status == SanitizerStatus.CONDITIONAL:
                return PathLabel.CONDITIONAL_SANITIZED
            else:
                # DEAD_CODE or UNKNOWN → treat as conditional (conservative)
                return PathLabel.CONDITIONAL_SANITIZED

        # No sanitizer → confirmed taint
        return PathLabel.CONFIRMED_TAINT

    # ── CDG sanitizer verification ──────────────────────────────────────

    def _verify_sanitizer_dominance(self, path: GraphPath, language: str = "") -> SanitizerStatus:
        """Check whether sanitizers on *path* are guaranteed to execute.

        Algorithm:
        1. Find sanitizer patterns on the path.
        2. For each sanitizer node, locate its basic block by line-range
           matching against CFG blocks.
        3. Check if the sanitizer block is control-dependent on any
           branch block via :meth:`CPGQuery.get_control_dependents`.
        4. If no control dependence → MUST_EXECUTE.
           If control-dependent → CONDITIONAL.
           If no CFG data → UNKNOWN.
        """
        # 1. Find sanitizer patterns
        sanitizer_patterns = self._query.get_sanitizers(path, taint_loader=self._taint_loader)
        if not sanitizer_patterns:
            # No sanitizer at all — caller should have checked this
            return SanitizerStatus.UNKNOWN

        # 2. For each sanitizer node, find its basic block
        sanitizer_nodes = self._find_sanitizer_nodes(path, sanitizer_patterns)
        if not sanitizer_nodes:
            return SanitizerStatus.UNKNOWN

        any_block_found = False
        for node_id, location_str in sanitizer_nodes:
            block_id = self._find_block_for_node(node_id, location_str)
            if block_id is None:
                continue
            any_block_found = True

            # Extract function name
            func_name = self._get_func_for_block(block_id)
            if not func_name:
                continue

            # 3. Check control dependence: is the sanitizer block's execution
            #    conditional on any branch block's decision?
            if self._is_conditional_on_any_branch(block_id, func_name):
                return SanitizerStatus.CONDITIONAL

            # Also check reachability
            entry = self._query.get_entry_block(func_name)
            if entry and not self._query.is_reachable(entry, block_id):
                return SanitizerStatus.DEAD_CODE

        # No block found → cannot verify; return UNKNOWN
        if not any_block_found:
            return SanitizerStatus.UNKNOWN

        # No control dependence found for any sanitizer
        return SanitizerStatus.MUST_EXECUTE

    def _is_conditional_on_any_branch(self, block_id: str, func_name: str) -> bool:
        """Return ``True`` if *block_id* is control-dependent on any branch
        block in *func_name*.

        A branch block is any basic block with ≥2 outgoing CTRL_FLOW edges.
        Control dependence on a branch means the block's execution is
        conditional — it only runs when the branch goes a particular way.
        """
        # Get all branch blocks for the function
        branch_blocks = self._get_branch_blocks(func_name)
        if not branch_blocks:
            return False

        for branch_id in branch_blocks:
            if self._query.is_control_dependent_on(block_id, branch_id, func_name):
                return True

        return False

    def _get_branch_blocks(self, func_name: str) -> list[str]:
        """Return all basic blocks in *func_name* that have ≥2 outgoing
        CTRL_FLOW edges (i.e. decision points).
        """
        graph = getattr(self._query, "_graph", None)
        if graph is None:
            return []

        from hyqagent.cpg.graph import EDGE_CTRL_FLOW, NODE_BASIC_BLOCK

        branch_blocks: list[str] = []
        for nid, data in graph.nodes(data=True):
            if data.get("node_type") != NODE_BASIC_BLOCK:
                continue
            if data.get("enclosing_function") != func_name:
                continue

            # Count outgoing CTRL_FLOW edges
            out_edges = 0
            for succ in graph.successors(nid):
                edge_data = graph.get_edge_data(nid, succ)
                for _key, ed in edge_data.items():
                    if ed.get("edge_type") == EDGE_CTRL_FLOW:
                        out_edges += 1
            if out_edges >= 2:
                branch_blocks.append(nid)

        return branch_blocks

    # ── Internal helpers ─────────────────────────────────────────────────

    def _get_known_categories(self, language: str) -> list[str]:
        """Return all taint categories defined in the YAML for *language*."""
        try:
            rules = self._taint_loader.rules_for(language)
            if rules:
                return sorted(rules.categories.keys())
        except (KeyError, AttributeError):
            pass
        return []

    def _find_sanitizer_nodes(self, path: GraphPath, patterns: list[str]) -> list[tuple[str, str]]:
        """Return ``(node_id, location_str)`` for path nodes containing sanitizers."""
        result: list[tuple[str, str]] = []
        for node in path.nodes:
            src = node.source.lower()
            for pat in patterns:
                if pat.lower() in src:
                    result.append((node.node_id, node.location))
                    break
        return result

    def _find_block_for_node(self, node_id: str, location_str: str) -> str | None:
        """Find the basic block containing *node_id* or location.

        Uses two strategies:
        a) Direct match by node ID (if the node IS a basic block).
        b) Line-range matching: find the basic block whose
           ``start_line``-``end_line`` range contains the node's line.
        """
        graph = getattr(self._query, "_graph", None)
        if graph is None:
            return None

        # Parse line from location_str ("file.py:42")
        target_line = 0
        if location_str and ":" in location_str:
            try:
                target_line = int(location_str.rsplit(":", 1)[-1])
            except (ValueError, IndexError):
                pass

        best_block: str | None = None
        best_distance = float("inf")

        from hyqagent.cpg.graph import NODE_BASIC_BLOCK

        for nid, data in graph.nodes(data=True):
            if data.get("node_type") != NODE_BASIC_BLOCK:
                continue
            start = data.get("start_line", 0)
            end = data.get("end_line", 0)

            if target_line > 0 and start <= target_line <= end:
                # Found a matching block — pick the tightest range
                distance = end - start
                if distance < best_distance:
                    best_distance = distance
                    best_block = nid

        return best_block

    def _get_func_for_block(self, block_id: str) -> str | None:
        """Return the enclosing function name for *block_id*."""
        graph = getattr(self._query, "_graph", None)
        if graph is None:
            return None

        data = graph.nodes.get(block_id, {})
        return data.get("enclosing_function")
