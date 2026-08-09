"""cpg/discovery.py — Heuristic sink discovery and source-completeness checking.

These components broaden coverage beyond the closed-world YAML rule set
by scoring *every* function call for dangerousness and checking whether
every HTTP endpoint has at least one known taint source.

All discovery is **zero-LLM** — pure CPG graph traversal + substring heuristics.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from hyqagent.cpg.graph import EDGE_CALLS, EDGE_DATA_FLOW, NODE_ASSIGNMENT
from hyqagent.cpg.types import ExposedEndpoint, HeuristicSink, UncoveredSink

if TYPE_CHECKING:
    import networkx as nx

    from hyqagent.cpg.taint_loader import TaintRuleLoader

# ── Heuristic scoring constants ──────────────────────────────────────────────

# Keywords that suggest a function call may be dangerous (case-insensitive)
_DANGEROUS_KEYWORDS: set[str] = {
    "sql",
    "exec",
    "system",
    "cmd",
    "eval",
    "query",
    "execute",
    "read",
    "write",
    "open",
    "process",
    "run",
    "popen",
    "pipeline",
    "load",
    "dump",
    "parse",
    "decode",
    "deseriali",
    "render",
    "template",
    "redirect",
    "include",
    "require",
    "send",
    "fetch",
    "request",
    "connect",
    "socket",
}

# Module prefixes that indicate a known dangerous library
_DANGEROUS_MODULES: dict[str, int] = {
    "os.": 25,
    "subprocess.": 25,
    "shlex.": 15,
    "pickle.": 25,
    "marshal.": 20,
    "yaml.": 15,
    "eval": 30,
    "exec": 30,
    "Runtime.": 25,
    "ProcessBuilder": 25,
    "ScriptEngine": 20,
    "ObjectInputStream": 20,
    "XMLReader": 15,
    "SAXParser": 15,
    "DOMParser": 15,
    "vm.": 20,
    "child_process": 25,
    "Function(": 30,
}


# ── SinkDiscoverer ───────────────────────────────────────────────────────────


class SinkDiscoverer:
    """Score every un-labelled assignment node for potential dangerousness.

    Walks the CPG graph in reverse from each node to check whether a known
    user-input source can reach it.  Nodes that score above *threshold* are
    reported as :class:`HeuristicSink` candidates for downstream annotation.
    """

    def __init__(
        self,
        graph: nx.MultiDiGraph,
        taint_loader: TaintRuleLoader,
    ) -> None:
        self._graph = graph
        self._taint_loader = taint_loader

    # ── Public API ──────────────────────────────────────────────────────

    def discover_heuristic_sinks(
        self,
        language: str,
        score_threshold: int = 60,
    ) -> list[HeuristicSink]:
        """Return all un-labelled assignments whose heuristic score ≥ *score_threshold*.

        Only considers ``NODE_ASSIGNMENT`` nodes that do **not** already have a
        ``taint_category`` attribute.
        """
        results: list[HeuristicSink] = []

        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            if data.get("taint_category"):
                continue  # already covered by a YAML rule

            source_text: str = data.get("source", "")
            if not source_text:
                continue

            dangerous, score = self.is_potentially_dangerous(nid, language)
            if not dangerous or score < score_threshold:
                continue

            results.append(
                HeuristicSink(
                    node_id=nid,
                    file_path=data.get("file_path", ""),
                    line=data.get("start_line", 0),
                    expression=source_text[:120],
                    score=score,
                    matched_keywords=self._match_keywords(source_text),
                    reachable_from_source=self._is_reachable_from_source(nid),
                )
            )

        results.sort(key=lambda h: h.score, reverse=True)
        return results

    def is_potentially_dangerous(self, node_id: str, language: str = "") -> tuple[bool, int]:
        """Score a single node.  Returns ``(is_dangerous, score)``."""
        data = self._graph.nodes.get(node_id, {})
        source_text: str = data.get("source", "")
        if not source_text:
            return False, 0

        score = 0
        src_lower = source_text.lower()

        # 1. String concatenation / interpolation (tainted data may be mixed)
        if any(op in source_text for op in ("+", "%", ".format(", "${", 'f"', "f'")):
            score += 20

        # 2. Dangerous keywords
        keywords = self._match_keywords(source_text)
        if keywords:
            score += min(30, len(keywords) * 8)

        # 3. Known dangerous module / library prefix
        for mod_prefix, mod_score in _DANGEROUS_MODULES.items():
            if mod_prefix.lower() in src_lower:
                score += mod_score
                break  # only count the highest match

        # 4. Reachable from a user-input source
        if self._is_reachable_from_source(node_id):
            score += 25

        # 5. Known sink substring from YAML rules (low-confidence match)
        if language and self._matches_any_sink_pattern(source_text, language):
            score += 15

        return score >= 40, min(score, 100)

    # ── Internal helpers ─────────────────────────────────────────────────

    def _match_keywords(self, text: str) -> list[str]:
        """Return which dangerous keywords appear in *text*."""
        low = text.lower()
        return sorted(kw for kw in _DANGEROUS_KEYWORDS if kw in low)

    def _is_reachable_from_source(self, node_id: str, max_depth: int = 20) -> bool:
        """BFS backwards to check whether any source-labelled node can reach *node_id*."""
        visited: set[str] = {node_id}
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])

        while queue:
            cur, depth = queue.popleft()
            if depth > max_depth:
                continue

            for pred in self._graph.predecessors(cur):
                if pred in visited:
                    continue
                visited.add(pred)

                pdata = self._graph.nodes.get(pred, {})
                # Check if predecessor is a taint source
                if pdata.get("node_type") == NODE_ASSIGNMENT and pdata.get("taint_category"):
                    # This assignment is labelled as a source — see if it matches
                    # a source pattern (not just a sink pattern assigned by
                    # _label_taint_nodes) by checking it has incoming DATA_FLOW
                    # from HTTP-param-shaped assignments
                    if self._has_source_ancestry(pred):
                        return True

                # Only follow DATA_FLOW and CALLS edges
                edge_data = self._graph.get_edge_data(pred, cur)
                valid = False
                for _key, ed in edge_data.items():
                    if ed.get("edge_type") in {EDGE_DATA_FLOW, EDGE_CALLS}:
                        valid = True
                        break
                if valid:
                    queue.append((pred, depth + 1))

        return False

    def _has_source_ancestry(self, node_id: str, max_depth: int = 5) -> bool:
        """Check whether *node_id* ultimately receives data from an HTTP parameter."""
        visited: set[str] = {node_id}
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])

        while queue:
            cur, depth = queue.popleft()
            if depth > max_depth:
                continue
            for pred in self._graph.predecessors(cur):
                if pred in visited:
                    continue
                visited.add(pred)
                pdata = self._graph.nodes.get(pred, {})
                src = pdata.get("source", "").lower()
                # Heuristic HTTP source patterns (language-agnostic subset)
                http_markers = [
                    ".args",
                    ".form",
                    ".query",
                    ".param",
                    ".body",
                    ".cookies",
                    ".headers",
                    "@request",
                    "@pathvar",
                    "request.",
                    "req.",
                ]
                if any(m in src for m in http_markers):
                    return True
                edge_data = self._graph.get_edge_data(pred, cur)
                valid = any(
                    ed.get("edge_type") in {EDGE_DATA_FLOW, EDGE_CALLS} for ed in edge_data.values()
                )
                if valid:
                    queue.append((pred, depth + 1))

        return False

    def _matches_any_sink_pattern(self, text: str, language: str) -> bool:
        """Return ``True`` if *text* matches any YAML sink pattern for *language*."""
        try:
            for pat in self._taint_loader.all_sinks(language):
                if pat in text.lower():
                    return True
        except (KeyError, AttributeError):
            pass
        return False


# ── SourceCompletenessChecker ──────────────────────────────────────────────────


class SourceCompletenessChecker:
    """Check which HTTP endpoints / framework routes lack known taint-source coverage.

    Uses the framework extractors' ``HttpEndpoint`` lists to enumerate every
    entry-point and then checks whether any ``NODE_ASSIGNMENT`` in the handler
    function matches a YAML source pattern.
    """

    def __init__(
        self,
        graph: nx.MultiDiGraph,
        taint_loader: TaintRuleLoader,
    ) -> None:
        self._graph = graph
        self._taint_loader = taint_loader
        self._endpoints: list = []  # set via set_endpoints()

    def set_endpoints(self, endpoints: list) -> None:
        """Register the framework-extracted HTTP endpoints."""
        self._endpoints = list(endpoints)

    # ── Public API ──────────────────────────────────────────────────────

    def find_exposed_no_source(self) -> list[ExposedEndpoint]:
        """Return every HTTP endpoint whose handler has **no** known taint source."""
        exposed: list[ExposedEndpoint] = []
        for ep in self._endpoints:
            handler = getattr(ep, "handler_func", "")
            route = getattr(ep, "route", "")
            file_path = getattr(ep, "file_path", "")
            line = getattr(ep, "line", 0)
            methods = getattr(ep, "methods", [])
            method_str = ",".join(methods) if methods else "ANY"

            if not handler:
                continue

            if not self._handler_has_source(handler, file_path):
                exposed.append(
                    ExposedEndpoint(
                        endpoint=f"{method_str} {route}",
                        handler_func=handler,
                        file_path=file_path,
                        line=line,
                    )
                )

        return exposed

    def find_uncovered_sinks(self, language: str) -> list[UncoveredSink]:
        """Return all ``NODE_ASSIGNMENT`` nodes that lack a ``taint_category`` label
        but whose expression text looks like a function call.
        """
        uncovered: list[UncoveredSink] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            if data.get("taint_category"):
                continue
            src = data.get("source", "")
            if not src or "(" not in src:
                continue

            reason = "no_known_rule"
            # Check if the node is in a basic block that is reachable
            # (heuristic — if file_path is present, assume reachable for now)
            if not data.get("file_path"):
                continue

            uncovered.append(
                UncoveredSink(
                    node_id=nid,
                    file_path=data.get("file_path", ""),
                    line=data.get("start_line", 0),
                    expression=src[:120],
                    reason=reason,
                )
            )

        return uncovered

    # ── Internal helpers ─────────────────────────────────────────────────

    def _handler_has_source(self, handler_func: str, file_path: str) -> bool:
        """Check whether any assignment in *handler_func* matches a YAML source pattern."""
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            if data.get("enclosing_function") != handler_func:
                continue
            if file_path and data.get("file_path") != file_path:
                continue
            src = data.get("source", "")
            if not src:
                continue

            # Try all available languages (source patterns are fairly cross-language)
            for lang in self._taint_loader.available_languages:
                try:
                    if self._taint_loader.match_source(lang, src):
                        return True
                except (KeyError, AttributeError):
                    continue

        return False
