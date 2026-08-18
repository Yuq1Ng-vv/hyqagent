"""cpg/query.py — High-level query interface over the CPG graph.

Provides path-finding and tracing operations on top of the NetworkX
MultiDiGraph built by :class:`CPGGraphBuilder`.

See DESIGN-IMPLEMENTATION.md Section 2.7 for the full interface specification.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx as nx

from hyqagent.cpg.graph import (
    EDGE_CALLS,
    EDGE_CTRL_FLOW,
    EDGE_DATA_FLOW,
    NODE_ASSIGNMENT,
    NODE_BASIC_BLOCK,
    NODE_FUNCTION,
    NODE_SINK,
    NODE_SOURCE,
)

# ─── Result types ────────────────────────────────────────────────────────────


@dataclass
class GraphNode:
    """A node in a query result path."""

    node_id: str
    node_type: str = ""
    location: str = ""
    name: str = ""
    source: str = ""
    taint_category: str = ""


@dataclass
class GraphPath:
    """A path through the CPG graph, returned by query methods."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)  # edge_type per hop

    def __len__(self) -> int:  # noqa: D105
        return len(self.nodes)

    def __bool__(self) -> bool:  # noqa: D105
        return len(self.nodes) > 0


# ─── Query interface ─────────────────────────────────────────────────────────


class CPGQuery:
    """High-level query interface over a CPG :class:`networkx.MultiDiGraph`.

    Usage::

        builder = CPGGraphBuilder(parser)
        builder.add_directory("./myapp")
        query = CPGQuery(builder.graph)

        paths = query.find_path("request.args.get", "cursor.execute")
        for p in paths:
            print(query.slice_path(p))
    """

    def __init__(self, graph: nx.MultiDiGraph) -> None:
        self._graph = graph

    # ── Path finding ────────────────────────────────────────────────────

    def find_path(
        self,
        source_pattern: str,
        sink_pattern: str,
        max_depth: int = 20,
        taint_loader: object | None = None,
        language: str = "",
    ) -> list[GraphPath]:
        """Find all paths from nodes matching source to sink patterns.

        Traverses ``DATA_FLOW`` and ``CALLS`` edges via BFS.  Returns up
        to 20 distinct paths, sorted shortest-first.

        When *taint_loader* and *language* are provided, prefers
        ``taint_category``-labeled nodes over substring matching.
        """
        # Exclude function nodes from source matching: function bodies
        # contain source/sink patterns as substring matches (e.g. the
        # parameter name `req` in `HttpServletRequest req`), but function
        # nodes are not the actual taint entry points — assignments are.
        sources = self._find_taint_nodes(
            source_pattern,
            taint_loader,
            language,
            exclude_types={NODE_FUNCTION},
            role="source",
        )
        sinks = set(
            self._find_taint_nodes(
                sink_pattern,
                taint_loader,
                language,
                exclude_types={NODE_FUNCTION},
                role="sink",
            )
        )
        if not sources or not sinks:
            return []

        paths: list[GraphPath] = []
        global_visited: set[str] = set()
        for src_id in sources:
            if len(paths) >= 20:
                break
            for path in self._bfs_paths(src_id, sinks, max_depth, visited=global_visited):
                if len(paths) >= 20:
                    break
                paths.append(path)

        paths.sort(key=len)
        return paths

    def find_taint_paths(
        self,
        max_depth: int = 20,
        max_paths: int = 200,
    ) -> list[GraphPath]:
        """Find taint paths from ANY ``taint_source`` node to ANY ``taint_sink`` node.

        Unlike :meth:`find_path` — which requires the source and sink to share
        the same YAML category (``find_path(cat, cat)``) — this enumerates every
        ``taint_source``-labeled node and forward-BFSes to any ``taint_sink``
        node along ``DATA_FLOW`` / ``CALLS`` edges.  The precise vulnerability
        category is determined by the sink, not the source (Session 1.45
        semantics: a conservative ``injection_general`` source such as
        ``@RequestParam`` only marks "user input"; the sink decides the real
        category).

        Each source is BFS-ed independently (no shared visited set) so a large
        early traversal cannot starve later sources.  Paths are deduplicated by
        their ``(first, last)`` node pair and returned shortest-first, up to
        *max_paths* in total.
        """
        source_ids = sorted(n for n, d in self._graph.nodes(data=True) if d.get("taint_source"))
        sink_set = {n for n, d in self._graph.nodes(data=True) if d.get("taint_sink")}
        if not source_ids or not sink_set:
            return []

        paths: list[GraphPath] = []
        seen: set[tuple[str, str]] = set()
        for src_id in source_ids:
            if len(paths) >= max_paths:
                break
            for path in self._bfs_paths(src_id, sink_set, max_depth):
                if not path.nodes or len(path.nodes) < 2:
                    continue
                key = (path.nodes[0].node_id, path.nodes[-1].node_id)
                if key in seen:
                    continue
                seen.add(key)
                paths.append(path)
                if len(paths) >= max_paths:
                    break

        paths.sort(key=len)
        return paths

    def find_sources(self, sink_pattern: str, max_depth: int = 15) -> list[GraphNode]:
        """Trace backwards from *sink_pattern* to find all upstream sources.

        Walks ``DATA_FLOW`` and ``CALLS`` edges in reverse.
        """
        sink_ids = self._find_nodes(sink_pattern)
        if not sink_ids:
            return []

        source_nodes: list[GraphNode] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque((s, 0) for s in sink_ids)

        while queue:
            node_id, depth = queue.popleft()
            if depth > max_depth or node_id in visited:
                continue
            visited.add(node_id)

            node_data = self._graph.nodes.get(node_id, {})
            ntype = node_data.get("node_type", "")
            has_taint = bool(node_data.get("taint_category"))
            if ntype in (NODE_SOURCE, NODE_ASSIGNMENT) or has_taint:
                source_nodes.append(self._to_graph_node(node_id, node_data))

            # Reverse: follow predecessors (DATA_FLOW + CALLS edges only)
            for pred in self._graph.predecessors(node_id):
                if pred not in visited and self._has_valid_edge(pred, node_id):
                    queue.append((pred, depth + 1))

        return source_nodes

    def find_sinks(self, source_pattern: str, max_depth: int = 15) -> list[GraphNode]:
        """Trace forward from *source_pattern* to find all downstream sinks."""
        source_ids = self._find_nodes(source_pattern)
        if not source_ids:
            return []

        sink_nodes: list[GraphNode] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque((s, 0) for s in source_ids)

        while queue:
            node_id, depth = queue.popleft()
            if depth > max_depth or node_id in visited:
                continue
            visited.add(node_id)

            node_data = self._graph.nodes.get(node_id, {})
            ntype = node_data.get("node_type", "")
            has_taint = bool(node_data.get("taint_category"))
            if ntype == NODE_SINK or has_taint:
                sink_nodes.append(self._to_graph_node(node_id, node_data))

            # Forward: follow successors (DATA_FLOW + CALLS edges only)
            for succ in self._graph.successors(node_id):
                if succ not in visited and self._has_valid_edge(node_id, succ):
                    queue.append((succ, depth + 1))

        return sink_nodes

    def get_call_chain(self, func_a: str, func_b: str) -> GraphPath | None:
        """Find a ``CALLS``-edge path from *func_a* to *func_b*."""
        # Find function nodes by name
        a_nodes = [
            n
            for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == NODE_FUNCTION and d.get("name") == func_a
        ]
        b_nodes = {
            n
            for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == NODE_FUNCTION and d.get("name") == func_b
        }
        if not a_nodes or not b_nodes:
            return None

        for start in a_nodes:
            for path in self._bfs_paths(start, b_nodes, 20, edge_types={EDGE_CALLS}):
                if path:
                    return path
        return None

    def slice_path(self, path: GraphPath, context_lines: int = 3) -> str:
        """Render a human-readable summary of *path*.

        Each node is shown with its type, location, and source snippet.
        """
        if not path:
            return "(empty path)"

        lines: list[str] = []
        for i, node in enumerate(path.nodes):
            prefix = "  " if i > 0 else "┌─"
            if i == len(path.nodes) - 1 and i > 0:
                prefix = "└─"
            elif i > 0:
                prefix = "├─"

            edge_label = ""
            if i < len(path.edges):
                edge_label = f"  --[{path.edges[i]}]-->"

            loc = node.location or node.node_id
            ntype = node.node_type
            name = node.name or ""
            src = node.source[:80] if node.source else ""

            lines.append(f"{prefix} [{ntype}] {name} @ {loc}{edge_label}")
            if src:
                lines.append(f"  │  {src}")

        return "\n".join(lines)

    def get_sanitizers(self, path: GraphPath, taint_loader: object | None = None) -> list[str]:
        """Check for sanitizer patterns along *path* nodes.

        If *taint_loader* (a :class:`TaintRuleLoader`) is provided, uses
        YAML-driven patterns.  Otherwise falls back to a minimal built-in list.
        """
        sanitizers: list[str] = []
        # Use YAML rules if available
        if taint_loader is not None and hasattr(taint_loader, "all_sources"):
            patterns: set[str] = set()
            for lang in getattr(taint_loader, "available_languages", []):
                if not hasattr(taint_loader, "rules_for"):
                    continue
                rules = taint_loader.rules_for(lang)
                if rules is None:
                    continue
                for cat in rules.categories.values():
                    patterns.update(s.lower() for s in cat.sanitizers)
            for node in path.nodes:
                src_lower = node.source.lower()
                for pat in patterns:
                    if pat in src_lower:
                        sanitizers.append(pat)
            return sanitizers

        # Minimal fallback patterns
        fallback = {"int(", "float(", "str(", "escape(", "sanitize", "filter", "validate"}
        for node in path.nodes:
            src_lower = node.source.lower()
            for pat in fallback:
                if pat in src_lower:
                    sanitizers.append(pat)
        return sanitizers

    # ── Internal helpers ─────────────────────────────────────────────────

    def _has_valid_edge(self, u: str, v: str) -> bool:
        """Return True if there is a DATA_FLOW or CALLS edge from *u* to *v*."""
        edge_data = self._graph.get_edge_data(u, v)
        if not edge_data:
            return False
        return any(d.get("edge_type") in {EDGE_DATA_FLOW, EDGE_CALLS} for d in edge_data.values())

    def _find_nodes(
        self,
        pattern: str,
        max_results: int = 200,
        exclude_types: set[str] | None = None,
    ) -> list[str]:
        """Find node ids where *pattern* appears in any attribute value.

        Stops early after *max_results* to prevent O(n) blowup on large graphs.

        Args:
            pattern: Substring to search for in node attribute values.
            max_results: Stop searching after this many matches.
            exclude_types: If set, skip nodes whose ``node_type`` is in this set.
               Used to exclude e.g. ``NODE_FUNCTION`` from source/sink matching,
               since function bodies contain source/sink patterns as substring
               matches but aren't the actual taint entry/exit points.

        """
        if not pattern:
            return []
        matches: list[str] = []
        for nid, data in self._graph.nodes(data=True):
            if len(matches) >= max_results:
                break
            if exclude_types and data.get("node_type") in exclude_types:
                continue
            for val in data.values():
                if isinstance(val, str) and pattern in val:
                    matches.append(nid)
                    break
        return matches

    def _find_taint_nodes(
        self,
        pattern: str,
        taint_loader: object | None,
        language: str,
        max_results: int = 200,
        exclude_types: set[str] | None = None,
        role: str | None = None,
    ) -> list[str]:
        """Find nodes by taint_category label (preferred) or substring fallback.

        When *taint_loader* and *language* are provided, first searches for
        nodes whose ``taint_category`` attribute matches the category
        resolved from *pattern*.  Falls back to plain ``_find_nodes``
        substring matching when the loader is unavailable or no labeled
        nodes match.

        When *role* is ``"source"``, only nodes with a ``taint_source``
        attribute matching *pattern* are returned (sink-labeled nodes are
        excluded).  When *role* is ``"sink"``, the ``taint_sink``
        attribute is used instead.  When *role* is ``None`` (the default),
        the combined ``taint_category`` attribute is used for backward
        compatibility.
        """
        if taint_loader is not None and language:
            # Resolve which taint category the pattern matches.
            # Two strategies:
            #   a) Direct: pattern IS a known category name (e.g. "sql_injection")
            #      → search taint_category-labeled nodes directly.
            #   b) Indirect: pattern is a code snippet (e.g. "executeQuery(")
            #      → use match_source/match_sink to resolve category first.
            cat = None
            rules = getattr(taint_loader, "rules_for", None)
            if rules is not None and callable(rules):
                try:
                    lang_rules = rules(language)
                    if pattern in lang_rules.categories:
                        cat = pattern
                except (KeyError, AttributeError):
                    pass

            if cat is None and hasattr(taint_loader, "match_source"):
                cat = taint_loader.match_source(language, pattern)
            if cat is None and hasattr(taint_loader, "match_sink"):
                cat = taint_loader.match_sink(language, pattern)

            if cat is not None:
                # Determine which attribute(s) to search based on role.
                if role == "source":
                    search_attrs = ["taint_source"]
                elif role == "sink":
                    search_attrs = ["taint_sink"]
                else:
                    # Backward-compat: search combined taint_category
                    search_attrs = ["taint_category"]

                matches: list[str] = []
                for nid, data in self._graph.nodes(data=True):
                    if len(matches) >= max_results:
                        break
                    if exclude_types and data.get("node_type") in exclude_types:
                        continue
                    for attr in search_attrs:
                        node_cats = data.get(attr, "")
                        if cat in node_cats.split(","):
                            matches.append(nid)
                            break
                if matches:
                    return matches

                # When role is specified we must NOT fall back to substring
                # matching — that would defeat source/sink separation.
                # An empty result for "source" means there are genuinely no
                # source-labeled nodes, and the path search should stop.
                if role is not None:
                    return []

        # Fall back to plain substring matching (role=None only)
        return self._find_nodes(pattern, max_results, exclude_types)

    def _bfs_paths(
        self,
        start: str,
        targets: set[str],
        max_depth: int,
        edge_types: set[str] | None = None,
        visited: set[str] | None = None,
    ) -> list[GraphPath]:
        """BFS from *start* to any node in *targets*.

        If *edge_types* is given, only traverse edges with matching
        ``edge_type`` attribute.  Defaults to ``{DATA_FLOW, CALLS}``.
        """
        if edge_types is None:
            edge_types = {EDGE_DATA_FLOW, EDGE_CALLS}

        result: list[GraphPath] = []
        local_visited: set[str] = {start}
        shared = visited is not None
        if shared:
            visited.add(start)
        queue: deque[tuple[str, list[str], list[str]]] = deque()
        queue.append((start, [start], []))

        while queue:
            cur, node_path, edge_path = queue.popleft()
            if len(node_path) > max_depth:
                continue

            if cur in targets and cur != start:
                nodes = [self._to_graph_node(n, self._graph.nodes.get(n, {})) for n in node_path]
                result.append(GraphPath(nodes=nodes, edges=edge_path))
                continue

            for succ in self._graph.successors(cur):
                if succ in local_visited or (shared and succ in visited):
                    continue
                # Filter by edge type
                edge_data = self._graph.get_edge_data(cur, succ)
                # MultiDiGraph: edge_data is a dict keyed by edge index (never None)
                valid = False
                etype = ""
                for _key, ed in edge_data.items():
                    etype = ed.get("edge_type", "")
                    if etype in edge_types:
                        valid = True
                        break
                if not valid:
                    continue

                local_visited.add(succ)
                if shared:
                    visited.add(succ)
                queue.append((succ, [*node_path, succ], [*edge_path, etype]))

        return result

    # ── CFG queries ──────────────────────────────────────────────────────

    def get_cfg_for_function(self, func_name: str, file_path: str | None = None) -> list[str]:
        """Return block IDs for *func_name*, sorted by ``start_line``."""
        blocks: list[tuple[int, str]] = []
        for nid, data in self._graph.nodes(data=True):
            if (
                data.get("node_type") == NODE_BASIC_BLOCK
                and data.get("enclosing_function") == func_name
            ) and (file_path is None or data.get("file_path") == file_path):
                blocks.append((data.get("start_line", 0), nid))
        blocks.sort(key=lambda x: x[0])
        return [bid for _line, bid in blocks]

    def get_entry_block(self, func_name: str, file_path: str | None = None) -> str | None:
        """Return the entry block ID for *func_name*, or ``None``."""
        for nid, data in self._graph.nodes(data=True):
            if (
                data.get("node_type") == NODE_BASIC_BLOCK
                and data.get("block_type") == "entry"
                and data.get("enclosing_function") == func_name
            ) and (file_path is None or data.get("file_path") == file_path):
                return nid
        return None

    def is_reachable(self, from_block_id: str, to_block_id: str, max_depth: int = 200) -> bool:
        """Return ``True`` if *to_block_id* is reachable from *from_block_id*
        via ``EDGE_CTRL_FLOW`` edges.
        """
        visited: set[str] = {from_block_id}
        queue: deque[tuple[str, int]] = deque([(from_block_id, 0)])
        while queue:
            cur, depth = queue.popleft()
            if depth > max_depth:
                continue
            if cur == to_block_id and cur != from_block_id:
                return True
            for succ in self._graph.successors(cur):
                if succ in visited:
                    continue
                edge_data = self._graph.get_edge_data(cur, succ)
                for _key, ed in edge_data.items():
                    if ed.get("edge_type") == EDGE_CTRL_FLOW:
                        visited.add(succ)
                        queue.append((succ, depth + 1))
                        break
        return False

    def get_reachable_blocks(self, from_block_id: str, max_depth: int = 200) -> list[str]:
        """Return all block IDs reachable from *from_block_id* via
        ``EDGE_CTRL_FLOW`` edges.
        """
        visited: set[str] = {from_block_id}
        queue: deque[tuple[str, int]] = deque([(from_block_id, 0)])
        while queue:
            cur, depth = queue.popleft()
            if depth > max_depth:
                continue
            for succ in self._graph.successors(cur):
                if succ in visited:
                    continue
                edge_data = self._graph.get_edge_data(cur, succ)
                for _key, ed in edge_data.items():
                    if ed.get("edge_type") == EDGE_CTRL_FLOW:
                        visited.add(succ)
                        queue.append((succ, depth + 1))
                        break
        return list(visited)

    def dominates(self, block_a_id: str, block_b_id: str, entry_block_id: str) -> bool:
        """Return ``True`` if *block_a_id* dominates *block_b_id*.

        Uses the classic iterative data-flow algorithm: a block **X**
        dominates block **Y** if every path from the entry block to **Y**
        must go through **X**.
        """
        # Collect all basic block IDs on CTRL_FLOW edges
        block_ids: set[str] = set()
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") == NODE_BASIC_BLOCK:
                block_ids.add(nid)

        all_blocks = list(block_ids)
        if not all_blocks:
            return block_a_id == block_b_id

        # Predecessor map (reversed CTRL_FLOW edges)
        preds: dict[str, set[str]] = {b: set() for b in all_blocks}
        for b in all_blocks:
            for pred in self._graph.predecessors(b):
                edge_data = self._graph.get_edge_data(pred, b)
                for _key, ed in edge_data.items():
                    if ed.get("edge_type") == EDGE_CTRL_FLOW:
                        preds[b].add(pred)

        # dom[B] = ∀ blocks (initially); dom[entry] = {entry}
        dom: dict[str, set[str]] = {}
        for b in all_blocks:
            dom[b] = set(all_blocks)
        entry = (
            entry_block_id
            if entry_block_id in dom
            else (all_blocks[0] if all_blocks else entry_block_id)
        )
        if entry in dom:
            dom[entry] = {entry}

        # Iterate to fixed point
        changed = True
        while changed:
            changed = False
            for b in all_blocks:
                if b == entry:
                    continue
                # dom[B] = {B} ∪ ⋂(dom[P] for each predecessor P)
                if preds[b]:
                    new_dom = set(all_blocks)
                    for p in preds[b]:
                        new_dom &= dom[p]
                    new_dom.add(b)
                else:
                    new_dom = {b}
                if new_dom != dom[b]:
                    dom[b] = new_dom
                    changed = True

        # Check: does A dominate B?
        if block_a_id not in dom or block_b_id not in dom:
            return block_a_id == block_b_id
        return block_a_id in dom[block_b_id]

    # ── Post-dominance & control dependence ───────────────────────────────

    def _collect_cfg_data_for_function(
        self, func_name: str, file_path: str | None = None
    ) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]], str | None, set[str]]:
        """Collect CFG block data from the graph for dominance analysis.

        Returns ``(block_ids, preds, succs, entry_id, exit_ids)``.
        """
        block_ids: set[str] = set()
        preds: dict[str, set[str]] = {}
        succs: dict[str, set[str]] = {}
        entry_id: str | None = None
        exit_ids: set[str] = set()

        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_BASIC_BLOCK:
                continue
            if data.get("enclosing_function") != func_name:
                continue
            if file_path is not None and data.get("file_path") != file_path:
                continue

            block_ids.add(nid)
            preds.setdefault(nid, set())
            succs.setdefault(nid, set())

            if data.get("block_type") == "entry":
                entry_id = nid
            elif data.get("block_type") == "exit":
                exit_ids.add(nid)

        # Collect CTRL_FLOW edges within this function
        for u, v, data in self._graph.edges(data=True):
            if data.get("edge_type") != EDGE_CTRL_FLOW:
                continue
            if u not in block_ids or v not in block_ids:
                continue
            succs.setdefault(u, set()).add(v)
            preds.setdefault(v, set()).add(u)

        return block_ids, preds, succs, entry_id, exit_ids

    def post_dominates(
        self,
        block_a_id: str,
        block_b_id: str,
        func_name: str,
        file_path: str | None = None,
    ) -> bool:
        """Return ``True`` if *block_a_id* post-dominates *block_b_id*.

        A block **P post-dominates B** if every path from B to any exit
        must go through P.  This is the reverse-path analogue of
        :meth:`dominates`.
        """
        block_ids, _preds, succs, entry_id, exit_ids = self._collect_cfg_data_for_function(
            func_name, file_path
        )
        if not block_ids or not exit_ids:
            return block_a_id == block_b_id

        from hyqagent.cpg.cfg import DominanceAnalyzer

        pd = DominanceAnalyzer.compute_post_dominators(block_ids, succs, exit_ids)
        if block_a_id not in pd or block_b_id not in pd:
            return block_a_id == block_b_id
        return block_a_id in pd[block_b_id]

    def get_control_dependents(
        self,
        from_block_id: str,
        func_name: str,
        file_path: str | None = None,
    ) -> list[str]:
        """Return block IDs that are **control-dependent** on *from_block_id*.

        A block L is control-dependent on B if B is a decision point
        (branch / loop header) whose outcome determines whether L executes.
        For example, a sanitizer inside an if-true branch is control-dependent
        on the if-condition block — if the condition is false, the sanitizer
        does not execute.

        Returns the list of block IDs that are control-dependent on
        *from_block_id*.
        """
        block_ids, _preds, succs, entry_id, exit_ids = self._collect_cfg_data_for_function(
            func_name, file_path
        )
        if not block_ids or not exit_ids:
            return []

        from hyqagent.cpg.cfg import DominanceAnalyzer

        pd = DominanceAnalyzer.compute_post_dominators(block_ids, succs, exit_ids)
        cd = DominanceAnalyzer.compute_control_dependence(block_ids, succs, pd)

        if from_block_id not in cd:
            return []

        # cd[L] = {B | L is control-dependent on B}
        # We want: which L are control-dependent on from_block_id?
        return sorted(lid for lid, controllers in cd.items() if from_block_id in controllers)

    def is_control_dependent_on(
        self,
        block_a_id: str,
        block_b_id: str,
        func_name: str,
        file_path: str | None = None,
    ) -> bool:
        """Return ``True`` if *block_a_id* is control-dependent on *block_b_id*.

        In other words: does the decision at *block_b_id* determine whether
        *block_a_id* executes?  (Block A depends on block B.)
        """
        return block_a_id in self.get_control_dependents(
            block_b_id,
            func_name,
            file_path,
        )

    # ── Coverage / discovery queries ────────────────────────────────────

    def get_nodes_by_type_in_file(self, node_type: str, file_path: str) -> list[GraphNode]:
        """Return all nodes of *node_type* in *file_path*.

        Useful for discovering which assignments / call-sites / basic-blocks
        exist in a particular source file before running heuristic scoring.
        """
        results: list[GraphNode] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != node_type:
                continue
            if data.get("file_path") != file_path:
                continue
            results.append(self._to_graph_node(nid, data))
        results.sort(key=lambda n: n.location)
        return results

    def get_endpoints_without_source(self) -> list[dict]:
        """Return every ``NODE_FUNCTION`` that has a framework route annotation
        but whose body contains **no** ``taint_category``-labelled assignment.

        These are candidates for IDOR / business-logic manual review.

        Heuristic: a function is a "handler" if its decorator list or source
        includes known route markers (``@app.route``, ``@GetMapping``, ``app.get(``, etc.).
        """
        route_markers = [
            "@app.route",
            "@app.get",
            "@app.post",
            "@app.put",
            "@app.delete",
            "@app.patch",
            "@blueprint.route",
            "@router.get",
            "@router.post",
            "app.get(",
            "app.post(",
            "app.put(",
            "app.delete(",
            "router.get(",
            "router.post(",
            "@GetMapping",
            "@PostMapping",
            "@PutMapping",
            "@DeleteMapping",
            "@RequestMapping",
        ]

        result: list[dict] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_FUNCTION:
                continue
            name = data.get("name", "")
            source = data.get("source", "")
            file_path = data.get("file_path", "")

            # Quick check: does this look like a route handler?
            has_route = any(m in source for m in route_markers) if source else False
            if not has_route:
                continue

            # Check whether any assignment in this function has taint_category
            has_source = False
            for anid, adata in self._graph.nodes(data=True):
                if adata.get("node_type") != NODE_ASSIGNMENT:
                    continue
                if adata.get("enclosing_function") != name:
                    continue
                if file_path and adata.get("file_path") != file_path:
                    continue
                if adata.get("taint_category"):
                    has_source = True
                    break

            if not has_source:
                result.append(
                    {
                        "node_id": nid,
                        "function": name,
                        "file_path": file_path,
                        "line": data.get("start_line", 0),
                    }
                )

        return result

    def get_all_sink_candidates(self, language: str = "") -> list[dict]:
        """Return every ``NODE_ASSIGNMENT`` whose source text looks like a
        function call — regardless of whether it is labelled.

        These are the "universe" of potential sinks against which coverage
        ratios are computed.
        """
        candidates: list[dict] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            src = data.get("source", "")
            if not src or "(" not in src:
                continue
            candidates.append(
                {
                    "node_id": nid,
                    "file_path": data.get("file_path", ""),
                    "start_line": data.get("start_line", 0),
                    "enclosing_function": data.get("enclosing_function", ""),
                    "source": src[:120],
                    "taint_category": data.get("taint_category", ""),
                }
            )

        # Sort by category first (unlabelled last), then by file+line
        candidates.sort(
            key=lambda c: (
                0 if c["taint_category"] else 1,
                c["file_path"],
                c["start_line"],
            )
        )
        return candidates

    def get_labeled_sinks(self) -> list[str]:
        """Return the node IDs of all ``NODE_ASSIGNMENT`` nodes with a
        ``taint_category`` attribute.

        Used to compute ``sink_coverage_ratio``.
        """
        return [
            nid
            for nid, data in self._graph.nodes(data=True)
            if data.get("node_type") == NODE_ASSIGNMENT and data.get("taint_category")
        ]

    def get_unlabeled_but_dangerous(self, language: str = "") -> list[dict]:
        """Return ``NODE_ASSIGNMENT`` nodes that are **not** taint-labelled
        but whose expression looks like a potentially dangerous call.

        Filters source text for common dangerous patterns (``execute(``,
        ``eval(``, ``system(``, etc.) as a fast pre-filter before the
        full heuristic scoring in :class:`SinkDiscoverer`.
        """
        danger_markers = [
            "execute",
            "query",
            "eval",
            "exec",
            "system",
            "popen",
            "read",
            "write",
            "open(",
            "process",
            "send",
            "load",
            "dump",
            "parse",
            "redirect",
            "render",
            "run(",
        ]
        candidates: list[dict] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            if data.get("taint_category"):
                continue
            src = data.get("source", "").lower()
            if not src or "(" not in src:
                continue
            if any(m in src for m in danger_markers):
                candidates.append(
                    {
                        "node_id": nid,
                        "file_path": data.get("file_path", ""),
                        "start_line": data.get("start_line", 0),
                        "enclosing_function": data.get("enclosing_function", ""),
                        "source": data.get("source", "")[:120],
                    }
                )

        candidates.sort(key=lambda c: (c["file_path"], c["start_line"]))
        return candidates

    def get_taint_paths_for_endpoint(
        self,
        endpoint_func: str,
        taint_loader: object | None = None,
        language: str = "",
        max_depth: int = 20,
    ) -> list[GraphPath]:
        """Find all taint paths that involve sources/sinks in *endpoint_func*.

        Scans assignments in the function body, extracts their
        ``taint_category``, and runs :meth:`find_path` for each source/sink
        pair within the same category.
        """
        # Collect taint categories in the handler function
        categories: set[str] = set()
        source_texts: list[str] = []
        sink_texts: list[str] = []
        for nid, data in self._graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            if data.get("enclosing_function") != endpoint_func:
                continue
            cat = data.get("taint_category", "")
            if not cat:
                continue
            # Multi-label support: one node may match multiple categories
            for single_cat in cat.split(","):
                categories.add(single_cat)
            src = data.get("source", "")
            if src:
                # Determine if it's a source or sink by matching YAML patterns
                if taint_loader and language:
                    if hasattr(taint_loader, "match_source") and taint_loader.match_source(
                        language, src
                    ):
                        source_texts.append(cat)
                    if hasattr(taint_loader, "match_sink") and taint_loader.match_sink(
                        language, src
                    ):
                        sink_texts.append(cat)

        # For each detected category, find paths
        all_paths: list[GraphPath] = []
        seen: set[tuple[str, str]] = set()
        for cat in categories:
            for path in self.find_path(cat, cat, max_depth, taint_loader, language):
                # Deduplicate by first+last node
                if path and len(path.nodes) >= 2:
                    key = (path.nodes[0].node_id, path.nodes[-1].node_id)
                    if key not in seen:
                        seen.add(key)
                        all_paths.append(path)

        return all_paths

    @staticmethod
    def _to_graph_node(node_id: str, data: dict) -> GraphNode:
        """Convert a NetworkX node to a :class:`GraphNode`."""
        return GraphNode(
            node_id=node_id,
            node_type=data.get("node_type", ""),
            location=data.get("location", data.get("file_path", "")),
            name=data.get("name", data.get("var_name", data.get("caller", ""))),
            source=data.get("source", data.get("expression", "")),
            taint_category=data.get("taint_category", ""),
        )
