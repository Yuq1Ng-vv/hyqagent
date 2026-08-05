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
    EDGE_DATA_FLOW,
    NODE_ASSIGNMENT,
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
    ) -> list[GraphPath]:
        """Find all paths from nodes matching source to sink patterns.

        Traverses ``DATA_FLOW`` and ``CALLS`` edges via BFS.  Returns up
        to 20 distinct paths, sorted shortest-first.
        """
        sources = self._find_nodes(source_pattern)
        sinks = set(self._find_nodes(sink_pattern))
        if not sources or not sinks:
            return []

        paths: list[GraphPath] = []
        for src_id in sources:
            for path in self._bfs_paths(src_id, sinks, max_depth):
                if len(paths) >= 20:
                    break
                paths.append(path)
            if len(paths) >= 20:
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
            if ntype in (NODE_SOURCE, NODE_ASSIGNMENT):
                source_nodes.append(self._to_graph_node(node_id, node_data))

            # Reverse: follow predecessors
            for pred in self._graph.predecessors(node_id):
                if pred not in visited:
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
            if ntype == NODE_SINK:
                sink_nodes.append(self._to_graph_node(node_id, node_data))

            # Forward: follow successors
            for succ in self._graph.successors(node_id):
                if succ not in visited:
                    queue.append((succ, depth + 1))

        return sink_nodes

    def get_call_chain(self, func_a: str, func_b: str) -> GraphPath | None:
        """Find a ``CALLS``-edge path from *func_a* to *func_b*."""
        # Find function nodes by name
        a_nodes = [
            n for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == NODE_FUNCTION and d.get("name") == func_a
        ]
        b_nodes = {
            n for n, d in self._graph.nodes(data=True)
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

    def get_sanitizers(self, path: GraphPath) -> list[str]:
        """Check for sanitizer patterns along *path* nodes."""
        # Simple heuristic: look for type-casting / escaping in assignment sources
        sanitizers: list[str] = []
        sanitizer_patterns = ["int(", "float(", "str(", "escape(", "sanitize", "filter", "validate"]
        for node in path.nodes:
            src_lower = node.source.lower()
            for pat in sanitizer_patterns:
                if pat.lower() in src_lower:
                    sanitizers.append(pat)
        return sanitizers

    # ── Internal helpers ─────────────────────────────────────────────────

    def _find_nodes(self, pattern: str, max_results: int = 200) -> list[str]:
        """Find node ids where *pattern* appears in any attribute value.

        Stops early after *max_results* to prevent O(n) blowup on large graphs.
        """
        if not pattern:
            return []
        matches: list[str] = []
        for nid, data in self._graph.nodes(data=True):
            if len(matches) >= max_results:
                break
            for val in data.values():
                if isinstance(val, str) and pattern in val:
                    matches.append(nid)
                    break
        return matches

    def _bfs_paths(
        self,
        start: str,
        targets: set[str],
        max_depth: int,
        edge_types: set[str] | None = None,
    ) -> list[GraphPath]:
        """BFS from *start* to any node in *targets*.

        If *edge_types* is given, only traverse edges with matching
        ``edge_type`` attribute.  Defaults to ``{DATA_FLOW, CALLS}``.
        """
        if edge_types is None:
            edge_types = {EDGE_DATA_FLOW, EDGE_CALLS}

        result: list[GraphPath] = []
        visited: set[str] = {start}
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
                if succ in visited:
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

                visited.add(succ)
                queue.append((succ, [*node_path, succ], [*edge_path, etype]))

        return result

    @staticmethod
    def _to_graph_node(node_id: str, data: dict) -> GraphNode:
        """Convert a NetworkX node to a :class:`GraphNode`."""
        return GraphNode(
            node_id=node_id,
            node_type=data.get("node_type", ""),
            location=data.get("location", data.get("file_path", "")),
            name=data.get("name", data.get("var_name", data.get("caller", ""))),
            source=data.get("source", data.get("expression", "")),
        )
