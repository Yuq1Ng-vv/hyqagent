"""cpg/graph.py — CPG graph builder using NetworkX MultiDiGraph.

Unifies AST nodes, call edges, and data-flow chains from the existing
CPG components into a single queryable graph.  Supports Python,
JavaScript, and Java source code.

Edge types
----------

* **AST** — syntactic parent → child relationships.
* **CALLS** — caller function node → callee function node (via call-site nodes).
* **DATA_FLOW** — data movement from definition / source through variable
  uses to the next definition or sink.

See DESIGN-IMPLEMENTATION.md Section 2.7 for the full interface specification.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import networkx as nx

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.dataflow import DataFlowBuilder
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:

    from hyqagent.cpg.callgraph_builder import CallGraphBuilder
    from hyqagent.cpg.parser import Parser

# ─── Node / edge type constants ──────────────────────────────────────────────

NODE_FUNCTION = "function"
NODE_CALL_SITE = "call_site"
NODE_ASSIGNMENT = "assignment"
NODE_VARIABLE_REF = "variable_ref"
NODE_SOURCE = "source"
NODE_SINK = "sink"

EDGE_AST = "AST"
EDGE_CALLS = "CALLS"
EDGE_DATA_FLOW = "DATA_FLOW"


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _uid(*parts: str) -> str:
    """Build a unique node id from string parts."""
    return ":".join(parts)


def _loc(node, file_path: str = "") -> str:
    """``"file:line"`` string."""
    line = node.start_point[0] + 1
    return f"{file_path}:{line}" if file_path else f"<string>:{line}"


def _src(node) -> str:
    """Decode node text."""
    return node.text.decode("utf-8") if node.text else ""


# ─── CPG Graph Builder ───────────────────────────────────────────────────────


class CPGGraphBuilder:
    """Build a Code Property Graph from source files.

    Usage::

        parser = Parser()
        builder = CPGGraphBuilder(parser)
        builder.add_file("app.py")
        graph = builder.graph  # nx.MultiDiGraph

        query = CPGQuery(graph)
        paths = query.find_path("request.args.get", "cursor.execute")
    """

    def __init__(self, parser: Parser) -> None:
        self._parser = parser
        self.graph = nx.MultiDiGraph()
        self._call_graph_builder: CallGraphBuilder | None = None
        self._dataflow = DataFlowBuilder(parser)
        self._indexed_files: set[str] = set()

    # ── File indexing ───────────────────────────────────────────────────

    def add_file(self, file_path: str | Path) -> None:
        """Parse *file_path* and add its AST, calls, and data-flow to the graph."""
        path = str(Path(file_path).resolve())
        if path in self._indexed_files:
            return
        self._indexed_files.add(path)

        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)
        provider = self._parser.get_provider(language)

        # 1 — Index function definitions
        funcs = self._parser.extract_functions(tree, language)
        func_nodes: dict[str, str] = {}  # func_name → node_id
        for fn in funcs:
            fid = _uid(NODE_FUNCTION, path, fn.name)
            self.graph.add_node(
                fid,
                node_type=NODE_FUNCTION,
                name=fn.name,
                file_path=path,
                start_line=fn.start_line,
                end_line=fn.end_line,
                is_method=fn.is_method,
                class_name=fn.class_name,
                source=fn.source[:200],
            )
            func_nodes[fn.name] = fid

        # 2 — Index AST: find the function body tree-node for each function
        fn_tree_nodes: dict[str, object] = {}  # func_name → tree-sitter Node
        for node in Traverser(tree).traverse():
            if node.type in provider.func_def_types:
                name = provider.extract_function_name(node)
                if name:
                    fn_tree_nodes[name] = node

        # 3 — Build intra-file call graph and index call edges
        cg = SingleFileCallGraph(self._parser)
        cg.build_from_file(path)
        for edge in cg.edges:
            cid = _uid(NODE_CALL_SITE, path, str(edge.call_line), edge.caller, edge.callee)
            self.graph.add_node(
                cid,
                node_type=NODE_CALL_SITE,
                caller=edge.caller,
                callee=edge.callee,
                file_path=path,
                line=edge.call_line,
                expression=edge.full_expression,
                is_resolved=edge.is_resolved,
            )
            # CALLS edge: caller function → call site
            caller_fid = func_nodes.get(edge.caller)
            if caller_fid:
                self.graph.add_edge(caller_fid, cid, edge_type=EDGE_CALLS)
            # If resolved locally: call site → callee function
            if edge.is_resolved:
                callee_fid = func_nodes.get(edge.callee)
                if callee_fid:
                    self.graph.add_edge(cid, callee_fid, edge_type=EDGE_CALLS)

        # 4 — Build def-use chains and add DATA_FLOW edges
        for fn_name, tree_node in fn_tree_nodes.items():
            chains = self._dataflow.build_def_use_chains(
                tree, tree_node, language, path  # type: ignore[arg-type]
            )
            fid = func_nodes.get(fn_name)
            if fid is None:
                continue

            for du in chains:
                # Assignment node
                aid = _uid(NODE_ASSIGNMENT, path, du.def_location.split(":")[-1], du.var_name)
                self.graph.add_node(
                    aid,
                    node_type=NODE_ASSIGNMENT,
                    var_name=du.var_name,
                    file_path=path,
                    location=du.def_location,
                    source=du.def_expression[:120],
                    enclosing_function=fn_name,
                )
                # DATA_FLOW: function → assignment (the function contains this def)
                self.graph.add_edge(fid, aid, edge_type=EDGE_DATA_FLOW)

                # Variable reference nodes for each use
                prev_node = aid
                for use_loc in du.use_locations:
                    use_line = use_loc.split(":")[-1]
                    vid = _uid(NODE_VARIABLE_REF, path, use_line, du.var_name)
                    self.graph.add_node(
                        vid,
                        node_type=NODE_VARIABLE_REF,
                        var_name=du.var_name,
                        file_path=path,
                        location=use_loc,
                        enclosing_function=fn_name,
                    )
                    # DATA_FLOW: assignment → use, use → use (chain)
                    self.graph.add_edge(prev_node, vid, edge_type=EDGE_DATA_FLOW)
                    prev_node = vid

    def add_directory(self, dir_path: str | Path) -> None:
        """Recursively add all source files in *dir_path*.

        Uses :class:`CallGraphBuilder` for cross-file import resolution.
        """
        from hyqagent.cpg.callgraph_builder import CallGraphBuilder
        from hyqagent.cpg.languages import detect_by_extension

        root = Path(dir_path).resolve()
        self._call_graph_builder = CallGraphBuilder(self._parser)

        # Index all files via CallGraphBuilder for import resolution
        for entry in sorted(root.rglob("*")):
            if not entry.is_file():
                continue
            if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
                continue
            if detect_by_extension(str(entry)) is not None:
                self._call_graph_builder.add_file(str(entry))

        # Build cross-file call edges
        cross_edges = self._call_graph_builder.build_calls()

        # Add each file's local information to the graph
        for file_path in self._call_graph_builder.files:
            self.add_file(file_path)

        # Add cross-file CALLS edges
        for edge in cross_edges:
            target_file = self._call_graph_builder.find_definition(edge.callee)
            caller_fid = _uid(NODE_FUNCTION, edge.file_path, edge.caller)
            if target_file:
                callee_fid = _uid(NODE_FUNCTION, target_file, edge.callee)
                # Add call-site node and edges
                cid = _uid(
                    NODE_CALL_SITE,
                    edge.file_path,
                    str(edge.call_line),
                    edge.caller,
                    edge.callee,
                )
                if cid not in self.graph:
                    self.graph.add_node(
                        cid,
                        node_type=NODE_CALL_SITE,
                        caller=edge.caller,
                        callee=edge.callee,
                        file_path=edge.file_path,
                        line=edge.call_line,
                        expression=edge.full_expression,
                        is_resolved=True,
                        cross_file=True,
                    )
                self.graph.add_edge(caller_fid, cid, edge_type=EDGE_CALLS)
                self.graph.add_edge(cid, callee_fid, edge_type=EDGE_CALLS)

    # ── Graph properties ─────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        """Total number of nodes in the graph."""
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        """Total number of edges in the graph."""
        return self.graph.number_of_edges()

    def nodes_by_type(self, node_type: str) -> list[str]:
        """Return all node ids matching *node_type*."""
        return [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == node_type]

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"CPGGraphBuilder(files={len(self._indexed_files)}, "
            f"nodes={self.node_count}, edges={self.edge_count})"
        )
