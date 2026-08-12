"""cpg/dataflow.py — Intra- and inter-procedural data-flow analysis.

Builds on the call-graph layer to track how variables flow through a
codebase: definition-use chains within functions, data flow across
function boundaries, and taint propagation from sources to sinks.

See DESIGN-IMPLEMENTATION.md Section 2.4 for the interface specification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from tree_sitter import Node, Tree

from hyqagent.cpg.traversal import Traverser, _loc, _source

if TYPE_CHECKING:
    from hyqagent.cpg.callgraph_builder import CallGraphBuilder
    from hyqagent.cpg.parser import Parser
    from hyqagent.cpg.types import FunctionNode

from hyqagent.cpg.types import DataFlowStep, DefUsePair

# ─── Helper: location string ───────────────────────────────────────────────


# ─── Core class ────────────────────────────────────────────────────────────


class DataFlowBuilder:
    """Build def-use chains and trace data flow within / across functions.

    Usage::

        parser = Parser()
        df = DataFlowBuilder(parser)
        tree = parser.parse_file("app.py")
        funcs = parser.extract_functions(tree, "python")

        for func in funcs:
            chains = df.build_def_use_chains(tree, func_node, "python")
            for du in chains:
                print(f"{du.var_name}: defined at {du.def_location}, "
                      f"used at {du.use_locations}")

    With a call graph for cross-function tracing::

        cg_builder = CallGraphBuilder(parser)
        cg_builder.add_directory("./myapp")
        df = DataFlowBuilder(parser, cg_builder)
    """

    def __init__(
        self,
        parser: Parser,
        call_graph: CallGraphBuilder | None = None,
    ) -> None:
        self._parser = parser
        self._call_graph = call_graph

    # ── Intra-procedural: def-use chains ─────────────────────────────────

    def build_def_use_chains(
        self,
        tree: Tree,
        func_node: Node,
        language: str,
        file_path: str = "",
    ) -> list[DefUsePair]:
        """Build def-use pairs for every variable in *func_node*.

        Walks the function body to find assignment sites (definitions) and
        identifier references (uses), pairing each definition with all of
        its subsequent uses within the same function.

        Args:
            tree: The full tree-sitter parse tree (needed for traversal).
            func_node: A function / method definition node.
            language: Language name (``"python"``, ``"javascript"``, ``"java"``).
            file_path: Optional label used in location strings.

        Returns:
            One :class:`DefUsePair` per assigned variable, sorted by
            definition line number.

        """
        provider = self._parser.get_provider(language)
        assign_types = provider.assignment_types
        body = func_node.child_by_field_name("body")
        if body is None:
            return []

        traverser = Traverser(tree)

        # Phase 1 — collect assignment targets within the function body
        # _Assign: (var_name, def_node, def_source, def_line)
        assignments: list[_Assign] = []
        for node in traverser.traverse():
            if not self._node_in_range(node, body):
                continue
            if node.type in assign_types:
                target = provider.extract_assignment_target(node)
                if target:
                    assignments.append(
                        _Assign(
                            var_name=target,
                            node=node,
                            source=_source(node),
                            line=node.start_point[0] + 1,
                        )
                    )

        # Phase 1.5 — collect parameter definitions (implicit assignments at
        # function entry).  This is critical for taint tracking: annotations
        # like ``@RequestParam`` mark parameters as sources, and data flow
        # must connect them to their uses in the function body.
        params_node = func_node.child_by_field_name("parameters")
        if params_node is not None:
            param_names = provider.extract_parameters(func_node)
            param_children = [c for c in params_node.children if c.is_named]
            func_def_line = func_node.start_point[0] + 1
            for i, pname in enumerate(param_names):
                # Parameter source text: the full declaration including
                # annotations (e.g. ``@RequestParam String fileName``).
                ptext = _source(param_children[i]) if i < len(param_children) else pname
                assignments.append(
                    _Assign(
                        var_name=pname,
                        node=func_node,
                        source=ptext,
                        line=func_def_line,
                    )
                )

        # Phase 2 — single pass: collect all variable uses, then associate with defs
        # Build a map from var_name → list of use locations in one tree traversal
        var_uses: dict[str, list[str]] = {}
        for node in traverser.traverse():
            if not self._node_in_range(node, body):
                continue
            if node.type != "identifier":
                continue
            if not provider.is_variable_identifier(node):
                continue
            var_name = _source(node)
            if var_name not in var_uses:
                var_uses[var_name] = []
            var_uses[var_name].append(_loc(node, file_path))

        # Associate each assignment with its uses (skip the definition site itself)
        results: list[DefUsePair] = []
        for assign in assignments:
            use_locations = [
                loc
                for loc in var_uses.get(assign.var_name, [])
                if not self._loc_matches_def(loc, assign.node, file_path)
            ]

            results.append(
                DefUsePair(
                    var_name=assign.var_name,
                    def_location=_loc(assign.node, file_path),
                    def_expression=assign.source,
                    use_locations=sorted(use_locations),
                )
            )

        results.sort(key=lambda d: d.def_location)
        return results

    # ── Inter-procedural: cross-function tracing ────────────────────────

    def trace_cross_function(
        self,
        var_name: str,
        from_func: str,
        to_func: str,
        file_path: str = "",
    ) -> list[DataFlowStep]:
        """Trace *var_name* from *from_func* to *to_func* across a call edge.

        Looks up *to_func* in the call graph, finds the call site in
        *from_func*, and traces how the argument flows into the callee's
        parameter.

        Requires *call_graph* to have been set via the constructor.

        Returns an empty list when the call graph is unavailable or the
        functions / edge cannot be resolved.
        """
        if self._call_graph is None:
            return []

        # Find the callee definition
        target_file = self._call_graph.find_definition(to_func)
        if target_file is None:
            return []

        # Parse callee file and find the function
        callee_tree = self._parser.parse_file(target_file)
        callee_lang = self._parser.get_language(callee_tree)
        callee_funcs = self._parser.extract_functions(callee_tree, callee_lang)

        callee_node = None
        for fn in callee_funcs:
            if fn.name == to_func:
                callee_node = fn
                break

        if callee_node is None:
            return []

        steps: list[DataFlowStep] = []

        # Step 1 — the variable at the call site
        loc_str = f"{file_path}:0" if file_path else "<string>:0"
        steps.append(
            DataFlowStep(
                location=loc_str,
                expression=var_name,
                enclosing_function=from_func,
                kind="call_arg",
            )
        )

        # Step 2 — the parameter in the callee
        for param in callee_node.params:
            loc_str2 = f"{target_file}:0"
            steps.append(
                DataFlowStep(
                    location=loc_str2,
                    expression=param,
                    enclosing_function=to_func,
                    kind="parameter",
                )
            )
            break  # First positional parameter

        # Trace parameter through callee body
        callee_ts_node = self._fn_to_node(callee_node, callee_tree)
        if callee_ts_node is not None:
            def_use = self.build_def_use_chains(
                callee_tree,
                callee_ts_node,
                callee_lang,
                target_file,
            )
        else:
            return steps

        for du in def_use:
            # Find def-use for the matched parameter
            if du.var_name in (p for p in (steps[-1].expression,)):
                for use_loc in du.use_locations:
                    steps.append(
                        DataFlowStep(
                            location=use_loc,
                            expression=du.var_name,
                            enclosing_function=to_func,
                            kind="assignment",
                        )
                    )
                # TODO: Complex return tracking — trace return value back to caller

        return steps

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _node_in_range(node: Node, container: Node) -> bool:
        """Return ``True`` if *node* is within *container*'s byte range."""
        return node.start_byte >= container.start_byte and node.end_byte <= container.end_byte

    def _loc_matches_def(self, loc: str, def_node: Node, file_path: str) -> bool:
        """Return True if *loc* refers to the definition site itself.

        Compares location strings since we no longer have the original
        use Node objects after the single-pass optimization.
        """
        def_loc = _loc(def_node, file_path)
        return loc == def_loc

    def _fn_to_node(self, fn: FunctionNode, tree: Tree) -> Node | None:
        """Convert a FunctionNode (dataclass) back to a tree-sitter Node.

        Uses a per-tree cache to avoid repeated full-tree traversals.

        BUG 23: The cache is capped at ``_MAX_FN_CACHE`` entries with
        FIFO eviction to prevent unbounded growth across many parses.
        """
        _MAX_FN_CACHE = 8192
        cache_key = (id(tree), fn.name, fn.start_line)
        if not hasattr(self, "_fn_cache"):
            self._fn_cache: dict[tuple, Node | None] = {}
            self._fn_cache_keys: list[tuple] = []
        if cache_key in self._fn_cache:
            return self._fn_cache[cache_key]

        # Evict oldest entry if at capacity
        if len(self._fn_cache) >= _MAX_FN_CACHE and self._fn_cache_keys:
            old_key = self._fn_cache_keys.pop(0)
            self._fn_cache.pop(old_key, None)

        for node in Traverser(tree).traverse():
            line = node.start_point[0] + 1
            if line == fn.start_line:
                provider = self._parser.get_provider(self._parser.get_language(tree))
                if node.type in provider.func_def_types:
                    name = provider.extract_function_name(node)
                    if name == fn.name:
                        self._fn_cache[cache_key] = node
                        self._fn_cache_keys.append(cache_key)
                        return node
        self._fn_cache[cache_key] = None
        self._fn_cache_keys.append(cache_key)
        return None


# ─── Internal helpers ──────────────────────────────────────────────────────


@dataclass
class _Assign:
    """Internal: a single assignment found during def-use analysis."""

    var_name: str
    node: Node
    source: str = ""
    line: int = 0
