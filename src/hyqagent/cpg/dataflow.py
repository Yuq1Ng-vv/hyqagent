"""cpg/dataflow.py — Intra- and inter-procedural data-flow analysis.

Builds on the call-graph layer to track how variables flow through a
codebase: definition-use chains within functions, data flow across
function boundaries, and taint propagation from sources to sinks.

See DESIGN-IMPLEMENTATION.md Section 2.4 for the interface specification.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tree_sitter import Node, Tree

from hyqagent.cpg.traversal import Traverser, _loc, _source

if TYPE_CHECKING:
    from hyqagent.cpg.callgraph_builder import CallGraphBuilder
    from hyqagent.cpg.languages.base import LanguageProvider
    from hyqagent.cpg.parser import Parser
    from hyqagent.cpg.types import FunctionNode

from hyqagent.cpg.types import DataFlowStep, DefUsePair, TaintConfig, TaintPath

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
        paths = df.propagate_taint("request.args.get", "cursor.execute")
    """

    def __init__(
        self,
        parser: Parser,
        call_graph: CallGraphBuilder | None = None,
    ) -> None:
        self._parser = parser
        self._call_graph = call_graph
        self._taint_config = TaintConfig()

    # ── Taint configuration ─────────────────────────────────────────────

    def set_taint_config(
        self,
        sources: list[str],
        sinks: list[str],
        sanitizers: list[str] | None = None,
    ) -> None:
        """Set the taint source / sink / sanitizer patterns."""
        self._taint_config = TaintConfig(
            sources=list(sources),
            sinks=list(sinks),
            sanitizers=list(sanitizers or []),
        )

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

        # Phase 2 — for each assigned variable, find all uses in the body
        results: list[DefUsePair] = []
        for assign in assignments:
            use_locations: list[str] = []
            for node in traverser.traverse():
                if not self._node_in_range(node, body):
                    continue
                if node.type != "identifier":
                    continue
                if not provider.is_variable_identifier(node):
                    continue
                if _source(node) != assign.var_name:
                    continue
                # Skip the definition site itself
                if node is assign.node or self._is_descendant_of(
                    node, assign.node
                ):
                    continue
                use_locations.append(_loc(node, file_path))

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
        callee_ts_node = (
            self._fn_to_node(callee_node, callee_tree)
            if hasattr(self, '_fn_to_node')
            else None
        )
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

    # ── Taint propagation ───────────────────────────────────────────────

    def propagate_taint(
        self,
        source_pattern: str = "",
        sink_pattern: str = "",
        max_depth: int = 10,
    ) -> list[TaintPath]:
        """Propagate taint from sources to sinks across the project.

        Uses BFS within each function and across call edges to track
        tainted variables.  Stops when *max_depth* hops are exceeded
        or a sink is reached.

        Requires *call_graph* to have been populated via ``add_directory``.

        Args:
            source_pattern: Substring to match taint sources
                            (e.g. ``"request.args.get"``).
            sink_pattern: Substring to match taint sinks
                          (e.g. ``"cursor.execute"``).
            max_depth: Maximum BFS depth (controls how many assignments /
                       call hops to follow).

        Returns:
            List of complete taint paths from source to sink.

        """
        if self._call_graph is None:
            return []

        paths: list[TaintPath] = []

        for file_path in sorted(self._call_graph.files):
            tree = self._parser.parse_file(file_path)
            language = self._parser.get_language(tree)
            provider = self._parser.get_provider(language)

            # Find all taint sources in this file
            sources = self._find_pattern_matches(
                tree, source_pattern, file_path
            )
            if not sources:
                continue

            # Find all sinks
            sinks = self._find_pattern_matches(
                tree, sink_pattern, file_path
            )

            # Build per-function def-use chains
            funcs = self._parser.extract_functions(tree, language)
            du_map: dict[str, list[DefUsePair]] = {}
            for fn in funcs:
                fn_node = self._fn_to_node(fn, tree)
                if fn_node is not None:
                    du_map[fn.name] = self.build_def_use_chains(
                        tree, fn_node, language, file_path
                    )

            # For each source, BFS through assignments
            for src_node in sources:
                src_text = _source(src_node)
                # Find the enclosing function for this source
                encl_func = self._find_enclosing_func(
                    src_node, provider, tree
                )
                if encl_func is None:
                    continue

                # Determine which variable holds the tainted value
                tainted_var = self._resolve_tainted_var(
                    src_node, encl_func, du_map.get(encl_func, []), tree, provider
                )
                if tainted_var is None:
                    # Source itself is the tainted expression
                    tainted_var = src_text

                # BFS from this source
                path = self._bfs_taint(
                    tainted_var,
                    src_node,
                    sinks,
                    du_map,
                    provider,
                    file_path,
                    language,
                    max_depth,
                    src_text,
                )
                if path:
                    paths.append(path)

        return paths

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _node_in_range(node: Node, container: Node) -> bool:
        """Return ``True`` if *node* is within *container*'s byte range."""
        return (
            node.start_byte >= container.start_byte
            and node.end_byte <= container.end_byte
        )

    @staticmethod
    def _is_descendant_of(node: Node, ancestor: Node) -> bool:
        """Return ``True`` if *node* is a descendant of *ancestor*."""
        current = node.parent
        while current is not None:
            if current is ancestor:
                return True
            current = current.parent
        return False

    def _find_pattern_matches(
        self,
        tree: Tree,
        pattern: str,
        file_path: str = "",
    ) -> list[Node]:
        """Find all nodes whose source text contains *pattern*."""
        if not pattern:
            return []
        matches: list[Node] = []
        for node in Traverser(tree).traverse():
            if pattern in _source(node):
                matches.append(node)
        return matches

    def _find_enclosing_func(
        self,
        node: Node,
        provider: LanguageProvider,
        tree: Tree,
    ) -> str | None:
        """Walk ancestors to find the nearest function definition name."""
        func_types = provider.func_def_types
        current = node.parent
        while current is not None:
            if current.type in func_types:
                return provider.extract_function_name(current)
            current = current.parent
        return None

    def _resolve_tainted_var(
        self,
        src_node: Node,
        encl_func: str,
        du_chains: list[DefUsePair],
        tree: Tree,
        provider: LanguageProvider,
    ) -> str | None:
        """Determine which variable holds the tainted value from *src_node*.

        If the source is directly assigned (``x = request.args.get(...)``),
        return ``"x"``.  Otherwise return ``None``.
        """
        parent = src_node.parent
        while parent is not None:
            if parent.type in provider.assignment_types:
                target = provider.extract_assignment_target(parent)
                if target:
                    return target
            parent = parent.parent
        return None

    def _bfs_taint(
        self,
        var_name: str,
        src_node: Node,
        sinks: list[Node],
        du_map: dict[str, list[DefUsePair]],
        provider: LanguageProvider,
        file_path: str,
        language: str,
        max_depth: int,
        src_text: str,
    ) -> TaintPath | None:
        """BFS from *var_name* through assignments and calls to find a sink."""
        visited: set[tuple[str, str]] = set()  # (var, location)
        queue: deque[tuple[str, str, list[DataFlowStep], int]] = deque()
        start_loc = _loc(src_node, file_path)
        queue.append((var_name, start_loc, [], 0))
        visited.add((var_name, start_loc))

        sanitizers_found: list[str] = []

        while queue:
            cur_var, _cur_loc, steps, depth = queue.popleft()
            if depth > max_depth:
                continue

            # Check if we've hit a sink
            for sink_node in sinks:
                sink_text = _source(sink_node)
                if cur_var in sink_text or sink_text in cur_var:
                    return TaintPath(
                        source=src_text,
                        sink=sink_text,
                        variable=var_name,
                        steps=steps,
                        sanitized=len(sanitizers_found) > 0,
                        sanitizers=list(sanitizers_found),
                    )

            # Follow the variable through def-use chains
            for func_name, chains in du_map.items():
                for du in chains:
                    if du.var_name == cur_var:
                        for use_loc in du.use_locations:
                            state = (cur_var, use_loc)
                            if state in visited:
                                continue
                            visited.add(state)
                            new_steps = [*steps, DataFlowStep(
                                location=use_loc,
                                expression=cur_var,
                                enclosing_function=func_name,
                                kind="assignment",
                            )]
                            queue.append((cur_var, use_loc, new_steps, depth + 1))

            # Check for sanitizers
            for sanitizer in self._taint_config.sanitizers:
                if sanitizer in cur_var:
                    sanitizers_found.append(sanitizer)

        return None

    def _fn_to_node(self, fn: FunctionNode, tree: Tree) -> Node | None:
        """Convert a FunctionNode (dataclass) back to a tree-sitter Node.

        Searches the tree for a function definition at the same location.
        """
        for node in Traverser(tree).traverse():
            line = node.start_point[0] + 1
            if line == fn.start_line:
                provider = self._parser.get_provider(
                    self._parser.get_language(tree)
                )
                if node.type in provider.func_def_types:
                    name = provider.extract_function_name(node)
                    if name == fn.name:
                        return node
        return None


# ─── Internal helpers ──────────────────────────────────────────────────────


@dataclass
class _Assign:
    """Internal: a single assignment found during def-use analysis."""

    var_name: str
    node: Node
    source: str = ""
    line: int = 0
