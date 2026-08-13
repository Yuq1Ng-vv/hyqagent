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

import hashlib
import pickle
import re
from pathlib import Path
from typing import TYPE_CHECKING

import networkx as nx

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.cfg import CFGBuilder
from hyqagent.cpg.dataflow import DataFlowBuilder
from hyqagent.cpg.traversal import Traverser

if TYPE_CHECKING:
    from hyqagent.cpg.callgraph_builder import CallGraphBuilder
    from hyqagent.cpg.parser import Parser
    from hyqagent.cpg.taint_loader import TaintRuleLoader

# ─── Node / edge type constants ──────────────────────────────────────────────

NODE_FUNCTION = "function"
NODE_CALL_SITE = "call_site"
NODE_ASSIGNMENT = "assignment"
NODE_VARIABLE_REF = "variable_ref"
NODE_PARAMETER = "parameter"
NODE_SOURCE = "source"
NODE_SINK = "sink"

EDGE_AST = "AST"
EDGE_CALLS = "CALLS"
EDGE_DATA_FLOW = "DATA_FLOW"
EDGE_CTRL_FLOW = "CTRL_FLOW"

NODE_BASIC_BLOCK = "basic_block"


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _uid(*parts: str) -> str:
    """Build a unique node id from string parts."""
    return ":".join(parts)


def _parse_line(location: str) -> int | None:
    """Extract the trailing line number from a ``file_path:line`` string."""
    if not location:
        return None
    parts = location.rsplit(":", 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


# ─── Parameter source classification ───────────────────────────────────────
#
# A Java method parameter is a taint source when it is annotated with a
# web-framework input annotation (Spring ``@RequestParam``, JAX-RS
# ``@PathParam``, ...) or is typed as the raw ``HttpServletRequest``.  Each
# annotation maps to exactly ONE taint category — the vulnerability class it
# most commonly feeds — instead of the ~18 categories a naive signature
# substring match would produce (see Session 1.45, NODE_PARAMETER 过度标记).

_PARAM_ANNOTATION_TO_CATEGORY: dict[str, str] = {
    "RequestParam": "injection_general",
    "RequestBody": "injection_general",
    "PathVariable": "path_traversal",
    "PathParam": "path_traversal",
    "RequestHeader": "header_injection",
    "HeaderParam": "header_injection",
    "CookieValue": "injection_general",
    "CookieParam": "injection_general",
    "ModelAttribute": "injection_general",
    "SessionAttribute": "injection_general",
    "RequestPart": "deserialization",
    "QueryParam": "injection_general",
    "FormParam": "injection_general",
    "MatrixParam": "injection_general",
    "BeanParam": "injection_general",
    "QueryValue": "injection_general",
    "Body": "injection_general",
}

# Raw request objects that carry arbitrary user input, mapped to the generic
# injection category when a parameter has no more specific annotation.
_REQUEST_PARAM_TYPE_HINTS: tuple[str, ...] = (
    "HttpServletRequest",
    "ServletRequest",
)


def _find_param_list(signature: str) -> tuple[int, int] | None:
    """Return ``(open_idx, close_idx)`` of a method's parameter list.

    Walks backward from the last ``)`` to its balanced ``(`` so that
    annotation arguments (``@PathVariable("name")``) and generic types do
    not confuse the search.
    """
    close_idx = signature.rfind(")")
    if close_idx == -1:
        return None
    depth = 0
    for i in range(close_idx, -1, -1):
        if signature[i] == ")":
            depth += 1
        elif signature[i] == "(":
            depth -= 1
            if depth == 0:
                return i, close_idx
    return None


def _split_top_level(text: str, delim: str) -> list[str]:
    """Split *text* on *delim* ignoring delimiters nested in ``()``/``<>``/``[]``/strings."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for ch in text:
        if quote is not None:
            current.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            current.append(ch)
        elif ch in "([<{":
            depth += 1
            current.append(ch)
        elif ch in ")]>}":
            depth -= 1
            current.append(ch)
        elif ch == delim and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    parts.append("".join(current).strip())
    return parts


def _classify_parameter_source(signature: str, param_index: int) -> list[str]:
    """Return taint categories for the parameter at *param_index*.

    Only annotations on that specific parameter (or its raw request-object
    type) are considered — never the enclosing function body.  Returns an
    empty list when the parameter is not a recognised input source.
    """
    pair = _find_param_list(signature)
    if pair is None:
        return []
    open_idx, close_idx = pair
    params_text = signature[open_idx + 1 : close_idx].strip()
    if not params_text:
        return []
    segments = _split_top_level(params_text, ",")
    if param_index >= len(segments):
        return []
    segment = segments[param_index]

    categories: list[str] = []
    for match in re.finditer(r"@([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)", segment):
        simple_name = match.group(1).rsplit(".", 1)[-1]
        cat = _PARAM_ANNOTATION_TO_CATEGORY.get(simple_name)
        if cat and cat not in categories:
            categories.append(cat)

    # Fall back to a raw request-object parameter (e.g. HttpServletRequest).
    if not categories and any(hint in segment for hint in _REQUEST_PARAM_TYPE_HINTS):
        categories.append("injection_general")

    return categories


def _extract_signature(fn_node: object, source: str) -> str:
    """Return a method's signature — everything before its body block.

    Uses tree-sitter's ``body`` field to locate the body precisely.  A naive
    ``source.find("{")`` would stop at a ``{`` inside an annotation string
    argument (``@GetMapping("/users/{id}")``) and truncate the signature
    before the parameter list.
    """
    body = fn_node.child_by_field_name("body")  # type: ignore[attr-defined]
    if body is not None:
        body_start = getattr(body, "start_byte", None)
        node_start = getattr(fn_node, "start_byte", None)
        if body_start is not None and node_start is not None and body_start >= node_start:
            return source[: body_start - node_start].rstrip()
    # Fallback: strip at the first brace (best effort).
    brace_idx = source.find("{")
    return source[:brace_idx].rstrip() if brace_idx != -1 else source


def _matches_sink_exclude(text: str, patterns: list[str]) -> bool:
    """Return True if *text* matches any sink-exclusion regex *pattern*.

    Exclusion patterns are user-supplied regexes (from ``sink_excludes`` in
    taint_rules.yaml).  Invalid patterns are skipped rather than raising.
    """
    for pat in patterns:
        try:
            if re.search(pat, text):
                return True
        except re.error:
            continue
    return False


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

    def __init__(
        self,
        parser: Parser,
        taint_loader: TaintRuleLoader | None = None,
    ) -> None:
        self._parser = parser
        self.graph = nx.MultiDiGraph()
        self._call_graph_builder: CallGraphBuilder | None = None
        self._dataflow = DataFlowBuilder(parser)
        self._cfg_builder: CFGBuilder | None = None  # created lazily
        self._taint_loader = taint_loader
        self._indexed_files: set[str] = set()
        self._cache_dir: Path | None = None

    # ── Cache helpers ────────────────────────────────────────────────────

    @staticmethod
    def _cache_path_for(directory: Path) -> Path:
        """Return the cache file path for *directory*."""
        cache_root = Path.home() / ".cache" / "hyqagent" / "cpg"
        cache_root.mkdir(parents=True, exist_ok=True)
        # Use a hash of the absolute path so cache is stable across cwd changes
        dir_hash = hashlib.sha256(str(directory.resolve()).encode()).hexdigest()[:16]
        return cache_root / f"{dir_hash}.pkl"

    @staticmethod
    def _compute_source_fingerprint(directory: Path) -> str:
        """Compute a fingerprint of all source files under *directory*.

        Uses (relative_path, file_size) tuples so the cache invalidates
        when files are added, removed, or changed in size.
        """
        from hyqagent.cpg.languages import detect_by_extension

        entries: list[str] = []
        for entry in sorted(directory.rglob("*")):
            if not entry.is_file():
                continue
            if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
                continue
            if detect_by_extension(str(entry)) is not None:
                rel = entry.relative_to(directory)
                entries.append(f"{rel}:{entry.stat().st_size}")
        return hashlib.sha256("\n".join(entries).encode()).hexdigest()

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

        # ── Helper: unique key per overload ──────────────────────────
        # BUG 30: Bare function names as dict keys lose overloaded
        # methods (e.g. AbstractResourceHandler.getResource is both
        # a concrete method with a body AND an abstract overload).
        # Using ``name$start_line`` keeps every overload distinct so
        # def-use chains are built for ALL methods, not just the last
        # one that happens to be visited.
        def _fkey(name: str, line: int) -> str:
            return f"{name}${line}"

        # 1 — Index function definitions
        funcs = self._parser.extract_functions(tree, language)
        func_nodes: dict[str, str] = {}  # _fkey → node_id
        _func_start_lines: dict[str, int] = {}  # bare name → start_line (last-wins)
        for fn in funcs:
            key = _fkey(fn.name, fn.start_line)
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
            func_nodes[key] = fid
            _func_start_lines[fn.name] = fn.start_line  # last-wins for bare-name lookups

            # 1.5 — Parameter nodes: for each function parameter, create a
            # NODE_PARAMETER node and DATA_FLOW edge from the function.
            # These serve as attachment points for cross-function taint
            # edges (caller argument var_refs → callee parameter nodes).
            for pi, pname in enumerate(fn.params):
                pid = _uid(NODE_PARAMETER, path, fn.name, pname)
                self.graph.add_node(
                    pid,
                    node_type=NODE_PARAMETER,
                    name=pname,
                    var_name=pname,
                    file_path=path,
                    location=f"{path}:{fn.start_line}",
                    enclosing_function=fn.name,
                    param_index=pi,
                )
                # DATA_FLOW: function → parameter
                self.graph.add_edge(fid, pid, edge_type=EDGE_DATA_FLOW)

        # 2 — Index AST: find function body tree-nodes and call arguments
        fn_tree_nodes: dict[str, object] = {}  # _fkey → tree-sitter Node
        # (line, caller_func, callee_bare_name) → list of argument expression texts
        call_args_index: dict[tuple[int, str, str], list[str]] = {}
        for node in Traverser(tree).traverse():
            if node.type in provider.func_def_types:
                name = provider.extract_function_name(node)
                if name:
                    line = node.start_point[0] + 1
                    fn_tree_nodes[_fkey(name, line)] = node
            elif node.type in provider.call_node_type:
                # Extract argument expressions for positional param matching
                callee_info = provider.extract_callee_info(node)
                if callee_info is not None:
                    bare_name, _full_expr, _is_method = callee_info
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        args: list[str] = []
                        for child in args_node.named_children:
                            text = child.text.decode("utf-8") if child.text else ""
                            if text:
                                args.append(text)
                        if args:
                            line = node.start_point[0] + 1
                            # Find enclosing function
                            encl: str | None = None
                            for anc in Traverser.get_ancestors(node):
                                if anc.type in provider.func_def_types:
                                    encl = provider.extract_function_name(anc)
                                    break
                            if encl:
                                call_args_index[(line, encl, bare_name)] = args

        # 2.5 — Store each function's full signature (text before the body
        # block) on its NODE_FUNCTION.  The tree-sitter ``body`` field gives a
        # precise cut — a naive ``source.find("{")`` would stop at a ``{``
        # inside an annotation string like ``@GetMapping("/users/{id}")``.
        # NODE_PARAMETER source labeling reads this signature back later.
        for fn in funcs:
            tree_key = _fkey(fn.name, fn.start_line)
            tree_node = fn_tree_nodes.get(tree_key)
            func_id = func_nodes.get(tree_key)
            if tree_node is None or func_id is None:
                continue
            self.graph.nodes[func_id]["signature"] = _extract_signature(tree_node, fn.source)

        # 3 — Build intra-file call graph and index call edges
        # BUG 15: Reuse already-parsed tree instead of re-parsing
        cg = SingleFileCallGraph(self._parser)
        cg.build_from_tree(tree, language, path)
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
            # Attach extracted call argument expressions for positional matching
            cargs = call_args_index.get((edge.call_line, edge.caller, edge.callee))
            if cargs:
                self.graph.nodes[cid]["call_args"] = cargs
            # CALLS edge: caller function → call site
            # BUG 30: edge.caller is a bare name — resolve via last-wins
            # start-line index (intra-file; overloads are fine because
            # only one caller contains this particular call line).
            caller_fid = self._resolve_bare_name(
                path, edge.caller, func_nodes, _func_start_lines, _fkey
            )
            if caller_fid:
                self.graph.add_edge(caller_fid, cid, edge_type=EDGE_CALLS)
            # If resolved locally: call site → callee function
            if edge.is_resolved:
                callee_fid = self._resolve_bare_name(
                    path, edge.callee, func_nodes, _func_start_lines, _fkey
                )
                if callee_fid:
                    self.graph.add_edge(cid, callee_fid, edge_type=EDGE_CALLS)

        # 4 — Build def-use chains and add DATA_FLOW edges.
        # BUG 30: Iterate over the *funcs list* (from extract_functions)
        # rather than fn_tree_nodes dict, so every overloaded method gets
        # its def-use chains built — not just the last one with that name.
        for fn in funcs:
            tree_key = _fkey(fn.name, fn.start_line)
            tree_node = fn_tree_nodes.get(tree_key)
            if tree_node is None:
                continue
            chains = self._dataflow.build_def_use_chains(
                tree,
                tree_node,
                language,
                path,  # type: ignore[arg-type]
            )
            fid = func_nodes.get(tree_key)
            if fid is None:
                continue

            for du in chains:
                # Assignment node
                # BUG 26: rsplit avoids breakage on Windows paths (C:\...)
                aid = _uid(NODE_ASSIGNMENT, path, du.def_location.rsplit(":", 1)[-1], du.var_name)
                self.graph.add_node(
                    aid,
                    node_type=NODE_ASSIGNMENT,
                    var_name=du.var_name,
                    file_path=path,
                    location=du.def_location,
                    source=du.def_expression[:120],
                    enclosing_function=fn.name,
                )
                # DATA_FLOW: function → assignment (the function contains this def)
                self.graph.add_edge(fid, aid, edge_type=EDGE_DATA_FLOW)

                # Variable reference nodes for each use
                prev_node = aid
                for use_loc in du.use_locations:
                    # BUG 26: rsplit avoids breakage on Windows paths
                    use_line = use_loc.rsplit(":", 1)[-1]
                    vid = _uid(NODE_VARIABLE_REF, path, use_line, du.var_name)
                    self.graph.add_node(
                        vid,
                        node_type=NODE_VARIABLE_REF,
                        var_name=du.var_name,
                        file_path=path,
                        location=use_loc,
                        enclosing_function=fn.name,
                    )
                    # DATA_FLOW: assignment → use, use → use (chain)
                    self.graph.add_edge(prev_node, vid, edge_type=EDGE_DATA_FLOW)
                    prev_node = vid

            # 4.5 — RHS→LHS data-flow edges: connect variable uses in an
            # assignment's right-hand side to the assignment itself.
            #
            # When `list = jdbc.queryForList(sql, map)` is executed, the
            # values of `sql` and `map` flow INTO `list`.  Without this step
            # the BFS can traverse the `sql` variable-ref chain all the way
            # to line 235 but never "cross over" to the `list` assignment
            # that is the actual sink.  This edge bridges that gap.
            self._add_rhs_to_lhs_edges(path)

        # 4.55 — Connect NODE_PARAMETER → NODE_ASSIGNMENT for the same
        # (enclosing_function, var_name).  Phase 1.5 of build_def_use_chains
        # creates NODE_ASSIGNMENT / NODE_VARIABLE_REF chains for parameters,
        # but NODE_PARAMETER (created in step 1.5) has no outgoing edges to
        # them.  Without this bridge, cross-function taint edges (caller
        # var_ref → callee NODE_PARAMETER) lead to a dead end in BFS.
        for nid, ndata in self.graph.nodes(data=True):
            if ndata.get("node_type") != NODE_PARAMETER:
                continue
            if ndata.get("file_path") != path:
                continue
            pname = ndata.get("var_name", "")
            encl = ndata.get("enclosing_function", "")
            if not pname:
                continue
            # Find the NODE_ASSIGNMENT that Phase 1.5 created for this
            # parameter (same var_name + enclosing_function + first line
            # of the function body, i.e. smallest line number match).
            best_aid: str | None = None
            best_line: int = 999999
            for aid, adata in self.graph.nodes(data=True):
                if adata.get("node_type") != NODE_ASSIGNMENT:
                    continue
                if adata.get("file_path") != path:
                    continue
                if adata.get("var_name") != pname:
                    continue
                if adata.get("enclosing_function") != encl:
                    continue
                loc = adata.get("location", "")
                line = _parse_line(loc)
                if line is not None and line < best_line:
                    best_line = line
                    best_aid = aid
            if best_aid is not None:
                self.graph.add_edge(nid, best_aid, edge_type=EDGE_DATA_FLOW)

        # 4.6 — Build CFG for each function
        self._build_cfg(tree, fn_tree_nodes, provider, path)

        # 5 — Label taint sources and sinks on assignment nodes
        if self._taint_loader is not None:
            self._label_taint_nodes(path, language)

    def add_directory(self, dir_path: str | Path, use_cache: bool = True) -> None:
        """Recursively add all source files in *dir_path*.

        Uses :class:`CallGraphBuilder` for cross-file import resolution.

        When *use_cache* is True (the default), the built graph is pickled
        to ``~/.cache/hyqagent/cpg/<hash>.pkl`` and reused on subsequent
        calls as long as the file list hasn't changed.  Set to False to
        force a fresh build.
        """
        from hyqagent.cpg.callgraph_builder import CallGraphBuilder
        from hyqagent.cpg.languages import detect_by_extension

        root = Path(dir_path).resolve()
        cache_path = self._cache_path_for(root)

        # ── Try cache ──────────────────────────────────────────────────
        if use_cache and cache_path.exists():
            try:
                fingerprint = self._compute_source_fingerprint(root)
                with cache_path.open("rb") as fh:
                    cached_fp, graph_data = pickle.load(fh)
                if cached_fp == fingerprint:
                    self.graph = graph_data
                    self._indexed_files = {
                        d.get("file_path", "")
                        for _, d in self.graph.nodes(data=True)
                        if d.get("file_path")
                    }
                    # Re-label taint nodes when loader is present
                    # (cache was built without labels or with different rules)
                    if self._taint_loader is not None:
                        for fpath in sorted(self._indexed_files):
                            lang = detect_by_extension(fpath)
                            if lang:
                                self._label_taint_nodes(fpath, lang)
                    return
            except (pickle.PickleError, EOFError, KeyError, OSError, ValueError, TypeError):
                pass  # Corrupted cache — rebuild

        # ── Build from scratch ─────────────────────────────────────────
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
        import contextlib

        for file_path in sorted(self._call_graph_builder.files):
            with contextlib.suppress(OSError, ValueError, FileNotFoundError):
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
                else:
                    self.graph.nodes[cid]["is_resolved"] = True
                    self.graph.nodes[cid]["cross_file"] = True
                self.graph.add_edge(caller_fid, cid, edge_type=EDGE_CALLS)
                self.graph.add_edge(cid, callee_fid, edge_type=EDGE_CALLS)

        # 5 — Cross-function DATA_FLOW edges: connect caller argument
        # variable-refs to callee parameter nodes so the BFS can trace
        # taint across function boundaries.
        #
        # For every resolved call-site, we find the callee's parameter
        # nodes and create DATA_FLOW edges from the caller's argument
        # variable-refs (at the call line) to those parameter nodes.
        # This is an over-approximation (all args → all params) but
        # guarantees no real taint flow is missed.
        self._add_cross_function_edges()

        # ── Save to cache ──────────────────────────────────────────────
        if use_cache:
            try:
                fingerprint = self._compute_source_fingerprint(root)
                with cache_path.open("wb") as fh:
                    pickle.dump((fingerprint, self.graph), fh, protocol=pickle.HIGHEST_PROTOCOL)
            except (pickle.PickleError, OSError):
                pass  # best-effort — build succeeded, cache is optional

    def _add_cross_function_edges(self) -> None:
        """Create DATA_FLOW edges from call-site argument variable-refs
        to the callee function's parameter nodes.

        Also creates edges from callee return-style assignments back to
        the caller's assignment at the call-site line (if any), enabling
        round-trip taint tracking through calls.

        Uses pre-built indexes to avoid O(N²) nested scans on large projects.
        """
        # ── Pre-build indexes (single pass over all nodes) ──────────────
        # (file_path, func_name) → function node id (local)
        func_index: dict[tuple[str, str], str] = {}
        # func_name → function node id (cross-file, last-write wins)
        func_by_name: dict[str, str] = {}
        # (file_path, enclosing_function) → list of parameter node ids
        param_index: dict[tuple[str, str], list[str]] = {}
        # (file_path, enclosing_function, line) → list of variable_ref node ids
        varref_index: dict[tuple[str, str, int], list[str]] = {}
        # (file_path, enclosing_function, line) → list of assignment node ids
        assign_index: dict[tuple[str, str, int], list[str]] = {}

        for nid, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", "")
            fp = data.get("file_path", "")
            ef = data.get("enclosing_function", "")
            name = data.get("name", "")

            if ntype == NODE_FUNCTION:
                if fp and name:
                    func_index[(fp, name)] = nid
                    func_by_name[name] = nid

            elif ntype == NODE_PARAMETER:
                if fp and ef:
                    param_index.setdefault((fp, ef), []).append(nid)

            elif ntype == NODE_VARIABLE_REF:
                loc = data.get("location", "")
                line = _parse_line(loc)
                if line is not None and fp and ef:
                    varref_index.setdefault((fp, ef, line), []).append(nid)

            elif ntype == NODE_ASSIGNMENT:
                loc = data.get("location", "")
                line = _parse_line(loc)
                if line is not None and fp and ef:
                    assign_index.setdefault((fp, ef, line), []).append(nid)

        # ── Resolve each call-site using the indexes ─────────────────────
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") != NODE_CALL_SITE:
                continue
            if not data.get("is_resolved"):
                continue
            callee_name = data.get("callee", "")
            caller_name = data.get("caller", "")
            call_file = data.get("file_path", "")
            call_line = data.get("line", 0)

            # Find the callee function
            if data.get("cross_file"):
                callee_fid = func_by_name.get(callee_name)
            else:
                callee_fid = func_index.get((call_file, callee_name))

            if callee_fid is None:
                continue

            # Callee parameter nodes (from any file for cross-file calls)
            param_nodes: list[str] = []
            if data.get("cross_file"):
                # Search across all indexed files
                for (_fp, _ef), pids in param_index.items():
                    if _ef == callee_name:
                        param_nodes.extend(pids)
            else:
                param_nodes = param_index.get((call_file, callee_name), [])

            if not param_nodes:
                continue

            # Caller variable-refs at the call line
            caller_var_refs = varref_index.get((call_file, caller_name, call_line), [])

            if not caller_var_refs:
                continue

            # ── Positional arg→param matching ──────────────────────
            # When call_args were extracted during add_file(), use them
            # for precise positional matching (arg_i → param_i).
            # Fall back to all-to-all otherwise.
            call_args: list[str] = data.get("call_args", [])
            # Sort params by param_index so param_nodes[i] is the i-th param
            sorted_params = sorted(
                param_nodes,
                key=lambda pid: self.graph.nodes[pid].get("param_index", 0),
            )
            # Build var_name → var_ref node id lookup (first-write wins)
            varref_by_name: dict[str, str] = {}
            for vid in caller_var_refs:
                vname = self.graph.nodes[vid].get("var_name", "")
                if vname and vname not in varref_by_name:
                    varref_by_name[vname] = vid

            did_positional = False
            if call_args and 0 < len(call_args) <= len(sorted_params):
                for i, arg_text in enumerate(call_args):
                    if i >= len(sorted_params):
                        break
                    matched_vid = varref_by_name.get(arg_text)
                    if matched_vid is not None:
                        self.graph.add_edge(
                            matched_vid,
                            sorted_params[i],
                            edge_type=EDGE_DATA_FLOW,
                        )
                        did_positional = True

            # Fall back to all-to-all if positional matching didn't fire
            if not did_positional:
                for arg_vid in caller_var_refs:
                    for param_nid in param_nodes:
                        self.graph.add_edge(
                            arg_vid,
                            param_nid,
                            edge_type=EDGE_DATA_FLOW,
                        )

            # DATA_FLOW edges through the call_site node itself:
            #   var_ref → call_site → callee_function → param
            for arg_vid in caller_var_refs:
                self.graph.add_edge(arg_vid, nid, edge_type=EDGE_DATA_FLOW)
                self.graph.add_edge(nid, callee_fid, edge_type=EDGE_DATA_FLOW)

            # Return value: connect callee_function → caller's assignment
            # at the call line (approximates "callee return → caller result")
            caller_assigns = assign_index.get((call_file, caller_name, call_line), [])
            for a_nid in caller_assigns:
                self.graph.add_edge(callee_fid, a_nid, edge_type=EDGE_DATA_FLOW)

        # ── Also connect callee_function directly to its parameter nodes ─
        # via DATA_FLOW edges, so BFS can traverse:
        #   caller_call_site → callee_function → callee_param
        # (already done in add_file() for each function, but add_directory
        #  may add cross-file functions that were added via add_file()
        #  earlier; this double-check guarantees the edges exist.)
        for (_fp, _ef), pids in param_index.items():
            fid = func_index.get((_fp, _ef))
            if fid is None:
                continue
            for pid in pids:
                if not any(
                    d.get("edge_type") == EDGE_DATA_FLOW
                    for d in self.graph.get_edge_data(fid, pid).values()
                ):
                    self.graph.add_edge(fid, pid, edge_type=EDGE_DATA_FLOW)

    # ── Control-flow graph ────────────────────────────────────────────────

    def _build_cfg(
        self,
        tree: object,
        fn_tree_nodes: dict[str, object],
        provider: object,
        path: str,
    ) -> None:
        """Build the CFG for each function and add nodes/edges to the graph.

        Creates ``NODE_BASIC_BLOCK`` nodes and ``EDGE_CTRL_FLOW`` edges,
        plus ``EDGE_DATA_FLOW`` edges from each function node to its entry
        block to keep the graph connected for BFS traversal.
        """
        if not fn_tree_nodes:
            return

        from hyqagent.cpg.cfg import CFGBuilder as _CFGBuilder

        cfg = _CFGBuilder(provider)

        for fn_key, tree_node in fn_tree_nodes.items():
            # fn_key is "funcName$startLine" (BUG 30 overload fix) —
            # strip the line suffix to get the bare function name for
            # graph node lookup (NODE_FUNCTION stores bare names).
            fn_name = fn_key.rsplit("$", 1)[0]
            fid = self._find_func_node_id(path, fn_name)
            if fid is None:
                continue

            blocks, edges = cfg.build_cfg(tree, tree_node, path)  # type: ignore[arg-type]

            for block in blocks:
                self.graph.add_node(
                    block.block_id,
                    node_type=NODE_BASIC_BLOCK,
                    file_path=block.file_path,
                    enclosing_function=block.enclosing_function,
                    start_line=block.start_line,
                    end_line=block.end_line,
                    statements=block.statements,
                    block_type=block.block_type,
                )

                # DATA_FLOW edge: function → entry block (connectivity)
                if block.block_type == "entry":
                    self.graph.add_edge(fid, block.block_id, edge_type=EDGE_DATA_FLOW)

            for edge in edges:
                self.graph.add_edge(
                    edge.source_id,
                    edge.target_id,
                    edge_type=EDGE_CTRL_FLOW,
                    ctrl_type=edge.kind,
                )

    @staticmethod
    def _resolve_bare_name(
        file_path: str,
        bare_name: str,
        func_nodes: dict[str, str],
        func_start_lines: dict[str, int],
        _fkey: object,
    ) -> str | None:
        """Resolve a bare function name to a NODE_FUNCTION id.

        Uses the last-wins start-line index (intra-file only).  For
        overloaded methods the last one wins, which is acceptable for
        intra-file CALLS edges because the call graph already determined
        *which* overload is called.
        """
        line = func_start_lines.get(bare_name)
        if line is not None:
            key = _fkey(bare_name, line)  # type: ignore[operator]
            return func_nodes.get(key)
        return None

    def _find_func_node_id(self, file_path: str, fn_name: str) -> str | None:
        """Return the graph node ID for a function by file + name."""
        for nid, data in self.graph.nodes(data=True):
            if (
                data.get("node_type") == NODE_FUNCTION
                and data.get("file_path") == file_path
                and data.get("name") == fn_name
            ):
                return nid
        return None

    # ── Graph properties ─────────────────────────────────────────────────

    def _add_rhs_to_lhs_edges(self, file_path: str) -> None:
        """Create DATA_FLOW edges from variable-refs on a line to the
        assignment on the same line whose RHS uses them.

        For a statement like ``list = jdbc.queryForList(sql, map)``,
        this adds edges::

            variable_ref(sql@L)  ──DATA_FLOW──▶ assignment(list@L)
            variable_ref(map@L)  ──DATA_FLOW──▶ assignment(list@L)

        which bridges the gap between the ``sql`` taint chain and the
        ``list`` sink assignment.  Without this step the BFS can follow
        ``sql`` all the way to the sink *line* but never reach the sink
        *node* because variable-ref nodes carry no source text for
        pattern matching.
        """
        # Collect assignments by line
        assignments_by_line: dict[str, list[str]] = {}
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") != NODE_ASSIGNMENT:
                continue
            fp = data.get("file_path", "")
            if fp != file_path:
                continue
            loc = data.get("location", "")
            assignments_by_line.setdefault(loc, []).append(nid)

        # Collect variable-refs by line
        var_refs_by_line: dict[str, list[str]] = {}
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") != NODE_VARIABLE_REF:
                continue
            fp = data.get("file_path", "")
            if fp != file_path:
                continue
            loc = data.get("location", "")
            var_refs_by_line.setdefault(loc, []).append(nid)

        # For each line that has both assignments and variable-refs,
        # add edges from each variable-ref to each assignment whose
        # target variable differs from the var-ref (a variable doesn't
        # "flow into" its own definition — that's already covered by
        # the def-use chain).
        for loc, assignment_ids in assignments_by_line.items():
            var_ref_ids = var_refs_by_line.get(loc, [])
            if not var_ref_ids:
                continue
            for aid in assignment_ids:
                a_var = self.graph.nodes[aid].get("var_name", "")
                for vid in var_ref_ids:
                    v_var = self.graph.nodes[vid].get("var_name", "")
                    if v_var != a_var:
                        self.graph.add_edge(
                            vid,
                            aid,
                            edge_type=EDGE_DATA_FLOW,
                        )

    # ── Taint node labeling ────────────────────────────────────────────────

    def _label_taint_nodes(self, file_path: str, language: str) -> None:
        """Tag nodes with taint source / sink categories.

        Processes ``NODE_ASSIGNMENT``, ``NODE_CALL_SITE``, and
        ``NODE_PARAMETER`` nodes.

        Sets three attributes on each labeled node:

        * ``taint_source`` — comma-separated *source* categories
        * ``taint_sink``   — comma-separated *sink* categories
        * ``taint_category`` — combined (for backward compatibility)

        Source check takes priority: if a node matches any source
        pattern its sink patterns are NOT evaluated (a node cannot
        be both source and sink).

        A single node can match patterns from multiple categories
        (e.g. ``getInputStream()`` is both an XXE and SSRF source).
        """
        if self._taint_loader is None:
            return

        # Pre-build function-signature lookup so NODE_PARAMETER nodes can
        # look up their enclosing function's declaration text (which carries
        # annotation-based source markers like ``@RequestParam`` in Spring).
        #
        # Only the function SIGNATURE (before the opening brace) is used.
        # Prefer the full ``signature`` attribute (stored at build time);
        # fall back to deriving it from ``source`` for graphs loaded from a
        # cache written before the ``signature`` attribute existed.
        func_signature_by_name: dict[str, str] = {}
        for _nid, data in self.graph.nodes(data=True):
            if data.get("file_path") == file_path and data.get("node_type") == NODE_FUNCTION:
                name = data.get("name", "")
                sig = data.get("signature", "")
                if not sig:
                    src = data.get("source", "")
                    brace_idx = src.find("{")
                    sig = src[:brace_idx] if brace_idx != -1 else src
                if name and sig:
                    func_signature_by_name[name] = sig

        for _nid, data in self.graph.nodes(data=True):
            if data.get("file_path") != file_path:
                continue

            node_type = data.get("node_type", "")
            source_text = ""

            if node_type == NODE_ASSIGNMENT:
                source_text = data.get("source", "")
            elif node_type == NODE_CALL_SITE:
                # Bare function calls (e.g. ``cursor.execute(sql)``) are
                # expression statements, not assignments.  Use the
                # ``expression`` attribute which stores the call text.
                source_text = data.get("expression", "")
            elif node_type == NODE_PARAMETER:
                # Java / Spring parameters (``@RequestParam String x``) carry
                # source annotations.  Classify THIS parameter's own
                # annotation (not the whole signature) into a precise
                # category — this is what stops one ``@PathVariable`` from
                # tagging every sibling parameter, and stops the ~18-category
                # explosion that comes from substring-matching the signature.
                encl_func = data.get("enclosing_function", "")
                signature = func_signature_by_name.get(encl_func, "")
                if not signature:
                    continue
                param_index = data.get("param_index", 0)
                param_cats = _classify_parameter_source(signature, param_index)
                if param_cats:
                    data["taint_source"] = ",".join(param_cats)
                    data["taint_category"] = ",".join(param_cats)
                continue
            else:
                continue

            if not source_text:
                continue

            # Source check takes priority — a node is EITHER source OR sink.
            src_cats = self._taint_loader.match_all_sources(language, source_text)
            if src_cats:
                data["taint_source"] = ",".join(src_cats)
                data["taint_category"] = ",".join(src_cats)
                continue

            sink_cats = self._taint_loader.match_all_sinks(language, source_text)
            if sink_cats:
                # Sink exclusion whitelist: generic utility methods
                # (``toString()``, ``I18nUtil.getString``, exception
                # ``getMessage()`` …) contain sink substrings but are not
                # injection points — drop them before labeling.
                excludes = getattr(self._taint_loader, "sink_excludes", None)
                exclude_patterns = excludes(language) if callable(excludes) else []
                if exclude_patterns and _matches_sink_exclude(source_text, exclude_patterns):
                    continue
                data["taint_sink"] = ",".join(sink_cats)
                data["taint_category"] = ",".join(sink_cats)

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
