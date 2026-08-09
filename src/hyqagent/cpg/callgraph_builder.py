"""cpg/callgraph_builder.py — Cross-file call graph builder.

Extends :class:`SingleFileCallGraph` to span multiple files.  Parses an
entire project directory, resolves imports between files, and produces
cross-file caller→callee edges.

See DESIGN-IMPLEMENTATION.md Section 2.2 for the interface specification.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from hyqagent.cpg.callgraph import CallEdge, SingleFileCallGraph
from hyqagent.cpg.languages import detect_by_extension
from hyqagent.cpg.parser import Parser


class CallGraphBuilder:
    """Build a cross-file call graph for a project.

    Usage::

        parser = Parser()
        builder = CallGraphBuilder(parser)
        builder.add_directory("./myapp")
        builder.resolve_imports()
        cross_edges = builder.build_calls()

        for edge in cross_edges:
            print(f"[{edge.file_path}] {edge.caller} -> {edge.callee}")
    """

    # Extensions we know how to parse (populated from provider registry)
    _KNOWN_EXTS: ClassVar[set[str]]

    def __init__(self, parser: Parser) -> None:
        self._parser = parser
        self._graphs: dict[str, SingleFileCallGraph] = {}
        self._imports: dict[str, list[_ResolvedImport]] = {}
        self._all_functions: dict[str, list[str]] = {}  # func_name → [file_paths]
        self._file_funcs: dict[str, set[str]] = {}  # file_path → {func_names}

    # ── File management ─────────────────────────────────────────────────

    def add_file(self, file_path: str | Path) -> None:
        """Parse a single file and index its functions and imports.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            ValueError: If the file's language is unsupported.

        """
        path = str(Path(file_path).resolve())
        if path in self._graphs:
            return

        # Parse once, reuse tree for both call graph and imports
        tree = self._parser.parse_file(path)
        language = self._parser.get_language(tree)

        cg = SingleFileCallGraph(self._parser)
        cg.build_from_tree(tree, language, path)
        self._graphs[path] = cg

        # Index functions: which file defines each function
        self._file_funcs[path] = cg.function_names
        for name in cg.function_names:
            self._all_functions.setdefault(name, []).append(path)
        # BUG 9: Also index qualified names (ClassName.methodName) for Java
        for qname in cg.qualified_function_names:
            self._all_functions.setdefault(qname, []).append(path)

        # Extract imports for later resolution (reuse same tree)
        imports = self._parser.extract_imports(tree, language)
        self._imports[path] = [
            _ResolvedImport(
                module=imp.module,
                names=imp.names,
                is_relative=imp.is_relative,
                file_path=path,
            )
            for imp in imports
        ]

        # Extract field-type names as virtual imports.  Frameworks like
        # Spring inject dependencies without explicit imports, but the
        # field type (e.g. `private ReportParser reportParser`) tells
        # us exactly which class is being used.  We add these type names
        # so that `resolve_imports` can connect them via the file_index.
        virtual_types = self._extract_field_types(tree, language)
        for vt in virtual_types:
            # Only add if not already covered by a real import
            already_imported = any(vt in imp.names for imp in imports)
            if not already_imported:
                self._imports[path].append(
                    _ResolvedImport(
                        module=vt,
                        names=[vt],
                        is_relative=False,
                        file_path=path,
                    )
                )

    def add_directory(self, dir_path: str | Path) -> None:
        """Recursively add all source files in *dir_path*.

        Only files whose extension matches a registered language provider
        are included.  Hidden directories and ``__pycache__`` are skipped.
        """
        root = Path(dir_path).resolve()
        for entry in sorted(root.rglob("*")):
            if not entry.is_file():
                continue
            # Skip hidden dirs and __pycache__
            if any(p.startswith(".") or p == "__pycache__" for p in entry.parts):
                continue
            lang = detect_by_extension(str(entry))
            if lang is not None:
                self.add_file(str(entry))

    # ── Import resolution ───────────────────────────────────────────────

    def resolve_imports(self) -> dict[str, str]:
        """Resolve imports across all added files.

        Returns a mapping ``{qualified_name: file_path}`` for all
        successfully-resolved imports.  Currently handles:

        * **Relative imports** (``from .module import X``) — resolved
          relative to the importing file's directory.
        * **Direct name matches** (``from mymodule import X`` where
          ``mymodule.py`` exists in the project).

        Third-party and standard-library imports are left unresolved.

        """
        # Pre-build a filename → [paths] index for collision-aware lookup.
        # Multiple directories may contain e.g. `utils.py` — we collect
        # all candidates and let `_resolve_module_path` pick the best one.
        file_index: dict[str, list[str]] = {}
        for fp in self._graphs:
            stem = Path(fp).stem
            file_index.setdefault(stem, []).append(fp)

        resolved: dict[str, str] = {}

        for file_path, imp_list in self._imports.items():
            base_dir = str(Path(file_path).parent)

            for imp in imp_list:
                if not imp.module:
                    continue

                target = self._resolve_module_path(
                    imp.module,
                    base_dir,
                    file_index,
                )
                if target is not None and target in self._graphs:
                    # Map each imported name to the target file
                    for name in imp.names:
                        if name == "*":
                            # Wildcard — resolve all exports from target
                            continue
                        qualified = f"{imp.module}.{name}"
                        resolved[qualified] = target
                        # Also register bare name for direct import style
                        resolved[name] = target

                    # Also resolve the module itself
                    resolved[imp.module] = target

        return resolved

    # ── Cross-file call resolution ──────────────────────────────────────

    def build_calls(self) -> list[CallEdge]:
        """Build cross-file call edges.

        For each file's unresolved calls, checks whether the callee is
        defined in another file that the caller imports.  Returns a flat
        list of all cross-file resolved call edges.

        """
        resolved_imports = self.resolve_imports()
        cross_edges: list[CallEdge] = []

        for file_path, cg in self._graphs.items():
            imports_for_file = self._imports.get(file_path, [])
            imported_modules = {imp.module for imp in imports_for_file}

            for uc in cg.unresolved:
                callee = uc.callee

                # Check if callee is defined in another indexed file
                candidates = self._all_functions.get(callee, [])
                if not candidates:
                    continue

                resolved_target: str | None = None
                for target_file in candidates:
                    if target_file == file_path:
                        continue  # already resolved as intra-file

                    # Same-directory always reachable for Java (same-package
                    # visibility).  Python and JS require explicit imports
                    # even for same-directory files, so we scope this to
                    # Java only.
                    same_dir = Path(file_path).parent == Path(
                        target_file
                    ).parent and file_path.endswith(".java")

                    if same_dir or self._is_reachable(
                        file_path, target_file, imported_modules, resolved_imports
                    ):
                        resolved_target = target_file
                        break  # first reachable candidate wins

                if resolved_target is None:
                    continue

                cross_edges.append(
                    CallEdge(
                        caller=uc.caller,
                        callee=callee,
                        call_line=uc.call_line,
                        full_expression=uc.full_expression,
                        is_resolved=True,
                        is_method_call=uc.is_method_call,
                        file_path=file_path,
                    )
                )

        return cross_edges

    # ── Query helpers ───────────────────────────────────────────────────

    @property
    def files(self) -> set[str]:
        """All file paths currently indexed."""
        return set(self._graphs.keys())

    @property
    def all_functions(self) -> dict[str, list[str]]:
        """Mapping ``{file_path: [function_names]}`` for all indexed files."""
        return {fp: sorted(fns) for fp, fns in self._file_funcs.items()}

    @property
    def function_index(self) -> dict[str, list[str]]:
        """Mapping ``{func_name: [file_paths]}`` (all definitions)."""
        return dict(self._all_functions)

    def find_definition(self, func_name: str) -> str | None:
        """Return the file path where *func_name* is defined, or None.

        When multiple files define a function with the same name, the
        first one indexed is returned.  Use :meth:`find_all_definitions`
        to get every candidate.
        """
        paths = self._all_functions.get(func_name, [])
        return paths[0] if paths else None

    def find_all_definitions(self, func_name: str) -> list[str]:
        """Return ALL file paths where *func_name* is defined."""
        return list(self._all_functions.get(func_name, []))

    # ── Internal helpers ────────────────────────────────────────────────

    # Extensions we try for JS/TS relative imports and absolute module paths
    _SRC_EXTS = (".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")

    @staticmethod
    def _extract_field_types(tree: object, language: str) -> list[str]:
        """Extract type names from field/variable declarations.

        Captures the class name from patterns like
        ``private ReportParser reportParser;`` so that
        framework-injected dependencies become reachable
        even when the source file has no explicit import.

        Filters out primitive types and common stdlib container
        names that would never resolve to a project file.
        """
        from hyqagent.cpg.traversal import Traverser

        _PRIMITIVES = {
            "int",
            "long",
            "float",
            "double",
            "boolean",
            "byte",
            "short",
            "char",
            "void",
            "String",
            "Integer",
            "Long",
            "Float",
            "Double",
            "Boolean",
            "Byte",
            "Short",
        }
        _CONTAINERS = {
            "List",
            "Map",
            "Set",
            "Collection",
            "ArrayList",
            "HashMap",
            "HashSet",
            "Optional",
            "Array",
            "Object",
            "HttpServletRequest",
            "HttpServletResponse",
            "ServletRequest",
            "ServletResponse",
            "ServletException",
            "IOException",
        }
        skip = _PRIMITIVES | _CONTAINERS

        types: list[str] = []
        seen: set[str] = set()

        for node in Traverser(tree).traverse():
            ntype = node.type

            # ── Java field declarations ────────────────────────────
            if ntype == "field_declaration" and language == "java":
                type_node = node.child_by_field_name("type")
                if type_node is not None:
                    # Collect every `type_identifier` descendant
                    # (handles generics: List<ReportProvider> →
                    #  we collect ReportProvider)
                    self_nodes = [type_node]
                    while self_nodes:
                        cur = self_nodes.pop()
                        if cur.type == "type_identifier":
                            name = cur.text.decode()
                            if name not in skip and name not in seen:
                                types.append(name)
                                seen.add(name)
                        for child in cur.children:
                            self_nodes.append(child)

            # ── Python typed assignments ───────────────────────────
            elif (ntype == "assignment" and language == "python") or (
                ntype
                in (
                    "field_definition",
                    "public_field_definition",
                    "variable_declarator",
                )
                and language in ("javascript", "typescript")
            ):
                type_node = node.child_by_field_name("type")
                if type_node is not None:
                    name = type_node.text.decode()
                    if name not in skip and name not in seen:
                        types.append(name)
                        seen.add(name)

        return types

    @staticmethod
    def _resolve_module_path(
        module: str,
        base_dir: str,
        file_index: dict[str, list[str]],
    ) -> str | None:
        """Convert a module name to a file path.

        Python
            ``".utils"`` → ``base_dir/../utils.py``
            ``"app.models"`` → ``root/app/models.py``

        Java
            ``"com.example.Foo"`` → ``root/com/example/Foo.java``

        JavaScript / TypeScript
            ``"./utils"`` → ``base_dir/utils.js`` (also tries .ts/.mjs/…)
            ``"../lib/foo"`` → ``base_dir/../lib/foo.js``
        """
        # ── JavaScript-style relative imports (./foo  or  ../foo) ─────
        if module.startswith("./") or module.startswith("../"):
            parts = module.split("/")
            # Count `..` segments (parent-directory steps)
            up_count = sum(1 for p in parts if p == "..")
            # The rest is everything except `.` and `..` segments
            rest_parts = [p for p in parts if p not in (".", "..")]
            parent = Path(base_dir)
            for _ in range(up_count):
                parent = parent.parent
            rest = "/".join(rest_parts) if rest_parts else ""
            if not rest:
                return None
            # Strip a known extension if present
            rest_no_ext = rest
            for ext in CallGraphBuilder._SRC_EXTS:
                if rest.endswith(ext):
                    rest_no_ext = rest[: -len(ext)]
                    break
            for ext in CallGraphBuilder._SRC_EXTS:
                candidate = parent / (rest_no_ext + ext)
                if candidate.exists():
                    return str(candidate.resolve())
                # Also try index files: ./foo/index.js
                candidate_index = parent / rest_no_ext / ("index" + ext)
                if candidate_index.exists():
                    return str(candidate_index.resolve())
            return None

        # ── Python relative imports (.module  or  ..module) ────────────
        if module.startswith("."):
            dots = len(module) - len(module.lstrip("."))
            rest = module.lstrip(".")
            parent = Path(base_dir)
            for _ in range(dots - 1):
                parent = parent.parent
            if rest:
                target = parent / (rest.replace(".", "/") + ".py")
            else:
                target = parent / "__init__.py"
            return str(target.resolve())

        # ── Absolute module paths ──────────────────────────────────────
        parts = module.split(".")

        # Walk up from base_dir, try *every* source-root
        # so we match the nearest parent directory.
        current = Path(base_dir)
        while current != current.parent:
            for ext in CallGraphBuilder._SRC_EXTS:
                candidate = current / (str(Path(*parts)) + ext)
                if candidate.exists():
                    return str(candidate.resolve())
            # Package init (Python)
            candidate_init = current / str(Path(*parts)) / "__init__.py"
            if candidate_init.exists():
                return str(candidate_init.resolve())
            # Index files (JS/TS package entry)
            for ext in (".js", ".ts", ".mjs"):
                candidate_index = current / str(Path(*parts)) / ("index" + ext)
                if candidate_index.exists():
                    return str(candidate_index.resolve())
            current = current.parent

        # ── Fallback: match by class name / module basename ────────────
        class_name = parts[-1]
        candidates = file_index.get(class_name, [])
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        # Multiple candidates → pick the one whose path best matches
        # the expected package structure (e.g. com/example/Foo.java).
        expected_suffix = str(Path(*parts))
        for fp in candidates:
            if fp.endswith(expected_suffix + Path(fp).suffix) or expected_suffix in fp:
                return fp
        # Tie-break: shortest path (closest to base_dir usually)
        return min(candidates, key=len)

    @staticmethod
    def _is_reachable(
        caller_file: str,
        target_file: str,
        imported_modules: set[str],
        resolved_imports: dict[str, str],
    ) -> bool:
        """Check if *caller_file* can reach *target_file* via imports."""
        # Direct resolution: check if any resolved import points to target
        for qualified, resolved_path in resolved_imports.items():
            if resolved_path == target_file:
                # Check if the caller imports some part of this module
                for mod in imported_modules:
                    if qualified.startswith(mod) or mod == qualified:
                        return True
        return False


# ─── Internal data type ──────────────────────────────────────────────────


class _ResolvedImport:
    """Internal: a single import statement, resolved to a file path."""

    __slots__ = ("file_path", "is_relative", "module", "names")

    def __init__(
        self,
        module: str,
        names: list[str],
        is_relative: bool,
        file_path: str,
    ) -> None:
        self.module = module
        self.names = names
        self.is_relative = is_relative
        self.file_path = file_path
