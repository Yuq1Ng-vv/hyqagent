"""tests/test_cpg/test_cg_builder_edge.py — CallGraphBuilder edge-case tests."""

from __future__ import annotations

import os
import tempfile

import pytest

from hyqagent.cpg.callgraph_builder import CallGraphBuilder
from hyqagent.cpg.parser import Parser


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


def _make_project(files: dict[str, str]) -> str:
    """Create a temporary project directory from a {relpath: content} map."""
    tmp = tempfile.mkdtemp(prefix="hyq_edge_")
    for path, content in files.items():
        full = os.path.join(tmp, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
    return tmp


class TestEmptyProject:
    """Empty or near-empty project directories."""

    def test_empty_directory(self, parser: Parser) -> None:
        tmp = tempfile.mkdtemp()
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        assert len(b.files) == 0
        assert b.build_calls() == []

    def test_directory_with_non_python_files(self, parser: Parser) -> None:
        tmp = _make_project({
            "readme.txt": "hello",
            "data.json": "{}",
            "notes.md": "# notes",
        })
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        assert len(b.files) == 0


class TestAddFileErrors:
    """add_file should raise proper errors for bad inputs."""

    def test_unsupported_extension(self, parser: Parser) -> None:
        with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
            f.write("hello")
            txt_path = f.name
        try:
            b = CallGraphBuilder(parser)
            with pytest.raises(ValueError, match="Cannot detect language"):
                b.add_file(txt_path)
        finally:
            os.unlink(txt_path)

    def test_file_with_parse_errors(self, parser: Parser) -> None:
        """A Python file with syntax errors should not crash add_file."""
        tmp = _make_project({
            "broken.py": "def foo(:\n    ???\n    bar()\n",
        })
        b = CallGraphBuilder(parser)
        # Should not crash — tree-sitter recovers
        b.add_directory(tmp)
        assert len(b.files) == 1


class TestCircularImports:
    """Circular imports should resolve without infinite loops."""

    def test_circular_two_files(self, parser: Parser) -> None:
        tmp = _make_project({
            "a.py": "from b import func_b\ndef func_a():\n    return func_b()\n",
            "b.py": "from a import func_a\ndef func_b():\n    return func_a()\n",
        })
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        cross = b.build_calls()
        # Both directions should resolve
        callee_pairs = {(e.caller, e.callee) for e in cross}
        assert ("func_a", "func_b") in callee_pairs
        assert ("func_b", "func_a") in callee_pairs


class TestDuplicateFunctions:
    """Same function name in multiple files — first-definition-wins."""

    def test_first_definition_wins(self, parser: Parser) -> None:
        tmp = _make_project({
            "x.py": "def dup(): return 1\n",
            "y.py": "def dup(): return 2\n",
            "main.py": "from x import dup\ndef run():\n    return dup()\n",
        })
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        # dup is defined in both x.py and y.py — first added wins
        definition = b.find_definition("dup")
        assert definition is not None
        # main.py's run() → dup should produce a cross edge
        cross = b.build_calls()
        assert any(e.callee == "dup" for e in cross)


class TestImportVariants:
    """Different import styles."""

    def test_single_dot_relative_import(self, parser: Parser) -> None:
        """`from . import sibling` should resolve."""
        tmp = _make_project({
            "pkg/__init__.py": "",
            "pkg/sibling.py": "def helper():\n    return 42\n",
            "pkg/main.py": "from . import sibling\ndef run():\n    return sibling.helper()\n",
        })
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        resolved = b.resolve_imports()
        # .sibling or sibling should resolve
        assert len(resolved) > 0

    def test_wildcard_import_handled(self, parser: Parser) -> None:
        """`from X import *` should not crash resolve_imports."""
        tmp = _make_project({
            "mod.py": "def f(): pass\ndef g(): pass\n",
            "main.py": "from mod import *\ndef run():\n    return f()\n",
        })
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        # Should not crash; wildcard not deeply resolved (known limitation)
        cross = b.build_calls()
        assert isinstance(cross, list)


class TestFileWithoutImports:
    """A file with no imports but cross-file calls — should produce no edges."""

    def test_no_imports_no_cross_edges(self, parser: Parser) -> None:
        tmp = _make_project({
            "lib.py": "def helper():\n    return 1\n",
            "main.py": "def run():\n    return helper()\n",  # no import!
        })
        b = CallGraphBuilder(parser)
        b.add_directory(tmp)
        cross = b.build_calls()
        # helper is not reachable because main.py doesn't import lib
        assert not any(e.callee == "helper" for e in cross)
