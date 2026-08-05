"""tests/test_cpg/test_callgraph_builder.py — Tests for CallGraphBuilder."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import CallEdge
from hyqagent.cpg.callgraph_builder import CallGraphBuilder
from hyqagent.cpg.parser import Parser

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def multi_file_project() -> str:
    """Create a temporary multi-file Python project."""
    tmp = tempfile.mkdtemp(prefix="hyq_test_")

    def write(path: str, content: str) -> None:
        full = os.path.join(tmp, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)

    write(
        "utils.py",
        """def helper(x):
    return x * 2

def other():
    return helper(1)
""",
    )
    write(
        "models.py",
        """class User:
    def __init__(self, name):
        self.name = name

def create_user(name):
    return User(name)
""",
    )
    write(
        "main.py",
        """from utils import helper
from models import create_user

def run():
    result = helper(10)
    user = create_user("alice")
    print(result)

def local():
    return run()
""",
    )
    write("subpkg/__init__.py", "")
    write(
        "subpkg/module.py",
        """from ..utils import helper, other

def process(x):
    val = helper(x)
    return other(val)
""",
    )
    return tmp


@pytest.fixture(scope="module")
def builder(parser: Parser, multi_file_project: str) -> CallGraphBuilder:
    b = CallGraphBuilder(parser)
    b.add_directory(multi_file_project)
    return b


# ════════════════════════════════════════════════════════════════════════
#  File indexing
# ════════════════════════════════════════════════════════════════════════


class TestFileIndexing:
    """Tests for add_file and add_directory."""

    def test_add_directory_finds_python_files(
        self, builder: CallGraphBuilder
    ) -> None:
        assert len(builder.files) >= 3  # main, models, utils at minimum

    def test_all_files_are_python(
        self, builder: CallGraphBuilder
    ) -> None:
        for fp in builder.files:
            assert fp.endswith(".py")

    def test_add_file_skips_duplicates(
        self, builder: CallGraphBuilder, multi_file_project: str
    ) -> None:
        """Adding the same file twice is a no-op."""
        before = len(builder.files)
        main_py = os.path.join(multi_file_project, "main.py")
        builder.add_file(main_py)
        assert len(builder.files) == before

    def test_functions_indexed(
        self, builder: CallGraphBuilder
    ) -> None:
        func_map = builder.all_functions
        all_names = set()
        for names in func_map.values():
            all_names.update(names)
        assert "helper" in all_names
        assert "create_user" in all_names
        assert "run" in all_names
        assert "process" in all_names


# ════════════════════════════════════════════════════════════════════════
#  Function definition lookup
# ════════════════════════════════════════════════════════════════════════


class TestFindDefinition:
    """Tests for find_definition."""

    def test_find_known_function(
        self, builder: CallGraphBuilder
    ) -> None:
        path = builder.find_definition("helper")
        assert path is not None
        assert "utils.py" in path

    def test_find_class_method(
        self, builder: CallGraphBuilder
    ) -> None:
        path = builder.find_definition("__init__")
        assert path is not None
        assert "models.py" in path

    def test_find_nonexistent(
        self, builder: CallGraphBuilder
    ) -> None:
        assert builder.find_definition("no_such_function") is None


# ════════════════════════════════════════════════════════════════════════
#  Cross-file calls
# ════════════════════════════════════════════════════════════════════════


class TestCrossFileCalls:
    """Tests for build_calls cross-file edges."""

    @pytest.fixture(scope="module")
    def cross_edges(self, builder: CallGraphBuilder) -> list[CallEdge]:
        return builder.build_calls()

    @pytest.fixture(scope="module")
    def edge_map(
        self, cross_edges: list[CallEdge]
    ) -> dict[tuple[str, str], CallEdge]:
        return {(e.caller, e.callee): e for e in cross_edges}

    def test_cross_file_helper_from_main(
        self, edge_map: dict[tuple[str, str], CallEdge]
    ) -> None:
        assert ("run", "helper") in edge_map
        edge = edge_map[("run", "helper")]
        assert edge.is_resolved
        assert "main.py" in edge.file_path

    def test_cross_file_create_user_from_main(
        self, edge_map: dict[tuple[str, str], CallEdge]
    ) -> None:
        assert ("run", "create_user") in edge_map

    def test_cross_file_helper_from_subpkg(
        self, edge_map: dict[tuple[str, str], CallEdge]
    ) -> None:
        """Relative import (..utils) in subpkg/module.py."""
        assert ("process", "helper") in edge_map

    def test_cross_file_other_from_subpkg(
        self, edge_map: dict[tuple[str, str], CallEdge]
    ) -> None:
        assert ("process", "other") in edge_map

    def test_intra_file_not_in_cross(
        self, cross_edges: list[CallEdge]
    ) -> None:
        """local() → run() is intra-file — should NOT be in cross edges."""
        for e in cross_edges:
            assert not (e.caller == "local" and e.callee == "run")

    def test_self_call_not_in_cross(
        self, cross_edges: list[CallEdge]
    ) -> None:
        """other() → helper() is intra-file (both in utils.py)."""
        for e in cross_edges:
            assert not (e.caller == "other" and e.callee == "helper")

    def test_builtin_not_in_cross(
        self, cross_edges: list[CallEdge]
    ) -> None:
        """print() should never be resolved cross-file."""
        for e in cross_edges:
            assert e.callee != "print"

    def test_all_cross_edges_resolved(
        self, cross_edges: list[CallEdge]
    ) -> None:
        assert all(e.is_resolved for e in cross_edges)


# ════════════════════════════════════════════════════════════════════════
#  Import resolution
# ════════════════════════════════════════════════════════════════════════


class TestImportResolution:
    """Tests for resolve_imports."""

    def test_relative_import_resolved(
        self, builder: CallGraphBuilder
    ) -> None:
        resolved = builder.resolve_imports()
        # ..utils → utils.py (from subpkg/module.py)
        assert "..utils" in resolved or any(
            v and "utils.py" in v for k, v in resolved.items() if "utils" in k
        )

    def test_absolute_import_resolved(
        self, builder: CallGraphBuilder
    ) -> None:
        resolved = builder.resolve_imports()
        # utils → utils.py (from main.py)
        assert "utils" in resolved

    def test_bare_name_resolved(
        self, builder: CallGraphBuilder
    ) -> None:
        resolved = builder.resolve_imports()
        # helper → utils.py
        assert resolved.get("helper", "").endswith("utils.py")


# ════════════════════════════════════════════════════════════════════════
#  Empty / edge cases
# ════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Edge cases for CallGraphBuilder."""

    def test_empty_builder(self, parser: Parser) -> None:
        b = CallGraphBuilder(parser)
        assert len(b.files) == 0
        assert b.build_calls() == []
        assert b.resolve_imports() == {}

    def test_single_file_no_imports(self, parser: Parser) -> None:
        b = CallGraphBuilder(parser)
        b.add_file(FIXTURES / "callgraph.py")
        assert len(b.files) == 1
        # Single file with no other files — no cross-file edges
        cross = b.build_calls()
        assert all(e.is_resolved for e in cross)

    def test_add_file_not_found(self, parser: Parser) -> None:
        b = CallGraphBuilder(parser)
        with pytest.raises(FileNotFoundError):
            b.add_file("/nonexistent/file.py")
