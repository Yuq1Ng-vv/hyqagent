"""tests/test_cpg/test_performance.py — Performance baselines.

These benchmarks establish baselines for common operations.  They are
**skipped by default** in CI (via ``--benchmark-disable`` in pyproject.toml).
Run locally with::

    uv run pytest tests/test_cpg/test_performance.py --benchmark-only
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.callgraph_builder import CallGraphBuilder
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.traversal import Traverser

# ── Path to a real large file (optional — skipped if not found) ────────────

_MYPY_CHECKER = Path(
    "/root/hyqagent/.venv/lib/python3.12/site-packages/mypy/checker.py"
)


def _make_large_python_file(n_funcs: int = 200, n_calls: int = 50) -> str:
    """Generate a synthetic medium-size Python file."""
    lines = []
    # 200 helper functions
    for i in range(n_funcs):
        lines.append(f"def helper_{i}(x):")
        lines.append(f"    return x * {i}")
        lines.append("")
    # One big function that calls half of them
    lines.append("def orchestrator(x):")
    for i in range(n_calls):
        lines.append(f"    r_{i} = helper_{i % n_funcs}(x)")
    lines.append("    return sum(locals().values())")
    lines.append("")
    return "\n".join(lines)


def _make_project(n_files: int = 10) -> str:
    """Generate a small multi-file project."""
    tmp = tempfile.mkdtemp(prefix="hyq_perf_")
    for i in range(n_files):
        path = Path(tmp) / f"module_{i}.py"
        # Each file calls a function from at least one other file
        callee = (i + 1) % n_files
        path.write_text(
            f"from module_{callee} import helper_{callee}\n"
            f"def helper_{i}():\n"
            f"    return helper_{callee}()\n"
        )
    return tmp


# ════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def large_code() -> str:
    return _make_large_python_file()


@pytest.fixture(scope="module")
def deep_code() -> str:
    code = "def deep():\n"
    for i in range(500):
        code += "  " * (i + 1) + "if True:\n"
    code += "  " * 501 + "pass\n"
    return code


class TestParsePerformance:
    """Benchmarks for parser.parse_code()."""

    @pytest.mark.benchmark(min_rounds=3)
    def test_parse_large_synthetic(self, parser: Parser, large_code: str, benchmark) -> None:  # type: ignore[no-untyped-def]
        result = benchmark(parser.parse_code, large_code, "python")
        assert result.root_node.type == "module"

    def test_parse_large_synthetic_slower_than_100ms(self, parser: Parser, large_code: str) -> None:
        """Regression check: large synthetic file should parse quickly."""
        import time

        start = time.perf_counter()
        parser.parse_code(large_code, "python")
        elapsed = time.perf_counter() - start
        # 200 funcs * 50 calls should be well under 100ms
        assert elapsed < 0.1, f"Parse took {elapsed*1000:.0f}ms, expected < 100ms"

    @pytest.mark.skipif(not _MYPY_CHECKER.exists(), reason="mypy not installed")
    @pytest.mark.benchmark(min_rounds=3)
    def test_parse_mypy_checker(self, parser: Parser, benchmark) -> None:  # type: ignore[no-untyped-def]
        code = _MYPY_CHECKER.read_text()
        result = benchmark(parser.parse_code, code, "python")
        assert result.root_node.type == "module"

    @pytest.mark.skipif(not _MYPY_CHECKER.exists(), reason="mypy not installed")
    def test_parse_mypy_checker_slower_than_500ms(self, parser: Parser) -> None:
        """Regression check: ~10K line file should parse in < 500ms."""
        import time

        code = _MYPY_CHECKER.read_text()
        start = time.perf_counter()
        parser.parse_code(code, "python")
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"Parse took {elapsed*1000:.0f}ms, expected < 500ms"


class TestTraversePerformance:
    """Benchmarks for Traverser."""

    @pytest.mark.benchmark(min_rounds=3)
    def test_traverse_deep_nesting(self, parser: Parser, deep_code: str, benchmark) -> None:  # type: ignore[no-untyped-def]
        tree = parser.parse_code(deep_code, "python")

        def walk() -> int:
            return sum(1 for _ in Traverser(tree).traverse())

        count = benchmark(walk)
        assert count > 0

    def test_traverse_deep_nesting_under_50ms(self, parser: Parser, deep_code: str) -> None:
        """500-deep if blocks should not cause stack overflow or slowness."""
        import time

        tree = parser.parse_code(deep_code, "python")
        start = time.perf_counter()
        _ = sum(1 for _ in Traverser(tree).traverse())
        elapsed = time.perf_counter() - start
        assert elapsed < 0.05, f"Deep traversal took {elapsed*1000:.0f}ms, expected < 50ms"


class TestCallGraphPerformance:
    """Benchmarks for SingleFileCallGraph."""

    @pytest.mark.benchmark(min_rounds=3)
    def test_callgraph_large_synthetic(self, parser: Parser, large_code: str, benchmark) -> None:  # type: ignore[no-untyped-def]
        def build() -> SingleFileCallGraph:
            cg = SingleFileCallGraph(parser)
            cg.build_from_tree(parser.parse_code(large_code, "python"), "python")
            return cg

        cg = benchmark(build)
        assert len(cg.function_names) > 0


class TestBuilderPerformance:
    """Benchmarks for CallGraphBuilder (cross-file)."""

    @pytest.mark.benchmark(min_rounds=3)
    def test_cross_file_small_project(self, parser: Parser, benchmark) -> None:  # type: ignore[no-untyped-def]
        tmp = _make_project(n_files=15)

        def build() -> list:
            b = CallGraphBuilder(parser)
            b.add_directory(tmp)
            return b.build_calls()

        result = benchmark(build)
        assert isinstance(result, list)
