"""tests/eval/conftest.py — Shared fixtures for eval tests.

All fixtures are module-scoped to minimise memory pressure
when running 28 parametrized golden cases.

Provides:
- ``parser`` — singleton :class:`Parser` (heavy, loaded once)
- ``taint_loader`` — singleton :class:`TaintRuleLoader` (~3700-line YAML)
- ``goldens`` — all 28 :class:`GoldenCase` objects from the JSON dataset
- ``golden_by_id`` — ``dict[str, GoldenCase]`` lookup helper
- ``case`` — parametrized fixture that yields one :class:`GoldenCase` per test
- ``build_graph_for_case`` — helper to build a CPG for a single fixture
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from hyqagent.cpg.parser import Parser
from hyqagent.cpg.taint_loader import TaintRuleLoader
from tests.eval.golden_loader import GoldenCase, GoldenDatasetLoader

if TYPE_CHECKING:
    from hyqagent.cpg.graph import CPGGraphBuilder


# ── Heavy shared fixtures (module-scoped) ──────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    """Module-scoped Parser — shared across all eval tests in the module."""
    return Parser()


@pytest.fixture(scope="module")
def taint_loader() -> TaintRuleLoader:
    """Module-scoped TaintRuleLoader — loads the 3700-line YAML once."""
    return TaintRuleLoader()


@pytest.fixture(scope="module")
def goldens() -> list[GoldenCase]:
    """Module-scoped golden dataset — load once, serve all parametrized tests."""
    loader = GoldenDatasetLoader()
    return loader.load()


@pytest.fixture(scope="module")
def golden_by_id(goldens: list[GoldenCase]) -> dict[str, GoldenCase]:
    """GoldenCase lookup by ID for parametrized test access."""
    return {c.id: c for c in goldens}


def _golden_case_ids() -> list[str]:
    """Load case IDs from the golden dataset JSON (called at collection time)."""
    loader = GoldenDatasetLoader()
    return [c.id for c in loader.load()]


@pytest.fixture(params=_golden_case_ids())
def case(request: pytest.FixtureRequest, golden_by_id: dict[str, GoldenCase]) -> GoldenCase:
    """Parametrized fixture — yields every :class:`GoldenCase` in the dataset.

    Each test that uses this fixture runs once per golden case (28x).
    """
    case_id: str = request.param
    c = golden_by_id.get(case_id)
    if c is None:
        pytest.fail(f"Golden case '{case_id}' not found in dataset")
    return c


# ── Helpers for test code ──────────────────────────────────────────────────


def build_graph_for_case(case: GoldenCase, parser: Parser) -> CPGGraphBuilder:
    """Build a :class:`CPGGraphBuilder` for a single golden case fixture."""
    from hyqagent.cpg.graph import CPGGraphBuilder

    fixture_path = str(case.fixture_abs_path)
    builder = CPGGraphBuilder(parser)
    builder.add_file(fixture_path)
    return builder


def build_labeled_graph_for_case(
    case: GoldenCase,
    parser: Parser,
    taint_loader: TaintRuleLoader,
) -> CPGGraphBuilder:
    """Build CPG **with taint node labeling enabled** for a single golden case.

    Unlike :func:`build_graph_for_case`, this passes *taint_loader* to
    :class:`CPGGraphBuilder` so that source/sink nodes are labeled with
    ``taint_category`` attributes.  Required for scanner-level tests.
    """
    from hyqagent.cpg.graph import CPGGraphBuilder

    fixture_path = str(case.fixture_abs_path)
    builder = CPGGraphBuilder(parser, taint_loader=taint_loader)
    builder.add_file(fixture_path)
    return builder


def build_scanner_for_case(
    case: GoldenCase,
    parser: Parser,
    taint_loader: TaintRuleLoader,
    frameworks: list | None = None,
) -> "DeterministicScanner":
    """Build a fully wired :class:`DeterministicScanner` for a single golden case.

    Constructs the full dependency chain:
    CPG graph (labeled) → CPGQuery → SinkDiscoverer + SourceChecker →
    PathAnnotator → DeterministicScanner

    *frameworks* is optional; required for ``scan_missing_auth()`` tests.
    """
    from hyqagent.cpg.discovery import SinkDiscoverer, SourceCompletenessChecker
    from hyqagent.cpg.query import CPGQuery
    from hyqagent.scanner.annotator import PathAnnotator
    from hyqagent.scanner.deterministic import DeterministicScanner

    builder = build_labeled_graph_for_case(case, parser, taint_loader)
    graph = builder.graph
    query = CPGQuery(graph)
    sink_disc = SinkDiscoverer(graph, taint_loader)
    src_check = SourceCompletenessChecker(graph, taint_loader)
    annotator = PathAnnotator(query, taint_loader, sink_disc, src_check)
    return DeterministicScanner(
        graph,
        query,
        taint_loader,
        annotator,
        frameworks=frameworks,
    )
