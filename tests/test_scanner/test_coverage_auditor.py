"""Tests for scanner/coverage_auditor.py — zero-LLM differential coverage analysis."""

from __future__ import annotations

from unittest.mock import MagicMock

from hyqagent.scanner.coverage_auditor import (
    CoverageAudit,
    CoverageAuditor,
    CoverageGap,
)


class TestCoverageGap:
    def test_defaults(self) -> None:
        gap = CoverageGap(location="app.py:42", category="endpoint",
                          reason="Not covered by analysis")
        assert gap.location == "app.py:42"
        assert gap.category == "endpoint"
        assert gap.risk == "unknown"


class TestCoverageAudit:
    def test_properties(self) -> None:
        audit = CoverageAudit(
            total_entries=10,
            covered=6,
            gaps=[
                CoverageGap("a.py:1", "endpoint", "reason", risk="high"),
                CoverageGap("b.py:2", "database_call", "reason", risk="medium"),
                CoverageGap("c.py:3", "file_operation", "reason", risk="low"),
            ],
            coverage_pct=0.6,
        )
        assert len(audit.high_risk_gaps) == 1
        assert len(audit.medium_risk_gaps) == 1
        assert audit.coverage_pct == 0.6


class TestCoverageAuditor:
    """Tests that don't require a full CPG graph."""

    def _make_mock_query(self) -> MagicMock:
        return MagicMock()

    def _make_mock_annotated(self, label_value: str = "confirmed_taint",
                              metadata: dict | None = None) -> MagicMock:
        """Create a mock AnnotatedPath."""
        ap = MagicMock()
        ap.label = MagicMock()
        ap.label.value = label_value
        ap.metadata = metadata or {}

        # Mock path.nodes for coverage tracking
        mock_node = MagicMock()
        mock_node.location = "test_file.py:42"
        ap.path = MagicMock()
        ap.path.nodes = [mock_node]
        return ap

    def test_empty_annotated_paths(self) -> None:
        auditor = CoverageAuditor(MagicMock(), [], language="python")
        audit = auditor.audit()
        # With 0 annotated paths, coverage is 0
        assert audit.covered == 0

    def test_covered_locations_tracking(self) -> None:
        ap = self._make_mock_annotated()
        auditor = CoverageAuditor(MagicMock(), [ap])
        assert auditor._covered_locations

    def test_heuristic_sink_endpoint_flagged(self) -> None:
        ap = self._make_mock_annotated(
            label_value="heuristic_sink",
            metadata={"endpoint": "GET /api/users/:id"},
        )
        auditor = CoverageAuditor(self._make_mock_query(), [ap])
        gaps = auditor._check_endpoints()
        assert len(gaps) >= 1
        assert any("heuristic_sink" in g.reason.lower() for g in gaps)

    def test_exposed_no_source_flagged(self) -> None:
        ap = self._make_mock_annotated(
            label_value="exposed_no_source",
            metadata={"endpoint": "POST /api/login"},
        )
        auditor = CoverageAuditor(self._make_mock_query(), [ap])
        gaps = auditor._check_endpoints()
        assert len(gaps) >= 1

    def test_uncovered_sink_flagged(self) -> None:
        ap = self._make_mock_annotated(
            label_value="uncovered_sink",
            metadata={"endpoint": "PUT /api/data"},
        )
        auditor = CoverageAuditor(self._make_mock_query(), [ap])
        gaps = auditor._check_endpoints()
        assert len(gaps) >= 1

    def test_high_heuristic_count_creates_gap(self) -> None:
        """5+ heuristic_sink labeled paths → high-risk gap."""
        aps = [
            self._make_mock_annotated(label_value="heuristic_sink")
            for _ in range(5)
        ]
        auditor = CoverageAuditor(self._make_mock_query(), aps)
        gaps = auditor._check_label_patterns()
        assert any("heuristic sink" in g.reason.lower() and g.risk == "high"
                   for g in gaps)

    def test_multiple_exposed_no_source_creates_gap(self) -> None:
        """3+ exposed_no_source paths → high-risk gap."""
        aps = [
            self._make_mock_annotated(label_value="exposed_no_source")
            for _ in range(3)
        ]
        auditor = CoverageAuditor(self._make_mock_query(), aps)
        gaps = auditor._check_label_patterns()
        assert any("expose" in g.reason.lower() and g.risk == "high"
                   for g in gaps)

    def test_uncovered_sink_label_pattern(self) -> None:
        aps = [self._make_mock_annotated(label_value="uncovered_sink")]
        auditor = CoverageAuditor(self._make_mock_query(), aps)
        gaps = auditor._check_label_patterns()
        assert any("no vulnerability rule covers" in g.reason.lower()
                   for g in gaps)

    def test_is_location_covered(self) -> None:
        ap = self._make_mock_annotated()
        auditor = CoverageAuditor(MagicMock(), [ap])
        # The exact location should be covered
        assert auditor._is_location_covered("test_file.py:42")
        # File-level match should work
        assert auditor._is_location_covered("test_file.py")
        # Unknown location should not be covered
        assert not auditor._is_location_covered("other_file.py:100")

    def test_full_audit_with_annotated_paths(self) -> None:
        aps = [
            self._make_mock_annotated(label_value="confirmed_taint"),
            self._make_mock_annotated(label_value="heuristic_sink"),
            self._make_mock_annotated(label_value="exposed_no_source",
                                       metadata={"endpoint": "GET /api/test"}),
        ]
        auditor = CoverageAuditor(self._make_mock_query(), aps)
        audit = auditor.audit()
        assert audit.total_entries > 0
        assert audit.coverage_pct >= 0.0
        assert isinstance(audit.gaps, list)

    def test_sink_patterns_defined(self) -> None:
        """Verify sink patterns cover all major categories."""
        assert "database_call" in CoverageAuditor.SINK_PATTERNS
        assert "file_operation" in CoverageAuditor.SINK_PATTERNS
        assert "command_exec" in CoverageAuditor.SINK_PATTERNS
        assert "deserialization" in CoverageAuditor.SINK_PATTERNS
        assert len(CoverageAuditor.SINK_PATTERNS["database_call"]) > 0
