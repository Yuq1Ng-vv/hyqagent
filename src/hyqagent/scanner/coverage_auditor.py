"""scanner/coverage_auditor.py — Zero-LLM differential coverage analysis.

方案 5 from COVERAGE-GAP-ANALYSIS.md §6.5:
Instead of looking for dangerous code, look for code that was NOT proven safe.
For every HTTP endpoint, database call, file operation, and command execution,
check: "Did our analysis cover this?"

Generates a blind-spot manifest that becomes an appendix to every report.
Zero LLM cost — purely CPG queries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from hyqagent.cpg.query import CPGQuery

logger = structlog.get_logger(__name__)


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class CoverageGap:
    """A single blind spot in the analysis coverage."""

    location: str
    category: str  # endpoint | database_call | file_operation | command_exec | deserialization
    reason: str
    risk: str = "unknown"  # "high" | "medium" | "low"


@dataclass
class CoverageAudit:
    """Complete differential coverage audit result."""

    total_entries: int = 0
    covered: int = 0
    gaps: list[CoverageGap] = field(default_factory=list)
    coverage_pct: float = 0.0

    @property
    def high_risk_gaps(self) -> list[CoverageGap]:
        return [g for g in self.gaps if g.risk == "high"]

    @property
    def medium_risk_gaps(self) -> list[CoverageGap]:
        return [g for g in self.gaps if g.risk == "medium"]


# ── CoverageAuditor ──────────────────────────────────────────────────────────


class CoverageAuditor:
    """Audit analysis coverage of security-relevant code elements.

    Zero-LLM: uses only CPG queries and label matching to determine
    whether each security-relevant code element was analyzed.

    Usage::

        auditor = CoverageAuditor(query, annotated_paths, language)
        audit = auditor.audit()
        print(f"Coverage: {audit.coverage_pct:.0%}")
        for gap in audit.high_risk_gaps:
            print(f"  HIGH: {gap.location} — {gap.reason}")
    """

    # Categories of security-relevant operations we want full coverage of
    SINK_PATTERNS: dict[str, list[str]] = {
        "database_call": [
            "execute", "query", "raw", "executemany", "bulk_create",
            "find", "findOne", "findById", "aggregate",
            "createQueryBuilder", "getRepository",
        ],
        "file_operation": [
            "open", "read", "write", "readFile", "writeFile",
            "readFileSync", "writeFileSync", "FileInputStream",
            "FileOutputStream", "FileReader", "FileWriter",
        ],
        "command_exec": [
            "exec", "system", "popen", "subprocess", "spawn",
            "Runtime.exec", "ProcessBuilder", "child_process",
            "os.system", "os.popen",
        ],
        "deserialization": [
            "pickle.load", "yaml.load", "json.loads",
            "ObjectInputStream.readObject", "readObject",
            "unserialize", "unmarshal", "XMLDecoder",
        ],
    }

    def __init__(
        self,
        query: CPGQuery,
        annotated_paths: list[Any],
        language: str = "",
    ) -> None:
        self._query = query
        self._annotated = annotated_paths
        self._language = language

        # Build set of locations covered by any annotated path
        self._covered_locations: set[str] = set()
        for ap in annotated_paths:
            path = getattr(ap, "path", None)
            if path is None:
                continue
            for node in getattr(path, "nodes", []):
                loc = getattr(node, "location", "")
                if loc:
                    self._covered_locations.add(loc.split(":")[0] if ":" in loc else loc)

    # ── Public API ──────────────────────────────────────────────────────

    def audit(self) -> CoverageAudit:
        """Run the full differential coverage audit."""
        gaps: list[CoverageGap] = []

        # 1. Check HTTP endpoints
        endpoint_gaps = self._check_endpoints()
        gaps.extend(endpoint_gaps)

        # 2. Check security-relevant sinks
        sink_gaps = self._check_sinks()
        gaps.extend(sink_gaps)

        # 3. Check annotated-path labels for suspicious patterns
        label_gaps = self._check_label_patterns()
        gaps.extend(label_gaps)

        total = len(gaps) + len(self._annotated)
        covered = len(self._annotated) if self._annotated else 0

        return CoverageAudit(
            total_entries=max(1, total),
            covered=covered,
            gaps=gaps,
            coverage_pct=covered / max(1, total) if total > 0 else 0.0,
        )

    # ── Internal ────────────────────────────────────────────────────────

    def _check_endpoints(self) -> list[CoverageGap]:
        """Check whether each endpoint has been analyzed."""
        gaps: list[CoverageGap] = []

        # Query all function nodes that look like HTTP handlers
        # (identified by framework extractors or naming conventions)
        for ap in self._annotated:
            metadata = getattr(ap, "metadata", {}) or {}
            endpoint = metadata.get("endpoint", "")
            if not endpoint:
                continue

            label = getattr(ap, "label", None)
            label_str = label.value if hasattr(label, "value") else str(label) if label else ""

            if label_str in ("heuristic_sink", "exposed_no_source", "uncovered_sink"):
                gaps.append(CoverageGap(
                    location=endpoint,
                    category="endpoint",
                    reason=(
                        f"Endpoint has suspicious label '{label_str}' — "
                        "deterministic analysis could not fully trace this path"
                    ),
                    risk="high",
                ))

            # Check if this endpoint's calls have coverage
            if not self._is_location_covered(endpoint):
                gaps.append(CoverageGap(
                    location=endpoint,
                    category="endpoint",
                    reason="Endpoint was not reached by any taint analysis path",
                    risk="medium",
                ))

        return gaps

    def _check_sinks(self) -> list[CoverageGap]:
        """Check security-relevant sinks for coverage."""
        gaps: list[CoverageGap] = []

        for category, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                try:
                    nodes = self._query.find_nodes(
                        node_type="call_expression",
                        pattern=pattern,
                        limit=50,
                    )
                except Exception:
                    continue

                for node in nodes:
                    loc = getattr(node, "location", "")
                    if not loc:
                        continue

                    file_path = loc.split(":")[0] if ":" in loc else loc

                    if not self._is_location_covered(file_path):
                        gaps.append(CoverageGap(
                            location=loc,
                            category=category,
                            reason=(
                                f"{category} '{pattern}' has no taint path "
                                "from any known source — either safe or source "
                                "list is incomplete"
                            ),
                            risk="medium",
                        ))

        return gaps

    def _check_label_patterns(self) -> list[CoverageGap]:
        """Check annotated-path label patterns for suspicious gaps."""
        gaps: list[CoverageGap] = []

        # Count labels
        label_counts: dict[str, int] = {}
        for ap in self._annotated:
            label = getattr(ap, "label", None)
            if label is not None:
                key = label.value if hasattr(label, "value") else str(label)
                label_counts[key] = label_counts.get(key, 0) + 1

        # High heuristic_sink count → scanner is finding things it can't classify
        heuristic_count = label_counts.get("heuristic_sink", 0)
        if heuristic_count >= 5:
            gaps.append(CoverageGap(
                location="(multiple locations)",
                category="endpoint",
                reason=(
                    f"{heuristic_count} heuristic sinks found — "
                    "the deterministic scanner found potentially dangerous "
                    "operations but could not classify the vulnerability type. "
                    "These need LLM hypothesis generation."
                ),
                risk="high",
            ))

        # Many exposed_no_source → data flow tracing is breaking
        exposed_count = label_counts.get("exposed_no_source", 0)
        if exposed_count >= 3:
            gaps.append(CoverageGap(
                location="(multiple locations)",
                category="endpoint",
                reason=(
                    f"{exposed_count} endpoints expose user input but data flow "
                    "tracing could not reach a sink. Possible causes: "
                    "dynamic dispatch, reflection, async callbacks, "
                    "or framework internals not modeled by CPG."
                ),
                risk="high",
            ))

        # uncovered_sink → rules don't cover this pattern
        uncovered = label_counts.get("uncovered_sink", 0)
        if uncovered > 0:
            gaps.append(CoverageGap(
                location="(multiple locations)",
                category="database_call",
                reason=(
                    f"{uncovered} sinks are reachable but no vulnerability rule "
                    "covers this source→sink combination. The YAML taint rules "
                    "may need expansion for this framework or codebase."
                ),
                risk="medium",
            ))

        return gaps

    def _is_location_covered(self, location: str) -> bool:
        """Check if *location* is covered by any annotated path."""
        if location in self._covered_locations:
            return True
        # Check substring match for file-level coverage
        for cl in self._covered_locations:
            if cl in location or location in cl:
                return True
        return False
