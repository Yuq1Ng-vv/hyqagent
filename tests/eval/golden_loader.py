"""tests/eval/golden_loader.py — Load and query the HyqAgent Golden Dataset.

Usage::

    loader = GoldenDatasetLoader()
    cases = loader.load()                    # all 28 cases
    taint = loader.filter_by(detection_method="cpg_taint")
    py = loader.filter_by(language="python")
    neg = loader.filter_by(negative_test=True)

The golden dataset is a versioned JSON file at ``evals/golden_dataset_v1.json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Data models ─────────────────────────────────────────────────────────────


@dataclass
class GroundTruth:
    """Expected scanner output for a single golden case."""

    has_finding: bool
    expected_category: str | None = None
    expected_label: str | None = None
    min_findings: int = 0
    max_findings: int = 999
    source_pattern: str | None = None
    sink_pattern: str | None = None
    confidence_min: str = "medium"


@dataclass
class GoldenCase:
    """A single labeled vulnerability case in the golden dataset."""

    id: str
    name: str
    language: str
    cwe: str
    vulnerability_type: str
    severity: str
    detection_method: str
    fixture_file: str
    description: str = ""
    ground_truth: GroundTruth = field(default_factory=lambda: GroundTruth(has_finding=True))
    detection_matrix_refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    negative_test: bool = False

    @property
    def fixture_abs_path(self) -> Path:
        """Absolute path to the fixture source file."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        return repo_root / self.fixture_file

    def source_code(self) -> str:
        """Read the fixture source code."""
        return self.fixture_abs_path.read_text(encoding="utf-8")


# ── Loader ──────────────────────────────────────────────────────────────────


class GoldenDatasetLoader:
    """Load and query the golden dataset from JSON.

    Caches loaded cases in memory.  Use ``filter_by()`` to slice
    by any :class:`GoldenCase` attribute.
    """

    _DEFAULT_PATH: str | None = None

    def __init__(self, dataset_path: str | Path | None = None) -> None:
        if dataset_path is None:
            if self._DEFAULT_PATH is None:
                repo_root = Path(__file__).resolve().parent.parent.parent
                dataset_path = repo_root / "evals" / "golden_dataset_v1.json"
            else:
                dataset_path = Path(self._DEFAULT_PATH)
        self._path = Path(dataset_path)
        self._cases: list[GoldenCase] = []

    # ── Load ───────────────────────────────────────────────────────────────

    def load(self) -> list[GoldenCase]:
        """Load all cases from the JSON file (idempotent)."""
        if self._cases:
            return self._cases

        data = json.loads(self._path.read_text(encoding="utf-8"))
        self._cases = [
            GoldenCase(
                id=c["id"],
                name=c["name"],
                language=c["language"],
                cwe=c["cwe"],
                vulnerability_type=c["vulnerability_type"],
                severity=c["severity"],
                detection_method=c["detection_method"],
                fixture_file=c["fixture_file"],
                description=c.get("description", ""),
                ground_truth=GroundTruth(**c["ground_truth"]),
                detection_matrix_refs=c.get("detection_matrix_refs", []),
                tags=c.get("tags", []),
                negative_test=c.get("negative_test", False),
            )
            for c in data["cases"]
        ]
        return self._cases

    # ── Query ──────────────────────────────────────────────────────────────

    def filter_by(self, **kwargs: Any) -> list[GoldenCase]:
        """Filter cases by attribute values.  Multiple kwargs are AND-ed.

        Example::

            loader.filter_by(language="python", detection_method="cpg_taint")
        """
        if not self._cases:
            self.load()
        result = self._cases
        for key, value in kwargs.items():
            result = [c for c in result if getattr(c, key, None) == value]
        return result

    def get(self, case_id: str) -> GoldenCase | None:
        """Get a single case by ID, or None if not found."""
        if not self._cases:
            self.load()
        for c in self._cases:
            if c.id == case_id:
                return c
        return None

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def languages(self) -> set[str]:
        if not self._cases:
            self.load()
        return {c.language for c in self._cases}

    @property
    def vulnerability_types(self) -> set[str]:
        if not self._cases:
            self.load()
        return {c.vulnerability_type for c in self._cases}

    @property
    def detection_methods(self) -> set[str]:
        if not self._cases:
            self.load()
        return {c.detection_method for c in self._cases}
