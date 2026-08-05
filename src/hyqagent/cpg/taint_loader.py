"""cpg/taint_loader.py — Load taint rules from YAML configuration.

Reads ``taint_rules.yaml`` and provides structured access to source /
sink / sanitizer patterns grouped by language and vulnerability category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class TaintCategory:
    """Patterns for a single vulnerability category in one language."""

    category: str  # "sql_injection", "xss", ...
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class LanguageTaintRules:
    """All taint rules for one programming language."""

    language: str
    categories: dict[str, TaintCategory] = field(default_factory=dict)


class TaintRuleLoader:
    """Load and query taint rules from a YAML file.

    Usage::

        loader = TaintRuleLoader()
        rules = loader.rules_for("python")

        for cat_name, cat in rules.categories.items():
            print(f"{cat_name}: {len(cat.sources)} sources, {len(cat.sinks)} sinks")
    """

    def __init__(self, rules_path: str | Path | None = None) -> None:
        if rules_path is None:
            rules_path = Path(__file__).resolve().parent / "taint_rules.yaml"
        self._path = Path(rules_path)
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as fh:
                self._data = yaml.safe_load(fh) or {}
        except FileNotFoundError:
            self._data = {}

    def rules_for(self, language: str) -> LanguageTaintRules:
        """Return all taint rules for *language*."""
        lang_data = self._data.get(language, {})
        categories: dict[str, TaintCategory] = {}

        # Collect all category names from sources, sinks, and sanitizers
        all_categories: set[str] = set()
        for section in ("sources", "sinks", "sanitizers"):
            section_data = lang_data.get(section, {})
            all_categories.update(section_data.keys())

        for cat_name in sorted(all_categories):
            sources_data = lang_data.get("sources", {}).get(cat_name, [])
            sinks_data = lang_data.get("sinks", {}).get(cat_name, [])
            sanitizers_data = lang_data.get("sanitizers", {}).get(cat_name, [])

            categories[cat_name] = TaintCategory(
                category=cat_name,
                sources=list(sources_data),
                sinks=list(sinks_data),
                sanitizers=list(sanitizers_data),
            )

        return LanguageTaintRules(language=language, categories=categories)

    def all_sources(self, language: str) -> list[str]:
        """Return all source patterns for *language* (flat list)."""
        rules = self.rules_for(language)
        result: list[str] = []
        for cat in rules.categories.values():
            result.extend(cat.sources)
        return sorted(set(result))

    def all_sinks(self, language: str) -> list[str]:
        """Return all sink patterns for *language* (flat list)."""
        rules = self.rules_for(language)
        result: list[str] = []
        for cat in rules.categories.values():
            result.extend(cat.sinks)
        return sorted(set(result))

    def match_source(self, language: str, text: str) -> str | None:
        """Return the category name if *text* matches a source pattern, else None."""
        rules = self.rules_for(language)
        for cat_name, cat in rules.categories.items():
            for pat in cat.sources:
                if pat in text:
                    return cat_name
        return None

    def match_sink(self, language: str, text: str) -> str | None:
        """Return the category name if *text* matches a sink pattern, else None."""
        rules = self.rules_for(language)
        for cat_name, cat in rules.categories.items():
            for pat in cat.sinks:
                if pat in text:
                    return cat_name
        return None

    @property
    def available_languages(self) -> list[str]:
        """Languages with rules defined in the YAML file."""
        return list(self._data.keys())
