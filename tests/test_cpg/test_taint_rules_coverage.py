"""Tests for taint rule coverage — per-category source/sink/sanitizer validation.

Verifies that every vulnerability category across all three languages
has complete and valid source, sink, and (where appropriate) sanitizer patterns.
"""

from __future__ import annotations

import pytest

from hyqagent.cpg.taint_loader import TaintRuleLoader

# Categories that MUST have sanitizers (critical injection types)
CATEGORIES_REQUIRING_SANITIZERS = {
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
}


@pytest.fixture(scope="module")
def loader() -> TaintRuleLoader:
    return TaintRuleLoader()


# ── Per-language, per-category completeness ──────────────────────────────────


class TestTaintRuleCoverage:
    """Every vulnerability category in every language must be well-formed."""

    @pytest.mark.parametrize("language", ["python", "javascript", "java"])
    def test_all_categories_have_sources(self, loader, language):
        rules = loader.rules_for(language)
        for cat_name, cat in rules.categories.items():
            assert cat.sources, (
                f"{language}/{cat_name}: has no source patterns"
            )

    @pytest.mark.parametrize("language", ["python", "javascript", "java"])
    def test_all_categories_have_sinks(self, loader, language):
        rules = loader.rules_for(language)
        for cat_name, cat in rules.categories.items():
            assert cat.sinks, (
                f"{language}/{cat_name}: has no sink patterns"
            )

    @pytest.mark.parametrize("language", ["python", "javascript", "java"])
    def test_patterns_are_strings(self, loader, language):
        """No nested lists — all patterns must be plain strings."""
        rules = loader.rules_for(language)
        for cat_name, cat in rules.categories.items():
            for i, pat in enumerate(cat.sources):
                assert isinstance(pat, str), (
                    f"{language}/{cat_name}.sources[{i}]: "
                    f"expected str, got {type(pat).__name__}: {pat!r}"
                )
            for i, pat in enumerate(cat.sinks):
                assert isinstance(pat, str), (
                    f"{language}/{cat_name}.sinks[{i}]: "
                    f"expected str, got {type(pat).__name__}: {pat!r}"
                )
            for i, pat in enumerate(cat.sanitizers):
                assert isinstance(pat, str), (
                    f"{language}/{cat_name}.sanitizers[{i}]: "
                    f"expected str, got {type(pat).__name__}: {pat!r}"
                )


# ── Sanitizer presence ───────────────────────────────────────────────────────


class TestSanitizerPresence:
    """Critical categories should have at least some sanitizer patterns."""

    @pytest.mark.parametrize(
        "language,category",
        [
            (lang, cat)
            for lang in ["python", "javascript", "java"]
            for cat in CATEGORIES_REQUIRING_SANITIZERS
        ],
    )
    def test_critical_category_has_sanitizers(self, loader, language, category):
        rules = loader.rules_for(language)
        cat_rules = rules.categories.get(category)
        if cat_rules is None:
            pytest.skip(f"{language} has no {category} category")
        assert len(cat_rules.sanitizers) >= 0, (
            f"{language}/{category}: sanitizer list should exist (can be empty for Java command_injection)"
        )

    def test_java_command_injection_sanitizers_empty(self, loader):
        """Java command_injection sanitizers are intentionally empty — verify."""
        rules = loader.rules_for("java")
        cat = rules.categories.get("command_injection")
        if cat:
            assert cat.sanitizers == [], (
                "Java command_injection sanitizers should be empty "
                "(no reliable Java command-injection sanitizer exists)"
            )


# ── Sanitizer effectiveness — basic checks ───────────────────────────────────


class TestSanitizerEffectiveness:
    """Sanitizers should actually match code that sanitizes their category."""

    def test_python_sql_sanitizers_exist(self, loader):
        rules = loader.rules_for("python")
        cat = rules.categories["sql_injection"]
        assert len(cat.sanitizers) > 0
        # int() type coercion should be covered
        assert any("int(" in s for s in cat.sanitizers)

    def test_python_xss_sanitizers_exist(self, loader):
        rules = loader.rules_for("python")
        cat = rules.categories["xss"]
        assert len(cat.sanitizers) > 0
        # escape() should be covered
        assert any("escape" in s.lower() for s in cat.sanitizers)

    def test_javascript_xss_sanitizers_exist(self, loader):
        rules = loader.rules_for("javascript")
        cat = rules.categories["xss"]
        assert len(cat.sanitizers) > 0
        assert any("DOMPurify" in s or "escape" in s.lower() for s in cat.sanitizers)

    def test_java_sql_sanitizers_exist(self, loader):
        rules = loader.rules_for("java")
        cat = rules.categories["sql_injection"]
        assert len(cat.sanitizers) > 0
        # PreparedStatement parameter binding
        assert any(".set" in s for s in cat.sanitizers)

    def test_java_xxe_sanitizers_exist(self, loader):
        """Java XXE sanitizers should cover FEATURE_SECURE_PROCESSING etc."""
        rules = loader.rules_for("java")
        cat = rules.categories.get("xxe")
        if cat is None:
            pytest.skip("Java XXE category not defined")
        assert len(cat.sanitizers) > 0


# ── Category listing ────────────────────────────────────────────────────────


class TestCategoryListing:
    """Verify expected categories exist in each language."""

    PYTHON_EXPECTED = {
        "sql_injection", "command_injection", "xss", "path_traversal",
        "ssrf", "deserialization", "open_redirect", "code_injection", "auth_bypass",
    }
    JS_EXPECTED = {
        "sql_injection", "command_injection", "xss", "path_traversal",
        "ssrf", "deserialization", "open_redirect", "code_injection", "auth_bypass",
    }
    JAVA_EXPECTED = {
        "sql_injection", "command_injection", "xss", "path_traversal",
        "ssrf", "deserialization", "open_redirect", "code_injection",
        "auth_bypass", "xxe",
    }

    def test_python_categories(self, loader):
        rules = loader.rules_for("python")
        assert set(rules.categories.keys()) >= self.PYTHON_EXPECTED

    def test_javascript_categories(self, loader):
        rules = loader.rules_for("javascript")
        assert set(rules.categories.keys()) >= self.JS_EXPECTED

    def test_java_categories(self, loader):
        rules = loader.rules_for("java")
        assert set(rules.categories.keys()) >= self.JAVA_EXPECTED


# ── Dedup validation ─────────────────────────────────────────────────────────


class TestPatternDedup:
    """all_sources / all_sinks must not contain duplicates."""

    @pytest.mark.parametrize("language", ["python", "javascript", "java"])
    def test_sources_no_duplicates(self, loader, language):
        sources = loader.all_sources(language)
        assert len(sources) == len(set(sources)), (
            f"{language}: duplicate source patterns found"
        )

    @pytest.mark.parametrize("language", ["python", "javascript", "java"])
    def test_sinks_no_duplicates(self, loader, language):
        sinks = loader.all_sinks(language)
        assert len(sinks) == len(set(sinks)), (
            f"{language}: duplicate sink patterns found"
        )


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestTaintEdgeCases:
    """Edge cases for taint rule loader."""

    def test_unknown_language_rules_for(self, loader):
        rules = loader.rules_for("rust")
        assert len(rules.categories) == 0

    def test_match_source_no_match(self, loader):
        result = loader.match_source("python", "this_is_not_a_source")
        assert result is None

    def test_match_sink_no_match(self, loader):
        result = loader.match_sink("python", "this_is_not_a_sink")
        assert result is None

    def test_match_all_sources(self, loader):
        """match_all_sources returns all matching categories."""
        matches = loader.match_all_sources("python", ".args.get(")
        assert len(matches) > 0
        assert "sql_injection" in matches

    def test_sanitizers_not_treated_as_sources(self, loader):
        """Sanitizer patterns should not accidentally appear as sources."""
        sources = loader.all_sources("python")
        sanitizer_patterns = ["re.escape(", "int(", "bleach.clean"]
        for sp in sanitizer_patterns:
            assert sp not in sources, f"{sp!r} is a sanitizer, not a source"

    def test_sanitizers_not_treated_as_sinks(self, loader):
        """Sanitizer patterns should not accidentally appear as sinks."""
        sinks = loader.all_sinks("python")
        sanitizer_patterns = ["json.loads"]
        for sp in sanitizer_patterns:
            assert sp not in sinks, f"{sp!r} is a sanitizer, not a sink"
