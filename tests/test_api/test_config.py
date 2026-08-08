"""Tests for api/config.py — HyqAgentConfig via pydantic-settings."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hyqagent.api.config import HyqAgentConfig


class TestHyqAgentConfig:
    def test_defaults(self):
        cfg = HyqAgentConfig()
        assert cfg.cheap_model == "deepseek-v4-flash-0731"
        assert cfg.mid_model == "claude-sonnet-5"
        assert cfg.strong_model == "claude-opus-5"
        assert cfg.default_language == ""
        assert cfg.scan_max_depth == 20
        assert cfg.heuristic_score_threshold == 60
        assert cfg.cache_dir == Path.home() / ".cache" / "hyqagent"

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("HYQAGENT_DEFAULT_LANGUAGE", "java")
        monkeypatch.setenv("HYQAGENT_SCAN_MAX_DEPTH", "30")
        monkeypatch.setenv("HYQAGENT_HEURISTIC_SCORE_THRESHOLD", "80")

        cfg = HyqAgentConfig()
        assert cfg.default_language == "java"
        assert cfg.scan_max_depth == 30
        assert cfg.heuristic_score_threshold == 80

    def test_resolve_language_uses_explicit(self):
        cfg = HyqAgentConfig()
        assert cfg.resolve_language("python") == "python"
        assert cfg.resolve_language("javascript") == "javascript"

    def test_resolve_language_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("HYQAGENT_DEFAULT_LANGUAGE", "java")
        cfg = HyqAgentConfig()
        assert cfg.resolve_language(None) == "java"

    def test_resolve_language_raises_when_no_lang(self):
        cfg = HyqAgentConfig()
        with pytest.raises(ValueError, match="No language specified"):
            cfg.resolve_language(None)

    def test_extra_vars_ignored(self, monkeypatch):
        """Ensure extra env vars don't cause validation errors."""
        monkeypatch.setenv("HYQAGENT_UNKNOWN_KEY", "should-be-ignored")
        cfg = HyqAgentConfig()
        assert cfg.default_language == ""  # default still fine
