"""api/config.py — Centralised configuration via pydantic-settings.

Environment variables are prefixed with ``HYQAGENT_``.
A ``.env`` file in the current working directory is loaded automatically.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class HyqAgentConfig(BaseSettings):
    """Configuration for the HyqAgent CLI and scanner pipeline.

    All values have sensible defaults so zero-config usage
    (``hyqagent scan <path>``) works out of the box.

    Environment variables:
        HYQAGENT_DEFAULT_LANGUAGE       — e.g. "python"
        HYQAGENT_SCAN_MAX_DEPTH         — CPG traversal depth cap
        HYQAGENT_HEURISTIC_THRESHOLD    — heuristic sink score floor (0-100)
        HYQAGENT_CACHE_DIR              — cache directory on disk
    """

    model_config = SettingsConfigDict(
        env_prefix="HYQAGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Model config (Phase 3/4 uses; Phase 2 reserves) ───────────────
    cheap_model: str = "claude-haiku-4-5-20251001"
    mid_model: str = "claude-sonnet-5"
    strong_model: str = "claude-opus-5"

    # ── Scanner config ─────────────────────────────────────────────────
    default_language: str = ""
    default_framework: str = ""
    scan_max_depth: int = 20
    heuristic_score_threshold: int = 60

    # ── Paths ──────────────────────────────────────────────────────────
    cache_dir: Path = Path.home() / ".cache" / "hyqagent"

    # ── Convenience ────────────────────────────────────────────────────

    def resolve_language(self, explicit: str | None) -> str:
        """Return *explicit* if given, else ``default_language``."""
        result = explicit or self.default_language
        if not result:
            raise ValueError(
                "No language specified.  Use --lang <LANG> or set "
                "HYQAGENT_DEFAULT_LANGUAGE in the environment."
            )
        return result
