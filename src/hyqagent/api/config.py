"""api/config.py — Centralised configuration via pydantic-settings.

Environment variables are prefixed with ``HYQAGENT_``.
A ``.env`` file in the current working directory is loaded automatically.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr
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
        HYQAGENT_ANTHROPIC_API_KEY      — Anthropic API key (Phase 3+)
        HYQAGENT_DEEPSEEK_API_KEY       — DeepSeek API key (Phase 3+)
    """

    model_config = SettingsConfigDict(
        env_prefix="HYQAGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Model config ───────────────────────────────────────────────────
    cheap_model: str = "deepseek-v4-flash"
    mid_model: str = "claude-sonnet-5"
    strong_model: str = "claude-opus-5"

    # ── API Keys (Phase 3+) ────────────────────────────────────────────
    anthropic_api_key: SecretStr = SecretStr("")
    deepseek_api_key: SecretStr = SecretStr("")
    deepseek_base_url: str = "https://api.deepseek.com/anthropic"

    # ── Budget (Phase 3+) ──────────────────────────────────────────────
    max_llm_budget: float = 1.39  # ≈ ¥10 (DeepSeek Flash: ~0.14/百万tokens)
    llm_max_retries: int = 3
    llm_timeout_seconds: int = 120

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

    @property
    def anthropic_key(self) -> str:
        """Reveal the Anthropic API key, falling back to env var."""
        key = self.anthropic_api_key.get_secret_value()
        if not key:
            import os

            key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ValueError(
                "Anthropic API key not configured. Set HYQAGENT_ANTHROPIC_API_KEY "
                "or ANTHROPIC_API_KEY in the environment."
            )
        return key

    @property
    def deepseek_key(self) -> str:
        """Reveal the DeepSeek API key, falling back to env var."""
        key = self.deepseek_api_key.get_secret_value()
        if not key:
            import os

            key = os.environ.get("DEEPSEEK_API_KEY", "")
        if not key:
            raise ValueError(
                "DeepSeek API key not configured. Set HYQAGENT_DEEPSEEK_API_KEY "
                "or DEEPSEEK_API_KEY in the environment."
            )
        return key
