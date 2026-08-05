"""cpg/languages/ — Language provider registry.

Each language is a :class:`LanguageProvider` implementation.  Adapters are
lazy-loaded: the grammar package is only imported when the language is
actually used.

To add a new language:

1. Create ``cpg/languages/golang.py`` implementing ``LanguageProvider``.
2. Add one line to ``_BUILDER`` below.
3. Done.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

from hyqagent.cpg.languages.base import LanguageProvider


def _make_python() -> LanguageProvider:
    from hyqagent.cpg.languages.python import PythonAdapter

    return PythonAdapter()


def _make_javascript() -> LanguageProvider:
    from hyqagent.cpg.languages.javascript import JavaScriptAdapter

    return JavaScriptAdapter()


def _make_java() -> LanguageProvider:
    from hyqagent.cpg.languages.java import JavaAdapter

    return JavaAdapter()


# ── Registry ──────────────────────────────────────────────────────────────

_BUILDER: dict[str, Callable[[], LanguageProvider]] = {
    "python": _make_python,
    "javascript": _make_javascript,
    "java": _make_java,
}


@lru_cache(maxsize=16)
def get_provider(name: str) -> LanguageProvider:
    """Return the :class:`LanguageProvider` singleton for *name*.

    The adapter is built once on first access and cached.
    Raises :class:`ValueError` if *name* is unknown.
    """
    builder = _BUILDER.get(name)
    if builder is None:
        raise ValueError(f"Unsupported language: {name!r}. Supported: {sorted(_BUILDER)}")
    return builder()


def get_all_names() -> list[str]:
    """Return all registered language names."""
    return sorted(_BUILDER)


def get_all_providers() -> list[LanguageProvider]:
    """Return provider instances for every registered language."""
    return [get_provider(name) for name in _BUILDER]


def detect_by_extension(path: str) -> str | None:
    """Return the language name matching *path*'s extension, or None."""
    # Collect extensions from all registered providers
    for name in _BUILDER:
        provider = get_provider(name)
        for ext in provider.extensions:
            if path.endswith(ext):
                return name
    # Try double extension (e.g., .test.js)
    dot = path.rfind(".")
    if dot > 0:
        double = path[path.rfind(".", 0, dot) :]
        for name in _BUILDER:
            provider = get_provider(name)
            if double in provider.extensions:
                return name
    return None
