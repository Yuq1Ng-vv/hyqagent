"""cpg/frameworks — Web framework route extractors.

Each supported framework implements :class:`BaseFrameworkExtractor`.
Adding a new framework means creating one file in this package and
registering it below — zero changes to the CPG graph or query layer.

Supported frameworks: Flask, Django, FastAPI, Express, Spring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hyqagent.cpg.frameworks.base import BaseFrameworkExtractor
    from hyqagent.cpg.parser import Parser

# Registry: framework_name → extractor class (lazy via builder functions)
_EXTRACTOR_BUILDERS: dict[str, "type[BaseFrameworkExtractor]"] = {}


def _register(name: str, builder: "type[BaseFrameworkExtractor]") -> None:
    _EXTRACTOR_BUILDERS[name] = builder


def get_extractor(name: str, parser: "Parser") -> "BaseFrameworkExtractor":
    """Get a framework extractor instance by name."""
    cls = _EXTRACTOR_BUILDERS.get(name)
    if cls is None:
        available = ", ".join(sorted(_EXTRACTOR_BUILDERS))
        raise ValueError(
            f"Unknown framework: {name!r}. Available: {available}"
        )
    return cls(parser)


def available_frameworks() -> list[str]:
    """Return sorted list of registered framework names."""
    return sorted(_EXTRACTOR_BUILDERS)


# ── Register built-in extractors ──────────────────────────────────────────

from hyqagent.cpg.frameworks.flask import FlaskExtractor  # noqa: E402
from hyqagent.cpg.frameworks.django import DjangoExtractor  # noqa: E402
from hyqagent.cpg.frameworks.fastapi import FastAPIExtractor  # noqa: E402
from hyqagent.cpg.frameworks.express import ExpressExtractor  # noqa: E402
from hyqagent.cpg.frameworks.spring import SpringExtractor  # noqa: E402

_register("flask", FlaskExtractor)
_register("django", DjangoExtractor)
_register("fastapi", FastAPIExtractor)
_register("express", ExpressExtractor)
_register("spring", SpringExtractor)
