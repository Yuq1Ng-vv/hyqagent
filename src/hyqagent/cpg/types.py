"""cpg/types.py — Shared data types for CPG analysis.

Extracted from ``parser.py`` so that both ``parser.py`` and
``languages/base.py`` can import them without circular dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FunctionNode:
    """Represents a function or method definition."""

    name: str
    start_line: int
    end_line: int
    source: str
    params: list[str] = field(default_factory=list)
    is_method: bool = False
    class_name: str | None = None
    decorators: list[str] = field(default_factory=list)
    return_type: str | None = None
    docstring: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("FunctionNode.name must be non-empty")
        if self.start_line < 1:
            raise ValueError(
                f"FunctionNode.start_line must be >= 1, got {self.start_line}"
            )


@dataclass
class ClassNode:
    """Represents a class definition."""

    name: str
    start_line: int
    end_line: int
    source: str
    methods: list[FunctionNode] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("ClassNode.name must be non-empty")
        if self.start_line < 1:
            raise ValueError(
                f"ClassNode.start_line must be >= 1, got {self.start_line}"
            )


@dataclass
class ImportNode:
    """Represents an import statement."""

    module: str
    start_line: int
    names: list[str] = field(default_factory=list)
    is_relative: bool = False
    alias: str | None = None
    source: str = ""

    def __post_init__(self) -> None:
        if self.start_line < 0:
            raise ValueError(
                f"ImportNode.start_line must be >= 0, got {self.start_line}"
            )
