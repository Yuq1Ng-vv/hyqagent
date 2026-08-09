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
            raise ValueError(f"FunctionNode.start_line must be >= 1, got {self.start_line}")


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
            raise ValueError(f"ClassNode.start_line must be >= 1, got {self.start_line}")


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
            raise ValueError(f"ImportNode.start_line must be >= 0, got {self.start_line}")


# ── Data-flow types (used by cpg/dataflow.py) ───────────────────────────


@dataclass
class DefUsePair:
    """A single definition → multiple uses of a variable within a function.

    Attributes:
        var_name: The variable name being tracked.
        def_location: Human-readable location of the definition (``"file.py:42"``).
        def_expression: Source code of the definition statement.
        use_locations: All use-site locations sorted by line number.

    """

    var_name: str
    def_location: str
    def_expression: str = ""
    use_locations: list[str] = field(default_factory=list)


@dataclass
class DataFlowStep:
    """One step in a data-flow path.

    Attributes:
        location: ``"file.py:42"`` style location string.
        expression: The relevant source code at this step.
        enclosing_function: Name of the function containing this step.
        kind: Role of this step — ``"assignment"``, ``"call_arg"``,
              ``"return"``, or ``"parameter"``.

    """

    location: str
    expression: str = ""
    enclosing_function: str = ""
    kind: str = "assignment"


@dataclass
class TaintPath:
    """A complete taint-propagation path from source to sink.

    Attributes:
        source: Human-readable description of the taint source.
        sink: Human-readable description of the taint sink.
        variable: The tainted variable being tracked.
        steps: Ordered list of data-flow steps from source to sink.
        sanitized: ``True`` if at least one sanitizer was encountered.
        sanitizers: Names or patterns of sanitizers on the path.

    """

    source: str
    sink: str
    variable: str = ""
    steps: list[DataFlowStep] = field(default_factory=list)
    sanitized: bool = False
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class TaintConfig:
    """Configuration for taint analysis — which patterns are sources / sinks / sanitizers.

    Patterns are matched against the source text of AST nodes using
    simple substring matching.  For example, a source of ``"request.args.get"``
    will match any node whose text contains that substring.
    """

    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)


# ── Control-flow types (used by cpg/cfg.py) ──────────────────────────────


@dataclass
class BasicBlock:
    """A maximal straight-line sequence of statements — the unit of a CFG.

    Attributes:
        block_id: Unique identifier, typically ``"bb_<func_id>_<index>"``.
        file_path: Source file containing this block.
        enclosing_function: Name of the function this block belongs to.
        start_line: 1-indexed line of the block's first statement.
        end_line: 1-indexed line of the block's last statement.
        statements: Source text of each statement in this block, in order.
        block_type: Semantic role — ``"entry"``, ``"exit"``, ``"normal"``,
                    ``"branch"``, or ``"loop_header"``.

    """

    block_id: str
    file_path: str
    enclosing_function: str
    start_line: int
    end_line: int
    statements: list[str] = field(default_factory=list)
    block_type: str = "normal"

    def __post_init__(self) -> None:
        if not self.block_id:
            raise ValueError("BasicBlock.block_id must be non-empty")
        if self.start_line < 0:
            raise ValueError(f"BasicBlock.start_line must be >= 0, got {self.start_line}")


# ── Discovery / coverage types (used by cpg/discovery.py, cpg/coverage.py) ──


@dataclass
class HeuristicSink:
    """A potential sink discovered via heuristic scoring rather than YAML rules.

    Attributes:
        node_id: The NetworkX node ID in the CPG graph.
        file_path: Source file containing this node.
        line: 1-indexed line number.
        expression: The source expression text (e.g. ``"cursor.execute("``).
        score: Heuristic risk score (0-100).
        matched_keywords: Which dangerous keywords were detected.
        reachable_from_source: ``True`` if a user-input source can reach this
            node via CPG edges.

    """

    node_id: str
    file_path: str
    line: int
    expression: str
    score: int = 0
    matched_keywords: list[str] = field(default_factory=list)
    reachable_from_source: bool = False


@dataclass
class ExposedEndpoint:
    """An HTTP endpoint that has no known taint-source coverage.

    These are high-priority candidates for manual IDOR / business-logic review.
    """

    endpoint: str  # e.g. "GET /api/orders/:id"
    handler_func: str  # e.g. "get_order"
    file_path: str
    line: int


@dataclass
class UncoveredSink:
    """A potential sink (function call) that has no taint_category label.

    Listed in the blind-spot manifest so the user knows what was *not* analysed.
    """

    node_id: str
    file_path: str
    line: int
    expression: str
    reason: str = ""  # e.g. "no_known_rule", "sink_in_unreachable_block"


@dataclass
class CoverageReport:
    """Snapshot of what the analyser covered (and what it didn't).

    Generated by :class:`CoverageTracker` after a scan completes.
    """

    endpoint_total: int = 0
    endpoint_analyzed: int = 0
    endpoint_coverage_ratio: float = 0.0
    sink_total: int = 0
    sink_labeled: int = 0
    sink_coverage_ratio: float = 0.0
    blind_spots: list[BlindSpot] = field(default_factory=list)


@dataclass
class BlindSpot:
    """A single entry in the blind-spot manifest — something the scan did not cover.

    Included in every report so the user has visibility into what was missed.
    """

    location: str  # "file.py:42"
    reason: str  # "endpoint_has_no_known_source"
    recommendation: str = ""
    severity: str = "medium"
