"""cpg/cfg.py — Control Flow Graph builder at the Basic Block level.

Builds a CFG for each function in the parsed tree, producing a flat list of
:class:`BasicBlock` instances and a list of :class:`CFGEdge` records.  The
algorithm operates entirely at the tree-sitter AST level — it does not depend
on NetworkX.

Architecture
------------
The builder walks the function body **recursively**, maintaining a
*current block* accumulator.  When it encounters a control-flow construct
(``if``, ``for``, ``while``, ``try``, …) it:

1. Terminates the current block (the condition / loop header ends a block).
2. Recursively processes each branch body — the caller wires the correct
   edge kind (``branch_true``, ``branch_false``, ``exception``) rather than
   relying on post-hoc re-labelling.
3. Creates a *merge block* for the code that follows the construct (if
   reachable from any branch).

Break / continue resolution
----------------------------
The builder maintains a **loop-nesting stack** that records the current
loop-header and loop-exit block IDs.  When a ``break`` or ``continue`` is
encountered the edge is wired to the appropriate block on the stack.

Limitations (by design — see the CFG plan)
------------------------------------------
* No ``with_statement`` or ``match_statement`` special handling.
* No ``switch`` fallthrough precision (Java / JS).
* Exception edges are coarse: try body → each handler + finalizer.
* Cross-function CFG is not built (every function is self-contained).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hyqagent.cpg.types import BasicBlock

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

    from hyqagent.cpg.languages.base import LanguageProvider

logger = structlog.get_logger(__name__)

# ── CFG edge representation ────────────────────────────────────────────────


class CFGEdge:
    """A single control-flow edge between two basic blocks.

    Attributes:
        source_id: The ``block_id`` of the source block.
        target_id: The ``block_id`` of the target block.
        kind: Edge kind — ``"fallthrough"``, ``"branch_true"``,
              ``"branch_false"``, ``"loop_back"``, ``"exception"``,
              or ``"return"``.

    """

    __slots__ = ("kind", "source_id", "target_id")

    def __init__(self, source_id: str, target_id: str, kind: str) -> None:
        self.source_id = source_id
        self.target_id = target_id
        self.kind = kind

    def __repr__(self) -> str:
        return f"CFGEdge({self.source_id!r} -[{self.kind}]→ {self.target_id!r})"


# ── Dominance Analysis ─────────────────────────────────────────────────────


class DominanceAnalyzer:
    """Compute dominators, post-dominators, and control dependence.

    All methods work on primitive dictionaries of sets — they are
    independent of NetworkX, tree-sitter, and the rest of the CPG.
    This makes them trivially testable and reusable outside graph.py.

    Usage::

        dom = DominanceAnalyzer.compute_dominators(block_ids, preds, entry_id)
        pd  = DominanceAnalyzer.compute_post_dominators(block_ids, succs, exit_ids)
        cd  = DominanceAnalyzer.compute_control_dependence(block_ids, succs, pd)
    """

    @staticmethod
    def compute_dominators(
        block_ids: set[str],
        preds: dict[str, set[str]],
        entry_id: str,
    ) -> dict[str, set[str]]:
        """Iterative dominator computation (Cooper-Harvey-Kennedy 2001 style).

        Returns ``{block_id: set_of_dominator_ids}``.
        """
        if not block_ids:
            return {}
        all_blocks = block_ids
        dom: dict[str, set[str]] = {b: set(all_blocks) for b in all_blocks}
        if entry_id in dom:
            dom[entry_id] = {entry_id}

        changed = True
        while changed:
            changed = False
            for b in sorted(all_blocks):
                if b == entry_id:
                    continue
                if preds.get(b):
                    new_dom: set[str] = set(all_blocks)
                    for p in preds[b]:
                        new_dom &= dom.get(p, set())
                    new_dom.add(b)
                else:
                    new_dom = {b}
                if new_dom != dom[b]:
                    dom[b] = new_dom
                    changed = True
        return dom

    @staticmethod
    def compute_post_dominators(
        block_ids: set[str],
        succs: dict[str, set[str]],
        exit_ids: set[str],
    ) -> dict[str, set[str]]:
        """Compute post-dominators by reversing the CFG.

        Post-dominator: block P **post-dominates** block B if every path
        from B to an exit block must go through P.  This is just dominator
        computation on the reversed CFG with a virtual EXIT node.
        """
        if not block_ids:
            return {}
        all_blocks = block_ids
        # Virtual exit node that connects all real exit blocks
        virtual_exit = "__virtual_exit__"
        rev_preds: dict[str, set[str]] = {b: set(succs.get(b, set())) for b in all_blocks}
        rev_preds[virtual_exit] = set(exit_ids)
        for exit_id in exit_ids:
            rev_preds.setdefault(exit_id, set()).add(virtual_exit)

        all_with_virtual = all_blocks | {virtual_exit}
        pd: dict[str, set[str]] = {b: set(all_with_virtual) for b in all_with_virtual}
        pd[virtual_exit] = {virtual_exit}

        changed = True
        while changed:
            changed = False
            for b in sorted(all_with_virtual):
                if b == virtual_exit:
                    continue
                if rev_preds.get(b):
                    new_pd: set[str] = set(all_with_virtual)
                    for p in rev_preds[b]:
                        new_pd &= pd.get(p, set())
                    new_pd.add(b)
                else:
                    new_pd = {b}
                if new_pd != pd[b]:
                    pd[b] = new_pd
                    changed = True

        # Remove virtual exit from result
        result: dict[str, set[str]] = {}
        for b in all_blocks:
            result[b] = pd[b] - {virtual_exit}
        return result

    @staticmethod
    def _build_ipd_tree(
        dom: dict[str, set[str]],
    ) -> dict[str, str | None]:
        """Build immediate-(post-)dominator tree from dominator sets.

        Returns ``{block_id: immediate_dominator_id | None}``.
        The entry node's IPD is ``None``.
        """
        ipd: dict[str, str | None] = {}
        for b, doms in dom.items():
            strict = doms - {b}
            if not strict:
                ipd[b] = None
            else:
                # The immediate dominator is the unique node in strict
                # that dominates all other nodes in strict.
                candidates = set(strict)
                for d1 in list(candidates):
                    for d2 in list(candidates):
                        if d1 != d2 and d1 in dom.get(d2, set()):
                            candidates.discard(d2)
                ipd[b] = candidates.pop() if len(candidates) == 1 else None
        return ipd

    @staticmethod
    def compute_control_dependence(
        block_ids: set[str],
        succs: dict[str, set[str]],
        post_dom: dict[str, set[str]],
    ) -> dict[str, set[str]]:
        """Compute control-dependence sets via post-dominance frontier.

        **Block L is control-dependent on block B** if B has at least two
        successors and L post-dominates one successor of B but not B
        itself.  This captures the standard definition: B is a decision
        point that determines whether L executes.

        Returns ``{block_id: set_of_controlling_block_ids}``.
        In other words: ``cd[L] = {B | L is control-dependent on B}``.
        """
        ipd = DominanceAnalyzer._build_ipd_tree(post_dom)

        cd: dict[str, set[str]] = {b: set() for b in block_ids}

        for b in block_ids:
            successors = succs.get(b, set())
            # Only branch nodes (≥2 successors) can be control-dependence sources.
            # Single-successor nodes only have fallthrough — no decision.
            if len(successors) < 2:
                continue

            for s in successors:
                # Walk up the post-dominator tree from s
                runner = s
                while runner is not None and runner != ipd.get(b):
                    # runner is control-dependent on b
                    cd.setdefault(runner, set()).add(b)
                    runner = ipd.get(runner)
                    if runner == b:
                        break

        return cd


# ── Builder ────────────────────────────────────────────────────────────────


class CFGBuilder:
    """Build a Basic-Block CFG for every function in a parse tree.

    Usage::

        builder = CFGBuilder(provider)
        blocks, edges = builder.build_cfg(tree, func_node, file_path)

    The returned *blocks* and *edges* are ready for ingestion by
    :class:`~hyqagent.cpg.graph.CPGGraphBuilder`.
    """

    def __init__(self, provider: LanguageProvider) -> None:
        self._provider = provider
        self._block_counter = 0
        self._func_name = ""
        self._file_path = ""
        # loop-nesting stack: (loop_header_block_id, loop_exit_block_id)
        self._loop_stack: list[tuple[str, str]] = []

    # ── Public API ────────────────────────────────────────────────────

    def build_cfg(
        self, tree: Tree, func_node: Node, file_path: str
    ) -> tuple[list[BasicBlock], list[CFGEdge]]:
        """Build the CFG for a single function.

        Every function produces at least an entry block and an exit block,
        so the returned lists are never empty.
        """
        self._block_counter = 0
        self._loop_stack.clear()
        self._func_name = self._resolve_func_name(func_node)
        self._file_path = file_path

        body = func_node.child_by_field_name("body")
        if body is None:
            return self._build_empty_cfg()

        blocks: list[BasicBlock] = []
        edges: list[CFGEdge] = []

        # Create entry + exit blocks upfront
        entry = self._new_block("entry")
        blocks.append(entry)
        exit_block = self._new_block("exit")
        blocks.append(exit_block)

        stmts = self._collect_statements(body)
        if not stmts:
            edges.append(CFGEdge(entry.block_id, exit_block.block_id, "fallthrough"))
            return blocks, edges

        # Process the top-level statement sequence.
        _live = self._process_stmt_sequence(
            body,
            entry.block_id,
            exit_block.block_id,
            blocks,
            edges,
            entry_edge_kind="fallthrough",
        )

        # Connect any remaining live blocks to exit
        visited_targets: set[str] = set()
        for e in edges:
            visited_targets.add(e.target_id)
        for b in blocks:
            if b.block_type not in ("entry", "exit") and b.block_id not in visited_targets:
                # Orphaned block — wire to exit
                pass  # Let query-time analysis handle orphans

        return blocks, edges

    # ── Statement collection ──────────────────────────────────────────

    def _collect_statements(self, block_node: Node) -> list[Node]:
        """Return ordered executable-statement children of *block_node*."""
        return [c for c in block_node.named_children if c.type in self._provider.statement_types]

    # ── Recursive statement-sequence processor ────────────────────────

    def _process_stmt_sequence(
        self,
        block_node: Node,
        entry_block_id: str,
        exit_block_id: str,
        blocks: list[BasicBlock],
        edges: list[CFGEdge],
        *,
        entry_edge_kind: str | None = None,
    ) -> list[str]:
        """Process the statement children of *block_node* in order.

        Parameters
        ----------
        entry_edge_kind:
            When not ``None``, an edge of this kind is created from
            *entry_block_id* to the first statement's block.
            Use ``"fallthrough"`` for the top-level function body,
            ``"branch_true"`` / ``"branch_false"`` for if/else branches,
            ``"exception"`` for except handlers, etc.

        Returns
        -------
        list[str]
            Block IDs that *fall through* to whatever follows this sequence.
            Empty list = all paths terminated by an unconditional jump.

        """
        stmts = self._collect_statements(block_node)
        if not stmts:
            if entry_edge_kind is not None:
                edges.append(CFGEdge(entry_block_id, exit_block_id, entry_edge_kind))
            return [entry_block_id]

        current: str | None = None  # current-block accumulator
        live: list[str] = []  # block IDs that reach end-of-sequence

        for i, stmt in enumerate(stmts):
            # Is this a fresh block start?
            if current is None:
                current = self._new_block("normal").block_id
                blocks.append(
                    BasicBlock(
                        block_id=current,
                        file_path=self._file_path,
                        enclosing_function=self._func_name,
                        start_line=stmt.start_point[0] + 1,
                        end_line=stmt.end_point[0] + 1,
                        statements=[],
                        block_type="normal",
                    )
                )
                # Wire predecessors → this new block
                if i == 0 and entry_edge_kind is not None:
                    edges.append(CFGEdge(entry_block_id, current, entry_edge_kind))
                else:
                    for pred_id in dedup(live):
                        edges.append(CFGEdge(pred_id, current, "fallthrough"))
                    live.clear()

            # Append statement source text to current block
            self._append_to_block(current, stmt, blocks)

            if self._is_terminator(stmt):
                # Unconditional jump — wire to the correct target.
                # Check BEFORE control_flow_node_types because
                # return/break/continue/raise/throw are in both sets.
                target_id = self._resolve_jump_target(
                    stmt,
                    current,
                    exit_block_id,
                )
                kind = _TERMINATOR_EDGE_KIND.get(stmt.type, "fallthrough")
                edges.append(CFGEdge(current, target_id, kind))
                current = None
                # live stays empty — nothing after this continues

            elif stmt.type in self._provider.control_flow_node_types:
                # Structural control-flow construct (if/for/while/try/switch):
                # stop accumulating, delegate to the specialised handler,
                # then the merge block becomes the next "live" source.
                new_live = self._process_ctrl_stmt(
                    stmt,
                    current,
                    exit_block_id,
                    blocks,
                    edges,
                )
                current = None
                live.extend(new_live)

            else:
                # Plain statement — the block continues
                live.append(current)

        # End of sequence: the last block (if still open) and the live
        # predecessors are the fallthrough exits.
        result: list[str] = []
        if current is not None:
            result.append(current)
        result.extend(live)

        # Wire remaining blocks to exit if this is the top-level
        if entry_edge_kind is not None and result:
            for bid in dedup(result):
                edges.append(CFGEdge(bid, exit_block_id, "fallthrough"))

        return dedup(result)

    # ── Control-flow dispatcher ───────────────────────────────────────

    def _process_ctrl_stmt(
        self,
        node: Node,
        header_block_id: str,
        exit_block_id: str,
        blocks: list[BasicBlock],
        edges: list[CFGEdge],
    ) -> list[str]:
        """Dispatch on *node.type* and return merge-block successors."""
        ntype = node.type
        targets = self._provider.get_branch_targets(node)

        if ntype == "if_statement":
            return self._process_if(node, header_block_id, targets, blocks, edges, exit_block_id)
        elif ntype in (
            "for_statement",
            "while_statement",
            "do_statement",
            "enhanced_for_statement",
            "for_in_statement",
        ):
            return self._process_loop(node, header_block_id, targets, blocks, edges, exit_block_id)
        elif ntype == "try_statement":
            return self._process_try(node, header_block_id, targets, blocks, edges, exit_block_id)
        elif ntype in ("switch_statement", "switch_expression"):
            return self._process_switch(
                node, header_block_id, targets, blocks, edges, exit_block_id
            )
        else:
            logger.debug("Unhandled CF node — pass-through", node_type=ntype)
            return [header_block_id]

    # ── If / else ─────────────────────────────────────────────────────

    def _process_if(
        self,
        node: Node,
        header_block_id: str,
        targets: dict,
        blocks: list[BasicBlock],
        edges: list[CFGEdge],
        exit_block_id: str,
    ) -> list[str]:
        consequence: Node | None = targets.get("consequence")
        alternative: Node | None = targets.get("alternative")

        merge = self._new_block("normal")
        blocks.append(
            BasicBlock(
                block_id=merge.block_id,
                file_path=self._file_path,
                enclosing_function=self._func_name,
                start_line=node.end_point[0] + 1,
                end_line=node.end_point[0] + 1,
                block_type="normal",
            )
        )

        # Then branch
        if consequence is not None:
            then_live = self._process_stmt_sequence(
                consequence,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="branch_true",
            )
            # Wire then-branch tails → merge as fallthrough
            for bid in then_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))
        else:
            edges.append(CFGEdge(header_block_id, merge.block_id, "branch_true"))

        # Else branch
        if alternative is not None:
            else_live = self._process_stmt_sequence(
                alternative,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="branch_false",
            )
            for bid in else_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))
        else:
            edges.append(CFGEdge(header_block_id, merge.block_id, "branch_false"))

        # Also wire header→merge as branch_false if no alternative
        return [merge.block_id]

    # ── Loops ─────────────────────────────────────────────────────────

    def _process_loop(
        self,
        node: Node,
        header_block_id: str,
        targets: dict,
        blocks: list[BasicBlock],
        edges: list[CFGEdge],
        exit_block_id: str,
    ) -> list[str]:
        body: Node | None = targets.get("body")
        alternative: Node | None = targets.get("alternative")

        merge = self._new_block("normal")
        blocks.append(
            BasicBlock(
                block_id=merge.block_id,
                file_path=self._file_path,
                enclosing_function=self._func_name,
                start_line=node.end_point[0] + 1,
                end_line=node.end_point[0] + 1,
                block_type="normal",
            )
        )

        # Push loop context for break / continue resolution
        self._loop_stack.append((header_block_id, merge.block_id))

        if body is not None:
            body_live = self._process_stmt_sequence(
                body,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="branch_true",
            )

            # Back-edges: body tail blocks → header
            for bid in body_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, header_block_id, "loop_back"))
        else:
            edges.append(CFGEdge(header_block_id, merge.block_id, "branch_true"))

        # Header → merge = branch_false (loop exit)
        if not _has_edge(edges, header_block_id, merge.block_id):
            edges.append(CFGEdge(header_block_id, merge.block_id, "branch_false"))

        self._loop_stack.pop()

        live = [merge.block_id]

        # Python for-else / while-else
        if alternative is not None:
            else_live = self._process_stmt_sequence(
                alternative,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="fallthrough",
            )
            # The else clause is entered via the header as well (loop
            # completed normally)
            # We don't re-label; the else body already has edges from header
            for bid in else_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))
            live.extend(else_live)

        return live

    # ── Try / except ──────────────────────────────────────────────────

    def _process_try(
        self,
        node: Node,
        header_block_id: str,
        targets: dict,
        blocks: list[BasicBlock],
        edges: list[CFGEdge],
        exit_block_id: str,
    ) -> list[str]:
        body: Node | None = targets.get("body")
        handlers: list[Node] = targets.get("handlers", []) or []
        finalizer: Node | None = targets.get("finalizer")

        merge = self._new_block("normal")
        blocks.append(
            BasicBlock(
                block_id=merge.block_id,
                file_path=self._file_path,
                enclosing_function=self._func_name,
                start_line=node.end_point[0] + 1,
                end_line=node.end_point[0] + 1,
                block_type="normal",
            )
        )

        if body is not None:
            body_live = self._process_stmt_sequence(
                body,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="fallthrough",
            )
            for bid in body_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))

        for handler in handlers:
            hdr_live = self._process_stmt_sequence(
                handler,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="exception",
            )
            for bid in hdr_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))

        if finalizer is not None:
            fin_live = self._process_stmt_sequence(
                finalizer,
                header_block_id,
                merge.block_id,
                blocks,
                edges,
                entry_edge_kind="fallthrough",
            )
            for bid in fin_live:
                if bid != merge.block_id:
                    edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))

        return [merge.block_id]

    # ── Switch ────────────────────────────────────────────────────────

    def _process_switch(
        self,
        node: Node,
        header_block_id: str,
        targets: dict,
        blocks: list[BasicBlock],
        edges: list[CFGEdge],
        exit_block_id: str,
    ) -> list[str]:
        merge = self._new_block("normal")
        blocks.append(
            BasicBlock(
                block_id=merge.block_id,
                file_path=self._file_path,
                enclosing_function=self._func_name,
                start_line=node.end_point[0] + 1,
                end_line=node.end_point[0] + 1,
                block_type="normal",
            )
        )

        body: Node | None = targets.get("body")
        if body is not None:
            for case_child in body.named_children:
                case_body = case_child.child_by_field_name(
                    "consequence"
                ) or case_child.child_by_field_name("body")
                if case_body is not None:
                    case_live = self._process_stmt_sequence(
                        case_body,
                        header_block_id,
                        merge.block_id,
                        blocks,
                        edges,
                        entry_edge_kind="branch_true",
                    )
                    for bid in case_live:
                        if bid != merge.block_id:
                            edges.append(CFGEdge(bid, merge.block_id, "fallthrough"))

        if not _has_edge(edges, header_block_id, merge.block_id):
            edges.append(CFGEdge(header_block_id, merge.block_id, "branch_false"))
        return [merge.block_id]

    # ── Block helpers ─────────────────────────────────────────────────

    def _new_block(self, block_type: str) -> BasicBlock:
        """Create an empty block with a unique ID (does NOT add to list)."""
        idx = self._block_counter
        self._block_counter += 1
        return BasicBlock(
            block_id=f"bb:{self._file_path}:{self._func_name}:{idx}",
            file_path=self._file_path,
            enclosing_function=self._func_name,
            start_line=0,
            end_line=0,
            statements=[],
            block_type=block_type,
        )

    def _append_to_block(
        self,
        block_id: str,
        stmt: Node,
        blocks: list[BasicBlock],
    ) -> None:
        """Append *stmt* source text to the block identified by *block_id*."""
        source = stmt.text.decode("utf-8") if stmt.text else ""
        stmt_start = stmt.start_point[0] + 1
        stmt_end = stmt.end_point[0] + 1

        for b in blocks:
            if b.block_id == block_id:
                b.statements.append(source)
                if b.start_line == 0:
                    b.start_line = stmt_start
                b.end_line = stmt_end
                return

        logger.warning("Appending to unknown block", block_id=block_id)

    # ── Terminator helpers ────────────────────────────────────────────

    def _is_terminator(self, node: Node) -> bool:
        """Return ``True`` if *node* unconditionally transfers control."""
        return node.type in _JUMP_NODE_TYPES

    def _resolve_jump_target(
        self,
        node: Node,
        current_block_id: str,
        exit_block_id: str,
    ) -> str:
        """Return the target block ID for an unconditional jump."""
        ntype = node.type
        if ntype in ("return_statement", "raise_statement", "throw_statement"):
            return exit_block_id
        if ntype == "break_statement" and self._loop_stack:
            _hdr, loop_exit = self._loop_stack[-1]
            return loop_exit
        if ntype == "continue_statement" and self._loop_stack:
            loop_hdr, _exit = self._loop_stack[-1]
            return loop_hdr
        return exit_block_id

    # ── Empty function ────────────────────────────────────────────────

    def _build_empty_cfg(
        self,
    ) -> tuple[list[BasicBlock], list[CFGEdge]]:
        """Trivial entry → exit CFG for a function with no body."""
        entry = BasicBlock(
            block_id=f"bb:{self._file_path}:{self._func_name}:0",
            file_path=self._file_path,
            enclosing_function=self._func_name,
            start_line=0,
            end_line=0,
            block_type="entry",
        )
        exit_b = BasicBlock(
            block_id=f"bb:{self._file_path}:{self._func_name}:1",
            file_path=self._file_path,
            enclosing_function=self._func_name,
            start_line=0,
            end_line=0,
            block_type="exit",
        )
        edge = CFGEdge(entry.block_id, exit_b.block_id, "fallthrough")
        return [entry, exit_b], [edge]

    @staticmethod
    def _resolve_func_name(func_node: Node) -> str:
        name_node = func_node.child_by_field_name("name")
        if name_node is not None and name_node.text:
            return name_node.text.decode("utf-8")
        return f"<anonymous:{func_node.start_point[0] + 1}>"


# ── Module-level helpers ───────────────────────────────────────────────────

# Tree-sitter node types that represent unconditional jumps.
_JUMP_NODE_TYPES: set[str] = {
    "return_statement",
    "break_statement",
    "continue_statement",
    "raise_statement",
    "throw_statement",
}

# Mapping from jump node type → CFG edge kind.
_TERMINATOR_EDGE_KIND: dict[str, str] = {
    "return_statement": "return",
    "raise_statement": "return",
    "throw_statement": "return",
    "break_statement": "fallthrough",  # resolved by loop stack
    "continue_statement": "fallthrough",  # resolved by loop stack
}


def dedup(items: list[str]) -> list[str]:
    """Deduplicate a list of strings while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            result.append(it)
    return result


def _has_edge(
    edges: list[CFGEdge],
    source_id: str,
    target_id: str,
) -> bool:
    """Return ``True`` if an edge *source_id* → *target_id* already exists."""
    return any(e.source_id == source_id and e.target_id == target_id for e in edges)
