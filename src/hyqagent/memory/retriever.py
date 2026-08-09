"""memory/retriever.py — Hybrid code retrieval for long-running audit sessions.

Provides three search strategies that complement each other:

1. **Exact** — text/pattern matching (ripgrep → Python re fallback)
   Fast, precise, good for finding exact symbols, strings, patterns.

2. **Structural** — tree-sitter AST queries (reuse cpg/parser + traversal)
   Finds functions, classes, calls by their structural role.

3. **Similarity** — deduplication by code similarity (>85% match → reuse
   prior conclusions). Prevents re-analyzing the same patterns.

Based on LONG-RUNNING-AGENT-ARCHITECTURE.md §2.4:
  ripgrep (exact) + tree-sitter (structural) + Qdrant (semantic, Phase 5)
"""

from __future__ import annotations

import difflib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class CodeChunk:
    """A searchable unit of code, typically a function or method."""

    file_path: str
    function_name: str | None
    start_line: int
    end_line: int
    code: str
    language: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Unique key for dedup: file + function + line range."""
        return f"{self.file_path}:{self.function_name or '<module>'}:{self.start_line}"


@dataclass
class SearchResult:
    """One search hit with score and metadata."""

    chunk: CodeChunk
    score: float  # 0.0 to 1.0
    match_type: str  # "exact" | "structural" | "similarity"
    match_detail: str = ""  # What matched (line, node type, etc.)


# ── CodeRetriever ─────────────────────────────────────────────────────────────


class CodeRetriever:
    r"""Hybrid code search over a set of source files.

    Indexes code at function granularity using tree-sitter AST parsing.
    Provides exact, structural, and similarity-based search.

    Usage::

        retriever = CodeRetriever(file_paths, language="python")
        retriever.build_index()

        # Exact search
        hits = retriever.search_exact(r"request\.args\.get")

        # Structural search
        hits = retriever.search_structural("function_definition", "login")

        # Dedup check — has this code been analyzed before?
        similar = retriever.search_similar(some_code, threshold=0.85)
    """

    def __init__(
        self,
        file_paths: list[str],
        language: str,
        *,
        cache_dir: str | None = None,
    ) -> None:
        self._file_paths = file_paths
        self._language = language
        self._cache_dir = Path(cache_dir) if cache_dir else None

        # Indexes
        self._chunks: dict[str, CodeChunk] = {}  # key → chunk
        self._text_index: dict[str, list[str]] = {}  # lowercase word → chunk keys
        self._function_index: dict[str, str] = {}  # function_name → chunk key
        self._analyzed: set[str] = set()  # chunk keys that have been analyzed

        # File content cache for regex search
        self._file_contents: dict[str, str] = {}

    # ── Index building ────────────────────────────────────────────────────

    def build_index(self) -> int:
        """Parse all files and build function-level index.

        Returns the number of chunks indexed.
        """
        from hyqagent.cpg.parser import Parser

        parser = Parser()
        chunk_count = 0

        for fp in self._file_paths:
            try:
                source = Path(fp).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            self._file_contents[fp] = source

            try:
                tree = parser.parse_code(source, self._language)
            except Exception:  # noqa: S112
                continue

            # Index module-level
            chunk = CodeChunk(
                file_path=fp,
                function_name=None,
                start_line=1,
                end_line=source.count("\n") + 1,
                code=source,
                language=self._language,
                metadata={"scope": "module"},
            )
            self._chunks[chunk.key] = chunk
            self._index_text(chunk)
            chunk_count += 1

            # Extract functions
            try:
                functions = parser.extract_functions(tree, self._language)
            except Exception:
                functions = []

            for func in functions:
                fn_name = getattr(func, "name", None)
                if not fn_name:
                    continue

                start = getattr(func, "start_line", 1)
                end = getattr(func, "end_line", start)
                lines = source.split("\n")
                code = "\n".join(lines[start - 1 : end]) if start <= len(lines) else ""

                chunk = CodeChunk(
                    file_path=fp,
                    function_name=fn_name,
                    start_line=start,
                    end_line=end,
                    code=code,
                    language=self._language,
                    metadata={
                        "scope": "function",
                        "params": getattr(func, "params", []),
                        "return_type": getattr(func, "return_type", None),
                    },
                )
                self._chunks[chunk.key] = chunk
                self._index_text(chunk)
                self._function_index[fn_name] = chunk.key
                chunk_count += 1

        return chunk_count

    def _index_text(self, chunk: CodeChunk) -> None:
        """Index lowercase words from chunk code for exact search."""
        words = set(re.findall(r"\w+", chunk.code.lower()))
        for word in words:
            if len(word) < 3:  # skip very short tokens
                continue
            if word not in self._text_index:
                self._text_index[word] = []
            if chunk.key not in self._text_index[word]:
                self._text_index[word].append(chunk.key)

    # ── Exact search ──────────────────────────────────────────────────────

    def search_exact(self, pattern: str) -> list[SearchResult]:
        """Search for a literal string or regex pattern.

        Uses ``ripgrep`` when available, falls back to Python ``re``.
        """
        results: list[SearchResult] = []

        # Try ripgrep first
        try:
            rg_hits = self._rg_search(pattern)
            if rg_hits:
                return rg_hits
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

        # Python re fallback
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            compiled = re.compile(re.escape(pattern), re.IGNORECASE)

        for fp, source in self._file_contents.items():
            for match in compiled.finditer(source):
                line_no = source[: match.start()].count("\n") + 1
                matched_text = match.group()[:120]

                # Find which chunk contains this line
                for chunk in self._chunks.values():
                    if chunk.file_path == fp and chunk.start_line <= line_no <= chunk.end_line:
                        results.append(
                            SearchResult(
                                chunk=chunk,
                                score=1.0,
                                match_type="exact",
                                match_detail=f"L{line_no}: {matched_text}",
                            )
                        )
                        break

        return self._dedup_results(results)

    def _rg_search(self, pattern: str) -> list[SearchResult]:
        """Search via ripgrep subprocess."""
        result = subprocess.run(  # noqa: S603
            ["rg", "--no-heading", "--line-number", "--color=never", pattern, *self._file_paths],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode not in (0, 1):  # 0=matches, 1=no matches
            return []

        results: list[SearchResult] = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            # rg output: file:line:text
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            fp, line_str, matched = parts
            try:
                line_no = int(line_str)
            except ValueError:
                continue

            # Find containing chunk
            for chunk in self._chunks.values():
                if chunk.file_path == fp and chunk.start_line <= line_no <= chunk.end_line:
                    results.append(
                        SearchResult(
                            chunk=chunk,
                            score=1.0,
                            match_type="exact",
                            match_detail=f"L{line_no}: {matched[:120]}",
                        )
                    )
                    break

        return self._dedup_results(results)

    # ── Structural search ─────────────────────────────────────────────────

    def search_structural(self, node_type: str, name: str | None = None) -> list[SearchResult]:
        """Search for code structures by AST node type and optional name.

        *node_type* examples: ``function_definition``, ``class_declaration``,
        ``call_expression``, ``import_statement``.

        *name*: if provided, only return nodes matching this identifier.
        """
        results: list[SearchResult] = []

        # Direct function name lookup (fast path)
        if name and node_type == "function_definition":
            key = self._function_index.get(name)
            if key and key in self._chunks:
                chunk = self._chunks[key]
                return [
                    SearchResult(
                        chunk=chunk,
                        score=1.0,
                        match_type="structural",
                        match_detail=f"function {name} @ {chunk.file_path}:{chunk.start_line}",
                    )
                ]

        # Tree-sitter fallback for broader structural queries
        from hyqagent.cpg.parser import Parser

        parser = Parser()
        for fp, source in self._file_contents.items():
            try:
                tree = parser.parse_code(source, self._language)
            except Exception:  # noqa: S112
                continue
            from hyqagent.cpg.traversal import Traverser

            traverser = Traverser(tree)
            matches = traverser.find_all(
                node_type=lambda n: n.type == node_type,
            )

            for node in matches:
                node_name = getattr(node, "name", None) or ""
                if name and name not in node_name:
                    continue

                line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 1

                # Find containing chunk
                for chunk in self._chunks.values():
                    if chunk.file_path == fp and chunk.start_line <= line_no <= chunk.end_line:
                        results.append(
                            SearchResult(
                                chunk=chunk,
                                score=0.9,
                                match_type="structural",
                                match_detail=f"{node_type} '{node_name}' @ {fp}:{line_no}",
                            )
                        )
                        break

        return self._dedup_results(results)

    # ── Similarity search (dedup) ─────────────────────────────────────────

    def search_similar(
        self,
        code: str,
        threshold: float = 0.85,
        max_results: int = 10,
    ) -> list[SearchResult]:
        """Find code chunks similar to *code* (deduplication).

        Uses ``difflib.SequenceMatcher`` for ratio-based comparison.
        Returns chunks with similarity >= *threshold*, sorted by score descending.
        """
        results: list[SearchResult] = []
        limit = min(max_results * 3, len(self._chunks))  # coarse filter limit

        for chunk in list(self._chunks.values())[:limit]:
            ratio = difflib.SequenceMatcher(None, code, chunk.code).ratio()
            if ratio >= threshold:
                results.append(
                    SearchResult(
                        chunk=chunk,
                        score=ratio,
                        match_type="similarity",
                        match_detail=f"{ratio:.0%} similar to {chunk.key}",
                    )
                )

        # Sort by score descending, limit
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:max_results]

    # ── Analysis tracking ─────────────────────────────────────────────────

    def mark_analyzed(self, chunk_key: str) -> None:
        """Mark a code chunk as having been analyzed."""
        self._analyzed.add(chunk_key)

    def is_analyzed(self, chunk_key: str) -> bool:
        """Check if a code chunk has already been analyzed."""
        return chunk_key in self._analyzed

    def find_related(self, chunk: CodeChunk) -> list[CodeChunk]:
        """Find code chunks related to *chunk* (same file, callers, callees)."""
        related: list[CodeChunk] = []

        # Same file
        for c in self._chunks.values():
            if c.file_path == chunk.file_path and c.key != chunk.key:
                related.append(c)

        return related

    # ── Accessors ─────────────────────────────────────────────────────────

    @property
    def chunk_count(self) -> int:
        """Number of code chunks in the index."""
        return len(self._chunks)

    @property
    def analyzed_count(self) -> int:
        """Number of code chunks that have been marked as analyzed."""
        return len(self._analyzed)

    def get_chunk(self, key: str) -> CodeChunk | None:
        """Retrieve a chunk by its key."""
        return self._chunks.get(key)

    def get_chunks_for_file(self, file_path: str) -> list[CodeChunk]:
        """Get all chunks belonging to a file."""
        return [c for c in self._chunks.values() if c.file_path == file_path]

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _dedup_results(results: list[SearchResult]) -> list[SearchResult]:
        """Deduplicate results by chunk key, keeping highest score."""
        seen: dict[str, SearchResult] = {}
        for r in results:
            key = r.chunk.key
            if key not in seen or r.score > seen[key].score:
                seen[key] = r
        return sorted(seen.values(), key=lambda r: r.score, reverse=True)
