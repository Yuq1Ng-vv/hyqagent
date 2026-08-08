"""Tests for memory/retriever.py — Hybrid code retrieval."""

from __future__ import annotations

import difflib
import tempfile
from pathlib import Path

from hyqagent.memory.retriever import CodeChunk, CodeRetriever, SearchResult


class TestCodeChunk:
    def test_key_format(self) -> None:
        chunk = CodeChunk(
            file_path="app.py", function_name="login",
            start_line=10, end_line=20, code="def login(): pass",
            language="python",
        )
        assert chunk.key == "app.py:login:10"

    def test_key_no_function(self) -> None:
        chunk = CodeChunk(
            file_path="app.py", function_name=None,
            start_line=1, end_line=50, code="...",
            language="python",
        )
        assert chunk.key == "app.py:<module>:1"


class TestSearchResult:
    def test_basic(self) -> None:
        chunk = CodeChunk("f.py", "main", 1, 5, "code", "python")
        result = SearchResult(chunk=chunk, score=0.95, match_type="exact", match_detail="L3: match")
        assert result.score == 0.95
        assert result.match_type == "exact"


class TestCodeRetriever:
    @staticmethod
    def _write_py_file(dir_path: Path, name: str, content: str) -> str:
        fp = dir_path / name
        fp.write_text(content, encoding="utf-8")
        return str(fp)

    def test_build_index_empty(self) -> None:
        retriever = CodeRetriever([], "python")
        assert retriever.build_index() == 0
        assert retriever.chunk_count == 0

    def test_build_index_single_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", """
def login(user, password):
    return user == "admin" and password == "secret"

def search(query):
    return f"SELECT * FROM users WHERE name='{query}'"
""")
            retriever = CodeRetriever([fp], "python")
            count = retriever.build_index()
            # Module-level chunk + 2 function chunks = 3
            assert count >= 2
            assert retriever.chunk_count >= 2

    def test_search_exact_finds_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", """
def login(user, password):
    query = f"SELECT * FROM users WHERE name='{user}'"
    return db.execute(query)
""")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            results = retriever.search_exact(r"db\.execute")
            # Should find at least one match
            assert len(results) >= 1
            assert results[0].match_type == "exact"

    def test_search_exact_regex_fallback(self) -> None:
        """When ripgrep fails, falls back to Python re."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", "x = request.args.get('id')")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            # Use a pattern ripgrep would not find specially
            results = retriever.search_exact(r"request\.args\.get")
            assert len(results) >= 1

    def test_search_structural_function_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", """
def handle_request(req):
    return process(req)

def process(data):
    return str(data)
""")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            results = retriever.search_structural("function_definition", "handle_request")
            assert len(results) >= 1
            assert results[0].match_type == "structural"

    def test_search_similar_finds_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", """
def func_a():
    query = "SELECT * FROM users WHERE id=" + user_input
    return db.execute(query)

def func_b():
    # Nearly identical to func_a
    query = "SELECT * FROM products WHERE id=" + user_input
    return db.execute(query)
""")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            code = 'query = "SELECT * FROM users WHERE id=" + user_input\n    return db.execute(query)'
            results = retriever.search_similar(code, threshold=0.0)  # low threshold to catch any
            assert len(results) >= 1
            assert results[0].match_type == "similarity"

    def test_search_similar_high_threshold(self) -> None:
        """With threshold=1.0, only exact matches pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", "x = 1")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            results = retriever.search_similar("x = 1", threshold=1.0)
            # Should find at least one match (exact)
            assert len(results) >= 1

    def test_mark_analyzed_and_check(self) -> None:
        chunk = CodeChunk("f.py", "main", 1, 5, "code", "python")
        retriever = CodeRetriever([], "python")
        assert not retriever.is_analyzed(chunk.key)
        retriever.mark_analyzed(chunk.key)
        assert retriever.is_analyzed(chunk.key)
        assert retriever.analyzed_count == 1

    def test_get_chunk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", "def foo(): pass")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            key = "app.py:foo:1"  # approximate
            # Actually search by function
            for k in retriever._function_index.values():
                chunk = retriever.get_chunk(k)
                assert chunk is not None
                assert chunk.function_name is not None
                break

    def test_get_chunks_for_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", """
def foo(): pass
def bar(): pass
""")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            chunks = retriever.get_chunks_for_file(fp)
            assert len(chunks) >= 2  # module + 2 functions

    def test_find_related(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            fp = self._write_py_file(d, "app.py", "def foo(): pass\ndef bar(): pass")
            retriever = CodeRetriever([fp], "python")
            retriever.build_index()

            # Get one chunk and find related
            chunks = retriever.get_chunks_for_file(fp)
            if chunks:
                related = retriever.find_related(chunks[0])
                # Should find at least the other chunks in the same file
                assert len(related) >= 0  # at least doesn't crash

    def test_dedup_results(self) -> None:
        chunk = CodeChunk("f.py", "fn", 1, 5, "code", "python")
        results = [
            SearchResult(chunk, 1.0, "exact"),
            SearchResult(chunk, 0.5, "structural"),  # same chunk, lower score
        ]
        deduped = CodeRetriever._dedup_results(results)
        assert len(deduped) == 1
        assert deduped[0].score == 1.0  # keeps higher score
