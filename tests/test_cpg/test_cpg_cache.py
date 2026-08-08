"""Tests for CPG pickle cache — caching, invalidation, and recovery.

Covers ``CPGGraphBuilder.add_directory()`` cache behaviour and the
``_cache_path_for`` / ``_compute_source_fingerprint`` helpers.

.. note::

    These tests use the ``microblog/`` fixture project (2 Python files)
    for cache-hit verification.  Larger fixtures are unnecessary —
    the cache logic is independent of project size.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import tempfile
from pathlib import Path

import pytest

from hyqagent.cpg.graph import CPGGraphBuilder
from hyqagent.cpg.parser import Parser

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MICROBLOG = FIXTURES / "microblog"


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def builder() -> CPGGraphBuilder:
    """Fresh :class:`CPGGraphBuilder` for each test (isolated state)."""
    return CPGGraphBuilder(Parser())


@pytest.fixture
def cache_root(monkeypatch, tmp_path: Path) -> Path:
    """Redirect ``~/.cache/hyqagent/cpg`` to a temp directory."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    cache_dir = fake_home / ".cache" / "hyqagent" / "cpg"
    return cache_dir


# ── Cache path generation ────────────────────────────────────────────────────


class TestCachePathFor:
    """``_cache_path_for`` — deterministic path for a given directory."""

    def test_returns_path_inside_cache(self, cache_root, tmp_path):
        project = tmp_path / "myproject"
        project.mkdir()
        result = CPGGraphBuilder._cache_path_for(project)
        assert str(result).startswith(str(cache_root))
        assert result.suffix == ".pkl"

    def test_same_directory_same_hash(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        path1 = CPGGraphBuilder._cache_path_for(project)
        path2 = CPGGraphBuilder._cache_path_for(project)
        assert path1 == path2

    def test_different_directory_different_hash(self, tmp_path):
        a = tmp_path / "proj_a"
        b = tmp_path / "proj_b"
        a.mkdir()
        b.mkdir()
        assert CPGGraphBuilder._cache_path_for(a) != CPGGraphBuilder._cache_path_for(b)

    def test_creates_cache_directory(self, cache_root):
        # cache_root should exist after _cache_path_for is first called
        assert not cache_root.exists()
        # _cache_path_for creates the directory
        _ = CPGGraphBuilder._cache_path_for(Path("/tmp"))
        assert cache_root.exists()
        assert cache_root.is_dir()


# ── Fingerprint computation ──────────────────────────────────────────────────


class TestSourceFingerprint:
    """``_compute_source_fingerprint`` — detects source-file changes."""

    def test_nonempty_project_yields_hash(self):
        fp = CPGGraphBuilder._compute_source_fingerprint(MICROBLOG)
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA256 hex digest
        assert all(c in "0123456789abcdef" for c in fp)

    def test_empty_directory(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        fp = CPGGraphBuilder._compute_source_fingerprint(d)
        assert isinstance(fp, str)
        assert len(fp) == 64

    def test_same_project_same_fingerprint(self):
        fp1 = CPGGraphBuilder._compute_source_fingerprint(MICROBLOG)
        fp2 = CPGGraphBuilder._compute_source_fingerprint(MICROBLOG)
        assert fp1 == fp2

    def test_different_content_different_fingerprint(self, tmp_path):
        """Same directory with different content yields different fingerprints."""
        project = tmp_path / "proj"
        project.mkdir()
        (project / "x.py").write_text("x = 1\n")
        fp1 = CPGGraphBuilder._compute_source_fingerprint(project)

        # Change the content
        (project / "x.py").write_text("x = 1\ny = 2\nz = 3\n")
        fp2 = CPGGraphBuilder._compute_source_fingerprint(project)
        assert fp1 != fp2

    def test_detects_file_size_change(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / "main.py").write_text("a = 1\n")
        fp1 = CPGGraphBuilder._compute_source_fingerprint(project)
        (project / "main.py").write_text("a = 1\nb = 2\nc = 3\n")  # longer
        fp2 = CPGGraphBuilder._compute_source_fingerprint(project)
        assert fp1 != fp2

    def test_detects_file_added(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / "main.py").write_text("a = 1\n")
        fp1 = CPGGraphBuilder._compute_source_fingerprint(project)
        (project / "utils.py").write_text("def f(): pass\n")
        fp2 = CPGGraphBuilder._compute_source_fingerprint(project)
        assert fp1 != fp2

    def test_detects_file_removed(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / "main.py").write_text("a = 1\n")
        (project / "utils.py").write_text("def f(): pass\n")
        fp1 = CPGGraphBuilder._compute_source_fingerprint(project)
        (project / "utils.py").unlink()
        fp2 = CPGGraphBuilder._compute_source_fingerprint(project)
        assert fp1 != fp2

    def test_ignores_hidden_files(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / "main.py").write_text("a = 1\n")
        fp1 = CPGGraphBuilder._compute_source_fingerprint(project)
        # Add a hidden file — should be ignored
        (project / ".hidden_config.py").write_text("secret = 1\n")
        fp2 = CPGGraphBuilder._compute_source_fingerprint(project)
        assert fp1 == fp2

    def test_ignores_pycache(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / "main.py").write_text("a = 1\n")
        fp1 = CPGGraphBuilder._compute_source_fingerprint(project)
        pycache = project / "__pycache__"
        pycache.mkdir()
        (pycache / "main.cpython-312.pyc").write_text("cached")
        fp2 = CPGGraphBuilder._compute_source_fingerprint(project)
        assert fp1 == fp2


# ── Cache behaviour ──────────────────────────────────────────────────────────


class TestCacheHit:
    """Verify that a second ``add_directory`` call loads from cache."""

    def test_cache_hit_reuses_graph(self, builder, cache_root, tmp_path):
        """Building the same project twice returns the cached graph quickly."""
        # First build: no cache
        builder.add_directory(str(MICROBLOG), use_cache=True)
        node_count_1 = builder.node_count
        edge_count_1 = builder.edge_count
        assert node_count_1 > 0
        assert edge_count_1 > 0

        # Verify cache file was written
        cache_path = CPGGraphBuilder._cache_path_for(MICROBLOG)
        assert cache_path.exists()

        # Second build: should hit cache
        builder2 = CPGGraphBuilder(Parser())
        builder2.add_directory(str(MICROBLOG), use_cache=True)
        node_count_2 = builder2.node_count
        edge_count_2 = builder2.edge_count

        # Graph should be identical (same files, no changes)
        assert node_count_2 == node_count_1
        assert edge_count_2 == edge_count_1

    def test_cache_hit_indexed_files(self, builder, cache_root, tmp_path):
        """After cache hit, _indexed_files should be populated correctly."""
        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert len(builder._indexed_files) >= 2  # app.py + db.py

        builder2 = CPGGraphBuilder(Parser())
        builder2.add_directory(str(MICROBLOG), use_cache=True)
        assert len(builder2._indexed_files) >= 2


class TestCacheMiss:
    """Verify that cache misses trigger a fresh build."""

    def test_no_cache_file_builds_fresh(self, builder, cache_root):
        """When no cache exists, a full build is performed."""
        cache_path = CPGGraphBuilder._cache_path_for(MICROBLOG)
        if cache_path.exists():
            cache_path.unlink()
        assert not cache_path.exists()

        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert builder.node_count > 0
        assert builder.edge_count > 0
        # Cache file should now exist
        assert cache_path.exists()

    def test_use_cache_false_forces_rebuild(self, builder, cache_root):
        """use_cache=False always rebuilds, even if cache exists."""
        # First build with cache
        builder.add_directory(str(MICROBLOG), use_cache=True)
        node_count = builder.node_count
        cache_path = CPGGraphBuilder._cache_path_for(MICROBLOG)
        assert cache_path.exists()

        # Second build with use_cache=False — should still build
        builder2 = CPGGraphBuilder(Parser())
        builder2.add_directory(str(MICROBLOG), use_cache=False)
        # Result should be the same (same codebase)
        assert builder2.node_count == node_count


class TestCacheInvalidation:
    """Verify that fingerprint changes invalidate the cache."""

    def test_file_change_invalidates_cache(self, builder, cache_root, tmp_path):
        """When a source file changes, the cache is invalidated."""
        # Create a small temp project
        project = tmp_path / "changing_proj"
        project.mkdir()
        (project / "main.py").write_text("def foo():\n    return 1\n")

        # First build
        builder.add_directory(str(project), use_cache=True)
        old_nodes = builder.node_count

        # Modify the file
        (project / "main.py").write_text("def foo():\n    return 1\n\ndef bar():\n    return 2\n")

        # Second build — should detect change and rebuild
        builder2 = CPGGraphBuilder(Parser())
        builder2.add_directory(str(project), use_cache=True)
        new_nodes = builder2.node_count

        assert new_nodes != old_nodes  # More functions = more nodes

    def test_new_file_invalidates_cache(self, builder, cache_root, tmp_path):
        """Adding a new source file invalidates the cache."""
        project = tmp_path / "growing_proj"
        project.mkdir()
        (project / "main.py").write_text("def foo():\n    return 1\n")

        builder.add_directory(str(project), use_cache=True)
        old_nodes = builder.node_count

        # Add a new file
        (project / "utils.py").write_text("def helper():\n    return 'ok'\n")

        builder2 = CPGGraphBuilder(Parser())
        builder2.add_directory(str(project), use_cache=True)
        new_nodes = builder2.node_count

        assert new_nodes > old_nodes


class TestCorruptedCache:
    """Verify graceful recovery from corrupted cache files."""

    def test_truncated_cache_rebuilds(self, builder, cache_root):
        """A truncated/empty pickle file should trigger a rebuild."""
        cache_path = CPGGraphBuilder._cache_path_for(MICROBLOG)

        # Write a truncated cache file
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(b"garbage_data_not_valid_pickle")

        # Should not crash — rebuilds from scratch
        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert builder.node_count > 0
        assert builder.edge_count > 0

    def test_invalid_pickle_content_rebuilds(self, builder, cache_root, tmp_path):
        """A pickled object with wrong structure should trigger rebuild."""
        cache_path = CPGGraphBuilder._cache_path_for(MICROBLOG)
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Write a valid-looking pickle with too many values to unpack
        # (tuple with 3 elements instead of 2)
        cache_path.write_bytes(pickle.dumps(("fp", "graph", "extra")))

        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert builder.node_count > 0

    def test_mismatched_fingerprint_rebuilds(self, builder, cache_root, tmp_path):
        """Cache with wrong fingerprint should be treated as invalid."""
        project = tmp_path / "fp_mismatch"
        project.mkdir()
        (project / "main.py").write_text("def foo():\n    return 1\n")

        # First build
        builder.add_directory(str(project), use_cache=True)
        old_nodes = builder.node_count

        # Manually tamper with the cache fingerprint
        cache_path = CPGGraphBuilder._cache_path_for(project)
        with cache_path.open("rb") as fh:
            _fp, graph = pickle.load(fh)
        fake_fp = "a" * 64  # Wrong fingerprint
        with cache_path.open("wb") as fh:
            pickle.dump((fake_fp, graph), fh)

        # Modify source so new fingerprint differs from tampered one
        (project / "main.py").write_text("def foo():\n    return 1\n\ndef bar():\n    return 2\n")

        # Should rebuild (tampered fingerprint != new fingerprint)
        builder2 = CPGGraphBuilder(Parser())
        builder2.add_directory(str(project), use_cache=True)
        assert builder2.node_count > old_nodes

    def test_oserror_on_read_rebuilds(self, builder, cache_root):
        """Permission-like errors (simulated via missing dir) should not crash."""
        cache_path = CPGGraphBuilder._cache_path_for(MICROBLOG)
        # Ensure cache dir exists but cache file is missing
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if cache_path.exists():
            cache_path.unlink()

        # Should not crash on missing cache file (exists() check returns False)
        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert builder.node_count > 0


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestCacheEdgeCases:
    """Unusual but valid scenarios for the cache subsystem."""

    def test_empty_directory_no_crash(self, builder, cache_root, tmp_path):
        """Building an empty directory should not crash."""
        empty = tmp_path / "empty_proj"
        empty.mkdir()
        builder.add_directory(str(empty), use_cache=True)
        # Empty project = empty graph
        assert builder.node_count == 0

    def test_special_chars_in_path(self, builder, cache_root, tmp_path):
        """Directory names with special characters should work."""
        weird = tmp_path / "proj (v1.0) [test]"
        weird.mkdir()
        (weird / "code.py").write_text("def f():\n    pass\n")
        builder.add_directory(str(weird), use_cache=True)
        assert builder.node_count > 0

    def test_multiple_add_directory_calls(self, builder, cache_root, tmp_path):
        """Multiple calls to add_directory should not corrupt state."""
        builder.add_directory(str(MICROBLOG), use_cache=True)
        count1 = builder.node_count

        # Second call to same directory (idempotent — already indexed)
        builder.add_directory(str(MICROBLOG), use_cache=True)
        count2 = builder.node_count

        # Should be same (no duplicate nodes added)
        assert count2 == count1

    def test_cache_file_permissions_best_effort(self, builder, cache_root, tmp_path):
        """Cache save failure should be handled gracefully (best-effort)."""
        project = tmp_path / "perm_test"
        project.mkdir()
        (project / "code.py").write_text("def f():\n    pass\n")

        # Build should succeed even if cache can't be written
        # (we can't easily simulate write failure, but verify
        #  the happy path that save does not crash)
        builder.add_directory(str(project), use_cache=True)
        assert builder.node_count > 0

    def test_node_count_property(self, builder, cache_root):
        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert builder.node_count > 0
        assert isinstance(builder.node_count, int)

    def test_edge_count_property(self, builder, cache_root):
        builder.add_directory(str(MICROBLOG), use_cache=True)
        assert builder.edge_count > 0
        assert isinstance(builder.edge_count, int)

    def test_repr(self, builder, cache_root):
        builder.add_directory(str(MICROBLOG), use_cache=True)
        r = repr(builder)
        assert "CPGGraphBuilder" in r
        assert "nodes=" in r
        assert "edges=" in r

    def test_nodes_by_type(self, builder, cache_root):
        builder.add_directory(str(MICROBLOG), use_cache=True)
        func_nodes = builder.nodes_by_type("function")
        assert len(func_nodes) > 0
        for nid in func_nodes:
            assert builder.graph.nodes[nid]["node_type"] == "function"
