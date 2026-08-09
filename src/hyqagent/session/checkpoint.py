"""session/checkpoint.py — Checkpoint save/restore for interrupt-resume.

Supports long-running audits (hours/days) where Ctrl+C or crashes should
not lose progress.  Saves enough state to resume from the exact pipeline
phase without re-running completed work.

See DESIGN-IMPLEMENTATION.md §4.4 and LONG-RUNNING-AGENT-ARCHITECTURE.md §6.1.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class Checkpoint:
    """Snapshot of audit progress at a specific pipeline phase."""

    id: str
    session_id: str
    phase: str  # "phase1_deterministic" | "phase2_understanding" | "phase3_llm" | ...
    state: dict[str, Any] = field(default_factory=dict)
    file_count: int = 0
    endpoint_count: int = 0
    finding_count: int = 0
    cost_total: float = 0.0
    created_at: str = ""

    def to_row(self) -> tuple[str, str, str, str, int, int, int, float, str]:
        """Convert to tuple for SQLite INSERT."""
        return (
            self.id,
            self.session_id,
            self.phase,
            json.dumps(self.state, ensure_ascii=False),
            self.file_count,
            self.endpoint_count,
            self.finding_count,
            self.cost_total,
            self.created_at or datetime.now(UTC).isoformat(),
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Checkpoint:
        """Reconstitute from a SQLite row."""
        return cls(
            id=row["id"],
            session_id=row["session_id"],
            phase=row["phase"],
            state=json.loads(row["state_json"]),
            file_count=row["file_count"] or 0,
            endpoint_count=row["endpoint_count"] or 0,
            finding_count=row["finding_count"] or 0,
            cost_total=row["cost_total"] or 0.0,
            created_at=row["created_at"],
        )


class CheckpointManager:
    """Save and restore checkpoints via SQLite.

    Usage::

        mgr = CheckpointManager(db_path)
        cp = Checkpoint(session_id="s1", phase="phase2_understanding",
                        state={"endpoints_done": 12})
        await mgr.save(cp)

        latest = await mgr.load_latest("s1")
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)

    # ── Public API ───────────────────────────────────────────────────────

    async def save(self, checkpoint: Checkpoint) -> str:
        """Persist a checkpoint. Returns its ID."""
        import asyncio
        return await asyncio.to_thread(self._save_sync, checkpoint)

    async def load_latest(self, session_id: str) -> Checkpoint | None:
        """Load the most recent checkpoint for *session_id*."""
        import asyncio
        return await asyncio.to_thread(self._load_latest_sync, session_id)

    async def list_all(self, session_id: str) -> list[Checkpoint]:
        """Return all checkpoints for *session_id*, oldest first."""
        import asyncio
        return await asyncio.to_thread(self._list_all_sync, session_id)

    async def delete_old(self, session_id: str, keep_latest: int = 5) -> int:
        """Delete old checkpoints for *session_id*, keeping the most recent *keep_latest*.

        Returns the number of deleted checkpoints.
        """
        import asyncio
        return await asyncio.to_thread(self._delete_old_sync, session_id, keep_latest)

    # ── Sync internals ──────────────────────────────────────────────────

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            conn.executescript(schema_path.read_text())
        conn.commit()

    def _save_sync(self, checkpoint: Checkpoint) -> str:
        if not checkpoint.id:
            checkpoint.id = str(uuid.uuid4())
        if not checkpoint.created_at:
            checkpoint.created_at = datetime.now(UTC).isoformat()

        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            conn.execute(
                """INSERT INTO checkpoints
                   (id, session_id, phase, state_json, file_count,
                    endpoint_count, finding_count, cost_total, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                checkpoint.to_row(),
            )
            conn.commit()
        return checkpoint.id

    def _load_latest_sync(self, session_id: str) -> Checkpoint | None:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            row = conn.execute(
                """SELECT * FROM checkpoints
                   WHERE session_id = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (session_id,),
            ).fetchone()
        return Checkpoint.from_row(row) if row else None

    def _list_all_sync(self, session_id: str) -> list[Checkpoint]:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            rows = conn.execute(
                """SELECT * FROM checkpoints
                   WHERE session_id = ?
                   ORDER BY created_at ASC""",
                (session_id,),
            ).fetchall()
        return [Checkpoint.from_row(r) for r in rows]

    def _delete_old_sync(self, session_id: str, keep_latest: int) -> int:
        """Delete all but the most recent *keep_latest* checkpoints for *session_id*."""
        with sqlite3.connect(self._db_path) as conn:
            self._ensure_schema(conn)
            # Find IDs to delete — all except the most recent *keep_latest*
            rows = conn.execute(
                """SELECT id FROM checkpoints
                   WHERE session_id = ?
                   ORDER BY created_at DESC""",
                (session_id,),
            ).fetchall()
            if len(rows) <= keep_latest:
                return 0
            to_delete = [r[0] for r in rows[keep_latest:]]
            conn.executemany(
                "DELETE FROM checkpoints WHERE id = ?",
                [(cid,) for cid in to_delete],
            )
            conn.commit()
            return len(to_delete)
