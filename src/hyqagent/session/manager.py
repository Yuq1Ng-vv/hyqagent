"""session/manager.py — SQLite-backed session persistence.

Implements :class:`AuditRepository` from ``core.protocols`` with
sync-sqlite3 + asyncio.to_thread (consistent with project's async-for-I/O
philosophy — SQLite is local, no network I/O).

See DESIGN-IMPLEMENTATION.md §3.3 Task 6.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hyqagent.core.protocols import (
    AuditRepository,
    FindingSeverity,
    HypothesisStatus,
    VulnerabilityHypothesis,
)


class SessionManager(AuditRepository):
    """SQLite-backed session + finding store.

    Usage::

        mgr = SessionManager(Path("~/.hyqagent/sessions.db").expanduser())
        sid = await mgr.save_session({"project": "myapp", "language": "python"})
        fid = await mgr.save_finding(sid, hypothesis)
        findings = await mgr.get_findings(sid, severity=FindingSeverity.HIGH)
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

    # ── Session CRUD ────────────────────────────────────────────────────────

    async def save_session(self, session: dict[str, Any]) -> str:
        """Persist a session dict. Returns the session ID."""
        import asyncio

        return await asyncio.to_thread(self._save_session_sync, session)

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Load a session by ID, or ``None``."""
        import asyncio

        return await asyncio.to_thread(self._get_session_sync, session_id)

    async def list_sessions(
        self, status: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """List recent sessions, optionally filtered by status."""
        import asyncio

        return await asyncio.to_thread(self._list_sessions_sync, status, limit)

    async def update_session_status(self, session_id: str, status: str) -> None:
        """Transition a session to a new status."""
        import asyncio

        await asyncio.to_thread(self._update_status_sync, session_id, status)

    # ── Finding CRUD ────────────────────────────────────────────────────────

    async def save_finding(self, session_id: str, hypothesis: VulnerabilityHypothesis) -> str:
        """Store a finding and return its ID."""
        import asyncio

        return await asyncio.to_thread(self._save_finding_sync, session_id, hypothesis)

    async def get_findings(
        self,
        session_id: str,
        severity: FindingSeverity | None = None,
    ) -> list[VulnerabilityHypothesis]:
        """Retrieve findings for *session_id*, optionally filtered by severity."""
        import asyncio

        return await asyncio.to_thread(self._get_findings_sync, session_id, severity)

    async def update_hypothesis_status(
        self, hypothesis_id: str, status: HypothesisStatus, confidence: float
    ) -> None:
        """Update a hypothesis's status and confidence."""
        import asyncio

        await asyncio.to_thread(
            self._update_hypothesis_sync, hypothesis_id, status.value, confidence
        )

    async def get_finding_count(self, session_id: str) -> int:
        """Return total finding count for a session."""
        import asyncio

        return await asyncio.to_thread(self._get_finding_count_sync, session_id)

    # ── Belief tracking ─────────────────────────────────────────────────────

    async def record_belief_update(
        self,
        finding_id: str,
        prior: float,
        likelihood: float,
        posterior: float,
        evidence_summary: str = "",
    ) -> None:
        """Record a Bayesian belief update for audit trail."""
        import asyncio

        await asyncio.to_thread(
            self._record_belief_sync,
            finding_id,
            prior,
            likelihood,
            posterior,
            evidence_summary,
        )

    # ── Sync internals ──────────────────────────────────────────────────────

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            conn.executescript(schema_path.read_text())
        conn.commit()

    def _save_session_sync(self, session: dict[str, Any]) -> str:
        sid = session.get("id") or str(uuid.uuid4())
        project_path = session.get("project_path", "")
        language = session.get("language", "")
        meta = session.get("metadata", session.get("metadata_json", {}))
        if not isinstance(meta, str):
            meta = json.dumps(meta, ensure_ascii=False)

        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            conn.execute(
                """INSERT OR REPLACE INTO sessions
                   (id, project_path, language, status, metadata_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    sid,
                    project_path,
                    language,
                    session.get("status", "running"),
                    meta,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
        return sid

    def _get_session_sync(self, session_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "project_path": row["project_path"],
            "language": row["language"],
            "status": row["status"],
            "metadata": json.loads(row["metadata_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _list_sessions_sync(self, status: str | None, limit: int) -> list[dict[str, Any]]:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            if status:
                rows = conn.execute(
                    """SELECT * FROM sessions WHERE status = ?
                       ORDER BY updated_at DESC LIMIT ?""",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [
            {
                "id": r["id"],
                "project_path": r["project_path"],
                "language": r["language"],
                "status": r["status"],
                "metadata": json.loads(r["metadata_json"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def _update_status_sync(self, session_id: str, status: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            self._ensure_schema(conn)
            conn.execute(
                "UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?",
                (status, datetime.now(UTC).isoformat(), session_id),
            )
            conn.commit()

    def _save_finding_sync(self, session_id: str, hypothesis: VulnerabilityHypothesis) -> str:
        fid = hypothesis.id or str(uuid.uuid4())

        # Extract source/sink as "file:line" strings
        src_loc = (
            f"{hypothesis.source.file_path}:{hypothesis.source.start_line}"
            if hypothesis.source
            else ""
        )
        snk_loc = (
            f"{hypothesis.sink.file_path}:{hypothesis.sink.start_line}" if hypothesis.sink else ""
        )

        # Serialize evidence chain
        evidence_str = json.dumps(hypothesis.evidence_chain, ensure_ascii=False)

        # Serialize data flow path as metadata
        df_path = [
            {
                "source": str(d.source) if hasattr(d, "source") else str(d),
                "sink": str(d.sink) if hasattr(d, "sink") else "",
                "label": getattr(d, "label", ""),
            }
            for d in hypothesis.data_flow_path
        ]
        meta = {
            "data_flow_path": df_path,
            "evidence_chain": hypothesis.evidence_chain,
        }
        meta_json = json.dumps(meta, ensure_ascii=False)

        with sqlite3.connect(self._db_path) as conn:
            self._ensure_schema(conn)
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, session_id, vuln_type, cwe_id, severity, confidence,
                    status, title, description, source_location, sink_location,
                    evidence, reasoning, remediation, metadata_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fid,
                    session_id,
                    hypothesis.vuln_type or "",
                    hypothesis.cwe_id or "",
                    hypothesis.severity.value,
                    hypothesis.confidence,
                    hypothesis.status.value,
                    hypothesis.title,
                    hypothesis.description,
                    src_loc,
                    snk_loc,
                    evidence_str,
                    "",  # reasoning — not a field on VulnerabilityHypothesis
                    hypothesis.remediation,
                    meta_json,
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
        return fid

    def _get_findings_sync(
        self,
        session_id: str,
        severity: FindingSeverity | None,
    ) -> list[VulnerabilityHypothesis]:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            self._ensure_schema(conn)
            if severity:
                rows = conn.execute(
                    """SELECT * FROM findings
                       WHERE session_id = ? AND severity = ?
                       ORDER BY confidence DESC""",
                    (session_id, severity.value),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM findings
                       WHERE session_id = ?
                       ORDER BY confidence DESC""",
                    (session_id,),
                ).fetchall()
        return [self._row_to_hypothesis(r) for r in rows]

    def _get_finding_count_sync(self, session_id: str) -> int:
        with sqlite3.connect(self._db_path) as conn:
            self._ensure_schema(conn)
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM findings WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return row[0] if row else 0

    def _update_hypothesis_sync(self, hypothesis_id: str, status: str, confidence: float) -> None:
        with sqlite3.connect(self._db_path) as conn:
            self._ensure_schema(conn)
            conn.execute(
                """UPDATE findings
                   SET status = ?, confidence = ?, updated_at = ?
                   WHERE id = ?""",
                (status, confidence, datetime.now(UTC).isoformat(), hypothesis_id),
            )
            conn.commit()

    def _record_belief_sync(
        self,
        finding_id: str,
        prior: float,
        likelihood: float,
        posterior: float,
        evidence_summary: str,
    ) -> None:
        with sqlite3.connect(self._db_path) as conn:
            self._ensure_schema(conn)
            conn.execute(
                """INSERT INTO belief_history
                   (finding_id, prior, likelihood, posterior, evidence_summary)
                   VALUES (?, ?, ?, ?, ?)""",
                (finding_id, prior, likelihood, posterior, evidence_summary),
            )
            conn.commit()

    @staticmethod
    def _row_to_hypothesis(row: sqlite3.Row) -> VulnerabilityHypothesis:
        from hyqagent.core.protocols import CodeLocation

        meta = json.loads(row["metadata_json"]) if isinstance(row["metadata_json"], str) else {}

        # Parse "file:line" strings back to CodeLocation
        def _parse_loc(raw: str) -> CodeLocation | None:
            if not raw or ":" not in raw:
                return None
            file_part, _, line_part = raw.rpartition(":")
            try:
                return CodeLocation(
                    file_path=file_part,
                    start_line=int(line_part),
                    end_line=int(line_part),
                    function_name="",
                )
            except (ValueError, TypeError):
                return None

        return VulnerabilityHypothesis(
            id=row["id"],
            vuln_type=row["vuln_type"],
            cwe_id=row["cwe_id"] or None,
            severity=FindingSeverity(row["severity"]),
            confidence=row["confidence"],
            title=row["title"],
            description=row["description"],
            source=_parse_loc(row["source_location"]),
            sink=_parse_loc(row["sink_location"]),
            status=HypothesisStatus(row["status"]),
            evidence_chain=meta.get("evidence_chain", []),
            remediation=row["remediation"],
        )
