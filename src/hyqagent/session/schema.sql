-- session/schema.sql
-- SQLite schema for HyqAgent session persistence, belief tracking,
-- and checkpoint/resume support.
--
-- See DESIGN-IMPLEMENTATION.md §3.3 Task 6.

-- ── Sessions ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,          -- UUID
    project_path    TEXT NOT NULL,             -- absolute path to audited project
    language        TEXT NOT NULL DEFAULT '',  -- python | javascript | java
    status          TEXT NOT NULL DEFAULT 'running',  -- running | paused | completed | failed
    metadata_json   TEXT NOT NULL DEFAULT '{}',       -- arbitrary JSON blob
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Findings (hypotheses + validation results) ──────────────────────────────

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,          -- UUID
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    vuln_type       TEXT NOT NULL,             -- sql_injection | xss | idor | …
    cwe_id          TEXT NOT NULL DEFAULT '',  -- CWE-89 | CWE-79 | …
    severity        TEXT NOT NULL DEFAULT 'medium',  -- critical | high | medium | low | info
    confidence      REAL NOT NULL DEFAULT 0.0, -- 0.0–1.0
    status          TEXT NOT NULL DEFAULT 'proposed',  -- proposed | investigating | supporting_evidence | refuting_evidence | confirmed | rejected | inconclusive
    title           TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    source_location TEXT NOT NULL DEFAULT '',  -- "file.py:42"
    sink_location   TEXT NOT NULL DEFAULT '',  -- "file.py:128"
    evidence        TEXT NOT NULL DEFAULT '',  -- quoted code snippet
    reasoning       TEXT NOT NULL DEFAULT '',  -- LLM explanation chain
    remediation     TEXT NOT NULL DEFAULT '',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(session_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(session_id, status);

-- ── Checkpoints (for interrupt/resume) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS checkpoints (
    id              TEXT PRIMARY KEY,          -- UUID
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    phase           TEXT NOT NULL,             -- which pipeline phase saved this
    state_json      TEXT NOT NULL,             -- full serialised state blob
    file_count      INTEGER NOT NULL DEFAULT 0,
    endpoint_count  INTEGER NOT NULL DEFAULT 0,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    cost_total      REAL NOT NULL DEFAULT 0.0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_session ON checkpoints(session_id);

-- ── Belief history (Bayesian updates per finding) ───────────────────────────

CREATE TABLE IF NOT EXISTS belief_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    prior           REAL NOT NULL,             -- P(H) before this observation
    likelihood      REAL NOT NULL,             -- P(E|H)
    posterior       REAL NOT NULL,             -- P(H|E) after update
    evidence_summary TEXT NOT NULL DEFAULT '', -- what triggered this update
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_belief_finding ON belief_history(finding_id);
