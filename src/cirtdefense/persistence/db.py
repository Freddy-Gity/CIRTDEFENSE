"""Ouverture de connexion et création du schéma."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    fingerprint   TEXT NOT NULL,
    incident_id   TEXT,
    occurred_at   TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    source        TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    asset_id      TEXT NOT NULL,
    site_id       TEXT NOT NULL,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       TEXT PRIMARY KEY,
    correlation_key   TEXT NOT NULL,
    category          TEXT NOT NULL,
    severity          TEXT NOT NULL,
    status            TEXT NOT NULL,
    risk_score        REAL NOT NULL DEFAULT 0,
    opened_at         TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    closed_at         TEXT,
    asset_criticality INTEGER NOT NULL DEFAULT 3,
    site_id           TEXT NOT NULL,
    payload           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents(correlation_key, status);
CREATE INDEX IF NOT EXISTS idx_incidents_score ON incidents(risk_score DESC);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id  TEXT PRIMARY KEY,
    incident_id  TEXT NOT NULL,
    event_id     TEXT,
    outcome      TEXT NOT NULL,
    decided_at   TEXT NOT NULL,
    payload      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_incident ON decisions(incident_id);

CREATE TABLE IF NOT EXISTS actions (
    action_id      TEXT PRIMARY KEY,
    incident_id    TEXT NOT NULL,
    decision_id    TEXT NOT NULL,
    actuator       TEXT NOT NULL,
    verb           TEXT NOT NULL,
    target         TEXT NOT NULL,
    reversibility  TEXT NOT NULL,
    status         TEXT NOT NULL,
    started_at     TEXT,
    finished_at    TEXT,
    rolled_back_at TEXT,
    payload        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);

-- Journal d'audit : append-only, chaine par empreinte (voir audit/ledger.py).
CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL,
    incident_id TEXT,
    decision_id TEXT,
    action_id   TEXT,
    payload     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);

-- Interdiction explicite de reecrire l'histoire : la contrainte est portee
-- par la base elle-meme et pas seulement par le code applicatif.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'journal d''audit immuable : mise a jour interdite');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'journal d''audit immuable : suppression interdite');
END;

CREATE TABLE IF NOT EXISTS policies (
    policy_id   TEXT NOT NULL,
    version     TEXT NOT NULL,
    checksum    TEXT NOT NULL,
    compiled_at TEXT NOT NULL,
    author      TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 0,
    payload     TEXT NOT NULL,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE IF NOT EXISTS breaker_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    state       TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    changed_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    channel         TEXT NOT NULL,
    incident_id     TEXT,
    action_id       TEXT,
    severity        TEXT NOT NULL,
    acknowledged_at TEXT,
    payload         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_ack ON notifications(acknowledged_at);
"""


def connect(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Transaction explicite : la connexion est en autocommit par défaut."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
