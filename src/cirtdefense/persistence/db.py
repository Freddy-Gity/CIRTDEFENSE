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

-- Conversations avec l'assistant. Elles sont conservees pour que l'analyste
-- retrouve un echange de la veille, pas comme trace opposable : ce qui engage
-- la plateforme est au journal d'audit, qui lui est immuable. Une conversation
-- s'archive et se supprime ; une entree d'audit, jamais.
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id TEXT PRIMARY KEY,
    title           TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL DEFAULT 'echange',
    status          TEXT NOT NULL DEFAULT 'active',
    started_at      TEXT NOT NULL,
    last_activity   TEXT NOT NULL,
    turns           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_conversations_activite
    ON conversations(status, last_activity DESC);

CREATE TABLE IF NOT EXISTS conversation_messages (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    role            TEXT NOT NULL,
    text            TEXT NOT NULL,
    intent          TEXT NOT NULL DEFAULT '',
    at              TEXT NOT NULL,
    payload         TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id)
        ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON conversation_messages(conversation_id, seq);

-- Parc surveille declare a la main par l'administrateur. Le parc de
-- demonstration reste code en dur ; cette table le complete, elle ne le
-- remplace pas, pour qu'une demonstration parte toujours d'un parc non vide.
CREATE TABLE IF NOT EXISTS monitored_targets (
    target_id     TEXT PRIMARY KEY,
    label         TEXT NOT NULL,
    kind          TEXT NOT NULL,
    ip            TEXT NOT NULL,
    segment       TEXT NOT NULL,
    owner         TEXT NOT NULL,
    criticality   INTEGER NOT NULL DEFAULT 3,
    latitude      REAL,
    longitude     REAL,
    declared_at   TEXT NOT NULL,
    declared_by   TEXT NOT NULL DEFAULT ''
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

-- Comptes et separation des roles (CDCF v3.0 : analyste / decideur /
-- administrateur). `kind` fige l'origine du compte (comment il a ete cree),
-- `role` porte les droits effectifs et peut evoluer (analyste -> admin).
CREATE TABLE IF NOT EXISTS users (
    user_id        TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,            -- analyste | decideur | admin
    role           TEXT NOT NULL,            -- analyste | decideur | admin | super_admin
    status         TEXT NOT NULL,            -- pending | active | suspended | refused
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email          TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
    nom            TEXT NOT NULL DEFAULT '',
    prenom         TEXT NOT NULL DEFAULT '',
    civility       TEXT NOT NULL DEFAULT '',  -- Monsieur | Madame | ''
    poste          TEXT NOT NULL DEFAULT '',
    password_hash  TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    validated_by   TEXT NOT NULL DEFAULT '',
    validated_at   TEXT,
    last_login_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Postes ouverts au sein du CIRT/ANTIC. Ceux de type `analyste` alimentent
-- le menu deroulant de l'inscription ; ceux de type `decideur` sont en
-- un-pour-un avec un compte decideur cree par l'administrateur.
CREATE TABLE IF NOT EXISTS postes (
    poste_id   TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,               -- analyste | decideur
    label      TEXT NOT NULL,
    civility   TEXT NOT NULL DEFAULT '',
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_postes_label ON postes(kind, label COLLATE NOCASE);

-- Sessions : la base ne garde que l'empreinte SHA-256 du jeton porteur.
CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    user_agent  TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON user_sessions(expires_at);
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
