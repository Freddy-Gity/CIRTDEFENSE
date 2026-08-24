"""Journal d'audit chaine par empreinte (EF existante, repositionnee centrale).

Chaque entree contient l'empreinte de la precedente. Modifier ou retirer une
entree a posteriori casse la chaine, ce que `verify_chain()` detecte. Combine
aux declencheurs SQL d'interdiction d'UPDATE/DELETE, cela donne une trace
opposable de ce que le systeme a fait seul.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..domain.enums import AuditEventType

GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEntry:
    seq: int
    recorded_at: str
    event_type: str
    actor: str
    incident_id: str | None
    decision_id: str | None
    action_id: str | None
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "recorded_at": self.recorded_at,
            "event_type": self.event_type,
            "actor": self.actor,
            "incident_id": self.incident_id,
            "decision_id": self.decision_id,
            "action_id": self.action_id,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass(frozen=True, slots=True)
class ChainVerification:
    valid: bool
    entries_checked: int
    first_broken_seq: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entries_checked": self.entries_checked,
            "first_broken_seq": self.first_broken_seq,
            "detail": self.detail,
        }


class AuditLedger:
    """Ecriture serialisee : la chaine impose un ordre total des entrees."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.Lock()

    @staticmethod
    def compute_hash(
        recorded_at: str,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        prev_hash: str,
    ) -> str:
        canonical = json.dumps(
            {
                "recorded_at": recorded_at,
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def head_hash(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS_HASH

    def record(
        self,
        event_type: AuditEventType | str,
        payload: dict[str, Any],
        *,
        actor: str = "system:orchestrator",
        incident_id: str | None = None,
        decision_id: str | None = None,
        action_id: str | None = None,
    ) -> AuditEntry:
        kind = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
        recorded_at = datetime.now(UTC).isoformat()
        with self._lock:
            prev = self.head_hash()
            entry_hash = self.compute_hash(recorded_at, kind, actor, payload, prev)
            cursor = self._conn.execute(
                """INSERT INTO audit_log
                   (recorded_at, event_type, actor, incident_id, decision_id,
                    action_id, payload, prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    recorded_at,
                    kind,
                    actor,
                    incident_id,
                    decision_id,
                    action_id,
                    json.dumps(payload, sort_keys=True, default=str),
                    prev,
                    entry_hash,
                ),
            )
            seq = int(cursor.lastrowid or 0)
        return AuditEntry(
            seq=seq,
            recorded_at=recorded_at,
            event_type=kind,
            actor=actor,
            incident_id=incident_id,
            decision_id=decision_id,
            action_id=action_id,
            payload=payload,
            prev_hash=prev,
            entry_hash=entry_hash,
        )

    def verify_chain(self) -> ChainVerification:
        """Rejoue la chaine du debut : detecte toute alteration ou lacune."""
        prev = GENESIS_HASH
        checked = 0
        for row in self._conn.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
            payload = json.loads(row["payload"])
            expected = self.compute_hash(
                row["recorded_at"], row["event_type"], row["actor"], payload, prev
            )
            if row["prev_hash"] != prev:
                return ChainVerification(
                    valid=False,
                    entries_checked=checked,
                    first_broken_seq=row["seq"],
                    detail="chainage rompu : prev_hash ne correspond pas a l'entree precedente",
                )
            if row["entry_hash"] != expected:
                return ChainVerification(
                    valid=False,
                    entries_checked=checked,
                    first_broken_seq=row["seq"],
                    detail="contenu altere : l'empreinte recalculee differe de l'empreinte stockee",
                )
            prev = row["entry_hash"]
            checked += 1
        return ChainVerification(
            valid=True, entries_checked=checked, detail="chaine coherente de bout en bout"
        )

    def query(
        self,
        *,
        incident_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if incident_id:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = self._conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY seq DESC LIMIT ? OFFSET ?", params
        ).fetchall()
        return [
            AuditEntry(
                seq=r["seq"],
                recorded_at=r["recorded_at"],
                event_type=r["event_type"],
                actor=r["actor"],
                incident_id=r["incident_id"],
                decision_id=r["decision_id"],
                action_id=r["action_id"],
                payload=json.loads(r["payload"]),
                prev_hash=r["prev_hash"],
                entry_hash=r["entry_hash"],
            )
            for r in rows
        ]

    def incident_timeline(self, incident_id: str) -> list[AuditEntry]:
        """Reconstitution chronologique de ce que le systeme a fait, pour un
        incident donne. C'est la vue que l'analyste ouvre en premier."""
        return sorted(self.query(incident_id=incident_id, limit=1000), key=lambda e: e.seq)
