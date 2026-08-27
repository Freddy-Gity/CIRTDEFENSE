"""Dépôts : seul endroit du code qui connaît le SQL."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from ..domain.action import ActionResult
from ..domain.decision import Decision
from ..domain.enums import IncidentStatus, Severity
from ..domain.events import DetectionEvent
from ..domain.incident import Incident
from ..domain.policy import ResponsePolicy

__all__ = [
    "EventRepository",
    "IncidentRepository",
    "DecisionRepository",
    "ActionRepository",
    "PolicyRepository",
    "BreakerRepository",
    "NotificationRepository",
    "MonitoredTargetRepository",
    "ConversationRepository",
    "UserRepository",
    "PosteRepository",
    "SessionRepository",
]


class EventRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def exists_fingerprint(self, fingerprint: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM events WHERE fingerprint = ? LIMIT 1", (fingerprint,)
        ).fetchone()
        return row is not None

    def save(self, event: DetectionEvent, incident_id: str | None = None) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO events
               (event_id, fingerprint, incident_id, occurred_at, received_at, source,
                category, severity, confidence, asset_id, site_id, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.fingerprint(),
                incident_id,
                event.occurred_at.isoformat(),
                event.received_at.isoformat(),
                event.source.value,
                event.category,
                event.severity.value,
                event.confidence,
                event.asset.asset_id,
                event.site_id,
                event.to_json(),
            ),
        )

    def get(self, event_id: str) -> DetectionEvent | None:
        row = self._conn.execute(
            "SELECT payload FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        return DetectionEvent.from_dict(json.loads(row["payload"])) if row else None

    def recent(self, limit: int = 50) -> list[DetectionEvent]:
        rows = self._conn.execute(
            "SELECT payload FROM events ORDER BY received_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [DetectionEvent.from_dict(json.loads(r["payload"])) for r in rows]

    def for_asset(self, asset_id: str, limit: int = 200) -> list[DetectionEvent]:
        rows = self._conn.execute(
            "SELECT payload FROM events WHERE asset_id = ? ORDER BY received_at DESC LIMIT ?",
            (asset_id, limit),
        ).fetchall()
        return [DetectionEvent.from_dict(json.loads(r["payload"])) for r in rows]


class IncidentRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, incident: Incident) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO incidents
               (incident_id, correlation_key, category, severity, status, risk_score,
                opened_at, updated_at, closed_at, asset_criticality, site_id, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.incident_id,
                incident.correlation_key,
                incident.category,
                incident.severity.value,
                incident.status.value,
                incident.risk_score(),
                incident.opened_at.isoformat(),
                incident.updated_at.isoformat(),
                incident.closed_at.isoformat() if incident.closed_at else None,
                incident.asset_criticality,
                incident.site_id,
                json.dumps(incident.to_dict(), default=str),
            ),
        )

    def find_open_by_key(self, correlation_key: str) -> Incident | None:
        row = self._conn.execute(
            """SELECT payload FROM incidents
               WHERE correlation_key = ? AND status IN ('open', 'contained')
               ORDER BY updated_at DESC LIMIT 1""",
            (correlation_key,),
        ).fetchone()
        return self._rehydrate(row) if row else None

    def get(self, incident_id: str) -> Incident | None:
        row = self._conn.execute(
            "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return self._rehydrate(row) if row else None

    def portfolio(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        """Portefeuille priorise (Axe 4) : lecture directe, sans rehydratation."""
        query = "SELECT payload FROM incidents"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY risk_score DESC, updated_at DESC LIMIT ?"
        params.append(limit)
        return [json.loads(r["payload"]) for r in self._conn.execute(query, params)]

    def _rehydrate(self, row: sqlite3.Row) -> Incident:
        """Recharge l'incident et rattache ses événements et actions.

        Le `payload` porte l'état de synthèse ; les collections viennent de
        leurs tables propres pour rester la source de verite.
        """
        data = json.loads(row["payload"])
        incident = Incident(
            incident_id=data["incident_id"],
            correlation_key=data["correlation_key"],
            category=data["category"],
            severity=Severity(data["severity"]),
            status=IncidentStatus(data["status"]),
            opened_at=datetime.fromisoformat(data["opened_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            closed_at=datetime.fromisoformat(data["closed_at"]) if data["closed_at"] else None,
            asset_criticality=data["asset_criticality"],
            site_id=data["site_id"],
            labels=data.get("labels", {}),
            # La classification doit survivre au rechargement : sans ces
            # champs, tout incident re-sauvegarde après une annulation
            # perdait son type, sa famille et sa priorité, et disparaissait
            # des répartitions du portefeuille et des rapports.
            attack_code=data.get("attack_code", ""),
            attack_label=data.get("attack_label", ""),
            family=data.get("family", ""),
            family_label=data.get("family_label", ""),
            dangerousness=data.get("dangerousness", 0.0),
            priority=data.get("priority", ""),
            priority_rank=data.get("priority_rank", 0),
        )
        rows = self._conn.execute(
            "SELECT payload FROM events WHERE incident_id = ? ORDER BY received_at ASC",
            (incident.incident_id,),
        ).fetchall()
        incident.events = [DetectionEvent.from_dict(json.loads(r["payload"])) for r in rows]
        incident.actions = ActionRepository(self._conn).for_incident(incident.incident_id)
        return incident


class DecisionRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, decision: Decision) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO decisions
               (decision_id, incident_id, event_id, outcome, decided_at, payload)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                decision.decision_id,
                decision.incident_id,
                decision.event_id,
                decision.outcome.value,
                decision.decided_at.isoformat(),
                json.dumps(decision.to_dict(), default=str),
            ),
        )

    def for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload FROM decisions WHERE incident_id = ? ORDER BY decided_at ASC",
            (incident_id,),
        ).fetchall()
        return [json.loads(r["payload"]) for r in rows]


class ActionRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, result: ActionResult) -> None:
        spec = result.spec
        self._conn.execute(
            """INSERT OR REPLACE INTO actions
               (action_id, incident_id, decision_id, actuator, verb, target,
                reversibility, status, started_at, finished_at, rolled_back_at, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.action_id,
                result.incident_id,
                result.decision_id,
                spec.actuator if spec else "",
                spec.verb if spec else "",
                spec.target if spec else "",
                spec.reversibility.value if spec else "",
                result.status.value,
                result.started_at.isoformat() if result.started_at else None,
                result.finished_at.isoformat() if result.finished_at else None,
                result.rolled_back_at.isoformat() if result.rolled_back_at else None,
                json.dumps(result.to_dict(), default=str),
            ),
        )

    def get(self, action_id: str) -> ActionResult | None:
        row = self._conn.execute(
            "SELECT payload FROM actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        return _action_from_payload(json.loads(row["payload"])) if row else None

    def for_incident(self, incident_id: str) -> list[ActionResult]:
        rows = self._conn.execute(
            "SELECT payload FROM actions WHERE incident_id = ? ORDER BY rowid ASC",
            (incident_id,),
        ).fetchall()
        return [_action_from_payload(json.loads(r["payload"])) for r in rows]

    def count_since(self, statuses: tuple[str, ...], since: datetime) -> int:
        """Compteur servant au coupe-circuit (EF-26)."""
        placeholders = ",".join("?" for _ in statuses)
        row = self._conn.execute(
            f"""SELECT COUNT(*) AS n FROM actions
                WHERE status IN ({placeholders})
                  AND COALESCE(rolled_back_at, finished_at, started_at) >= ?""",
            (*statuses, since.isoformat()),
        ).fetchone()
        return int(row["n"])

    def status_counts(self) -> dict[str, int]:
        """Répartition globale par statut, lue depuis la table des actions.

        Le portefeuille ne doit pas déduire ces chiffrés de l'instantané
        stocke avec l'incident : cet instantané est fige au moment de
        l'exécution et ignore les annulations survenues ensuite.
        """
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM actions GROUP BY status"
        ).fetchall()
        return {r["status"]: int(r["n"]) for r in rows}

    def status_counts_by_incident(self) -> dict[str, dict[str, int]]:
        rows = self._conn.execute(
            "SELECT incident_id, status, COUNT(*) AS n FROM actions GROUP BY incident_id, status"
        ).fetchall()
        counts: dict[str, dict[str, int]] = {}
        for row in rows:
            counts.setdefault(row["incident_id"], {})[row["status"]] = int(row["n"])
        return counts

    def executed_reversible(self, limit: int = 200) -> list[ActionResult]:
        rows = self._conn.execute(
            """SELECT payload FROM actions
               WHERE status = 'executed' AND reversibility != 'irreversible'
               ORDER BY rowid DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [_action_from_payload(json.loads(r["payload"])) for r in rows]


def _action_from_payload(data: dict[str, Any]) -> ActionResult:
    from ..domain.action import ActionSpec
    from ..domain.enums import ActionStatus, Reversibility

    reversibility = Reversibility(data["reversibility"]) if data.get("reversibility") else None
    spec = None
    if data.get("verb"):
        rollback_verb = data.get("rollback_verb")
        if reversibility is not Reversibility.IRREVERSIBLE and not rollback_verb:
            # Reconstitution : le verbe d'annulation est déduit par convention
            # `un<verbe>` uniquement pour re-hydrater une trace existante.
            rollback_verb = f"un{data['verb']}"
        spec = ActionSpec(
            verb=data["verb"],
            actuator=data["actuator"],
            target=data["target"],
            parameters=data.get("parameters", {}),
            reversibility=reversibility or Reversibility.IRREVERSIBLE,
            rollback_verb=rollback_verb,
        )
    result = ActionResult(
        action_id=data["action_id"],
        spec=spec,
        incident_id=data.get("incident_id", ""),
        decision_id=data.get("decision_id", ""),
        status=ActionStatus(data["status"]),
        output=data.get("output", {}),
        error=data.get("error"),
        rollback_token=data.get("rollback_token"),
        rollback_reason=data.get("rollback_reason"),
        rollback_actor=data.get("rollback_actor", ""),
    )
    for field_name in ("started_at", "finished_at", "rolled_back_at"):
        raw = data.get(field_name)
        if raw:
            setattr(result, field_name, datetime.fromisoformat(raw))
    return result


class PolicyRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, policy: ResponsePolicy, activate: bool = True) -> None:
        payload = json.dumps(policy.to_dict(), default=str)
        if activate:
            self._conn.execute(
                "UPDATE policies SET active = 0 WHERE policy_id = ?", (policy.policy_id,)
            )
        self._conn.execute(
            """INSERT OR REPLACE INTO policies
               (policy_id, version, checksum, compiled_at, author, active, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                policy.policy_id,
                policy.version,
                policy.checksum(),
                policy.compiled_at.isoformat(),
                policy.author,
                1 if activate else 0,
                payload,
            ),
        )

    def active(self, policy_id: str = "default") -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload FROM policies WHERE policy_id = ? AND active = 1", (policy_id,)
        ).fetchone()
        return json.loads(row["payload"]) if row else None

    def history(self, policy_id: str = "default") -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload, active FROM policies WHERE policy_id = ? ORDER BY compiled_at DESC",
            (policy_id,),
        ).fetchall()
        return [{**json.loads(r["payload"]), "active": bool(r["active"])} for r in rows]


class BreakerRepository:
    """État persistant du coupe-circuit : il doit survivre à un redémarrage,
    sinon un simple restart reactiverait l'autonomie après un incident."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def read(self) -> dict[str, Any]:
        row = self._conn.execute("SELECT * FROM breaker_state WHERE id = 1").fetchone()
        if not row:
            return {"state": "closed", "reason": "", "actor": "", "changed_at": None}
        return dict(row)

    def write(self, state: str, reason: str, actor: str) -> None:
        self._conn.execute(
            """INSERT INTO breaker_state (id, state, reason, actor, changed_at)
               VALUES (1, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 state = excluded.state, reason = excluded.reason,
                 actor = excluded.actor, changed_at = excluded.changed_at""",
            (state, reason, actor, datetime.now(UTC).isoformat()),
        )


class NotificationRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, notification: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO notifications
               (notification_id, created_at, channel, incident_id, action_id,
                severity, acknowledged_at, payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                notification["notification_id"],
                notification["created_at"],
                notification["channel"],
                notification.get("incident_id"),
                notification.get("action_id"),
                notification.get("severity", "medium"),
                notification.get("acknowledged_at"),
                json.dumps(notification, default=str),
            ),
        )

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """SELECT payload FROM notifications WHERE acknowledged_at IS NULL
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def acknowledge(self, notification_id: str, actor: str) -> bool:
        now = datetime.now(UTC).isoformat()
        row = self._conn.execute(
            "SELECT payload FROM notifications WHERE notification_id = ?", (notification_id,)
        ).fetchone()
        if not row:
            return False
        payload = json.loads(row["payload"])
        payload["acknowledged_at"] = now
        payload["acknowledged_by"] = actor
        self._conn.execute(
            "UPDATE notifications SET acknowledged_at = ?, payload = ? WHERE notification_id = ?",
            (now, json.dumps(payload, default=str), notification_id),
        )
        return True


class MonitoredTargetRepository:
    """Plateformes déclarées à la main par l'administrateur.

    Le parc de démonstration reste codé en dur : ce dépôt le complète pour
    qu'une plateforme réelle du site puisse être suivie sans toucher au code,
    et pour qu'une démonstration parte toujours d'un parc non vide.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def save(self, target: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO monitored_targets
               (target_id, label, kind, ip, segment, owner, criticality,
                latitude, longitude, declared_at, declared_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target["target_id"],
                target["label"],
                target["kind"],
                target["ip"],
                target["segment"],
                target["owner"],
                int(target.get("criticality", 3)),
                target.get("latitude"),
                target.get("longitude"),
                target.get("declared_at") or datetime.now(UTC).isoformat(),
                target.get("declared_by", ""),
            ),
        )

    def list(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM monitored_targets ORDER BY label COLLATE NOCASE"
        ).fetchall()
        return [dict(r) for r in rows]

    def get(self, target_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM monitored_targets WHERE target_id = ?", (target_id,)
        ).fetchone()
        return dict(row) if row else None

    def delete(self, target_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM monitored_targets WHERE target_id = ?", (target_id,)
        )
        return cursor.rowcount > 0


class ConversationRepository:
    """Conversations avec l'assistant.

    Conservees pour que l'analyste retrouve un échange de la veille, pas comme
    trace opposable : ce qui engage la plateforme est au journal d'audit, qui
    lui est immuable. Une conversation s'archive et se supprime ; une entrée
    d'audit, jamais. Confondre les deux serait grave — on croirait pouvoir
    effacer une action en effaçant la discussion qui l'a demandée.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def toucher(self, conversation_id: str, *, titre: str = "", genre: str = "") -> None:
        """Crée la conversation si besoin, et repousse sa dernière activité."""
        maintenant = datetime.now(UTC).isoformat()
        self._conn.execute(
            """INSERT INTO conversations
               (conversation_id, title, kind, status, started_at, last_activity, turns)
               VALUES (?, ?, ?, 'active', ?, ?, 0)
               ON CONFLICT(conversation_id) DO UPDATE SET
                 last_activity = excluded.last_activity,
                 title = CASE WHEN conversations.title = '' THEN excluded.title
                              ELSE conversations.title END,
                 kind  = CASE WHEN excluded.kind <> '' THEN excluded.kind
                              ELSE conversations.kind END""",
            (conversation_id, titre, genre or "echange", maintenant, maintenant),
        )

    def ajouter_message(
        self,
        conversation_id: str,
        role: str,
        texte: str,
        *,
        intent: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        self._conn.execute(
            """INSERT INTO conversation_messages
               (conversation_id, role, text, intent, at, payload)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                conversation_id,
                role,
                texte,
                intent,
                datetime.now(UTC).isoformat(),
                json.dumps(payload or {}, default=str),
            ),
        )
        if role == "humain":
            self._conn.execute(
                "UPDATE conversations SET turns = turns + 1 WHERE conversation_id = ?",
                (conversation_id,),
            )

    def lister(
        self,
        *,
        genre: str = "tous",
        depuis: datetime | None = None,
        statut: str = "active",
        limit: int = 60,
    ) -> list[dict[str, Any]]:
        clauses, parametres = ["turns > 0"], []
        if statut != "tous":
            clauses.append("status = ?")
            parametres.append(statut)
        if genre != "tous":
            clauses.append("kind = ?")
            parametres.append(genre)
        if depuis is not None:
            clauses.append("last_activity >= ?")
            parametres.append(depuis.isoformat())

        rows = self._conn.execute(
            f"""SELECT * FROM conversations WHERE {" AND ".join(clauses)}
                ORDER BY last_activity DESC LIMIT ?""",
            (*parametres, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get(self, conversation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM conversations WHERE conversation_id = ?", (conversation_id,)
        ).fetchone()
        if row is None:
            return None
        messages = self._conn.execute(
            """SELECT role, text, intent, at, payload FROM conversation_messages
               WHERE conversation_id = ? ORDER BY seq""",
            (conversation_id,),
        ).fetchall()
        conversation = dict(row)
        conversation["messages"] = [
            {**dict(m), "payload": json.loads(m["payload"] or "{}")} for m in messages
        ]
        return conversation

    def archiver(self, conversation_id: str, *, archivee: bool = True) -> bool:
        curseur = self._conn.execute(
            "UPDATE conversations SET status = ? WHERE conversation_id = ?",
            ("archived" if archivee else "active", conversation_id),
        )
        return curseur.rowcount > 0

    def supprimer(self, conversation_id: str) -> bool:
        self._conn.execute(
            "DELETE FROM conversation_messages WHERE conversation_id = ?", (conversation_id,)
        )
        curseur = self._conn.execute(
            "DELETE FROM conversations WHERE conversation_id = ?", (conversation_id,)
        )
        return curseur.rowcount > 0


# ---------------------------------------------------------------------------
# Comptes, postes, sessions — separation des roles (CDCF v3.0)
# ---------------------------------------------------------------------------


def _nouvel_id(prefixe: str) -> str:
    return f"{prefixe}_{uuid.uuid4().hex[:16]}"


class UserRepository:
    """Comptes analystes, decideurs et administrateurs."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get(self, user_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def by_username(self, username: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        return dict(row) if row else None

    def username_taken(self, username: str) -> bool:
        return self.by_username(username) is not None

    def email_taken(self, email: str) -> bool:
        if not email:
            return False
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE LIMIT 1", (email,)
        ).fetchone()
        return row is not None

    def has_super_admin(self) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE role = 'super_admin' LIMIT 1"
        ).fetchone()
        return row is not None

    def list(self, *, status: str = "", role: str = "", kind: str = "") -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for colonne, valeur in (("status", status), ("role", role), ("kind", kind)):
            if valeur:
                clauses.append(f"{colonne} = ?")
                params.append(valeur)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM users {where} ORDER BY created_at DESC", params
        ).fetchall()
        return [dict(r) for r in rows]

    def count_by_role(self, role: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = ?", (role,)
        ).fetchone()
        return int(row["n"])

    def create(
        self,
        *,
        username: str,
        password_hash: str,
        kind: str,
        role: str,
        status: str,
        email: str = "",
        nom: str = "",
        prenom: str = "",
        civility: str = "",
        poste: str = "",
        validated_by: str = "",
    ) -> dict[str, Any]:
        user_id = _nouvel_id("usr")
        now = datetime.now(UTC).isoformat()
        validated_at = now if status == "active" else None
        self._conn.execute(
            """INSERT INTO users
               (user_id, kind, role, status, username, email, nom, prenom,
                civility, poste, password_hash, created_at, validated_by, validated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                kind,
                role,
                status,
                username,
                email,
                nom,
                prenom,
                civility,
                poste,
                password_hash,
                now,
                validated_by,
                validated_at,
            ),
        )
        created = self.get(user_id)
        assert created is not None
        return created

    def set_status(self, user_id: str, status: str, *, by: str = "") -> None:
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            """UPDATE users SET status = ?,
                 validated_by = CASE WHEN ? = 'active' THEN ? ELSE validated_by END,
                 validated_at = CASE WHEN ? = 'active' THEN ? ELSE validated_at END
               WHERE user_id = ?""",
            (status, status, by, status, now, user_id),
        )

    def set_role(self, user_id: str, role: str) -> None:
        self._conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, user_id))

    def delete(self, user_id: str) -> bool:
        """Suppression definitive. Les sessions tombent par cascade ; les
        entrees d'audit deja ecrites par ce compte restent (elles sont
        immuables et portent l'identifiant en clair)."""
        cur = self._conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        return cur.rowcount > 0

    def set_password(self, user_id: str, password_hash: str) -> None:
        self._conn.execute(
            "UPDATE users SET password_hash = ? WHERE user_id = ?", (password_hash, user_id)
        )

    def touch_login(self, user_id: str) -> None:
        self._conn.execute(
            "UPDATE users SET last_login_at = ? WHERE user_id = ?",
            (datetime.now(UTC).isoformat(), user_id),
        )


class PosteRepository:
    """Postes ouverts au sein du CIRT/ANTIC (analystes et decideurs)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get(self, poste_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM postes WHERE poste_id = ?", (poste_id,)).fetchone()
        return dict(row) if row else None

    def list(self, *, kind: str = "", active_only: bool = False) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if active_only:
            clauses.append("active = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM postes {where} ORDER BY kind, label", params
        ).fetchall()
        return [dict(r) for r in rows]

    def label_taken(self, kind: str, label: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM postes WHERE kind = ? AND label = ? COLLATE NOCASE LIMIT 1",
            (kind, label),
        ).fetchone()
        return row is not None

    def create(self, *, kind: str, label: str, civility: str = "", by: str = "") -> dict[str, Any]:
        poste_id = _nouvel_id("pos")
        self._conn.execute(
            """INSERT INTO postes
               (poste_id, kind, label, civility, active, created_at, created_by)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (poste_id, kind, label, civility, datetime.now(UTC).isoformat(), by),
        )
        created = self.get(poste_id)
        assert created is not None
        return created

    def update(
        self,
        poste_id: str,
        *,
        label: str | None = None,
        civility: str | None = None,
        active: bool | None = None,
    ) -> None:
        sets: list[str] = []
        params: list[Any] = []
        if label is not None:
            sets.append("label = ?")
            params.append(label)
        if civility is not None:
            sets.append("civility = ?")
            params.append(civility)
        if active is not None:
            sets.append("active = ?")
            params.append(1 if active else 0)
        if not sets:
            return
        params.append(poste_id)
        self._conn.execute(f"UPDATE postes SET {', '.join(sets)} WHERE poste_id = ?", params)

    def delete(self, poste_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM postes WHERE poste_id = ?", (poste_id,))
        return cur.rowcount > 0

    def seed_defaults(self, defaults: list[tuple[str, str, str]]) -> None:
        """Insere les postes fournis s'ils n'existent pas — (kind, label, civility)."""
        for kind, label, civility in defaults:
            if not self.label_taken(kind, label):
                self.create(kind=kind, label=label, civility=civility, by="system:seed")


class SessionRepository:
    """Sessions porteuses opaques ; la base ne stocke que l'empreinte du jeton."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def open(self, user_id: str, token_hash: str, *, ttl_hours: int, user_agent: str = "") -> None:
        now = datetime.now(UTC)
        self._conn.execute(
            """INSERT OR REPLACE INTO user_sessions
               (token_hash, user_id, created_at, expires_at, user_agent)
               VALUES (?, ?, ?, ?, ?)""",
            (
                token_hash,
                user_id,
                now.isoformat(),
                (now + timedelta(hours=ttl_hours)).isoformat(),
                user_agent[:200],
            ),
        )

    def resolve(self, token_hash: str) -> str | None:
        """Retourne l'``user_id`` d'une session valide, sinon None."""
        row = self._conn.execute(
            "SELECT user_id, expires_at FROM user_sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
            self._conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
            return None
        return str(row["user_id"])

    def close(self, token_hash: str) -> None:
        self._conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))

    def close_all_for(self, user_id: str) -> None:
        self._conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))

    def purge_expired(self) -> None:
        self._conn.execute(
            "DELETE FROM user_sessions WHERE expires_at <= ?",
            (datetime.now(UTC).isoformat(),),
        )
