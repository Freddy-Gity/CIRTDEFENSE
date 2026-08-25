"""Collecte des faits, uniquement à partir des données de la plateforme."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ..audit.ledger import AuditLedger
from ..domain.taxonomy import BY_CODE
from ..orchestration.portfolio import PortfolioService
from ..persistence.repositories import ActionRepository, IncidentRepository


@dataclass(slots=True)
class OperationsFacts:
    """Photographie factuelle d'une période d'exploitation."""

    period_label: str
    since: datetime
    until: datetime
    incidents_total: int = 0
    incidents_by_family: dict[str, int] = field(default_factory=dict)
    incidents_by_priority: dict[str, int] = field(default_factory=dict)
    incidents_by_attack_type: dict[str, int] = field(default_factory=dict)
    actions_executed: int = 0
    actions_rolled_back: int = 0
    actions_failed: int = 0
    actions_blocked: int = 0
    rollback_ratio: float = 0.0
    autonomous_rollbacks: int = 0
    manual_rollbacks: int = 0
    refusals: dict[str, int] = field(default_factory=dict)
    """Refus d'agir par motif : contexte non fonde, politique, coupe-circuit."""
    breaker_trips: int = 0
    breaker_state: str = "closed"
    audit_entries: int = 0
    audit_chain_valid: bool = True
    top_incidents: list[dict[str, Any]] = field(default_factory=list)
    most_dangerous: dict[str, Any] | None = None
    notifications_pending: int = 0
    actuation_mode: str = "simulation"
    autonomy_effective: bool = True

    @property
    def acted(self) -> bool:
        return self.actions_executed > 0 or self.actions_rolled_back > 0

    @property
    def refusals_total(self) -> int:
        return sum(self.refusals.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "periode": self.period_label,
            "debut": self.since.isoformat(),
            "fin": self.until.isoformat(),
            "incidents_total": self.incidents_total,
            "incidents_par_famille": self.incidents_by_family,
            "incidents_par_priorite": self.incidents_by_priority,
            "incidents_par_type": self.incidents_by_attack_type,
            "actions_executees": self.actions_executed,
            "actions_annulees": self.actions_rolled_back,
            "actions_en_echec": self.actions_failed,
            "actions_refusees": self.actions_blocked,
            "taux_annulation": self.rollback_ratio,
            "annulations_autonomes": self.autonomous_rollbacks,
            "annulations_manuelles": self.manual_rollbacks,
            "refus_d_agir": self.refusals,
            "declenchements_coupe_circuit": self.breaker_trips,
            "etat_coupe_circuit": self.breaker_state,
            "entrees_journal": self.audit_entries,
            "chaine_audit_intacte": self.audit_chain_valid,
            "incidents_prioritaires": self.top_incidents,
            "incident_le_plus_dangereux": self.most_dangerous,
            "notifications_non_acquittees": self.notifications_pending,
            "mode_actionnement": self.actuation_mode,
            "autonomie_effective": self.autonomy_effective,
        }


class FactCollector:
    """Interroge les dépôts. Ne calcule rien qu'il ne puisse justifier."""

    def __init__(
        self,
        ledger: AuditLedger,
        incidents: IncidentRepository,
        actions: ActionRepository,
        portfolio: PortfolioService,
        notifications: Any = None,
        breaker: Any = None,
        settings: Any = None,
    ) -> None:
        self._ledger = ledger
        self._incidents = incidents
        self._actions = actions
        self._portfolio = portfolio
        self._notifications = notifications
        self._breaker = breaker
        self._settings = settings

    def collect(self, hours: int = 24, label: str = "dernières 24 heures") -> OperationsFacts:
        until = datetime.now(UTC)
        since = until - timedelta(hours=hours)

        entries = [e for e in self._ledger.query(limit=100_000) if _parse(e.recorded_at) >= since]
        facts = OperationsFacts(period_label=label, since=since, until=until)

        types = Counter(e.event_type for e in entries)
        facts.audit_entries = len(entries)
        facts.breaker_trips = types.get("breaker.tripped", 0)
        facts.autonomous_rollbacks = sum(
            1
            for e in entries
            if e.event_type == "rollback.completed" and e.actor.startswith("system:")
        )
        facts.manual_rollbacks = sum(
            1
            for e in entries
            if e.event_type in ("rollback.completed", "manual.rollback")
            and e.actor.startswith("human:")
        )
        facts.refusals = self._refusals(entries)

        incident_ids = {e.incident_id for e in entries if e.incident_id}
        portfolio = [
            i
            for i in self._portfolio.list(limit=1000)
            if i.incident_id in incident_ids or not incident_ids
        ]
        facts.incidents_total = len(portfolio)
        facts.incidents_by_family = _count(portfolio, "family_label")
        facts.incidents_by_priority = _count(portfolio, "priority")
        facts.incidents_by_attack_type = _count(portfolio, "attack_code")

        stats = self._portfolio.statistics()
        facts.actions_executed = stats["actions_executed"]
        facts.actions_rolled_back = stats["actions_rolled_back"]
        facts.actions_failed = stats["actions_failed"]
        facts.actions_blocked = stats.get("actions_blocked", 0)
        facts.rollback_ratio = stats["rollback_ratio"]

        facts.top_incidents = [
            {
                "incident_id": i.incident_id,
                "type": i.attack_code,
                "libelle": i.attack_label,
                "famille": i.family_label,
                "criticite": i.severity,
                "dangerosite": i.dangerousness,
                "priorite": i.priority,
                "risque": i.risk_score,
                "actions_executees": i.actions_executed,
                "actions_annulees": i.actions_rolled_back,
            }
            for i in sorted(portfolio, key=lambda x: -x.risk_score)[:5]
        ]
        if portfolio:
            pire = max(portfolio, key=lambda x: x.dangerousness)
            facts.most_dangerous = {
                "type": pire.attack_code,
                "libelle": pire.attack_label,
                "dangerosite": pire.dangerousness,
                "incident_id": pire.incident_id,
            }

        verification = self._ledger.verify_chain()
        facts.audit_chain_valid = verification.valid

        if self._notifications is not None:
            facts.notifications_pending = len(self._notifications.pending(limit=1000))
        if self._breaker is not None:
            status = self._breaker.status()
            facts.breaker_state = status.state.value
            facts.autonomy_effective = status.autonomy_active
        if self._settings is not None:
            facts.actuation_mode = self._settings.autonomy.actuation_mode
            facts.autonomy_effective = facts.autonomy_effective and self._settings.autonomy.enabled

        return facts

    @staticmethod
    def _refusals(entries: list[Any]) -> dict[str, int]:
        """Compte les refus d'agir par motif.

        Ce compteur merite autant d'attention que celui des actions : un taux
        de refus élève signale une base de connaissance en retard sur les
        menaces observées, pas un dysfonctionnement.
        """
        motifs = Counter()
        libelles = {
            "no_grounded_context": "contexte non fonde documentairement",
            "policy_denied": "refuse par la politique de réponse",
            "breaker_open": "coupe-circuit ouvert",
            "out_of_catalog": "action hors catalogue de réversibilité",
            "no_action_needed": "aucune action requise",
        }
        for entry in entries:
            if entry.event_type != "decision.made":
                continue
            outcome = entry.payload.get("outcome", "")
            if outcome and outcome != "autonomous_execution":
                motifs[libelles.get(outcome, outcome)] += 1
        return dict(motifs)

    def incident_detail(self, incident_id: str) -> dict[str, Any] | None:
        """Faits complets d'un incident, chronologie comprise."""
        incident = self._incidents.get(incident_id)
        if incident is None:
            return None
        return {
            "incident": incident.to_dict(),
            "chronologie": [
                {
                    "seq": e.seq,
                    "horodatage": e.recorded_at,
                    "type": e.event_type,
                    "acteur": e.actor,
                }
                for e in self._ledger.incident_timeline(incident_id)
            ],
            "actions": [a.to_dict() for a in incident.actions],
        }

    def catalog_facts(self) -> dict[str, Any]:
        """Ce que la plateforme sait traiter, et ce qu'elle ne traite pas."""
        return {
            "types_catalogues": len(BY_CODE),
            "par_famille": _count_codes(),
            "hors_perimetre_autonome": [
                a.code for a in BY_CODE.values() if not a.autonomously_actionable
            ],
        }


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _count(items: list[Any], attribute: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        value = getattr(item, attribute, "") or ""
        if value:
            counts[value] += 1
    return dict(counts)


def _count_codes() -> dict[str, int]:
    counts: Counter[str] = Counter()
    for attack in BY_CODE.values():
        counts[attack.family.code] += 1
    return dict(counts)


def dumps(facts: OperationsFacts) -> str:
    return json.dumps(facts.to_dict(), ensure_ascii=False, indent=2, default=str)
