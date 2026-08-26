"""Portefeuille d'incidents priorise (Axe 4).

L'Axe 4 est conceptuellement inchange par le pivot v3.0 : seule sa sortie
change. Le portefeuille ne sert plus a dire à l'analyste quoi traiter en
premier, mais a lui montrer ce que le système a déjà traité, dans l'ordre de
l'enjeu. C'est la vue du décideur.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..domain.enums import IncidentStatus
from ..persistence.repositories import ActionRepository, IncidentRepository


@dataclass(slots=True)
class PortfolioEntry:
    incident_id: str
    category: str
    severity: str
    status: str
    risk_score: float
    updated_at: str
    actions_executed: int
    actions_rolled_back: int
    autonomous: bool
    # Qualification au catalogue CIRT : c'est elle qui donne son sens a
    # l'ordre du portefeuille, la priorité Axe 4 pesant sur le score.
    attack_code: str = ""
    attack_label: str = ""
    family: str = ""
    family_label: str = ""
    dangerousness: float = 0.0
    priority: str = ""
    priority_rank: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "risk_score": self.risk_score,
            "updated_at": self.updated_at,
            "actions_executed": self.actions_executed,
            "actions_rolled_back": self.actions_rolled_back,
            "autonomous": self.autonomous,
            "attack_code": self.attack_code,
            "attack_label": self.attack_label,
            "family": self.family,
            "family_label": self.family_label,
            "dangerousness": self.dangerousness,
            "priority": self.priority,
            "priority_rank": self.priority_rank,
        }


class PortfolioService:
    """Les compteurs d'actions viennent de la table des actions, jamais de
    l'instantané stocke avec l'incident.

    L'instantané est fige au moment de l'exécution : il ignore les annulations
    survenues ensuite. S'en servir affichait un taux d'annulation de 0 % alors
    même que le système venait d'annuler cinq actions — c'est-a-dire faux sur
    précisément l'indicateur qui mesure la fiabilité de l'autonomie.
    """

    def __init__(self, incidents: IncidentRepository, actions: ActionRepository) -> None:
        self._incidents = incidents
        self._actions = actions

    def list(self, limit: int = 50, status: str | None = None) -> list[PortfolioEntry]:
        counts = self._actions.status_counts_by_incident()
        entries: list[PortfolioEntry] = []
        for data in self._incidents.portfolio(limit=limit, status=status):
            per_incident = counts.get(data["incident_id"], {})
            entries.append(
                PortfolioEntry(
                    incident_id=data["incident_id"],
                    category=data["category"],
                    severity=data["severity"],
                    status=data["status"],
                    risk_score=data.get("risk_score", 0.0),
                    updated_at=data["updated_at"],
                    actions_executed=per_incident.get("executed", 0),
                    actions_rolled_back=per_incident.get("rolled_back", 0),
                    autonomous=bool(per_incident),
                    attack_code=data.get("attack_code", ""),
                    attack_label=data.get("attack_label", ""),
                    family=data.get("family", ""),
                    family_label=data.get("family_label", ""),
                    dangerousness=data.get("dangerousness", 0.0),
                    priority=data.get("priority", ""),
                    priority_rank=data.get("priority_rank", 0),
                )
            )
        return entries

    def statistics(self) -> dict[str, Any]:
        """Indicateurs de pilotage.

        Le taux d'annulation est le plus important : il mesure la fréquence à
        laquelle le système doit se corriger lui-même. C'est l'indicateur que
        la soutenance interrogera, et celui qui, s'il dérive, justifie de
        rouvrir la question de la posture d'autonomie.
        """
        data = self._incidents.portfolio(limit=1000)
        counts = self._actions.status_counts()
        executed = counts.get("executed", 0)
        rolled_back = counts.get("rolled_back", 0)
        rollback_failed = counts.get("rollback_failed", 0)
        total_terminal = executed + rolled_back + rollback_failed
        return {
            "incidents_total": len(data),
            "incidents_by_status": {
                status.value: sum(1 for d in data if d["status"] == status.value)
                for status in IncidentStatus
            },
            "actions_total": sum(counts.values()),
            "actions_executed": executed,
            "actions_rolled_back": rolled_back,
            "actions_failed": counts.get("failed", 0),
            "actions_rollback_failed": rollback_failed,
            "actions_blocked": counts.get("blocked_by_policy", 0),
            "rollback_ratio": round(rolled_back / total_terminal, 3) if total_terminal else 0.0,
            "top_categories": _top_categories(data),
            "by_family": _count(data, "family_label"),
            "by_attack_type": _count(data, "attack_code"),
            "by_priority": _count(data, "priority"),
        }


def _top_categories(data: list[dict[str, Any]]) -> list[tuple[str, int]]:
    return sorted(_count(data, "category").items(), key=lambda kv: (-kv[1], kv[0]))[:5]


def _count(data: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in data:
        value = item.get(key) or ""
        if value:
            counts[value] = counts.get(value, 0) + 1
    return counts
