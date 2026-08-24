"""Portefeuille d'incidents priorise (Axe 4).

L'Axe 4 est conceptuellement inchange par le pivot v3.0 : seule sa sortie
change. Le portefeuille ne sert plus a dire a l'analyste quoi traiter en
premier, mais a lui montrer ce que le systeme a deja traite, dans l'ordre de
l'enjeu. C'est la vue du decideur.
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
        }


class PortfolioService:
    """Les compteurs d'actions viennent de la table des actions, jamais de
    l'instantane stocke avec l'incident.

    L'instantane est fige au moment de l'execution : il ignore les annulations
    survenues ensuite. S'en servir affichait un taux d'annulation de 0 % alors
    meme que le systeme venait d'annuler cinq actions — c'est-a-dire faux sur
    precisement l'indicateur qui mesure la fiabilite de l'autonomie.
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
                )
            )
        return entries

    def statistics(self) -> dict[str, Any]:
        """Indicateurs de pilotage.

        Le taux d'annulation est le plus important : il mesure la frequence a
        laquelle le systeme doit se corriger lui-meme. C'est l'indicateur que
        la soutenance interrogera, et celui qui, s'il derive, justifie de
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
        }


def _top_categories(data: list[dict[str, Any]]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in data:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
