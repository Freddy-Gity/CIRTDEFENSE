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
from ..persistence.repositories import IncidentRepository


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
    def __init__(self, incidents: IncidentRepository) -> None:
        self._incidents = incidents

    def list(self, limit: int = 50, status: str | None = None) -> list[PortfolioEntry]:
        entries: list[PortfolioEntry] = []
        for data in self._incidents.portfolio(limit=limit, status=status):
            actions = data.get("actions", [])
            entries.append(
                PortfolioEntry(
                    incident_id=data["incident_id"],
                    category=data["category"],
                    severity=data["severity"],
                    status=data["status"],
                    risk_score=data.get("risk_score", 0.0),
                    updated_at=data["updated_at"],
                    actions_executed=sum(1 for a in actions if a["status"] == "executed"),
                    actions_rolled_back=sum(1 for a in actions if a["status"] == "rolled_back"),
                    autonomous=bool(actions),
                )
            )
        return entries

    def statistics(self) -> dict[str, Any]:
        """Indicateurs de pilotage. Le taux d'annulation est le plus important :
        il mesure la frequence a laquelle le systeme se corrige lui-meme, et
        c'est lui que la soutenance interrogera."""
        data = self._incidents.portfolio(limit=1000)
        actions = [a for d in data for a in d.get("actions", [])]
        executed = sum(1 for a in actions if a["status"] == "executed")
        rolled_back = sum(1 for a in actions if a["status"] == "rolled_back")
        total_terminal = executed + rolled_back
        return {
            "incidents_total": len(data),
            "incidents_by_status": {
                status.value: sum(1 for d in data if d["status"] == status.value)
                for status in IncidentStatus
            },
            "actions_total": len(actions),
            "actions_executed": executed,
            "actions_rolled_back": rolled_back,
            "actions_failed": sum(1 for a in actions if a["status"] == "failed"),
            "rollback_ratio": round(rolled_back / total_terminal, 3) if total_terminal else 0.0,
            "top_categories": _top_categories(data),
        }


def _top_categories(data: list[dict[str, Any]]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in data:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
