"""Portefeuille d'incidents (Axe 4) et consultation detaillee."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("")
def portfolio(platform: PlatformDep, limit: int = 50, incident_status: str | None = None) -> dict:
    entries = platform.portfolio.list(limit=limit, status=incident_status)
    return {"count": len(entries), "incidents": [e.to_dict() for e in entries]}


@router.get("/statistics")
def statistics(platform: PlatformDep) -> dict:
    return platform.portfolio.statistics()


@router.get("/{incident_id}")
def detail(incident_id: str, platform: PlatformDep) -> dict:
    incident = platform.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"incident '{incident_id}' inconnu")
    return {
        "incident": incident.to_dict(),
        "events": [e.to_dict() for e in incident.events],
        "decisions": platform.decisions.for_incident(incident_id),
        "timeline": [e.to_dict() for e in platform.ledger.incident_timeline(incident_id)],
    }
