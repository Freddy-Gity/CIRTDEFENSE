"""Journal d'audit des decisions.

En v3.0 ce journal est la **seule** trace de ce que le systeme a fait sans
intervention humaine. Les points d'entree exposent aussi la verification
d'integrite de la chaine : un journal qu'on ne peut pas prouver intact ne vaut
rien comme piece d'audit.
"""

from __future__ import annotations

from fastapi import APIRouter

from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
def query(
    platform: PlatformDep,
    incident_id: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    entries = platform.ledger.query(
        incident_id=incident_id, event_type=event_type, limit=limit, offset=offset
    )
    return {"count": len(entries), "entries": [e.to_dict() for e in entries]}


@router.get("/verify")
def verify(platform: PlatformDep) -> dict:
    """Rejoue la chaine d'empreintes de bout en bout."""
    return platform.ledger.verify_chain().to_dict()


@router.get("/timeline/{incident_id}")
def timeline(incident_id: str, platform: PlatformDep) -> dict:
    entries = platform.ledger.incident_timeline(incident_id)
    return {"incident_id": incident_id, "count": len(entries),
            "timeline": [e.to_dict() for e in entries]}


notifications_router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


@notifications_router.get("")
def pending(platform: PlatformDep, limit: int = 100) -> dict:
    """Notifications a posteriori non encore acquittees par l'analyste."""
    items = platform.notifications.pending(limit)
    return {"count": len(items), "notifications": items}


@notifications_router.post("/{notification_id}/acknowledge")
def acknowledge(notification_id: str, platform: PlatformDep) -> dict:
    acknowledged = platform.notifications.acknowledge(notification_id, actor="human:analyst")
    return {"notification_id": notification_id, "acknowledged": acknowledged}
