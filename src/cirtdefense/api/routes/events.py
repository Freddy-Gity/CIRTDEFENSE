"""Ingestion d'événements (EF-18) et déclenchement de la chaîne autonome."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...ingestion.adapter import UnknownSourceError
from ..deps import PlatformDep
from ..schemas import IngestBatchRequest, IngestRequest

router = APIRouter(prefix="/api/v1/events", tags=["evenements"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def ingest(request: IngestRequest, platform: PlatformDep) -> dict:
    """Ingere un événement et exécute immédiatement la réponse qui en decoule.

    Le code 202 est deliberé : la réponse rend compte de ce qui a *déjà* été
    fait, elle n'annonce pas une action à venir soumise a validation.
    """
    try:
        result = platform.ingest_and_respond(request.source, request.payload)
    except UnknownSourceError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    if result is None:
        return {
            "accepted": False,
            "reason": "événement dupliqué, ou plateforme en mode dégrade "
            "(l'événement a été mis en file)",
            "degraded_mode": platform.degraded,
        }
    return {"accepted": True, **result.to_dict()}


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED)
def ingest_batch(request: IngestBatchRequest, platform: PlatformDep) -> dict:
    results = []
    for payload in request.payloads:
        try:
            outcome = platform.ingest_and_respond(request.source, payload)
        except UnknownSourceError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        results.append(outcome.to_dict() if outcome else None)
    return {
        "submitted": len(request.payloads),
        "processed": sum(1 for r in results if r),
        "results": results,
    }


@router.get("")
def recent(platform: PlatformDep, limit: int = 50) -> dict:
    events = platform.events.recent(limit)
    return {"count": len(events), "events": [e.to_dict() for e in events]}


@router.get("/sources")
def sources() -> dict:
    from ...ingestion import registry

    return {"sources": registry.available()}
