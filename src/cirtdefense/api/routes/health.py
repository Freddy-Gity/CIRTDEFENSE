"""État de la plateforme : posture d'autonomie effective et santé technique."""

from __future__ import annotations

from fastapi import APIRouter

from ..deps import PlatformDep

router = APIRouter(tags=["etat"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/api/v1/status")
def status(platform: PlatformDep) -> dict:
    """Vue complète de la posture. C'est l'ecran qu'on ouvre en premier pour
    savoir si le système agit réellement, et sous quelles contraintes."""
    return platform.status()
