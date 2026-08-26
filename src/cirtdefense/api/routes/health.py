"""État de la plateforme : posture d'autonomie effective et santé technique."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request

import cirtdefense

from ..deps import PlatformDep

router = APIRouter(tags=["etat"])


@router.get("/health")
def health(request: Request) -> dict:
    """Sante technique, et **d'ou vient le code servi**.

    Le second point a l'air anodin ; il ne l'est pas. L'interface est cherchee
    a cote du paquet importe, pas du repertoire courant : un `pip install`
    ayant enregistre un ancien clone fait servir une ancienne interface quoi
    qu'on tire ailleurs. Sans ces deux chemins, le symptome — « ma mise a jour
    ne change rien » — n'a aucune explication visible.
    """
    racine = getattr(request.app.state, "web_root", None)
    return {
        "status": "ok",
        "package": str(Path(cirtdefense.__file__).resolve().parent),
        "web_root": str(racine) if racine else None,
        "web_root_exists": bool(racine and (racine / "index.html").exists()),
    }


@router.get("/api/v1/status")
def status(platform: PlatformDep) -> dict:
    """Vue complète de la posture. C'est l'ecran qu'on ouvre en premier pour
    savoir si le système agit réellement, et sous quelles contraintes."""
    return platform.status()
