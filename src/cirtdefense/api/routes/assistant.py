"""Assistant d'exploitation et génération de rapports."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])


class QuestionRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)


@router.post("/ask")
def ask(request: QuestionRequest, platform: PlatformDep) -> dict:
    """Répond à partir des seules données de la plateforme.

    Une question hors du périmètre reconnu reçoit un refus explicite,
    accompagne de ce que l'assistant sait faire — jamais une réponse
    fabriquée.
    """
    return platform.assistant.ask(request.question).to_dict()


@router.get("/brief")
def brief(platform: PlatformDep) -> dict:
    """Bilan des opérations du jour."""
    return platform.assistant.daily_brief().to_dict()


@router.get("/suggestions")
def suggestions(platform: PlatformDep) -> dict:
    return {"suggestions": platform.assistant.suggestions()}


@router.get("/report")
def report(platform: PlatformDep, hours: int = 24) -> dict:
    """Rapport d'opérations sur une période, au format structure et Markdown."""
    if not 1 <= hours <= 8760:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "période invalide : entre 1 heure et 1 an (8760 heures)",
        )
    return platform.reports.build(hours=hours)


@router.get("/report.md", response_class=Response)
def report_markdown(platform: PlatformDep, hours: int = 24) -> Response:
    """Le même rapport, en Markdown téléchargeable."""
    if not 1 <= hours <= 8760:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "période invalide")
    contenu = platform.reports.build(hours=hours)["markdown"]
    # Un en-tête HTTP ne transporte que de l'ASCII : le nom du fichier reste
    # sans accent, le corps du rapport est en UTF-8.
    nom = f"rapport-operations-{hours}h.md"
    return Response(
        content=contenu,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{nom}"'},
    )
