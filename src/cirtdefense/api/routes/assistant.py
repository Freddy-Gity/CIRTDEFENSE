"""Assistant d'exploitation et génération de rapports."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ...assistant.service import Answer
from ...demo.scenarios import SCENARIOS, build_payload, get_scenario
from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])


class QuestionRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    conversation_id: str | None = Field(
        default=None,
        max_length=64,
        description="Fil de discussion : sans lui, chaque question repart de zéro",
    )


@router.post("/ask")
def ask(request: QuestionRequest, platform: PlatformDep) -> dict:
    """Répond à partir des seules données de la plateforme.

    Une question hors du périmètre reconnu reçoit un refus explicite,
    accompagné de ce que l'assistant sait faire — jamais une réponse
    fabriquée. Quand la question demande un effet — déclencher une simulation,
    produire un rapport — l'assistant reconnaît l'intention et **la route
    l'exécute** : le texte produit ne décide jamais d'une action.
    """
    reponse = platform.assistant.ask(request.question, conversation_id=request.conversation_id)
    corps = reponse.to_dict()
    if reponse.action:
        corps["action_result"] = _executer(reponse.action, platform)
    return corps


@router.get("/stream")
def stream(
    question: str, platform: PlatformDep, conversation_id: str | None = None
) -> StreamingResponse:
    """La même réponse, servie en flux pour un affichage progressif.

    Le contenu est calculé d'abord et diffusé ensuite : ce n'est pas un modèle
    qui écrit au fil de l'eau, c'est une réponse déterministe rendue lisible
    au rythme de la lecture. Les étapes annoncées sont les collectes réelles,
    pas une animation décorative.
    """
    return StreamingResponse(
        _evenements(question, platform, conversation_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(type_: str, **donnees: object) -> str:
    return f"data: {json.dumps({'type': type_, **donnees}, ensure_ascii=False)}\n\n"


def _evenements(
    question: str, platform: PlatformDep, conversation_id: str | None = None
) -> Iterator[str]:
    """Diffuse la réponse à mesure qu'elle se construit.

    Les étapes annoncées sont celles que l'assistant a réellement suivies —
    l'intention qu'il a reconnue et sur quel indice, la période qu'il a
    retenue, les sources lues, la vérification faite. Ce n'est pas une
    animation : c'est la trace, et elle est contestable.

    Le contenu est calculé d'abord, diffusé ensuite. Aucun modèle n'écrit au
    fil de l'eau ; le rythme sert la lecture, pas l'illusion.
    """
    yield _sse("thinking", label="Lecture de la question", detail=question.strip()[:120])
    time.sleep(0.25)

    reponse: Answer = platform.assistant.ask(question, conversation_id=conversation_id)

    for etape in reponse.reasoning:
        yield _sse("thinking", label=etape["label"], detail=etape.get("detail", ""))
        time.sleep(0.32)

    if reponse.action:
        yield _sse("thinking", label="Exécution de la demande", detail=_dire(reponse.action))
        resultat = _executer(reponse.action, platform)
        yield _sse("action", action=reponse.action, result=resultat)
        time.sleep(0.2)

    yield _sse("answer_start")

    # Découpe par mot : la ponctuation reste collée au mot qui la précède,
    # sinon le texte s'afficherait avec des espaces avant les virgules.
    mots = reponse.text.split(" ")
    for index, mot in enumerate(mots):
        yield _sse("delta", text=mot if index == 0 else f" {mot}")
        time.sleep(0.024)

    yield _sse(
        "done",
        intent=reponse.intent.value,
        facts=reponse.facts,
        sources=reponse.sources,
        provider=reponse.provider,
        reasoning=reponse.reasoning,
        follow_ups=reponse.follow_ups,
    )


def _dire(action: dict) -> str:
    """Ce que l'effet demandé va faire, en clair."""
    match action.get("kind"):
        case "run_scenario":
            return f"scénario {action.get('code')} du catalogue CIRT"
        case "run_family":
            return f"tous les scénarios de la famille {action.get('family')}"
        case "run_all":
            return "les 22 scénarios du catalogue"
        case "report":
            return f"rapport sur {action.get('hours', 24)} heures"
        case _:
            return ""


def _executer(action: dict, platform: PlatformDep) -> dict:
    """Exécute l'effet reconnu. Refuse tout ce qui n'est pas prévu ici.

    La liste est close : une intention inconnue ne déclenche rien, elle est
    rapportée telle quelle. C'est la même règle que pour le moteur — ce qui
    n'est pas explicitement permis n'a pas lieu.
    """
    if platform.settings.autonomy.is_live:
        return {
            "executed": False,
            "reason": (
                "la plateforme est en actionnement « live » : une simulation y aurait "
                "des effets réels sur les équipements"
            ),
        }

    match action.get("kind"):
        case "run_scenario":
            return _lancer([str(action["code"])], platform)
        case "run_family":
            famille = str(action["family"]).upper()
            codes = [s.code for s in SCENARIOS if s.attack_type.family.code == famille]
            return _lancer(codes, platform)
        case "run_all":
            return _lancer([s.code for s in SCENARIOS], platform)
        case "report":
            heures = int(action.get("hours", 24))
            rapport = platform.reports.build(hours=heures)
            return {"executed": True, "kind": "report", "hours": heures, "report": rapport}
        case _:
            return {"executed": False, "reason": "effet non reconnu"}


def _lancer(codes: list[str], platform: PlatformDep) -> dict:
    resultats = []
    for code in codes:
        scenario = get_scenario(code)
        if scenario is None:
            continue
        issue = platform.ingest_and_respond(scenario.source, build_payload(code))
        resultats.append(
            {
                "code": code,
                "label": scenario.title,
                "accepted": issue is not None,
                "outcome": issue.decision.outcome.value if issue else "",
                "actions_executed": issue.execution.executed if issue else 0,
                "incident_id": issue.incident.incident_id if issue else "",
                "classification": issue.decision.classification if issue else {},
            }
        )
    return {
        "executed": True,
        "kind": "simulation",
        "scenarios_run": len(resultats),
        "actions_executed": sum(r["actions_executed"] for r in resultats),
        "results": resultats,
    }


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
