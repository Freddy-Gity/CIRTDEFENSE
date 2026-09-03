"""Gestes à effet durable en attente d'une décision humaine (EF-28).

**Ce n'est pas une validation préalable.** La distinction est celle sur
laquelle tout le projet repose, et elle doit se lire dans le code : les gestes
listés ici n'ont jamais été planifiés pour exécution autonome. Le planificateur
de repli les a écartés au moment de la décision, parce que le catalogue de
réversibilité les déclare à effet durable. Rien n'attend ici pour partir : ce
qui attend, c'est une décision *humaine* sur un geste que la plateforme a
refusé de s'autoriser.

Trois issues, et le CIRT les a toutes voulues :

- **confirmer** — l'humain assume l'effet durable, la plateforme exécute et
  journalise l'action comme toute autre ;
- **j'ai agi moi-même** — l'humain est intervenu directement sur l'équipement ;
  la plateforme en prend acte et l'inscrit, pour que le journal reste le
  reflet fidèle de ce qui a été fait, y compris hors d'elle ;
- **écarter** — l'humain juge le geste inutile ou disproportionné.

Aucune de ces trois issues n'est un silence : les trois sont inscrites au
journal avec leur auteur et leur motif.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...domain.action import ActionSpec
from ...domain.enums import AuditEventType, Reversibility
from ..deps import AnalystDep, PlatformDep
from ..schemas import PendingResolutionRequest

router = APIRouter(prefix="/api/v1/pending", tags=["decisions-humaines"])


@router.get("")
def liste(platform: PlatformDep, limit: int = 100) -> dict:
    """L'alerte persistante : ce qui attend encore, et depuis quand."""
    attentes = platform.pending.pending(limit)
    return {
        "count": len(attentes),
        "pending": attentes,
        "explanation": (
            "Ces gestes n'ont pas été exécutés : le catalogue de réversibilité les "
            "déclare à effet durable, et la plateforme n'engage seule que ce qu'elle "
            "sait annuler entièrement. Ils restent listés tant qu'aucune décision "
            "humaine n'est prise."
        ),
    }


@router.get("/{pending_id}")
def detail(pending_id: str, platform: PlatformDep) -> dict:
    entree = platform.pending.get(pending_id)
    if entree is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"attente '{pending_id}' inconnue")
    return entree


@router.post("/{pending_id}/confirm")
def confirmer(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """L'humain assume l'effet durable : la plateforme exécute.

    L'action passe par l'exécuteur nominal, donc par le contrôle de pré-vol,
    le journal et l'armement de la boucle de contrôle. Une action confirmée
    par un humain n'est pas une action de seconde classe : elle est traitée
    exactement comme les autres, et reste annulable a posteriori.
    """
    entree = _attente_ouverte(platform, pending_id)
    acteur = f"human:{role.value}"

    spec = ActionSpec(
        verb=entree["verb"],
        actuator=entree["actuator"],
        target=entree["target"],
        parameters=dict(entree.get("parameters") or {}),
        reversibility=_reversibilite(entree),
        rollback_verb=_verbe_annulation(platform, entree),
        blast_radius=int(entree.get("blast_radius", 1)),
        expected_effect=entree.get("expected_effect", ""),
    )
    resultat = platform.executor.execute(
        spec,
        incident_id=entree["incident_id"],
        decision_id=entree["decision_id"],
        watch_target=entree["target"],
    )
    resolue = platform.pending.resolve(
        pending_id,
        status="confirmed",
        actor=acteur,
        note=request.reason,
        action_id=resultat.action_id,
    )
    _inscrire(platform, resolue, acteur, request.reason, action_id=resultat.action_id)
    return {"pending": resolue, "action": resultat.to_dict()}


@router.post("/{pending_id}/handled")
def deja_traite(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """« J'ai agi moi-même sur l'équipement. »

    La plateforme n'exécute rien et prend acte. Sans cette issue, un geste
    réalisé à la main resterait éternellement « en attente » et le journal
    donnerait à croire que rien n'a été fait — ce serait une trace fausse.
    """
    _attente_ouverte(platform, pending_id)
    acteur = f"human:{role.value}"
    resolue = platform.pending.resolve(
        pending_id, status="handled_by_human", actor=acteur, note=request.reason
    )
    _inscrire(platform, resolue, acteur, request.reason)
    return {"pending": resolue, "action": None}


@router.post("/{pending_id}/decline")
def ecarter(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """L'humain juge le geste inutile ou disproportionné. Le motif est inscrit."""
    _attente_ouverte(platform, pending_id)
    acteur = f"human:{role.value}"
    resolue = platform.pending.resolve(
        pending_id, status="declined", actor=acteur, note=request.reason
    )
    _inscrire(platform, resolue, acteur, request.reason)
    return {"pending": resolue, "action": None}


# ------------------------------------------------------------------ helpers


def _attente_ouverte(platform, pending_id: str) -> dict:
    entree = platform.pending.get(pending_id)
    if entree is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"attente '{pending_id}' inconnue")
    if entree["status"] != "pending":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cette attente a déjà été résolue ({entree['status']}) "
            f"par {entree['resolved_by']} le {entree['resolved_at']}",
        )
    return entree


def _reversibilite(entree: dict) -> Reversibility:
    try:
        return Reversibility(entree.get("reversibility", ""))
    except ValueError:
        return Reversibility.IRREVERSIBLE


def _verbe_annulation(platform, entree: dict) -> str | None:
    """Le verbe d'annulation vient du catalogue, jamais de la requête.

    Laisser l'appelant le fournir permettrait de déclarer réversible une action
    qui ne l'est pas, et de contourner l'invariant que tout le reste protège.
    """
    catalogue = platform.catalog.get(entree["actuator"], entree["verb"])
    return catalogue.rollback_verb if catalogue else None


def _inscrire(
    platform, entree: dict, acteur: str, motif: str, action_id: str | None = None
) -> None:
    platform.ledger.record(
        AuditEventType.CONFIRMATION_RESOLVED,
        {
            "pending_id": entree["pending_id"],
            "resolution": entree["status"],
            "action": f"{entree['actuator']}:{entree['verb']}",
            "target": entree["target"],
            "reason": motif,
            "action_id": action_id,
        },
        actor=acteur,
        incident_id=entree["incident_id"],
        decision_id=entree["decision_id"],
        action_id=action_id,
    )
