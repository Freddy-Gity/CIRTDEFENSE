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
- **je m'en charge** — l'agent annonce qu'il intervient lui-même. Le dossier
  ne se referme pas : il passe en « prise en charge » et reste visible jusqu'à
  ce que l'agent dise ce qu'il a fait. Un engagement que plus personne ne voit
  est exactement le défaut que l'alerte persistante corrige ;
- **écarter** — l'agent juge le geste inutile ou disproportionné. La plateforme
  n'exécute pas le geste refusé, et ne reste pas inerte pour autant : elle
  cherche un geste plus léger servant le même but, et applique une mesure
  proportionnée à la dangerosité (voir :mod:`orchestration.escalade`).

Aucune de ces issues n'est un silence : toutes sont inscrites au journal avec
leur auteur et leur motif.
"""

from __future__ import annotations

from datetime import UTC, datetime

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
def prendre_en_charge(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """« Je m'en charge moi-même. »

    La plateforme n'exécute rien et pose un statut de **prise en charge**. Le
    dossier reste ouvert et visible : ce n'est pas une clôture, c'est un
    engagement. Il se referme par ``/resolved`` quand l'agent dit ce qu'il a
    fait — sans quoi la plateforme afficherait un geste comme traité alors que
    personne n'a encore touché à l'équipement.
    """
    _attente_ouverte(platform, pending_id, attendu="pending")
    acteur = f"human:{role.value}"
    resolue = platform.pending.resolve(
        pending_id,
        status="taken_over",
        actor=acteur,
        note=request.reason,
        extra={"taken_over_at": _maintenant(), "taken_over_by": acteur},
    )
    _inscrire(platform, resolue, acteur, request.reason)
    return {
        "pending": resolue,
        "action": None,
        "suite": (
            "Intervention notée à votre nom. Le dossier reste ouvert jusqu'à ce que "
            "vous indiquiez ce qui a été fait sur l'équipement."
        ),
    }


@router.post("/{pending_id}/resolved")
def clore_prise_en_charge(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """L'agent qui s'était chargé du geste rend compte : le dossier se ferme.

    Le motif devient la trace de ce qui a été fait hors de la plateforme. Sans
    lui, le journal serait muet précisément là où la plateforme n'a pas agi
    elle-même — et c'est là qu'il doit être le plus explicite.
    """
    _attente_ouverte(platform, pending_id, attendu="taken_over")
    acteur = f"human:{role.value}"
    resolue = platform.pending.resolve(
        pending_id, status="handled_by_human", actor=acteur, note=request.reason
    )
    _inscrire(platform, resolue, acteur, request.reason)
    return {"pending": resolue, "action": None, "suite": "Dossier clos."}


@router.post("/{pending_id}/decline")
def ecarter(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """L'agent juge le geste inutile ou disproportionné.

    Le refus est appliqué : le geste écarté n'est jamais exécuté, ni sous ce
    nom ni sous un autre. Mais la menace, elle, reste entière — la plateforme
    cherche donc ce qu'elle sait encore faire, et prend une mesure
    proportionnée à la dangerosité de l'intervention.
    """
    attente = _attente_ouverte(platform, pending_id)
    acteur = f"human:{role.value}"
    escalade = platform.escalade.apres_refus(attente, acteur, request.reason)
    resolue = platform.pending.resolve(
        pending_id,
        status="declined",
        actor=acteur,
        note=request.reason,
        extra={"escalade": escalade.to_dict()},
    )
    _inscrire(platform, resolue, acteur, request.reason)
    return {
        "pending": resolue,
        "action": escalade.action.to_dict() if escalade.action else None,
        "escalade": escalade.to_dict(),
        "suite": escalade.intitule,
    }


@router.post("/{pending_id}/substitute")
def appliquer_substitution(
    pending_id: str,
    request: PendingResolutionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """L'agent accepte le geste de remplacement proposé après son refus.

    Une proposition qu'on ne peut pas accepter n'est pas une proposition, c'est
    un commentaire. Cette route ferme la boucle : le geste retenu par le
    conseil est exécuté, avec les mêmes garanties que tout autre — contrôle de
    pré-vol, journal, jeton d'annulation, boucle de contrôle.

    Le geste appliqué vient du conseil enregistré, jamais de la requête :
    laisser l'appelant nommer l'action permettrait d'exécuter n'importe quoi
    sous couvert d'accepter une proposition.
    """
    entree = platform.pending.get(pending_id)
    if entree is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"attente '{pending_id}' inconnue")
    if entree["status"] != "declined":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "un geste de remplacement ne se propose qu'après un refus ; "
            f"cette attente est {_LIBELLE_STATUT.get(entree['status'], entree['status'])}",
        )

    escalade = entree.get("escalade") or {}
    if escalade.get("action"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "la plateforme avait déjà appliqué ce geste de remplacement au moment "
            "du refus ; il n'y a rien à ajouter",
        )
    propose = escalade.get("alternative")
    if not propose:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "aucun geste de remplacement n'avait été proposé pour cette attente",
        )

    acteur = f"human:{role.value}"
    spec = ActionSpec(
        verb=propose["verb"],
        actuator=propose["actuator"],
        target=propose["target"],
        parameters=dict(entree.get("parameters") or {}),
        reversibility=Reversibility(propose["reversibility"]),
        rollback_verb=_verbe_annulation(
            platform, {"actuator": propose["actuator"], "verb": propose["verb"]}
        ),
        blast_radius=int(propose.get("blast_radius", 1)),
        expected_effect=propose.get("description", ""),
    )
    resultat = platform.executor.execute(
        spec,
        incident_id=entree["incident_id"],
        decision_id=entree["decision_id"],
        watch_target=propose["target"],
    )
    incident = platform.incidents.get(entree["incident_id"])
    if incident is not None:
        incident.register_action(resultat)
        platform.incidents.save(incident)

    escalade["action"] = resultat.to_dict()
    escalade["mesure"] = "quarantaine"
    entree = platform.pending.annoter(pending_id, {"escalade": escalade}) or entree
    _inscrire(platform, entree, acteur, request.reason, action_id=resultat.action_id)
    return {
        "pending": entree,
        "action": resultat.to_dict(),
        "suite": "Geste de remplacement appliqué.",
    }


# ------------------------------------------------------------------ helpers


_LIBELLE_STATUT = {
    "pending": "en attente d'une décision",
    "taken_over": "prise en charge par un agent",
    "confirmed": "confirmée et exécutée",
    "handled_by_human": "traitée à la main",
    "declined": "écartée",
}


def _attente_ouverte(platform, pending_id: str, attendu: str | None = None) -> dict:
    """Vérifie qu'on peut encore agir sur cette attente, et depuis quel état.

    `attendu` sert aux transitions qui n'ont de sens qu'à partir d'un état
    précis : on ne clôt une prise en charge que si elle a commencé, et on ne
    prend en charge que ce qui attend encore.
    """
    entree = platform.pending.get(pending_id)
    if entree is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"attente '{pending_id}' inconnue")
    if entree["status"] not in platform.pending.OUVERTS:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cette attente est déjà {_LIBELLE_STATUT.get(entree['status'], entree['status'])} "
            f"— par {entree['resolved_by']} le {entree['resolved_at']}",
        )
    if attendu and entree["status"] != attendu:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cette attente est {_LIBELLE_STATUT.get(entree['status'], entree['status'])} : "
            f"l'opération demandée suppose qu'elle soit "
            f"{_LIBELLE_STATUT.get(attendu, attendu)}",
        )
    return entree


def _maintenant() -> str:
    return datetime.now(UTC).isoformat()


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
