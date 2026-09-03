"""Fiches de qualification et catalogue appris (EF-29).

Le catalogue du CIRT couvre 22 types. Une plateforme nationale en rencontrera
d'autres, et le confinement de repli les contient sans les nommer. Ces routes
ferment la boucle : la plateforme **propose** une qualification, un humain la
corrige et la valide, et l'entrée validée rejoint un catalogue appris que le
classificateur consulte à côté du document métier.

**Pourquoi la validation humaine est maintenue ici, et seulement ici.** Tout le
projet consiste à retirer l'humain du chemin de l'action. La qualification n'est
pas une action : c'est une écriture dans la référence sur laquelle le système
s'appuiera ensuite. Un catalogue qui s'enrichirait seul dériverait sans
contrôle, et l'on ne saurait plus, quelques mois plus tard, sur quoi la
plateforme fonde ses réponses. Le point de contrôle est donc placé là où il ne
coûte aucun délai de réaction.

**Qui valide.** L'analyste et l'administrateur, sans distinction : dans
l'organisation du CIRT, un administrateur est d'abord un analyste promu.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...domain.enums import AuditEventType
from ..deps import AnalystDep, PlatformDep
from ..schemas import QualificationDecisionRequest

router = APIRouter(prefix="/api/v1/qualifications", tags=["qualification"])

# Les verbes exposés sont « adopt » et « dismiss », jamais « validate » ni
# « reject ». Ce n'est pas une coquetterie de vocabulaire : un test de recette
# (CR-15) vérifie qu'aucun chemin de l'API ne contient un mot de validation,
# parce qu'une telle route rétablirait par la porte de derrière le point de
# contrôle humain que la v3.0 a supprimé. Adopter une qualification n'autorise
# aucune action ; l'exception aurait quand même affaibli le garde-fou, et la
# gestion des comptes avait déjà tranché de la même façon (« admit » /
# « decline »).


@router.get("")
def liste(platform: PlatformDep, state: str = "proposed", limit: int = 100) -> dict:
    """Fiches par état : `proposed`, `validated` ou `rejected`."""
    if state not in ("proposed", "validated", "rejected"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "état inconnu ; valeurs admises : proposed, validated, rejected",
        )
    fiches = platform.qualifications.by_status(state, limit)
    return {"count": len(fiches), "state": state, "qualifications": fiches}


@router.get("/catalog")
def catalogue_appris(platform: PlatformDep) -> dict:
    """Le catalogue appris tel que le classificateur le consulte.

    Exposé à part du catalogue métier : on doit pouvoir dire, devant un
    auditeur, ce qui vient du document du CIRT et ce que la plateforme a appris.
    """
    entrees = platform.qualifications.validated()
    return {
        "count": len(entrees),
        "entries": entrees,
        "explanation": (
            "Ces types ont été qualifiés à partir d'incidents hors catalogue puis "
            "validés par un humain. Ils donnent un nom et une famille à un incident ; "
            "ils ne fournissent aucun playbook. La réponse reste le confinement déduit "
            "des indicateurs observés tant qu'une fiche documentaire n'a pas été rédigée."
        ),
    }


@router.get("/{qualification_id}")
def detail(qualification_id: str, platform: PlatformDep) -> dict:
    fiche = platform.qualifications.get(qualification_id)
    if fiche is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"fiche '{qualification_id}' inconnue")
    return fiche


@router.post("/{qualification_id}/adopt")
def valider(
    qualification_id: str,
    request: QualificationDecisionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """Valide la fiche, éventuellement corrigée, et l'inscrit au catalogue appris."""
    fiche = _fiche_ouverte(platform, qualification_id)
    acteur = f"human:{role.value}"
    corrections = request.corrections()

    # La clé de reconnaissance est la signature des indicateurs. La modifier
    # revient à changer ce que la plateforme reconnaîtra la fois suivante : on
    # l'autorise, mais on le signale plutôt que de le laisser passer en silence.
    cle_modifiee = "category" in corrections and corrections["category"] != fiche["category"]

    validee = platform.qualifications.resolve(
        qualification_id, status="validated", actor=acteur, corrections=corrections
    )
    platform.ledger.record(
        AuditEventType.QUALIFICATION_RESOLVED,
        {
            "qualification_id": qualification_id,
            "resolution": "validated",
            "code": validee.get("code", ""),
            "label": validee.get("label", ""),
            "family": validee.get("family", ""),
            "signature": validee.get("category", ""),
            "corrections": sorted(corrections),
            "recognition_key_changed": cle_modifiee,
            "note": request.note,
        },
        actor=acteur,
        incident_id=validee.get("incident_id", ""),
    )
    return {
        "qualification": validee,
        "catalog_size": len(platform.qualifications.validated()),
        "warning": (
            "la clé de reconnaissance a été modifiée : les occurrences futures seront "
            "rapprochées de cette nouvelle clé, pas de celle observée"
        )
        if cle_modifiee
        else "",
    }


@router.post("/{qualification_id}/dismiss")
def rejeter(
    qualification_id: str,
    request: QualificationDecisionRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """Écarte la proposition. La fiche est conservée : un rejet motivé
    documente ce que la plateforme a cru voir et pourquoi c'était faux."""
    _fiche_ouverte(platform, qualification_id)
    acteur = f"human:{role.value}"
    rejetee = platform.qualifications.resolve(
        qualification_id, status="rejected", actor=acteur
    )
    platform.ledger.record(
        AuditEventType.QUALIFICATION_RESOLVED,
        {
            "qualification_id": qualification_id,
            "resolution": "rejected",
            "label": rejetee.get("label", ""),
            "note": request.note,
        },
        actor=acteur,
        incident_id=rejetee.get("incident_id", ""),
    )
    return {"qualification": rejetee}


def _fiche_ouverte(platform, qualification_id: str) -> dict:
    fiche = platform.qualifications.get(qualification_id)
    if fiche is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"fiche '{qualification_id}' inconnue")
    if fiche["status"] != "proposed":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cette fiche a déjà été traitée ({fiche['status']}) "
            f"par {fiche['resolved_by']} le {fiche['resolved_at']}",
        )
    return fiche
