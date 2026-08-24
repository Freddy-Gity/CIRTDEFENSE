"""Politique de reponse (EF-15) et catalogue de reversibilite (EF-14).

Reserves a l'administrateur, dont le role est renforce en v3.0 : ce qu'il
ecrit ici determine ce que le systeme s'autorise a faire seul.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...domain.enums import Reversibility
from ...orchestration.policy_compiler import PolicyCompiler
from ...orchestration.reversibility import CatalogEntry
from ..deps import AdminDep, PlatformDep
from ..schemas import CatalogEntryRequest, PolicyCompileRequest

router = APIRouter(prefix="/api/v1/policy", tags=["politique"])


@router.get("")
def current(platform: PlatformDep) -> dict:
    return platform.engine.policy.to_dict()


@router.get("/history")
def history(platform: PlatformDep) -> dict:
    return {"versions": platform.policies.history()}


@router.post("/compile")
def compile_policy(
    request: PolicyCompileRequest, platform: PlatformDep, role: AdminDep
) -> dict:
    """Compile une politique en langage naturel en contraintes deterministes.

    La reponse expose explicitement les phrases **non compilees** : elles
    n'auront aucun effet, et l'administrateur doit le savoir avant de croire
    sa consigne appliquee.
    """
    report = PolicyCompiler().compile(
        request.text,
        version=request.version,
        author=f"human:{role.value}",
        default_effect=request.default_effect,
    )
    if request.activate:
        platform.policies.save(report.policy)
        platform.engine.set_policy(report.policy)
        platform.ledger.record(
            "policy.compiled",
            {
                "version": report.policy.version,
                "checksum": report.policy.checksum(),
                "compiled": len(report.compiled_sentences),
                "unparsed": report.unparsed_sentences,
            },
            actor=f"human:{role.value}",
        )
    return report.to_dict()


@router.post("/preview")
def preview(request: PolicyCompileRequest) -> dict:
    """Compile sans activer : permet de verifier ce qu'une consigne produira."""
    return PolicyCompiler().compile(request.text, default_effect=request.default_effect).to_dict()


catalog_router = APIRouter(prefix="/api/v1/catalog", tags=["reversibilite"])


@catalog_router.get("")
def list_catalog(platform: PlatformDep) -> dict:
    return platform.catalog.to_dict()


@catalog_router.get("/autonomous")
def autonomous_subset(platform: PlatformDep) -> dict:
    """Le perimetre exact de ce que le systeme peut faire seul."""
    entries = platform.catalog.autonomous_subset()
    return {"count": len(entries), "entries": [e.to_dict() for e in entries]}


@catalog_router.post("")
def add_entry(request: CatalogEntryRequest, platform: PlatformDep, role: AdminDep) -> dict:
    try:
        reversibility = Reversibility(request.reversibility)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"reversibilite invalide ; valeurs admises : "
            f"{[r.value for r in Reversibility]}",
        ) from exc

    if reversibility is not Reversibility.IRREVERSIBLE and not request.rollback_verb:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "une action declaree reversible doit porter un verbe d'annulation, "
            "sans quoi la boucle de controle ne pourrait pas la retirer",
        )

    entry = CatalogEntry(
        verb=request.verb,
        actuator=request.actuator,
        reversibility=reversibility,
        rollback_verb=request.rollback_verb,
        description=request.description,
        rollback_description=request.rollback_description,
        residual_effect=request.residual_effect,
        typical_blast_radius=request.typical_blast_radius,
        max_rollback_seconds=request.max_rollback_seconds,
    )
    platform.catalog.add(entry)
    platform.ledger.record(
        "catalog.updated", entry.to_dict(), actor=f"human:{role.value}"
    )
    return entry.to_dict()


@catalog_router.delete("/{actuator}/{verb}")
def remove_entry(actuator: str, verb: str, platform: PlatformDep, role: AdminDep) -> dict:
    removed = platform.catalog.remove(actuator, verb)
    if not removed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"'{actuator}:{verb}' absent du catalogue")
    platform.ledger.record(
        "catalog.updated", {"removed": f"{actuator}:{verb}"}, actor=f"human:{role.value}"
    )
    return {"removed": f"{actuator}:{verb}"}
