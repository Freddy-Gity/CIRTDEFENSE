"""Actions exécutées et annulation manuelle a posteriori.

Il n'existe ici **aucun** point d'entrée de validation préalable. C'est
volontaire et central : l'analyste consulte ce qui a été fait et peut
l'annuler, jamais l'autoriser.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ..deps import AnalystDep, PlatformDep
from ..schemas import RollbackRequest

router = APIRouter(prefix="/api/v1/actions", tags=["actions"])


@router.get("/{action_id}")
def detail(action_id: str, platform: PlatformDep) -> dict:
    result = platform.actions.get(action_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"action '{action_id}' inconnue")
    return result.to_dict()


@router.post("/{action_id}/rollback")
def rollback(
    action_id: str,
    request: RollbackRequest,
    platform: PlatformDep,
    role: AnalystDep,
) -> dict:
    """Porte de sortie humaine : annulation après coup, jamais en amont."""
    outcome = platform.rollback.rollback_by_id(
        action_id, request.reason, actor=f"human:{role.value}"
    )
    if not outcome.success:
        raise HTTPException(status.HTTP_409_CONFLICT, outcome.reason)
    return outcome.to_dict()


@router.post("/control-loop/run")
def run_control_loop(platform: PlatformDep, role: AnalystDep) -> dict:
    """Déclenche un passage de la boucle EF-25.

    En exploitation, ce passage est déclenché par le planificateur périodique ;
    l'exposer permet de le rejouer en recette et en soutenance.
    """
    return platform.engine.run_control_loop().to_dict()
