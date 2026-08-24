"""Administration : coupe-circuit (EF-26), mode degrade, sondes de sante."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...detection.infra.health import HealthSnapshot, StaticProbe
from ..deps import AdminDep, PlatformDep
from ..schemas import BreakerRequest, HealthReportRequest

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])


@router.get("/breaker")
def breaker_status(platform: PlatformDep) -> dict:
    return platform.breaker.status().to_dict()


@router.post("/breaker/trip")
def trip(request: BreakerRequest, platform: PlatformDep, role: AdminDep) -> dict:
    """Arret d'urgence global de l'autonomie (EF-26).

    Suspend toute execution ; n'introduit aucune validation par action.
    """
    return platform.breaker.trip(request.reason, actor=f"human:{role.value}").to_dict()


@router.post("/breaker/reset")
def reset(request: BreakerRequest, platform: PlatformDep, role: AdminDep) -> dict:
    """Rearmement. Le systeme ne se rearme jamais seul : il ne peut pas juger
    que la cause de son propre emballement a disparu."""
    return platform.breaker.reset(actor=f"human:{role.value}", reason=request.reason).to_dict()


@router.post("/degraded/enter")
def enter_degraded(request: BreakerRequest, platform: PlatformDep, role: AdminDep) -> dict:
    platform.enter_degraded_mode(request.reason)
    platform.ledger.record(
        "degraded.enter", {"reason": request.reason}, actor=f"human:{role.value}"
    )
    return {"degraded_mode": True, "reason": request.reason}


@router.post("/degraded/leave")
def leave_degraded(platform: PlatformDep, role: AdminDep) -> dict:
    report = platform.leave_degraded_mode()
    platform.ledger.record("degraded.replay", report, actor=f"human:{role.value}")
    return {"degraded_mode": False, "replay": report}


@router.get("/degraded/spool")
def spool(platform: PlatformDep) -> dict:
    items = platform.spool.items()
    return {"size": len(items), "items": [i.to_dict() for i in items]}


@router.post("/health-report")
def report_health(request: HealthReportRequest, platform: PlatformDep, role: AdminDep) -> dict:
    """Alimente la sonde de sante depuis l'exterieur.

    Utile en recette et en soutenance pour rejouer une degradation post-action
    sans casser un service reel.
    """
    if not isinstance(platform.probe, StaticProbe):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "la sonde active n'est pas alimentee de l'exterieur ; ce point "
            "d'entree n'a de sens qu'avec la sonde statique",
        )
    platform.probe.set(
        HealthSnapshot(
            target=request.target,
            reachable=request.reachable,
            latency_ms=request.latency_ms,
            error_rate=request.error_rate,
            throughput=request.throughput,
            active_sessions=request.active_sessions,
        )
    )
    return {"target": request.target, "recorded": True}
