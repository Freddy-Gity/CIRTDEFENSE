"""Surveillance des plateformes supervisées (EF-21 a EF-23).

Vue de l'état de sécurité du parc : ce que la plateforme observe, et ce qu'elle
en conclut. Distincte du portefeuille, qui montre les incidents déjà traités.

Le périmètre surveillé est déduit de trois sources, dans cet ordre : les cibles
déclarées avec des seuils de service, le parc de démonstration, et les actifs
effectivement vus dans des événements. Une plateforme réelle tiendrait un
inventaire explicite ; ici, l'inventaire se constitue de ce qui est observé,
ce qui évite d'afficher un parc théorique sans rapport avec l'activité.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from ...demo.scenarios import ASSETS
from ...detection.infra.health import HealthSnapshot, StaticProbe
from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/monitoring", tags=["surveillance"])


@router.get("")
def overview(platform: PlatformDep) -> dict:
    """État de santé de chaque plateforme surveillée."""
    targets = _targets(platform)
    incidents = platform.portfolio.list(limit=500)

    # La clé de corrélation d'un incident porte l'actif : « catégorie::actif ».
    par_actif: dict[str, list[Any]] = {}
    for incident in incidents:
        data = platform.incidents.get(incident.incident_id)
        if data is None:
            continue
        actif = data.correlation_key.split("::", 1)[-1]
        par_actif.setdefault(actif, []).append(incident)

    lignes: list[dict[str, Any]] = []
    for nom, meta in sorted(targets.items()):
        snapshot = platform.probe.measure(nom)
        seuils = platform.monitor.thresholds_for(nom)
        breaches = seuils.breaches(snapshot)
        rattaches = par_actif.get(nom, [])

        lignes.append(
            {
                "target": nom,
                "hostname": meta.get("hostname", nom),
                "ip": meta.get("ip"),
                "criticality": meta.get("criticality", 3),
                "zone": meta.get("zone", "inconnue"),
                "health": snapshot.to_dict(),
                "thresholds": {
                    "max_latency_ms": seuils.max_latency_ms,
                    "max_error_rate": seuils.max_error_rate,
                    "min_throughput": seuils.min_throughput,
                },
                "breaches": breaches,
                "state": _etat(snapshot, breaches),
                "incidents": len(rattaches),
                "actions_executed": sum(i.actions_executed for i in rattaches),
                "actions_rolled_back": sum(i.actions_rolled_back for i in rattaches),
                "worst_priority": _pire_priorite(rattaches),
            }
        )

    resume = {
        "total": len(lignes),
        "nominal": sum(1 for x in lignes if x["state"] == "nominal"),
        "degrade": sum(1 for x in lignes if x["state"] == "degrade"),
        "injoignable": sum(1 for x in lignes if x["state"] == "injoignable"),
    }

    return {
        "probe": platform.probe.name,
        "probe_is_manual": isinstance(platform.probe, StaticProbe),
        "summary": resume,
        "targets": lignes,
        "post_action_watches": _watches(platform),
    }


@router.post("/simulate/{target}")
def simulate(target: str, platform: PlatformDep, degraded: bool = True) -> dict:
    """Force l'état de santé d'une cible, pour éprouver la boucle EF-25.

    Sans ce point d'entrée, démontrer l'annulation autonome exigerait de casser
    un service réel. Il n'est disponible qu'avec la sonde alimentée à la main
    et hors actionnement réel.
    """
    if platform.settings.autonomy.is_live:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "refuse : la plateforme est en actionnement 'live', l'état de santé "
            "doit y provenir de sondes réelles",
        )
    if not isinstance(platform.probe, StaticProbe):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "la sonde active n'est pas alimentée de l'extérieur",
        )
    if target not in _targets(platform):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"cible '{target}' hors du périmètre")

    snapshot = (
        HealthSnapshot(
            target=target, reachable=False, latency_ms=9000, error_rate=1.0, throughput=0
        )
        if degraded
        else HealthSnapshot(
            target=target,
            reachable=True,
            latency_ms=80,
            error_rate=0.01,
            throughput=400,
            active_sessions=20,
        )
    )
    platform.probe.set(snapshot)
    return {"target": target, "degraded": degraded, "health": snapshot.to_dict()}


def _targets(platform: PlatformDep) -> dict[str, dict[str, Any]]:
    connus: dict[str, dict[str, Any]] = {nom: dict(meta) for nom, meta in ASSETS.items()}
    for event in platform.events.recent(limit=500):
        cle = event.asset.correlation_key()
        if cle and cle != "unknown":
            connus.setdefault(
                cle,
                {
                    "hostname": event.asset.hostname or cle,
                    "ip": event.asset.ip,
                    "criticality": event.asset.criticality,
                    "zone": event.asset.zone,
                },
            )
    return connus


def _etat(snapshot: Any, breaches: list[str]) -> str:
    if not snapshot.reachable:
        return "injoignable"
    return "degrade" if breaches else "nominal"


def _pire_priorite(incidents: list[Any]) -> str:
    if not incidents:
        return ""
    return max(incidents, key=lambda i: i.priority_rank).priority


def _watches(platform: PlatformDep) -> list[dict[str, Any]]:
    """Actions sous surveillance post-action (EF-25) en attente de verdict."""
    return [
        {
            "action_id": result.action_id,
            "verb": result.spec.key if result.spec else "",
            "target": result.spec.target if result.spec else "",
            "incident_id": result.incident_id,
            "watched": platform.watcher.has_baseline(result.action_id),
        }
        for result in platform.actions.executed_reversible(limit=50)
    ]
