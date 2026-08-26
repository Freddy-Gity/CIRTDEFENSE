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

import re
import unicodedata
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status

from ...demo.scenarios import ASSETS
from ...detection.infra.health import HealthSnapshot, StaticProbe
from ..deps import AdminDep, PlatformDep
from ..schemas import MonitoredTargetRequest

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
                "kind": meta.get("kind", "actif"),
                "owner": meta.get("owner", ""),
                "declared": bool(meta.get("declared")),
                "latitude": meta.get("latitude"),
                "longitude": meta.get("longitude"),
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


@router.post("/targets", status_code=status.HTTP_201_CREATED)
def declare(request: MonitoredTargetRequest, platform: PlatformDep, role: AdminDep) -> dict:
    """Déclare une plateforme à surveiller.

    L'identifiant est dérivé du libellé plutôt que tiré au hasard : c'est lui
    qui apparaît dans la clé de corrélation d'un incident, il doit rester
    lisible dans le journal d'audit.
    """
    identifiant = _identifiant(request.label)
    if identifiant in _targets(platform):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"une plateforme '{identifiant}' est déjà surveillée"
        )

    cible = {
        "target_id": identifiant,
        "label": request.label.strip(),
        "kind": request.kind.strip(),
        "ip": request.ip.strip(),
        "segment": request.segment.strip(),
        "owner": request.owner.strip(),
        "criticality": request.criticality,
        "latitude": request.latitude,
        "longitude": request.longitude,
        "declared_at": datetime.now(UTC).isoformat(),
        "declared_by": role.value,
    }
    platform.targets.save(cible)

    # Déclarer un actif change le périmètre de l'exécution autonome : la trace
    # en revient au journal, au même titre qu'une action.
    platform.ledger.record(
        event_type="monitored_target_declared",
        actor=role.value,
        payload={k: v for k, v in cible.items() if k != "declared_by"},
    )
    return cible


@router.delete("/targets/{target_id}")
def withdraw(target_id: str, platform: PlatformDep, role: AdminDep) -> dict:
    """Retire une plateforme déclarée. Le parc de démonstration n'est pas
    retirable : il est porté par le code, pas par la base."""
    if not platform.targets.delete(target_id):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"'{target_id}' n'est pas une plateforme déclarée à la main",
        )
    platform.ledger.record(
        event_type="monitored_target_withdrawn",
        actor=role.value,
        payload={"target_id": target_id},
    )
    return {"target_id": target_id, "withdrawn": True}


@router.get("/targets/{target_id}")
def detail(target_id: str, platform: PlatformDep) -> dict:
    """Tout ce que la plateforme sait d'une seule cible.

    La vue d'ensemble compte ; celle-ci explique. Elle rassemble la mesure,
    les incidents rattachés à cet actif, les actions engagées sur lui et la
    chronologie d'audit correspondante — rien qui concerne une autre cible.
    """
    cibles = _targets(platform)
    meta = cibles.get(target_id)
    if meta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"'{target_id}' hors du périmètre")

    snapshot = platform.probe.measure(target_id)
    seuils = platform.monitor.thresholds_for(target_id)
    breaches = seuils.breaches(snapshot)

    incidents, actions, chronologie = [], [], []
    for resume in platform.portfolio.list(limit=500):
        incident = platform.incidents.get(resume.incident_id)
        if incident is None or incident.correlation_key.split("::", 1)[-1] != target_id:
            continue
        actes = platform.actions.for_incident(incident.incident_id)
        incidents.append(
            {
                "incident_id": incident.incident_id,
                "category": incident.category,
                "attack_code": resume.attack_code,
                "attack_label": resume.attack_label,
                "family_label": resume.family_label,
                "severity": incident.severity.value,
                "dangerousness": resume.dangerousness,
                "priority": resume.priority,
                "risk_score": resume.risk_score,
                "status": incident.status.value,
                "opened_at": incident.opened_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "event_count": len(incident.events),
                "actions": len(actes),
            }
        )
        for acte in actes:
            actions.append(
                {
                    "action_id": acte.action_id,
                    "verb": acte.spec.key if acte.spec else "",
                    "target": acte.spec.target if acte.spec else "",
                    "status": acte.status.value,
                    "reversibility": acte.spec.reversibility.value if acte.spec else "",
                    "rolled_back_at": acte.rolled_back_at.isoformat()
                    if acte.rolled_back_at
                    else None,
                    "rollback_reason": acte.rollback_reason,
                    "incident_id": acte.incident_id,
                }
            )
        for entree in platform.ledger.incident_timeline(incident.incident_id):
            chronologie.append(entree.to_dict())

    chronologie.sort(key=lambda e: e["recorded_at"], reverse=True)
    annulees = sum(1 for a in actions if a["rolled_back_at"])

    return {
        "target": target_id,
        "hostname": meta.get("hostname", target_id),
        "ip": meta.get("ip"),
        "kind": meta.get("kind", "actif"),
        "owner": meta.get("owner", ""),
        "zone": meta.get("zone", "inconnue"),
        "criticality": meta.get("criticality", 3),
        "declared": bool(meta.get("declared")),
        "latitude": meta.get("latitude"),
        "longitude": meta.get("longitude"),
        "health": snapshot.to_dict(),
        "thresholds": {
            "max_latency_ms": seuils.max_latency_ms,
            "max_error_rate": seuils.max_error_rate,
            "min_throughput": seuils.min_throughput,
        },
        "breaches": breaches,
        "state": _etat(snapshot, breaches),
        "summary": {
            "incidents": len(incidents),
            "actions_executed": len(actions),
            "actions_rolled_back": annulees,
            "worst_priority": incidents[0]["priority"] if incidents else "",
            "audit_entries": len(chronologie),
        },
        "incidents": incidents,
        "actions": actions,
        "timeline": chronologie[:60],
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


def _identifiant(libelle: str) -> str:
    """Identifiant lisible dérivé du libellé : « Serveur Web 03 » → srv-web-03."""
    sans_accent = "".join(
        c for c in unicodedata.normalize("NFKD", libelle.lower()) if not unicodedata.combining(c)
    )
    return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", sans_accent)).strip("-") or "cible"


def _targets(platform: PlatformDep) -> dict[str, dict[str, Any]]:
    connus: dict[str, dict[str, Any]] = {nom: dict(meta) for nom, meta in ASSETS.items()}

    # Une plateforme declaree a la main prime sur l'homonyme du parc de
    # demonstration : c'est la seule dont les informations viennent d'un
    # administrateur plutot que du code.
    for declaree in platform.targets.list():
        connus[declaree["target_id"]] = {
            "hostname": declaree["label"],
            "ip": declaree["ip"],
            "criticality": declaree["criticality"],
            "zone": declaree["segment"],
            "kind": declaree["kind"],
            "owner": declaree["owner"],
            "latitude": declaree["latitude"],
            "longitude": declaree["longitude"],
            "declared": True,
            "declared_at": declaree["declared_at"],
        }

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
