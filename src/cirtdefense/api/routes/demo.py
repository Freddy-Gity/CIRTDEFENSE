"""Mode demonstration : declenchement des attaques du catalogue depuis l'interface.

Ces points d'entree ne fabriquent pas d'attaque : ils fabriquent la charge
utile qu'un collecteur emettrait pour l'attaque decrite, puis la remettent a
l'adaptateur d'ingestion nominal. La plateforme ne fait aucune difference
entre une attaque declenchee ici et une alerte venue d'un Wazuh de production.

Ils sont volontairement accessibles sans role : le mode demonstration est
inoffensif tant que `CIRT_ACTUATION_MODE` vaut `simulation`. En posture
`live`, les actions seraient reelles — un garde-fou l'interdit alors.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...demo import build_payload, get_scenario, list_scenarios
from ...demo.scenarios import ASSETS, by_family
from ...domain.taxonomy import summary as taxonomy_summary
from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/demo", tags=["demonstration"])


@router.get("/scenarios")
def scenarios() -> dict:
    """Catalogue des attaques simulables, groupe par famille."""
    return {
        "count": len(list_scenarios()),
        "by_family": by_family(),
        "scenarios": list_scenarios(),
    }


@router.get("/catalog")
def catalog() -> dict:
    """Le catalogue CIRT complet : les 22 lignes et leurs metadonnees."""
    return taxonomy_summary()


@router.get("/assets")
def assets() -> dict:
    """Parc fictif utilise par les scenarios."""
    return {"count": len(ASSETS), "assets": {k: dict(v) for k, v in ASSETS.items()}}


@router.post("/run/{code}", status_code=status.HTTP_202_ACCEPTED)
def run(code: str, platform: PlatformDep) -> dict:
    """Simule l'attaque `code` et rend la chaine complete de traitement."""
    _refuse_in_live_mode(platform)

    scenario = get_scenario(code)
    if scenario is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"scenario '{code}' inconnu ; consulter /api/v1/demo/scenarios",
        )

    payload = build_payload(scenario.code)
    result = platform.ingest_and_respond(scenario.source, payload)

    if result is None:
        return {
            "code": scenario.code,
            "accepted": False,
            "reason": "evenement duplique (deduplication EF-19), ou plateforme en mode degrade",
            "scenario": scenario.to_dict(),
        }

    return {
        "code": scenario.code,
        "accepted": True,
        "scenario": scenario.to_dict(),
        "expected_actions": list(scenario.expected_actions),
        **result.to_dict(),
    }


@router.post("/run-all", status_code=status.HTTP_202_ACCEPTED)
def run_all(platform: PlatformDep, family: str | None = None) -> dict:
    """Rejoue toute une famille, ou le catalogue entier.

    Utile en soutenance : une seule commande produit un portefeuille complet
    et un journal d'audit representatif.
    """
    _refuse_in_live_mode(platform)

    selected = [
        s for s in list_scenarios() if family is None or s["family_code"].upper() == family.upper()
    ]
    if not selected:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"famille '{family}' inconnue ; valeurs attendues : A, B, C, D",
        )

    results = []
    for item in selected:
        outcome = platform.ingest_and_respond(
            get_scenario(item["code"]).source, build_payload(item["code"])
        )
        results.append(
            {
                "code": item["code"],
                "label": item["label"],
                "outcome": outcome.decision.outcome.value if outcome else "duplique",
                "classification": outcome.decision.classification if outcome else {},
                "actions": (
                    [r.spec.key for r in outcome.execution.results]
                    if outcome and outcome.execution
                    else []
                ),
                "incident_id": outcome.incident.incident_id if outcome else None,
            }
        )

    executed = sum(len(r["actions"]) for r in results)
    return {
        "family": family,
        "scenarios_run": len(results),
        "actions_executed": executed,
        "results": results,
    }


@router.post("/reset")
def reset(platform: PlatformDep) -> dict:
    """Remet le mode demonstration a zero.

    Le journal d'audit n'est **pas** efface : il est immuable par construction,
    et une remise a zero qui le viderait contredirait le mecanisme meme qu'il
    incarne. Seuls les incidents, decisions, actions et notifications sont
    retires, et l'operation est elle-meme journalisee.
    """
    _refuse_in_live_mode(platform)

    with platform.connection:
        for table in ("actions", "decisions", "events", "incidents", "notifications"):
            platform.connection.execute(f"DELETE FROM {table}")

    for actuator_name in platform.registry.names():
        actuator = platform.registry.get(actuator_name)
        if hasattr(actuator, "_state"):
            actuator._state.clear()
            actuator._by_key.clear()

    platform.ledger.record(
        "demo.reset",
        {
            "cleared": ["actions", "decisions", "events", "incidents", "notifications"],
            "audit_log": "conserve — immuable par construction",
        },
        actor="human:demo",
    )
    return {
        "reset": True,
        "audit_entries_kept": platform.ledger.verify_chain().entries_checked,
        "note": "le journal d'audit est conserve : il est immuable par construction",
    }


def _refuse_in_live_mode(platform: PlatformDep) -> None:
    """Le mode demonstration est inoffensif en simulation ; en posture reelle
    il declencherait de vraies actions sur les equipements."""
    if platform.settings.autonomy.is_live:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "mode demonstration refuse : la plateforme est en actionnement "
            "'live' et les actions simulees auraient des effets reels sur les "
            "equipements. Repasser CIRT_ACTUATION_MODE a 'simulation'.",
        )
