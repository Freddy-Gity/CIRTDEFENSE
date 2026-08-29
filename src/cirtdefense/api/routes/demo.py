"""Mode démonstration : déclenchement des attaques du catalogue depuis l'interface.

Ces points d'entrée ne fabriquent pas d'attaque : ils fabriquent la charge
utile qu'un collecteur émettrait pour l'attaque decrite, puis la remettent à
l'adaptateur d'ingestion nominal. La plateforme ne fait aucune difference
entre une attaque déclenchée ici et une alerte venue d'un Wazuh de production.

Ils sont volontairement accessibles sans rôle : le mode démonstration est
inoffensif tant que `CIRT_ACTUATION_MODE` vaut `simulation`. En posture
`live`, les actions seraient réelles — un garde-fou l'interdit alors.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from ...demo import build_payload, get_scenario, list_scenarios
from ...demo.inconnus import build_payload_inconnu, get_inconnu, lister_inconnus
from ...demo.scenarios import ASSETS, by_family
from ...domain.taxonomy import summary as taxonomy_summary
from ..deps import AdminDep, PlatformDep

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
    """Parc fictif utilise par les scénarios."""
    return {"count": len(ASSETS), "assets": {k: dict(v) for k, v in ASSETS.items()}}


@router.post("/run/{code}", status_code=status.HTTP_202_ACCEPTED)
def run(code: str, platform: PlatformDep, role: AdminDep) -> dict:
    """Simule l'attaque `code` et rend la chaîne complète de traitement."""
    _refuse_in_live_mode(platform)

    scenario = get_scenario(code)
    if scenario is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"scénario '{code}' inconnu ; consulter /api/v1/demo/scénarios",
        )

    payload = build_payload(scenario.code)
    result = platform.ingest_and_respond(scenario.source, payload)

    if result is None:
        return {
            "code": scenario.code,
            "accepted": False,
            "reason": "événement dupliqué (deduplication EF-19), ou plateforme en mode dégrade",
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
def run_all(platform: PlatformDep, role: AdminDep, family: str | None = None) -> dict:
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


# ------------------------------------------------ menaces hors catalogue
# Le catalogue couvre 22 types ; ces scenarios eprouvent ce que fait la
# plateforme devant ce qu'elle ne connait pas. C'est le cas le plus important
# a montrer : une menace inedite est celle contre laquelle personne n'est
# prepare.


@router.get("/unknown")
def unknown_scenarios() -> dict:
    """Scénarios de menaces absentes du catalogue."""
    scenarios = lister_inconnus()
    return {"count": len(scenarios), "scenarios": scenarios}


@router.post("/run-unknown/{code}", status_code=status.HTTP_202_ACCEPTED)
def run_unknown(code: str, platform: PlatformDep, role: AdminDep) -> dict:
    """Injecte une menace non catalogüée et rend ce que la plateforme en fait.

    La réponse porte les deux volets du repli : ce qui est parti seul parce
    que réversible, et ce qui attend une confirmation humaine parce que
    durable.
    """
    _refuse_in_live_mode(platform)

    scenario = get_inconnu(code)
    if scenario is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"scénario inconnu '{code}' ; consulter /api/v1/demo/unknown",
        )

    resultat = platform.ingest_and_respond(scenario.source, build_payload_inconnu(scenario.code))
    if resultat is None:
        return {
            "code": scenario.code,
            "accepted": False,
            "reason": "événement dupliqué (deduplication EF-19), ou plateforme en mode dégradé",
            "scenario": scenario.to_dict(),
        }

    decision = resultat.decision
    repli = decision.fallback or {}
    return {
        "code": scenario.code,
        "accepted": True,
        "scenario": scenario.to_dict(),
        "catalogued": bool(decision.classification.get("catalogued")),
        "outcome": decision.outcome.value,
        "rationale": decision.rationale,
        "observations": repli.get("observations", []),
        "autonomous": repli.get("autonomous", []),
        "requires_confirmation": repli.get("requires_confirmation", []),
        **resultat.to_dict(),
    }


@router.post("/reset")
def reset(platform: PlatformDep, role: AdminDep) -> dict:
    """Remet le mode démonstration à zero.

    Le journal d'audit n'est **pas** efface : il est immuable par construction,
    et une remise à zero qui le viderait contredirait le mécanisme même qu'il
    incarne. Seuls les incidents, décisions, actions et notifications sont
    retirés, et l'opération est elle-même journalisée.
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
    """Le mode démonstration est inoffensif en simulation ; en posture réelle
    il declencherait de vraies actions sur les équipements."""
    if platform.settings.autonomy.is_live:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "mode démonstration refuse : la plateforme est en actionnement "
            "'live' et les actions simulées auraient des effets réels sur les "
            "équipements. Repasser CIRT_ACTUATION_MODE a 'simulation'.",
        )
