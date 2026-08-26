#!/usr/bin/env python3
"""Scénario de démonstration : une attaque, une réponse autonome, un rollback.

Rejoue en quelques secondes ce que la soutenance doit montrer :

  1. une attaque détectée et confinee sans intervention humaine ;
  2. une menace inconnue qui, elle, ne déclenche rien (limite assumee) ;
  3. un confinement errone que le système annule seul, dans un délai mesure ;
  4. un emballement qui déclenche le coupe-circuit ;
  5. le journal d'audit, vérifie de bout en bout.

Usage :
    python scripts/demo_attaque.py [--pas-a-pas]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cirtdefense.config import AutonomySettings, Settings  # noqa: E402
from cirtdefense.detection.infra.health import HealthSnapshot, StaticProbe  # noqa: E402
from cirtdefense.platform import build_platform  # noqa: E402

PAUSE = False


def titre(numero: str, texte: str) -> None:
    print(f"\n\033[1m{'═' * 74}\033[0m")
    print(f"\033[1m  {numero} — {texte}\033[0m")
    print(f"\033[1m{'═' * 74}\033[0m")
    if PAUSE:
        input("  (entrée pour continuer) ")


def ligne(cle: str, valeur: object) -> None:
    print(f"  {cle:.<32} {valeur}")


def main() -> int:
    global PAUSE
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pas-a-pas", action="store_true", help="marquer une pause entre chaque étape"
    )
    PAUSE = parser.parse_args().pas_a_pas

    tmp = Path(tempfile.mkdtemp(prefix="cirtdemo-"))
    settings = Settings(
        env="demo",
        db_path=tmp / "demo.db",
        degraded_spool=tmp / "spool",
        autonomy=AutonomySettings(
            enabled=True,
            actuation_mode="simulation",
            circuit_breaker_enabled=True,
            breaker_rollback_threshold=3,
        ),
    )
    probe = StaticProbe()
    probe.set(
        HealthSnapshot(
            target="srv-web-01",
            reachable=True,
            latency_ms=95,
            error_rate=0.01,
            throughput=480,
            active_sessions=37,
        )
    )
    platform = build_platform(settings, probe=probe)

    try:
        etape_1(platform)
        etape_2(platform)
        etape_3(platform, probe)
        etape_4(platform, probe)
        etape_5(platform)
    finally:
        platform.close()
    return 0


def etape_1(platform) -> None:
    titre("1", "Attaque détectée — réponse exécutée SANS validation humaine")
    alerte = {
        "timestamp": "2026-08-24T10:00:00Z",
        "rule": {
            "level": 10,
            "description": "Multiple failed password attempts",
            "groups": ["authentication_failed"],
        },
        "agent": {"id": "srv-web-01", "name": "srv-web-01", "ip": "10.0.0.5"},
        "data": {"srcip": "41.202.1.9", "dstuser": "jdupont"},
    }
    print("  Alerte Wazuh recue : force brute depuis 41.202.1.9 sur le compte jdupont.\n")

    debut = time.monotonic()
    result = platform.ingest_and_respond("wazuh", alerte)
    duree = (time.monotonic() - debut) * 1000

    ligne("Incident", result.incident.incident_id)
    ligne("Categorie", f"{result.incident.category} / {result.incident.severity.value}")
    ligne("Decision", result.decision.outcome.value)
    ligne("Délai décision -> action", f"{duree:.0f} ms")
    print()
    for r in result.execution.results:
        ligne(f"  {r.spec.key}", f"{r.spec.target}  [{r.status.value}]")
        ligne("    réversibilité", r.spec.reversibility.value)
    print(f"\n  Motif : {result.decision.rationale}")
    print(
        f"  Sources : {', '.join(s.split('/')[-1] for s in result.decision.trace.context_sources)}"
    )
    print("\n  \033[2mAucun humain n'est intervenu entre la détection et l'action.\033[0m")


def etape_2(platform) -> None:
    titre("2", "Menace inconnue — le système REFUSE d'agir (limite assumee)")
    result = platform.ingest_and_respond(
        "generic_json",
        {
            "category": "vecteur_inedit_non_repertorie",
            "severity": "critical",
            "confidence": 0.95,
            "asset_id": "srv-db-01",
            "title": "signal jamais observe",
        },
    )
    ligne("Decision", result.decision.outcome.value)
    ligne("Actions exécutées", 0)
    print(f"\n  Motif : {result.decision.rationale}")
    print("\n  \033[2mL'autonomie totale s'exerce sur un catalogue documente.\033[0m")
    print("  \033[2mHors catalogue, le système s'abstient plutôt que d'improviser.\033[0m")


def etape_3(platform, probe) -> None:
    titre("3", "Le confinement était errone — annulation AUTONOME (EF-25)")
    print("  La surveillance constate que srv-web-01 est tombe après notre action.\n")
    probe.set(
        HealthSnapshot(
            target="srv-web-01", reachable=False, latency_ms=9000, error_rate=1.0, throughput=0
        )
    )

    debut = time.monotonic()
    report = platform.engine.run_control_loop()
    duree = time.monotonic() - debut

    ligne("Actions vérifiées", report.checked)
    ligne("Degradations imputees", report.degraded)
    ligne("Annulations réussies", report.rolled_back)
    ligne("Délai total", f"{duree * 1000:.0f} ms")
    ligne("Délai maximal admis", f"{platform.settings.autonomy.rollback_max_latency_seconds} s")
    print()
    for o in report.outcomes:
        ligne(
            f"  {o.action_id[:16]}",
            f"{o.latency_seconds * 1000:.0f} ms — "
            f"délai {'respecte' if o.within_bound else 'DEPASSE'}",
        )
    if report.outcomes:
        print(f"\n  Motif : {report.outcomes[0].reason}")

    firewall = platform.registry.require("firewall")
    print()
    ligne("Blocage encore actif ?", firewall.is_applied("block_ip", "41.202.1.9"))
    print("\n  \033[2mLe système a défait sa propre erreur, sans qu'on le lui demande.\033[0m")


def etape_4(platform, probe) -> None:
    titre("4", "Emballement — le COUPE-CIRCUIT s'ouvre seul (EF-26)")
    print("  Trois nouvelles actions, toutes suivies d'une dégradation.\n")
    probe.set(
        HealthSnapshot(
            target="srv-app-02", reachable=True, latency_ms=100, error_rate=0.0, throughput=300
        )
    )
    for i in range(3):
        platform.ingest_and_respond(
            "generic_json",
            {
                "category": "bruteforce",
                "severity": "high",
                "confidence": 0.8,
                "asset": {"asset_id": "srv-app-02", "criticality": 3},
                "indicators": {"srcip": f"41.202.9.{i}"},
                "occurred_at": f"2026-08-24T1{i}:30:00Z",
            },
        )
    probe.set(HealthSnapshot(target="srv-app-02", reachable=False, error_rate=1.0, throughput=0))
    platform.engine.run_control_loop()

    status = platform.breaker.status()
    ligne("État du coupe-circuit", status.state.value.upper())
    ligne(
        "Annulations dans la fenêtre", f"{status.rollbacks_in_window} / {status.rollback_threshold}"
    )
    print(f"\n  Motif : {status.reason}")

    print("\n  Un nouvel événement arrive pendant la coupure :")
    result = platform.ingest_and_respond(
        "generic_json",
        {
            "category": "malware",
            "severity": "critical",
            "confidence": 0.9,
            "asset": {"asset_id": "srv-x", "criticality": 3},
            "indicators": {"file_path": "/tmp/mal"},
        },
    )
    ligne("  Décision", result.decision.outcome.value)
    ligne("  Actions exécutées", 0)
    print("\n  \033[2mLe système s'est arrêté lui-même. Seul l'administrateur rearme :\033[0m")
    print("  \033[2mil ne peut pas juger que la cause de son propre emballement a disparu.\033[0m")


def etape_5(platform) -> None:
    titre("5", "Journal d'audit — la seule trace de ce que le système a fait seul")
    entries = platform.ledger.query(limit=200)
    types: dict[str, int] = {}
    for e in entries:
        types[e.event_type] = types.get(e.event_type, 0) + 1
    for kind, count in sorted(types.items()):
        ligne(kind, count)

    verification = platform.ledger.verify_chain()
    print()
    ligne("Entrées vérifiées", verification.entries_checked)
    ligne("Chaîne intacte", verification.valid)
    print(f"  {verification.detail}")

    stats = platform.portfolio.statistics()
    print()
    ligne("Incidents traités", stats["incidents_total"])
    ligne("Actions exécutées", stats["actions_executed"])
    ligne("Actions annulées", stats["actions_rolled_back"])
    ligne("Taux d'annulation", f"{stats['rollback_ratio']:.0%}")
    print("\n  \033[2mLe taux d'annulation est l'indicateur à surveiller : il mesure\033[0m")
    print("  \033[2mla fréquence à laquelle le système doit se corriger lui-même.\033[0m\n")


if __name__ == "__main__":
    raise SystemExit(main())
