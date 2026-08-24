#!/usr/bin/env python3
"""Alimente la base avec un jeu d'incidents varie, pour l'interface et la recette.

Contrairement au scenario de demonstration, ce script ne raconte pas une
histoire : il produit un etat realiste et heterogene — incidents traites,
incidents refuses faute de contexte, actions annulees — de facon a ce que le
tableau de bord et le portefeuille aient quelque chose a montrer.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cirtdefense.detection.infra.health import HealthSnapshot, StaticProbe  # noqa: E402
from cirtdefense.platform import build_platform  # noqa: E402

SCENARIOS: list[dict] = [
    {
        "source": "wazuh",
        "payload": {
            "timestamp": "2026-08-24T08:12:00Z",
            "rule": {"level": 10, "description": "Multiple failed password attempts"},
            "agent": {"id": "srv-web-01", "name": "srv-web-01", "ip": "10.0.0.5"},
            "data": {"srcip": "41.202.1.9", "dstuser": "jdupont"},
        },
    },
    {
        "source": "suricata",
        "payload": {
            "timestamp": "2026-08-24T08:40:00Z",
            "alert": {"signature": "ET TROJAN Beacon callback",
                      "category": "command and control", "severity": 1},
            "src_ip": "10.0.0.22", "dest_ip": "185.244.25.11", "proto": "TCP",
        },
    },
    {
        "source": "generic_json",
        "payload": {
            "category": "exfiltration", "severity": "high", "confidence": 0.75,
            "occurred_at": "2026-08-24T09:05:00Z",
            "asset": {"asset_id": "srv-db-01", "criticality": 5, "zone": "interne"},
            "title": "Volume sortant anormal vers un service de stockage externe",
            "indicators": {"dest_ip": "104.18.32.7", "bytes": 8_400_000_000},
        },
    },
    {
        "source": "generic_json",
        "payload": {
            "category": "scan", "severity": "low", "confidence": 0.5,
            "occurred_at": "2026-08-24T09:20:00Z",
            "asset": {"asset_id": "fw-dmz-01", "criticality": 3, "zone": "dmz"},
            "title": "Balayage de ports depuis une source interne",
            "indicators": {"srcip": "10.0.4.51"},
        },
    },
    {
        "source": "generic_json",
        "payload": {
            "category": "malware", "severity": "critical", "confidence": 0.88,
            "occurred_at": "2026-08-24T09:45:00Z",
            "asset": {"asset_id": "poste-114", "criticality": 2, "zone": "bureautique"},
            "title": "Rancongiciel detecte en cours de chiffrement",
            "indicators": {"file_path": "C:/Users/public/enc.exe", "process": "enc.exe"},
        },
    },
    {
        "source": "generic_json",
        "payload": {
            "category": "lateral_movement", "severity": "high", "confidence": 0.7,
            "occurred_at": "2026-08-24T10:10:00Z",
            "asset": {"asset_id": "srv-file-02", "criticality": 4,
                      "user": "svc-deploy", "zone": "interne"},
            "title": "Progression laterale via partage administratif",
            "indicators": {"srcip": "10.0.2.19"},
        },
    },
    {
        "source": "generic_json",
        "payload": {
            "category": "web_attack", "severity": "high", "confidence": 0.8,
            "occurred_at": "2026-08-24T10:32:00Z",
            "asset": {"asset_id": "srv-web-02", "criticality": 4, "zone": "dmz"},
            "title": "Tentative d'injection SQL sur le portail",
            "indicators": {"srcip": "197.149.90.4"},
        },
    },
    {
        # Menace hors catalogue : doit etre refusee (limite assumee, CDCF §1.4.3).
        "source": "generic_json",
        "payload": {
            "category": "vecteur_inedit_non_repertorie", "severity": "critical",
            "confidence": 0.9, "occurred_at": "2026-08-24T10:50:00Z",
            "asset": {"asset_id": "srv-app-09", "criticality": 4},
            "title": "Signal jamais observe auparavant",
        },
    },
    {
        "source": "generic_json",
        "payload": {
            "category": "infrastructure_degradation", "severity": "high",
            "confidence": 0.9, "occurred_at": "2026-08-24T11:05:00Z",
            "asset": {"asset_id": "srv-mail-01", "criticality": 5},
            "title": "Latence excessive sur le service de messagerie",
        },
    },
]


def main() -> int:
    platform = build_platform()
    if not isinstance(platform.probe, StaticProbe):
        print("Note : la sonde active n'est pas alimentable ; "
              "aucune degradation ne sera simulee.")
    else:
        for target in ("srv-web-01", "srv-db-01", "poste-114", "srv-web-02",
                       "srv-file-02", "srv-mail-01", "fw-dmz-01"):
            platform.probe.set(
                HealthSnapshot(target=target, reachable=True, latency_ms=90,
                               error_rate=0.01, throughput=400)
            )

    try:
        agi = refuse = 0
        for scenario in SCENARIOS:
            result = platform.ingest_and_respond(scenario["source"], scenario["payload"])
            if result is None:
                continue
            executees = result.execution.executed if result.execution else 0
            if executees:
                agi += 1
            else:
                refuse += 1
            print(f"  {result.incident.category:32} {result.decision.outcome.value:24} "
                  f"{executees} action(s)")

        # Une degradation post-action, pour que le portefeuille montre aussi
        # un cas d'annulation autonome.
        if isinstance(platform.probe, StaticProbe):
            platform.probe.set(HealthSnapshot(target="srv-web-02", reachable=False,
                                              error_rate=1.0, throughput=0))
            report = platform.engine.run_control_loop()
            print(f"\n  Boucle de controle : {report.rolled_back} annulation(s) autonome(s)")

        stats = platform.portfolio.statistics()
        print(f"\n  Incidents : {stats['incidents_total']} "
              f"| executees : {stats['actions_executed']} "
              f"| annulees : {stats['actions_rolled_back']} "
              f"| refus d'agir : {refuse}")
        print(f"  Journal : {platform.ledger.verify_chain().entries_checked} entrees, "
              f"chaine intacte = {platform.ledger.verify_chain().valid}")
    finally:
        platform.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
