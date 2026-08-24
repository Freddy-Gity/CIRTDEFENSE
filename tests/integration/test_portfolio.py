"""Portefeuille et indicateurs de pilotage (Axe 4)."""

from __future__ import annotations

from cirtdefense.detection.infra.health import HealthSnapshot


class TestIndicateurs:
    def test_le_taux_d_annulation_reflete_l_etat_reel(self, platform, probe, bruteforce_payload):
        """Regression : les compteurs etaient lus dans l'instantane fige avec
        l'incident, qui ignore les annulations survenues apres. Le taux
        affichait 0 % alors que toutes les actions venaient d'etre annulees —
        faux sur l'indicateur meme qui mesure la fiabilite de l'autonomie."""
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert platform.portfolio.statistics()["actions_rolled_back"] == 0

        probe.set(
            HealthSnapshot(target="srv-web-01", reachable=False, error_rate=1.0, throughput=0)
        )
        report = platform.engine.run_control_loop()

        stats = platform.portfolio.statistics()
        assert stats["actions_rolled_back"] == report.rolled_back
        assert stats["actions_executed"] == 0
        assert stats["rollback_ratio"] == 1.0

    def test_compteurs_par_incident_a_jour(self, platform, probe, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        probe.set(
            HealthSnapshot(target="srv-web-01", reachable=False, error_rate=1.0, throughput=0)
        )
        platform.engine.run_control_loop()

        entree = platform.portfolio.list()[0]
        assert entree.actions_rolled_back > 0
        assert entree.actions_executed == 0

    def test_incident_sans_confinement_actif_n_est_plus_contenu(
        self, platform, probe, bruteforce_payload
    ):
        """Le portefeuille ne doit pas afficher une maitrise que la realite
        dement."""
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert platform.incidents.get(result.incident.incident_id).status.value == "contained"

        probe.set(
            HealthSnapshot(target="srv-web-01", reachable=False, error_rate=1.0, throughput=0)
        )
        platform.engine.run_control_loop()

        assert platform.incidents.get(result.incident.incident_id).status.value == "rolled_back"

    def test_annulation_manuelle_prise_en_compte(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        for action in result.execution.results:
            platform.rollback.rollback_by_id(action.action_id, "faux positif", "human:analyst")

        assert platform.portfolio.statistics()["actions_rolled_back"] == len(
            result.execution.results
        )


class TestPriorisation:
    def test_ordre_decroissant_par_enjeu(self, platform):
        platform.ingest_and_respond(
            "generic_json",
            {
                "category": "scan",
                "severity": "low",
                "asset": {"asset_id": "poste-01", "criticality": 1},
                "indicators": {"srcip": "41.202.1.1"},
            },
        )
        platform.ingest_and_respond(
            "generic_json",
            {
                "category": "malware",
                "severity": "critical",
                "confidence": 0.9,
                "asset": {"asset_id": "srv-01", "criticality": 5},
                "indicators": {"file_path": "/tmp/x"},
            },
        )
        scores = [e.risk_score for e in platform.portfolio.list()]
        assert scores == sorted(scores, reverse=True)
