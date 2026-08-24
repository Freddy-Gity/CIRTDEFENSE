"""Boucle de controle fermee (EF-25) et coupe-circuit (EF-26)."""

from __future__ import annotations

from cirtdefense.detection.infra.health import HealthSnapshot
from cirtdefense.domain.enums import ActionStatus, DecisionOutcome


def _degrader(probe, cible="srv-web-01"):
    probe.set(
        HealthSnapshot(
            target=cible, reachable=False, latency_ms=5000, error_rate=0.95, throughput=0
        )
    )


class TestBoucleDeControle:
    def test_action_saine_est_conservee(self, platform, probe, bruteforce_payload):
        """Le risque symetrique du rollback autonome : annuler un confinement
        qui fonctionne. La boucle ne doit rien defaire sans motif."""
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        report = platform.engine.run_control_loop()

        assert report.checked > 0
        assert report.degraded == 0
        assert report.rolled_back == 0
        assert platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

    def test_action_nuisible_est_annulee_seule(self, platform, probe, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        _degrader(probe)

        report = platform.engine.run_control_loop()

        assert report.degraded > 0
        assert report.rolled_back == report.degraded
        assert not platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

    def test_le_motif_de_l_annulation_est_consigne(self, platform, probe, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        _degrader(probe)
        report = platform.engine.run_control_loop()

        assert all("degradation constatee" in o.reason for o in report.outcomes)
        assert platform.ledger.query(event_type="rollback.completed")

    def test_degradation_imputee_a_la_bonne_cible(self, platform, probe, bruteforce_payload):
        """Regression : la boucle comparait la sante de la machine surveillee
        a celle de la cible de l'action (une adresse IP, un compte), deux
        grandeurs sans rapport, et annulait donc a peu pres tout."""
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        _degrader(probe)
        report = platform.engine.run_control_loop()

        assert all(v["target"] == "srv-web-01" for v in report.verdicts)

    def test_sans_mesure_de_reference_la_boucle_s_abstient(self, platform, probe):
        """Sans reference, on ne peut pas imputer une degradation a l'action."""
        _degrader(probe)
        report = platform.engine.run_control_loop()
        assert report.rolled_back == 0


class TestRollbackManuel:
    def test_analyste_peut_annuler_apres_coup(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        action_id = result.execution.results[0].action_id

        outcome = platform.rollback.rollback_by_id(
            action_id, "faux positif confirme", actor="human:analyst"
        )
        assert outcome.success
        assert platform.actions.get(action_id).status is ActionStatus.ROLLED_BACK

    def test_annulation_idempotente(self, platform, bruteforce_payload):
        """La boucle et l'analyste peuvent viser la meme action."""
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        action_id = result.execution.results[0].action_id

        platform.rollback.rollback_by_id(action_id, "motif", actor="human:analyst")
        seconde = platform.rollback.rollback_by_id(action_id, "motif", actor="human:analyst")
        assert seconde.success

    def test_action_inconnue_refusee(self, platform):
        outcome = platform.rollback.rollback_by_id("act_inexistant", "motif", "human:analyst")
        assert not outcome.success


class TestCoupeCircuit:
    def test_ouverture_suspend_toute_execution(self, platform, bruteforce_payload):
        platform.breaker.trip("comportement anormal", actor="human:admin")

        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert result.decision.outcome is DecisionOutcome.BREAKER_OPEN
        assert result.execution is None

    def test_declenchement_automatique_sur_annulations_en_rafale(
        self, platform, probe, bruteforce_payload
    ):
        """La voie qui protege reellement : personne n'est devant l'ecran."""
        for i in range(3):
            platform.ingest_and_respond(
                "generic_json",
                {
                    "category": "bruteforce",
                    "severity": "high",
                    "confidence": 0.8,
                    "asset_id": "srv-web-01",
                    "indicators": {"srcip": f"41.202.1.{i}"},
                    "occurred_at": f"2026-08-24T1{i}:00:00Z",
                },
            )
        _degrader(probe)
        platform.engine.run_control_loop()

        assert not platform.breaker.status().autonomy_active

    def test_le_systeme_ne_se_rearme_jamais_seul(self, platform, probe, bruteforce_payload):
        platform.breaker.trip("emballement", actor="system:breaker")
        probe.set(
            HealthSnapshot(target="srv-web-01", reachable=True, latency_ms=50, throughput=500)
        )
        platform.engine.run_control_loop()

        assert not platform.breaker.status().autonomy_active

    def test_rearmement_par_administrateur_journalise(self, platform):
        platform.breaker.trip("emballement", actor="system:breaker")
        platform.breaker.reset(actor="human:admin", reason="cause traitee")

        assert platform.breaker.status().autonomy_active
        assert platform.ledger.query(event_type="breaker.reset")

    def test_etat_persistant_entre_redemarrages(self, settings, probe):
        """Un simple redemarrage ne doit pas relancer l'autonomie qu'on
        venait d'interrompre."""
        from cirtdefense.platform import build_platform

        first = build_platform(settings, probe=probe)
        first.breaker.trip("emballement", actor="human:admin")
        first.close()

        second = build_platform(settings, probe=probe)
        try:
            assert not second.breaker.status().autonomy_active
        finally:
            second.close()
