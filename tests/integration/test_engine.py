"""Chaîne complète : de l'événement brut a l'action exécutée."""

from __future__ import annotations

from cirtdefense.domain.enums import ActionStatus, DecisionOutcome


class TestExecutionAutonome:
    def test_reponse_executee_sans_validation(self, platform, bruteforce_payload):
        """EF-07 : aucune étape d'attente entre la décision et l'action."""
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)

        assert result.decision.outcome is DecisionOutcome.AUTONOMOUS_EXECUTION
        assert result.execution.executed >= 1
        assert all(r.status is ActionStatus.EXECUTED for r in result.execution.results)

    def test_effet_reel_sur_l_actuateur(self, platform, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

    def test_deduplication_empeche_la_double_action(self, platform, bruteforce_payload):
        """EF-19 : deux remontees de la même observation ne doivent pas
        produire deux actions sur la même cible."""
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert platform.ingest_and_respond("wazuh", bruteforce_payload) is None

    def test_notification_a_posteriori_emise(self, platform, bruteforce_payload):
        """EF-13 revisee : l'analyste est informe, sans avoir rien bloque."""
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        notifications = platform.notifications.pending()
        assert notifications
        assert "après coup" in notifications[0]["body"]


class TestRefusDAgir:
    def test_menace_non_documentee_bloque_l_action(self, platform):
        """EF-04 : la limite assumee du périmètre autonome."""
        result = platform.ingest_and_respond(
            "generic_json",
            {
                "category": "menace_totalement_inconnue",
                "severity": "critical",
                "asset_id": "srv-01",
                "title": "signal opaque",
            },
        )
        assert result.decision.outcome is DecisionOutcome.NO_GROUNDED_CONTEXT
        assert result.execution is None

    def test_politique_refusant_toutes_les_actions(self, platform, bruteforce_payload):
        """Quand plus aucune action candidate ne passe, la décision est un
        refus — jamais une mise en attente d'un humain."""
        from cirtdefense.orchestration.policy_compiler import PolicyCompiler

        report = PolicyCompiler().compile(
            "Ne jamais bloquer une adresse. "
            "Ne jamais révoquer de sessions. "
            "Ne jamais verrouiller de compte. "
            "Ne jamais forcer le second facteur. "
            "Ne jamais notifier. "
            "Ne jamais limiter le rythme"
        )
        platform.engine.set_policy(report.policy)

        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert result.decision.outcome is DecisionOutcome.POLICY_DENIED
        assert result.execution is None

    def test_politique_appliquee_partiellement(self, platform, bruteforce_payload):
        """Le cas courant : la politique retire certaines actions et laisse
        passer les autres. Le refus doit être trace action par action, sans
        empêcher la réponse restante de s'appliquer."""
        from cirtdefense.orchestration.policy_compiler import PolicyCompiler

        report = PolicyCompiler().compile("Ne jamais bloquer une adresse")
        platform.engine.set_policy(report.policy)

        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        verbes = {a.verb for a in result.decision.actions}

        assert result.decision.outcome is DecisionOutcome.AUTONOMOUS_EXECUTION
        assert "block_ip" not in verbes, "l'action interdite a été retenue"
        assert verbes, "toutes les actions ont été retirées alors qu'une seule était interdite"

        refus = [v for v in result.decision.trace.policy_verdicts if not v["allowed"]]
        assert refus, "le refus n'apparait pas dans la trace de décision"
        assert all(v["rule_text"] for v in refus), "le refus ne cite pas la consigne d'origine"

    def test_autonomie_desactivee_journalise_sans_agir(self, settings, probe):
        from dataclasses import replace

        from cirtdefense.platform import build_platform

        muted = replace(settings, autonomy=replace(settings.autonomy, enabled=False))
        platform = build_platform(muted, probe=probe)
        try:
            result = platform.ingest_and_respond(
                "generic_json",
                {
                    "category": "bruteforce",
                    "severity": "high",
                    "asset_id": "srv-01",
                    "indicators": {"srcip": "41.202.1.9"},
                },
            )
            assert result.execution is None
            assert platform.ledger.query(event_type="decision.made")
        finally:
            platform.close()


class TestTracabilite:
    def test_chaque_etape_est_journalisee(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        types = [
            e.event_type for e in platform.ledger.incident_timeline(result.incident.incident_id)
        ]

        assert "event.ingested" in types
        assert "context.enriched" in types
        assert "decision.made" in types
        assert "action.executed" in types
        assert "analyst.notified" in types

    def test_la_decision_porte_ses_sources(self, platform, bruteforce_payload):
        """Sans validation humaine en amont, la décision doit se defendre
        seule après coup."""
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        trace = result.decision.trace

        assert trace.playbook_id
        assert trace.matched_conditions
        assert trace.context_sources
        assert trace.policy_verdicts

    def test_chaine_d_audit_intacte(self, platform, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert platform.ledger.verify_chain().valid


class TestGraduationDeLaReponse:
    def test_source_interne_traitee_avec_moins_de_severite(self, platform):
        """Bloquer une source interne coupe un usage légitime plus souvent
        qu'il n'arrête un attaquant."""
        result = platform.ingest_and_respond(
            "generic_json",
            {
                "category": "bruteforce",
                "severity": "medium",
                "confidence": 0.8,
                "asset_id": "srv-01",
                "indicators": {"srcip": "10.0.0.42"},
            },
        )
        verbes = [a.verb for a in result.decision.actions]
        assert "block_ip" not in verbes
        assert "rate_limit_ip" in verbes

    def test_degradation_infra_ne_declenche_aucune_correction(self, platform):
        """Une panne dont la cause n'est pas établie comme malveillante ne
        justifie pas d'agir : le risque d'aggraver depasse le bénéfice."""
        result = platform.ingest_and_respond(
            "generic_json",
            {
                "category": "infrastructure_degradation",
                "severity": "high",
                "asset_id": "srv-web-01",
                "title": "latence excessive",
            },
        )
        verbes = {a.verb for a in result.decision.actions}
        assert verbes <= {"notify"}
