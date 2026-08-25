"""Critères de recette du CDCF §5, version v3.0.

Chaque test porte le numéro du critère qu'il demontre. La suite tient lieu de
proces-verbal de recette reproductible : elle peut être rejouee devant le jury
et son résultat ne depend d'aucun équipement réel.

Les critères CR-01 a CR-10 heritent de la v2.1 mais ont été **reformules** :
plusieurs supposaient une étape de validation humaine qui n'existe plus. Les
critères CR-11 a CR-15 sont propres au pivot d'autonomie totale.
"""

from __future__ import annotations

import time

import pytest

from cirtdefense.detection.infra.health import HealthSnapshot
from cirtdefense.domain.enums import (
    ActionStatus,
    DecisionOutcome,
    Reversibility,
    Severity,
)

pytestmark = pytest.mark.acceptance


class TestCR01_NormalisationMultiSources:
    """CR-01 — Toute source supportee produit un `DetectionEvent` exploitable,
    sans modification du moteur d'orchestration (EF-18 a EF-20)."""

    @pytest.mark.parametrize(
        "source,payload",
        [
            (
                "wazuh",
                {
                    "rule": {"level": 10, "description": "Multiple failed password"},
                    "agent": {"id": "srv-01"},
                    "data": {"srcip": "41.202.1.9"},
                },
            ),
            (
                "suricata",
                {
                    "alert": {"signature": "ET TROJAN Beacon", "severity": 1},
                    "src_ip": "10.0.0.5",
                    "dest_ip": "185.1.1.1",
                },
            ),
            (
                "syslog",
                {
                    "line": "<131>1 2026-08-24T10:05:00Z fw-01 sshd 1 ID47 "
                    "Failed password for user root from 41.202.1.9"
                },
            ),
            (
                "generic_json",
                {
                    "category": "scan",
                    "severity": "low",
                    "asset_id": "srv-01",
                    "indicators": {"srcip": "41.202.1.9"},
                },
            ),
        ],
    )
    def test_source_traitee_de_bout_en_bout(self, platform, source, payload):
        result = platform.ingest_and_respond(source, payload)
        assert result is not None
        assert result.decision.decision_id


class TestCR02_Deduplication:
    """CR-02 — Une même observation remontee deux fois ne produit qu'un seul
    traitement (EF-19). En autonomie totale, ce critère devient critique :
    un doublon non filtre est une action exécutée deux fois."""

    def test_second_envoi_ignore(self, platform, bruteforce_payload):
        assert platform.ingest_and_respond("wazuh", bruteforce_payload) is not None
        assert platform.ingest_and_respond("wazuh", bruteforce_payload) is None


class TestCR03_Correlation:
    """CR-03 — Les événements portant sur la même cible et la même famille de
    menace sont regroupes en un incident unique (EF-20)."""

    def test_regroupement(self, platform):
        for i in range(3):
            platform.ingest_and_respond(
                "generic_json",
                {
                    "category": "bruteforce",
                    "severity": "high",
                    "asset_id": "srv-01",
                    "indicators": {"srcip": f"41.202.1.{i}"},
                    "occurred_at": f"2026-08-24T10:0{i}:00Z",
                },
            )
        assert len(platform.portfolio.list()) == 1


class TestCR04_EnrichissementFonde:
    """CR-04 — Aucune action n'est engagee sur un contexte non fonde
    documentairement (EF-04). Reformulation v3.0 : en v2.1 le contexte
    halluciner produisait une recommandation douteuse qu'un humain filtrait ;
    il produirait desormais une action réelle."""

    def test_menace_documentee_permet_d_agir(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert result.decision.outcome is DecisionOutcome.AUTONOMOUS_EXECUTION
        assert result.decision.trace.context_sources

    def test_menace_non_documentee_bloque_l_action(self, platform):
        result = platform.ingest_and_respond(
            "generic_json",
            {
                "category": "menace_inedite_non_repertoriee",
                "severity": "critical",
                "asset_id": "srv-01",
                "title": "signal inconnu",
            },
        )
        assert result.decision.outcome is DecisionOutcome.NO_GROUNDED_CONTEXT
        assert result.execution is None


class TestCR05_ExecutionAutonome:
    """CR-05 — L'action retenue est exécutée sans validation humaine préalable
    (EF-07, revisee). Remplace le critère v2.1 « Valider recommandation »."""

    def test_action_executee_immediatement(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)

        assert result.execution is not None
        assert result.execution.executed >= 1
        assert all(r.status is ActionStatus.EXECUTED for r in result.execution.results)

    def test_aucun_etat_d_attente_dans_le_systeme(self, platform, bruteforce_payload):
        """Il n'existe aucun statut « en attente de validation » : ce serait le
        signe d'une validation humaine residuelle."""
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        statuts = {
            a.status.value
            for i in platform.portfolio.list()
            for a in platform.incidents.get(i.incident_id).actions
        }
        assert not any("attente" in s or "pending" in s for s in statuts)


class TestCR06_PerimetreReversible:
    """CR-06 — Aucune action irréversible n'est exécutée en autonomie (EF-14).
    C'est la mesure compensatoire principale du CDCF §1.4.3."""

    def test_le_catalogue_borne_le_perimetre(self, platform):
        autonomes = platform.catalog.autonomous_subset()
        assert autonomes
        assert all(e.reversibility is not Reversibility.IRREVERSIBLE for e in autonomes)
        assert all(e.rollback_verb for e in autonomes)

    def test_action_irreversible_refusee_a_l_execution(self, platform):
        """Vérification au point de non-retour, et non seulement à la
        planification : une action peut arriver par un autre chemin."""
        from cirtdefense.domain.action import ActionSpec

        result = platform.executor.execute(
            ActionSpec(verb="wipe_disk", actuator="edr", target="srv-01"),
            incident_id="inc_test",
            decision_id="dec_test",
        )
        assert result.status is ActionStatus.BLOCKED_BY_POLICY
        assert "hors du périmètre" in (result.error or "")

    def test_toute_action_executee_reste_annulable(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert all(r.is_reversible for r in result.execution.results)


class TestCR07_PolitiqueCompilee:
    """CR-07 — La politique exprimee en langage naturel par l'administrateur
    contraint effectivement le moteur (EF-15, revisee)."""

    def test_une_interdiction_est_respectee(self, platform, bruteforce_payload):
        from cirtdefense.orchestration.policy_compiler import PolicyCompiler

        report = PolicyCompiler().compile("Ne jamais bloquer une adresse")
        platform.engine.set_policy(report.policy)

        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        verbes = [a.verb for a in result.decision.actions]
        assert "block_ip" not in verbes

    def test_une_consigne_non_comprise_est_signalee(self, platform):
        """Une politique qui parait appliquée sans l'être serait le pire
        résultat possible."""
        from cirtdefense.orchestration.policy_compiler import PolicyCompiler

        report = PolicyCompiler().compile("Soyez raisonnables avec la production")
        assert report.unparsed_sentences
        assert not report.fully_compiled


class TestCR08_NotificationAPosteriori:
    """CR-08 — L'analyste est informe de toute action exécutée, sans que cette
    information ne conditionne l'exécution (EF-13, revisee)."""

    def test_notification_emise_et_exploitable(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        notifications = platform.notifications.pending()

        assert notifications
        corps = notifications[0]["body"]
        assert result.incident.incident_id in corps
        assert "MOTIF DE LA DÉCISION" in corps
        assert "POUR ANNULER" in corps

    def test_echec_de_notification_ne_bloque_pas_l_action(self, platform, bruteforce_payload):
        """L'action a déjà eu lieu : un canal indisponible ne peut pas la
        défaire, et ne doit surtout pas la retenir."""
        actuateur = platform.registry.require("notify")
        actuateur.sinks.append(lambda payload: (_ for _ in ()).throw(RuntimeError("canal HS")))

        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert result.execution.executed >= 1


class TestCR09_PortefeuillePriorise:
    """CR-09 — Le portefeuille classe les incidents par enjeu decroissant
    (Axe 4). Sa sortie change en v3.0 : il montre ce qui a été traité."""

    def test_ordre_par_score_de_risque(self, platform):
        platform.ingest_and_respond(
            "generic_json",
            {
                "category": "scan",
                "severity": "low",
                "asset_id": "poste-01",
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

    def test_indicateurs_de_pilotage(self, platform, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        stats = platform.portfolio.statistics()

        assert stats["actions_executed"] >= 1
        assert "rollback_ratio" in stats


class TestCR10_ModeDegrade:
    """CR-10 — En perte de connectivite, la plateforme met en file et rejoue à
    la reprise (Axe 5). Precision v3.0 : elle n'agit pas, faute de pouvoir
    observer l'effet de ses actions."""

    def test_file_puis_rejeu(self, platform, bruteforce_payload):
        platform.enter_degraded_mode("perte de connectivite")
        assert platform.ingest_and_respond("wazuh", bruteforce_payload) is None
        assert platform.spool.size() == 1

        report = platform.leave_degraded_mode()
        assert report["replayed"] == 1


class TestCR11_RollbackAutonome:
    """CR-11 (nouveau) — Une action suivie d'une dégradation de la cible est
    annulée automatiquement, sans intervention humaine (EF-25)."""

    def test_annulation_automatique(self, platform, probe, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        probe.set(
            HealthSnapshot(target="srv-web-01", reachable=False, error_rate=0.95, throughput=0)
        )

        report = platform.engine.run_control_loop()

        assert report.rolled_back >= 1
        assert not platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")


class TestCR12_CoupeCircuit:
    """CR-12 (nouveau) — L'autonomie peut être suspendue globalement, par
    l'administrateur ou par le système lui-même (EF-26).

    Le critère répond à la question de soutenance : « comment arretez-vous le
    système s'il se trompe en boucle ? »."""

    def test_suspension_manuelle(self, platform, bruteforce_payload):
        platform.breaker.trip("comportement anormal constate", actor="human:admin")
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert result.execution is None

    def test_suspension_automatique_sur_emballement(self, platform, probe):
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
        probe.set(
            HealthSnapshot(target="srv-web-01", reachable=False, error_rate=0.95, throughput=0)
        )
        platform.engine.run_control_loop()

        assert not platform.breaker.status().autonomy_active


class TestCR13_JournalImmuable:
    """CR-13 — Le journal d'audit est complet, immuable et verifiable.

    Repositionne comme mécanisme CENTRAL en v3.0 : c'est la seule trace de ce
    que le système a fait sans intervention humaine."""

    def test_chaine_complete_et_verifiable(self, platform, bruteforce_payload):
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        types = [
            e.event_type for e in platform.ledger.incident_timeline(result.incident.incident_id)
        ]

        assert types[0] == "event.ingested"
        assert {"context.enriched", "decision.made", "action.executed"} <= set(types)
        assert platform.ledger.verify_chain().valid

    def test_alteration_detectee(self, platform, bruteforce_payload):
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        platform.connection.execute("DROP TRIGGER audit_log_no_update")
        platform.connection.execute("UPDATE audit_log SET payload = '{}' WHERE seq = 2")
        assert not platform.ledger.verify_chain().valid


class TestCR14_NonRegressionSecuritaire:
    """CR-14 (CDCF §5.3) — Une action erronee est détectée ET annulée dans un
    délai borne.

    C'est le critère que le jury interrogera en premier : il ne suffit pas que
    le rollback fonctionne, il faut demontrer qu'il aboutit dans un temps
    connu. Un rollback dont on ignore la durée ne compense rien.
    """

    def test_scenario_de_demonstration_complet(self, platform, probe, bruteforce_payload):
        # 1. Une attaque est detectee et confinee automatiquement.
        result = platform.ingest_and_respond("wazuh", bruteforce_payload)
        assert result.execution.executed >= 1
        assert platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

        # 2. Le confinement s'avere errone : le service legitime tombe.
        probe.set(
            HealthSnapshot(
                target="srv-web-01", reachable=False, latency_ms=9000, error_rate=1.0, throughput=0
            )
        )

        # 3. La boucle de controle constate et annule, seule.
        debut = time.monotonic()
        report = platform.engine.run_control_loop()
        duree = time.monotonic() - debut

        assert report.degraded >= 1, "la dégradation n'a pas été détectée"
        assert report.rolled_back == report.degraded, "toutes n'ont pas été annulées"
        assert report.rollback_failures == 0

        # 4. Le delai est borne, et mesure pour chaque action.
        borne = platform.settings.autonomy.rollback_max_latency_seconds
        assert duree < borne
        assert all(o.within_bound for o in report.outcomes), (
            "une annulation a depasse le délai maximal admis pour son type d'action"
        )

        # 5. L'etat reel de l'equipement est retabli.
        assert not platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

        # 6. L'ensemble est trace de facon opposable.
        assert platform.ledger.query(event_type="rollback.completed")
        assert platform.ledger.verify_chain().valid


class TestCR15_AbsenceDeValidationPrealable:
    """CR-15 (nouveau) — Le système ne comporte aucun point de validation
    humaine en amont d'une exécution.

    Contrepartie de la checklist du CDCF §5 : « le diagramme revise ne montre
    plus aucun cas de validation cote Analyste en amont d'une exécution ».
    Ce critère le vérifie sur le code, pas seulement sur le diagramme.
    """

    def test_aucune_route_de_validation_exposee(self, client):
        chemins = client.get("/openapi.json").json()["paths"]
        interdits = ("valider", "validate", "approve", "approuver", "reject", "rejeter")
        assert not [c for c in chemins if any(m in c.lower() for m in interdits)]

    def test_la_porte_de_sortie_humaine_existe_bien(self, client):
        """L'autonomie totale n'est pas l'absence de recours : elle deplace le
        recours après l'action."""
        chemins = client.get("/openapi.json").json()["paths"]
        assert any("rollback" in c for c in chemins)


class TestCR16_ClassificationDesAttaques:
    """CR-16 (nouveau) — Toute attaque du catalogue CIRT est qualifiee selon
    son type, sa famille, sa criticité et sa dangerosité.

    Réponse a l'exigence du document de classification : la réponse autonome
    ne suffit pas, encore faut-il que le système sache dire a quoi il a eu
    affaire et avec quel enjeu.
    """

    def test_les_22_types_sont_qualifies(self, platform, probe):
        from cirtdefense.demo import SCENARIOS, build_payload
        from cirtdefense.demo.scenarios import ASSETS

        for nom in ASSETS:
            probe.set(
                HealthSnapshot(
                    target=nom, reachable=True, latency_ms=80, error_rate=0.01, throughput=400
                )
            )
        platform.breaker._enabled = False

        for scenario in SCENARIOS:
            result = platform.ingest_and_respond(scenario.source, build_payload(scenario.code))
            c = result.decision.classification
            assert c["code"] == scenario.code
            assert c["family_label"]
            assert c["severity"]
            assert 0 < c["dangerousness"] <= 10
            assert c["priority"]

    def test_la_qualification_est_explicable(self, platform):
        """Sans validation humaine en amont, une qualification qu'on ne sait
        pas justifier a posteriori ne vaut rien."""
        from cirtdefense.demo import build_payload

        result = platform.ingest_and_respond("generic_json", build_payload("A6"))
        assert result.decision.classification["factors"]

    def test_criticite_et_dangerosite_sont_distinctes(self, platform):
        """Les deux mesurent des choses differentes, et les confondre
        conduirait a mal prioriser.

        Un balayage (A3) casse peu — criticité basse — mais annonce une
        intrusion : sa dangerosité n'est pas nulle. Une panne de service (D3)
        est l'inverse : elle gêne fortement sans donner la main à un
        attaquant.
        """
        from cirtdefense.domain.events import Asset, DetectionEvent
        from cirtdefense.orchestration.classifier import Classifier

        classifier = Classifier()
        scan = classifier.classify(
            DetectionEvent(
                category="scan",
                severity=Severity.LOW,
                asset=Asset(asset_id="a", criticality=2),
            )
        )
        panne = classifier.classify(
            DetectionEvent(
                category="service_unavailable",
                severity=Severity.HIGH,
                asset=Asset(asset_id="b", criticality=5),
            )
        )

        assert scan.severity is Severity.LOW
        assert scan.dangerousness > 0, "un precurseur n'est jamais sans danger"
        assert panne.severity > scan.severity
        # La panne est plus critique mais pas la plus dangereuse du catalogue :
        # elle interrompt un service, elle n'ouvre pas d'acces.
        assert panne.dangerousness < 9


class TestCR17_ModeDemonstration:
    """CR-17 (nouveau) — Les competences de la plateforme sont eprouvables
    depuis l'interface, sans mener d'attaque réelle."""

    def test_le_catalogue_est_simulable(self, client):
        body = client.get("/api/v1/demo/scenarios").json()
        assert body["count"] == 22

    def test_une_attaque_se_declenche_d_un_appel(self, client):
        body = client.post("/api/v1/demo/run/B3").json()
        assert body["accepted"]
        assert body["execution"]["executed"] >= 1

    def test_le_mode_demonstration_est_refuse_en_actionnement_reel(self, settings, probe):
        """En posture `live`, une attaque simulée declencherait de vraies
        actions sur les équipements."""
        from dataclasses import replace

        from fastapi.testclient import TestClient

        from cirtdefense.api.deps import set_platform
        from cirtdefense.main import create_app
        from cirtdefense.platform import build_platform

        reel = replace(settings, autonomy=replace(settings.autonomy, actuation_mode="live"))
        platform = build_platform(reel, probe=probe)
        try:
            set_platform(platform)
            with TestClient(create_app()) as client:
                response = client.post("/api/v1/demo/run/A1")
            assert response.status_code == 409
            assert "effets réels" in response.json()["detail"]
        finally:
            set_platform(None)
            platform.close()


class TestCR18_AssistantEtRapports:
    """CR-18 (nouveau) — L'assistant rend compte des opérations à partir des
    seules données observées, et produit un rapport transmissible."""

    def test_le_bilan_repose_sur_des_faits_verifiables(self, platform):
        from cirtdefense.demo import build_payload

        platform.ingest_and_respond("generic_json", build_payload("A6"))
        answer = platform.assistant.daily_brief()

        assert answer.facts["incidents_total"] == len(platform.portfolio.list(limit=10))
        assert answer.sources

    def test_l_assistant_refuse_ce_qu_il_ne_sait_pas(self, platform):
        """Un bilan de sécurité comportant un fait invente serait pire
        qu'une absence de réponse."""
        answer = platform.assistant.ask("Quel temps fera-t-il demain ?")
        assert "ne sais pas répondre" in answer.text.lower()

    def test_le_rapport_est_exportable(self, client):
        response = client.get("/api/v1/assistant/report.md?hours=24")
        assert response.status_code == 200
        assert response.text.startswith("# Rapport d'opérations")
