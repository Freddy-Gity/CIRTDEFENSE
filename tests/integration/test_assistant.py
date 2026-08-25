"""Assistant d'exploitation : bilan, questions, rapports.

Le test central est celui de la non-invention : l'assistant ne doit jamais
citer un chiffre qu'il n'a pas calcule. Un bilan de sécurité comportant un
nombre fabrique conduirait un décideur a se croire informe alors qu'il ne
l'est pas.
"""

from __future__ import annotations

import re

import pytest

from cirtdefense.assistant.service import Intent
from cirtdefense.demo import build_payload
from cirtdefense.demo.scenarios import ASSETS
from cirtdefense.detection.infra.health import HealthSnapshot


@pytest.fixture
def parc(platform, probe):
    for nom in ASSETS:
        probe.set(
            HealthSnapshot(
                target=nom, reachable=True, latency_ms=80, error_rate=0.01, throughput=400
            )
        )
    platform.breaker._enabled = False
    return platform


class TestBilanSurBaseVide:
    def test_ne_fabrique_rien_sans_donnees(self, platform):
        """Le piege classique : rendre un bilan plausible alors qu'il n'y a
        rien à rapporter."""
        answer = platform.assistant.daily_brief()

        assert answer.facts["incidents_total"] == 0
        assert answer.facts["actions_executees"] == 0
        assert "aucun incident" in answer.text.lower()

    def test_aucun_nombre_non_nul_invente(self, platform):
        answer = platform.assistant.daily_brief()
        # Le libelle de période (« dernières 24 heures ») porte un nombre
        # légitime : il est retiré avant de chercher des chiffrés fabriques.
        texte = answer.text.replace(answer.facts["periode"], "")
        nombres = [int(n) for n in re.findall(r"\b(\d+)\b", texte)]
        assert all(n == 0 for n in nombres), (
            f"chiffrés cités sans donnée correspondante : {nombres}"
        )


class TestBilanSurDonneesReelles:
    def test_les_chiffres_correspondent_aux_faits(self, parc):
        for code in ("A6", "B3", "C4"):
            parc.ingest_and_respond("generic_json", build_payload(code))

        answer = parc.assistant.daily_brief()
        stats = parc.portfolio.statistics()

        assert answer.facts["incidents_total"] == len(parc.portfolio.list(limit=100))
        assert answer.facts["actions_executees"] == stats["actions_executed"]
        assert str(answer.facts["incidents_total"]) in answer.text

    def test_les_repartitions_totalisent_le_nombre_d_incidents(self, parc):
        """Régression : la classification était perdue au rechargement d'un
        incident, si bien que les répartitions ne totalisaient plus le
        nombre d'incidents annonce."""
        for code in ("A1", "A6", "B1", "C4", "D3"):
            parc.ingest_and_respond("generic_json", build_payload(code))
        probe_cible = "srv-web-01"
        parc.probe.set(
            HealthSnapshot(target=probe_cible, reachable=False, error_rate=1.0, throughput=0)
        )
        parc.engine.run_control_loop()

        facts = parc.assistant.daily_brief().facts
        assert sum(facts["incidents_par_famille"].values()) == facts["incidents_total"]
        assert sum(facts["incidents_par_priorite"].values()) == facts["incidents_total"]

    def test_le_taux_d_annulation_eleve_est_signale(self, parc):
        parc.ingest_and_respond("generic_json", build_payload("A1"))
        parc.probe.set(
            HealthSnapshot(target="fw-dmz-01", reachable=False, error_rate=1.0, throughput=0)
        )
        parc.engine.run_control_loop()

        texte = parc.assistant.daily_brief().text
        assert "annulée" in texte.lower()
        assert "anormalement élevé" in texte.lower()

    def test_les_sources_sont_citees(self, parc):
        parc.ingest_and_respond("generic_json", build_payload("A6"))
        answer = parc.assistant.daily_brief()
        assert answer.sources


class TestReconnaissanceDIntention:
    @pytest.mark.parametrize(
        "question,attendu",
        [
            ("Fais le bilan des opérations du jour", Intent.DAILY_BRIEF),
            ("Combien d'actions ont été annulées ?", Intent.ROLLBACKS),
            ("Pourquoi le système a-t-il refuse d'agir ?", Intent.REFUSALS),
            ("Quelle est la posture d'autonomie ?", Intent.POSTURE),
            ("Quels types d'attaques sais-tu traiter ?", Intent.CATALOG),
            ("Génère un rapport", Intent.REPORT),
            ("Donne-moi les statistiques", Intent.STATISTICS),
        ],
    )
    def test_intentions_reconnues(self, platform, question, attendu):
        assert platform.assistant.ask(question).intent is attendu

    def test_insensible_aux_accents(self, platform):
        avec = platform.assistant.ask("Pourquoi a-t-il refusé d'agir ?")
        sans = platform.assistant.ask("Pourquoi a-t-il refuse d'agir ?")
        assert avec.intent is sans.intent

    def test_periode_extraite_de_la_question(self, platform):
        answer = platform.assistant.ask("Fais le bilan sur 7 jours")
        assert "7 jour" in answer.facts["periode"]


class TestRefusDeRepondre:
    @pytest.mark.parametrize(
        "question",
        [
            "Quel temps fera-t-il demain a Douala ?",
            "Ecris-moi un poeme",
            "Quelle est la capitale du Cameroun ?",
        ],
    )
    def test_question_hors_perimetre_declinee(self, platform, question):
        answer = platform.assistant.ask(question)
        assert answer.intent is Intent.UNKNOWN
        assert "ne sais pas répondre" in answer.text.lower()

    def test_le_refus_indique_ce_que_l_assistant_sait_faire(self, platform):
        answer = platform.assistant.ask("Raconte-moi une histoire")
        assert "bilan" in answer.text.lower()

    def test_incident_inexistant_declare_tel_quel(self, platform):
        answer = platform.assistant.ask("Détaille l'incident inc_abcdef123456")
        assert answer.intent is Intent.INCIDENT_DETAIL
        assert "aucun incident" in answer.text.lower()


class TestDetailIncident:
    def test_chronologie_et_actions_restituees(self, parc):
        result = parc.ingest_and_respond("generic_json", build_payload("A6"))
        answer = parc.assistant.ask(f"Détaille {result.incident.incident_id}")

        assert answer.intent is Intent.INCIDENT_DETAIL
        assert "A6" in answer.text
        assert answer.facts["chronologie"]
        assert answer.facts["actions"]


class TestRapports:
    def test_structure_du_rapport(self, parc):
        parc.ingest_and_respond("generic_json", build_payload("A6"))
        rapport = parc.reports.build(hours=24)

        assert rapport["site_id"]
        assert rapport["markdown"].startswith("# Rapport d'opérations")
        for section in ("Posture d'exploitation", "Volumétrie", "Traçabilité"):
            assert section in rapport["markdown"]

    def test_numerotation_sans_trou(self, parc):
        """Les sections vides sont omises : la numérotation doit se
        recalculer, sans quoi le rapport saute des numéros."""
        rapport = parc.reports.build(hours=24)["markdown"]
        numeros = [int(n) for n in re.findall(r"^## (\d+)\.", rapport, re.M)]
        assert numeros == list(range(1, len(numeros) + 1))

    def test_le_rapport_porte_la_note_de_lecture(self, parc):
        """Un rapport transmis hors contexte doit rappeler que les actions
        ont été decidees sans validation humaine."""
        rapport = parc.reports.build(hours=24)["markdown"]
        assert "sans validation" in rapport

    def test_rupture_de_chaine_signalee(self, parc):
        parc.ingest_and_respond("generic_json", build_payload("A1"))
        parc.connection.execute("DROP TRIGGER audit_log_no_update")
        parc.connection.execute("UPDATE audit_log SET payload = '{}' WHERE seq = 2")

        rapport = parc.reports.build(hours=24)["markdown"]
        assert "ROMPUE" in rapport
        assert "incident de sécurité" in rapport


class TestApiAssistant:
    def test_bilan(self, client):
        body = client.get("/api/v1/assistant/brief").json()
        assert body["intent"] == "bilan_du_jour"
        assert body["text"]

    def test_question(self, client):
        body = client.post(
            "/api/v1/assistant/ask", json={"question": "Quelle est la posture ?"}
        ).json()
        assert body["intent"] == "posture"

    def test_question_vide_refusee(self, client):
        assert client.post("/api/v1/assistant/ask", json={"question": "x"}).status_code == 422

    def test_rapport_markdown_telechargeable(self, client):
        response = client.get("/api/v1/assistant/report.md?hours=24")
        assert response.status_code == 200
        assert "markdown" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]

    def test_periode_invalide_refusee(self, client):
        assert client.get("/api/v1/assistant/report?hours=99999").status_code == 400
