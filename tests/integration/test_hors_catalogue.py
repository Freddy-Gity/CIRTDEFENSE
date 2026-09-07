"""Menaces absentes du catalogue CIRT.

Le catalogue couvre 22 types ; une plateforme nationale en rencontrera
d'autres. C'est le cas le plus important à éprouver : une menace inédite est
précisément celle contre laquelle personne n'est préparé.

La règle que ces tests verrouillent tient en une phrase : la plateforme ne
devine jamais le type d'attaque, mais elle agit sur ce qu'elle observe — et
seulement par des gestes qu'elle sait défaire.
"""

from __future__ import annotations

import pytest

from cirtdefense.demo.inconnus import INCONNUS, build_payload_inconnu, get_inconnu
from cirtdefense.domain.enums import DecisionOutcome, Reversibility


@pytest.fixture
def menace_inconnue():
    return build_payload_inconnu("Z1")


class TestQualification:
    def test_la_menace_est_declaree_non_catalogüee(self, platform, menace_inconnue):
        """Le repli est `unknown`, jamais une catégorie plausible : une
        catégorie inventée orienterait le choix de la réponse sur une base
        non fondée."""
        result = platform.ingest_and_respond("wazuh", menace_inconnue)

        assert result.event.category == "unknown"
        assert result.decision.classification["catalogued"] is False
        assert result.decision.classification["code"] == "?"

    def test_l_incident_entre_quand_meme_au_portefeuille(self, platform, menace_inconnue):
        """Ne pas savoir qualifier n'est pas une raison de perdre l'incident."""
        platform.ingest_and_respond("wazuh", menace_inconnue)
        assert len(platform.portfolio.list()) == 1

    def test_criticite_et_dangerosite_restent_calculees(self, platform, menace_inconnue):
        classification = platform.ingest_and_respond(
            "wazuh", menace_inconnue
        ).decision.classification
        assert classification["severity"]
        assert classification["dangerousness"] > 0


class TestConfinementDeRepli:
    """EF-04 n'est pas levé : il change de fondement. Le repli ne déduit rien
    du type d'attaque — il part des indicateurs effectivement observés."""

    def test_aucun_playbook_n_est_choisi(self, platform, menace_inconnue):
        result = platform.ingest_and_respond("wazuh", menace_inconnue)
        assert result.decision.trace.playbook_id == ""

    def test_seuls_des_gestes_reversibles_partent_seuls(self, platform):
        for scenario in INCONNUS:
            result = platform.ingest_and_respond(
                scenario.source, build_payload_inconnu(scenario.code)
            )
            if result is None or result.execution is None:
                continue
            for action in result.execution.results:
                assert action.spec.reversibility is Reversibility.REVERSIBLE, (
                    f"{scenario.code} : {action.spec.key} n'est pas réversible "
                    "et ne devait pas partir sans confirmation"
                )

    def test_les_gestes_durables_attendent_une_confirmation(self, platform, menace_inconnue):
        result = platform.ingest_and_respond("wazuh", menace_inconnue)
        a_confirmer = result.decision.fallback["requires_confirmation"]

        assert a_confirmer, "isoler un hôte a un effet durable et doit être proposé"
        engages = {a.key for a in result.decision.actions}
        for suggestion in a_confirmer:
            assert f"{suggestion['actuator']}:{suggestion['verb']}" not in engages

    def test_chaque_geste_porte_le_fait_qui_le_motive(self, platform, menace_inconnue):
        """C'est ce qui distingue le repli d'une devinette : on peut contester
        « j'ai vu cette adresse », pas « j'ai jugé opportun »."""
        result = platform.ingest_and_respond("wazuh", menace_inconnue)
        for suggestion in result.decision.fallback["autonomous"]:
            assert suggestion["basis"], f"{suggestion['verb']} n'expose pas son fondement"

    def test_la_reponse_depend_des_indicateurs_pas_du_type(self, platform):
        """Deux menaces également inconnues, des indicateurs différents, donc
        des réponses différentes."""
        avec_domaine = platform.ingest_and_respond("suricata", build_payload_inconnu("Z5"))
        sans_domaine = platform.ingest_and_respond("wazuh", build_payload_inconnu("Z4"))

        verbes = lambda r: {a.spec.verb for a in r.execution.results}  # noqa: E731
        assert "block_resolution" in verbes(avec_domaine)
        assert "block_resolution" not in verbes(sans_domaine)

    def test_une_adresse_interne_n_est_jamais_bloquee(self, platform):
        """Bloquer une adresse du parc reviendrait à s'auto-infliger la panne
        que l'on cherche à éviter."""
        result = platform.ingest_and_respond(
            "generic_json",
            {
                "category": "signal_inconnu_interne",
                "severity": "critical",
                "asset_id": "srv-app-01",
                "indicators": {"srcip": "10.0.2.30"},
            },
        )
        cibles = {a.spec.target for a in (result.execution.results if result.execution else [])}
        assert "10.0.2.30" not in cibles

    def test_la_politique_s_applique_aussi_au_repli(self, platform, menace_inconnue):
        """« Ne jamais bloquer une adresse » vaut aussi pour une menace
        inconnue : l'urgence ne dispense pas de la politique."""
        from cirtdefense.orchestration.policy_compiler import PolicyCompiler

        rapport = PolicyCompiler().compile(
            "Ne jamais bloquer une adresse. Ne jamais déclencher un instantané. "
            "Ne jamais forcer le second facteur. Ne jamais bloquer la résolution. "
            "Ne jamais fermer un port."
        )
        platform.engine.set_policy(rapport.policy)

        result = platform.ingest_and_respond("wazuh", menace_inconnue)
        assert result.decision.outcome is DecisionOutcome.POLICY_DENIED
        assert result.execution is None


class TestAlerteEtTracabilite:
    def test_l_analyste_est_prevenu(self, platform, menace_inconnue):
        result = platform.ingest_and_respond("wazuh", menace_inconnue)
        assert result.notifications

    def test_le_motif_dit_que_le_type_reste_a_qualifier(self, platform, menace_inconnue):
        motif = platform.ingest_and_respond("wazuh", menace_inconnue).decision.rationale
        assert "non catalog" in motif.lower() or "qualifier" in motif.lower()

    def test_tout_est_journalise(self, platform, menace_inconnue):
        result = platform.ingest_and_respond("wazuh", menace_inconnue)
        entrees = platform.ledger.query(incident_id=result.incident.incident_id, limit=50)
        types = {e.event_type for e in entrees}
        assert "decision.made" in types
        assert platform.ledger.verify_chain().valid


class TestApiDemonstration:
    def test_les_scenarios_inconnus_sont_listes(self, client):
        corps = client.get("/api/v1/demo/unknown").json()
        assert corps["count"] == len(INCONNUS)
        assert all(s["catalogued"] is False for s in corps["scenarios"])

    def test_declenchement_rend_les_deux_volets(self, client, admin_headers):
        corps = client.post("/api/v1/demo/run-unknown/Z1", headers=admin_headers).json()

        assert corps["accepted"] is True
        assert corps["catalogued"] is False
        assert corps["observations"]
        assert corps["autonomous"]
        assert corps["requires_confirmation"]

    def test_scenario_inexistant(self, client, admin_headers):
        assert client.post("/api/v1/demo/run-unknown/Z99", headers=admin_headers).status_code == 404

    def test_reserve_a_l_administrateur(self, client):
        assert client.post("/api/v1/demo/run-unknown/Z1").status_code == 403

    def test_chaque_scenario_est_jouable(self, client, admin_headers):
        for scenario in INCONNUS:
            reponse = client.post(
                f"/api/v1/demo/run-unknown/{scenario.code}", headers=admin_headers
            )
            assert reponse.status_code == 202, f"{scenario.code} : {reponse.text[:120]}"
            assert get_inconnu(scenario.code) is not None
