"""Mode démonstration : les 22 types simulables de bout en bout."""

from __future__ import annotations

import pytest

from cirtdefense.demo import SCENARIOS, build_payload
from cirtdefense.demo.scenarios import ASSETS
from cirtdefense.detection.infra.health import HealthSnapshot
from cirtdefense.domain.enums import DecisionOutcome
from cirtdefense.domain.taxonomy import BY_CODE


@pytest.fixture
def parc(platform, probe):
    """Tout le parc fictif en bonne santé : sans cela, la boucle de contrôle
    imputerait à nos actions une dégradation preexistante."""
    for nom in ASSETS:
        probe.set(
            HealthSnapshot(
                target=nom, reachable=True, latency_ms=80, error_rate=0.01, throughput=400
            )
        )
    platform.breaker._enabled = False
    return platform


class TestCouverture:
    def test_un_scenario_par_type_du_catalogue(self):
        assert {s.code for s in SCENARIOS} == set(BY_CODE)

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.code)
    def test_la_charge_utile_est_normalisable(self, scenario):
        payload = build_payload(scenario.code)
        assert isinstance(payload, dict) and payload

    def test_code_inconnu_refuse(self):
        with pytest.raises(KeyError, match="inconnu"):
            build_payload("Z9")


class TestChaineComplete:
    @pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.code)
    def test_chaque_scenario_produit_une_reponse(self, parc, scenario):
        result = parc.ingest_and_respond(scenario.source, build_payload(scenario.code))

        assert result is not None, f"{scenario.code} n'a produit aucun résultat"
        assert result.decision.outcome is DecisionOutcome.AUTONOMOUS_EXECUTION, (
            f"{scenario.code} : {result.decision.rationale}"
        )
        assert result.execution.executed >= 1, f"{scenario.code} n'a exécuté aucune action"

    @pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.code)
    def test_chaque_scenario_est_classifie(self, parc, scenario):
        result = parc.ingest_and_respond(scenario.source, build_payload(scenario.code))
        classification = result.decision.classification

        assert classification["code"] == scenario.code
        assert classification["family_code"] == scenario.code[0]
        assert 0 < classification["dangerousness"] <= 10
        assert classification["priority"]

    def test_le_portefeuille_recoit_tous_les_incidents(self, parc):
        for scenario in SCENARIOS:
            parc.ingest_and_respond(scenario.source, build_payload(scenario.code))

        portefeuille = parc.portfolio.list(limit=100)
        assert len(portefeuille) == len(SCENARIOS)
        assert all(i.attack_code for i in portefeuille), (
            "des incidents sont arrives au portefeuille sans classification"
        )

    def test_le_portefeuille_est_ordonne_par_enjeu(self, parc):
        for scenario in SCENARIOS:
            parc.ingest_and_respond(scenario.source, build_payload(scenario.code))

        scores = [i.risk_score for i in parc.portfolio.list(limit=100)]
        assert scores == sorted(scores, reverse=True)


class TestConformiteAuCatalogue:
    def test_aucune_action_irreversible_sur_tout_le_catalogue(self, parc):
        """Principe de conception du document, vérifié à l'exécution et non
        seulement dans la taxonomie."""
        for scenario in SCENARIOS:
            result = parc.ingest_and_respond(scenario.source, build_payload(scenario.code))
            if result is None or result.execution is None:
                continue
            for action in result.execution.results:
                assert action.spec.reversibility.value != "irreversible", (
                    f"{scenario.code} a exécuté une action irréversible : {action.spec.key}"
                )

    def test_le_rancongiciel_ne_declenche_aucune_remediation(self, parc):
        """A6 : isolation uniquement, jamais d'effacement ni de restauration."""
        result = parc.ingest_and_respond("generic_json", build_payload("A6"))
        verbes = {a.spec.verb for a in result.execution.results}

        assert "move_to_vlan" in verbes
        assert not verbes & {"wipe_disk", "shutdown_host", "delete_account"}

    def test_le_certificat_tls_ne_declenche_que_la_notification(self, parc):
        """D1 dépend d'une autorité externe : la plateforme s'abstient."""
        result = parc.ingest_and_respond("generic_json", build_payload("D1"))
        assert {a.spec.verb for a in result.execution.results} == {"notify"}

    def test_l_acces_hors_profil_ne_revoque_pas_le_compte(self, parc):
        """C2 : le document exclut la révocation, le risque de faux positif
        y étant plus élève qu'ailleurs."""
        result = parc.ingest_and_respond("generic_json", build_payload("C2"))
        verbes = {a.spec.verb for a in result.execution.results}
        assert not verbes & {"disable_account", "lock_account"}


class TestApiDemonstration:
    def test_catalogue_expose(self, client):
        body = client.get("/api/v1/demo/scenarios").json()
        assert body["count"] == 22
        assert set(body["by_family"]) == {"A", "B", "C", "D"}

    def test_declenchement_unitaire(self, client):
        body = client.post("/api/v1/demo/run/A6").json()
        assert body["accepted"]
        assert body["decision"]["classification"]["code"] == "A6"

    def test_declenchement_par_famille(self, client):
        body = client.post("/api/v1/demo/run-all?family=C").json()
        assert body["scenarios_run"] == 4

    def test_famille_inconnue(self, client):
        assert client.post("/api/v1/demo/run-all?family=Z").status_code == 404

    def test_scenario_inconnu(self, client):
        assert client.post("/api/v1/demo/run/Z9").status_code == 404

    def test_remise_a_zero_conserve_le_journal(self, client):
        """Le journal est immuable par construction : une remise à zero qui
        le viderait contredirait le mécanisme qu'il incarne."""
        client.post("/api/v1/demo/run/A1")
        avant = client.get("/api/v1/audit/verify").json()["entries_checked"]

        body = client.post("/api/v1/demo/reset").json()

        assert body["reset"]
        assert body["audit_entries_kept"] >= avant
        assert client.get("/api/v1/incidents").json()["count"] == 0
        assert client.get("/api/v1/audit/verify").json()["valid"]
