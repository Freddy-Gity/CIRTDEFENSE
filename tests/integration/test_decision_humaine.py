"""Alerte persistante (EF-28) et qualification du hors-catalogue (EF-29).

Ces deux mécanismes ferment la boucle ouverte par le confinement de repli : ce
que la plateforme refuse d'engager seule doit rester visible jusqu'à décision,
et ce qu'elle ne sait pas nommer doit finir par l'être.

Le point que ces tests protègent avant tout : **rien ici ne réintroduit une
validation préalable**. Les gestes listés n'ont jamais été planifiés pour
exécution autonome ; ils ont été écartés au moment de la décision.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cirtdefense.api.deps import set_platform
from cirtdefense.demo.inconnus import build_payload_inconnu
from cirtdefense.domain.enums import ActionStatus
from cirtdefense.main import app
from cirtdefense.platform import build_platform


@pytest.fixture
def platform():
    plateforme = build_platform(db_path=":memory:")
    set_platform(plateforme)
    yield plateforme
    set_platform(None)
    plateforme.close()


@pytest.fixture
def client(platform):
    return TestClient(app)


@pytest.fixture
def entetes(platform):
    return {"Authorization": f"Bearer {platform.settings.admin_token}"}


@pytest.fixture
def incident_hors_catalogue(platform):
    """Z2 : le scénario le plus riche — compte, port, destination, actif critique."""
    return platform.ingest_and_respond("wazuh", build_payload_inconnu("Z2"))


class TestAlertePersistante:
    def test_les_gestes_durables_sont_inscrits_et_non_executes(
        self, platform, incident_hors_catalogue
    ):
        resultat = incident_hors_catalogue
        assert resultat.pending, "aucun geste durable n'a été mis en attente"

        engages = {r.spec.key for r in resultat.execution.results}
        attendus = {f"{p['actuator']}:{p['verb']}" for p in resultat.pending}
        assert not (engages & attendus), (
            "un geste en attente a aussi été exécuté : la règle de partage est cassée"
        )

    def test_l_attente_survit_a_la_consultation(self, platform, client, incident_hors_catalogue):
        """C'est ce qui distingue l'alerte de la notification : elle ne se
        consomme pas à la lecture."""
        avant = client.get("/api/v1/pending").json()["count"]
        client.get("/api/v1/pending")
        client.get("/api/v1/pending")
        assert client.get("/api/v1/pending").json()["count"] == avant

    def test_l_attente_est_visible_depuis_l_etat_global(self, platform, incident_hors_catalogue):
        assert platform.status()["awaiting_human_decision"] == len(incident_hors_catalogue.pending)

    def test_confirmer_execute_reellement_le_geste(
        self, platform, client, entetes, incident_hors_catalogue
    ):
        attente = client.get("/api/v1/pending").json()["pending"][0]
        reponse = client.post(
            f"/api/v1/pending/{attente['pending_id']}/confirm",
            json={"reason": "effet durable assumé après analyse"},
            headers=entetes,
        )
        assert reponse.status_code == 200
        corps = reponse.json()
        assert corps["pending"]["status"] == "confirmed"
        assert corps["action"]["status"] == ActionStatus.EXECUTED.value

        # Une action confirmée n'est pas de seconde classe : elle reste
        # annulable a posteriori comme toute autre.
        resultat = platform.actions.get(corps["action"]["action_id"])
        assert resultat is not None
        assert resultat.rollback_token

    def test_se_charger_soi_meme_n_execute_rien_et_engage(
        self, client, entetes, incident_hors_catalogue
    ):
        """« Je m'en charge » ouvre une prise en charge, ne clôt pas le dossier.

        La plateforme n'exécute toujours rien — c'est l'invariant d'origine.
        Mais le dossier reste ouvert jusqu'à ce que l'agent dise ce qu'il a
        fait : un engagement que plus personne ne voit est exactement le défaut
        que l'alerte persistante corrige.
        """
        attente = client.get("/api/v1/pending").json()["pending"][0]
        corps = client.post(
            f"/api/v1/pending/{attente['pending_id']}/handled",
            json={"reason": "intervention manuelle sur l'annuaire"},
            headers=entetes,
        ).json()
        assert corps["pending"]["status"] == "taken_over"
        assert corps["action"] is None

        encore = client.get("/api/v1/pending").json()["pending"]
        assert attente["pending_id"] in {a["pending_id"] for a in encore}

        clos = client.post(
            f"/api/v1/pending/{attente['pending_id']}/resolved",
            json={"reason": "compte desactive a la main dans l annuaire"},
            headers=entetes,
        ).json()
        assert clos["pending"]["status"] == "handled_by_human"
        assert clos["action"] is None

    def test_ecarter_conserve_le_motif(self, client, entetes, incident_hors_catalogue):
        attente = client.get("/api/v1/pending").json()["pending"][0]
        corps = client.post(
            f"/api/v1/pending/{attente['pending_id']}/decline",
            json={"reason": "compte de service légitime"},
            headers=entetes,
        ).json()
        assert corps["pending"]["status"] == "declined"
        assert corps["pending"]["resolution_note"] == "compte de service légitime"

    def test_une_attente_resolue_ne_se_rejoue_pas(
        self, client, entetes, incident_hors_catalogue
    ):
        """Deux analystes qui cliquent en même temps ne doivent pas produire
        deux exécutions du même geste durable."""
        attente = client.get("/api/v1/pending").json()["pending"][0]
        premier = client.post(
            f"/api/v1/pending/{attente['pending_id']}/confirm",
            json={"reason": "première décision"},
            headers=entetes,
        )
        second = client.post(
            f"/api/v1/pending/{attente['pending_id']}/confirm",
            json={"reason": "second clic"},
            headers=entetes,
        )
        assert premier.status_code == 200
        assert second.status_code == 409

    def test_les_trois_issues_sont_inscrites_au_journal(
        self, platform, client, entetes, incident_hors_catalogue
    ):
        attentes = client.get("/api/v1/pending").json()["pending"]
        for attente, issue in zip(attentes, ("confirm", "handled", "decline"), strict=False):
            client.post(
                f"/api/v1/pending/{attente['pending_id']}/{issue}",
                json={"reason": f"issue {issue}"},
                headers=entetes,
            )
        inscrites = platform.ledger.query(event_type="confirmation.resolved")
        # Trois décisions, mais quatre inscriptions : écarter en produit deux,
        # la décision de l'agent puis la suite que la plateforme y donne. C'est
        # voulu — la mesure prise après un refus est un fait à part entière, et
        # la confondre avec le refus rendrait le journal muet sur ce que la
        # plateforme a décidé toute seule.
        resolutions = {e.payload.get("resolution") for e in inscrites}
        assert resolutions == {"confirmed", "taken_over", "declined"}
        assert len(inscrites) >= 3
        assert any(e.payload.get("suite") for e in inscrites), (
            "la suite donnée au refus doit figurer au journal"
        )
        assert all(e.actor.startswith("human:") for e in inscrites)
        assert platform.ledger.verify_chain().valid

    def test_le_motif_est_obligatoire(self, client, entetes, incident_hors_catalogue):
        attente = client.get("/api/v1/pending").json()["pending"][0]
        reponse = client.post(
            f"/api/v1/pending/{attente['pending_id']}/decline",
            json={"reason": ""},
            headers=entetes,
        )
        assert reponse.status_code == 422, "une décision humaine sans motif ne se rejuge pas"

    def test_aucune_route_de_validation_prealable_n_est_apparue(self, client):
        """CR-15 s'applique aussi à ce qui vient d'être ajouté : ces routes
        tranchent sur un geste écarté, elles n'autorisent pas une action
        planifiée."""
        chemins = client.get("/openapi.json").json()["paths"]
        interdits = ("valider", "validate", "approve", "approuver", "reject", "rejeter")
        suspects = [c for c in chemins if any(m in c.lower() for m in interdits)]
        assert not suspects, f"routes de validation détectées : {suspects}"


class TestQualification:
    def test_une_menace_hors_catalogue_ouvre_une_fiche(self, incident_hors_catalogue):
        fiche = incident_hors_catalogue.qualification
        assert fiche is not None
        assert fiche["status"] == "proposed"
        assert fiche["label"]
        assert fiche["signal"], "la fiche doit porter ce qui a été observé"

    def test_la_fiche_decrit_sans_diagnostiquer(self, incident_hors_catalogue):
        """Nommer « exfiltration » ce qui pourrait être une sauvegarde mal
        configurée serait l'invention que la garde EF-04 interdit ailleurs."""
        fiche = incident_hors_catalogue.qualification
        for mot in ("exfiltration", "ransomware", "rançongiciel", "intrusion"):
            assert mot not in fiche["label"].lower()

    def test_une_menace_cataloguee_n_ouvre_aucune_fiche(self, platform):
        from cirtdefense.demo import build_payload, get_scenario

        scenario = get_scenario("A1")
        resultat = platform.ingest_and_respond(scenario.source, build_payload("A1"))
        assert resultat.decision.classification["catalogued"] is True
        assert resultat.qualification is None

    def test_une_seule_fiche_par_incident(self, platform, incident_hors_catalogue):
        """Les événements corrélés au même incident ne doivent pas noyer
        l'analyste sous des propositions identiques."""
        platform.ingest_and_respond("wazuh", build_payload_inconnu("Z2"))
        proposees = platform.qualifications.by_status("proposed")
        incidents = {f["incident_id"] for f in proposees}
        assert len(proposees) == len(incidents)

    def test_la_proposition_n_a_aucun_effet_avant_validation(
        self, platform, incident_hors_catalogue
    ):
        assert platform.qualifications.validated() == []
        assert platform.status()["learned_catalog"] == 0

    def test_valider_inscrit_au_catalogue_appris(self, client, entetes, incident_hors_catalogue):
        fiche = client.get("/api/v1/qualifications").json()["qualifications"][0]
        corps = client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/adopt",
            json={"label": "Dépendance logicielle compromise", "dangerousness": 8.5},
            headers=entetes,
        ).json()
        assert corps["qualification"]["status"] == "validated"
        assert corps["qualification"]["code"].startswith("L")
        assert corps["qualification"]["label"] == "Dépendance logicielle compromise"
        assert corps["catalog_size"] == 1

    def test_la_seconde_occurrence_est_reconnue(
        self, platform, client, entetes, incident_hors_catalogue
    ):
        """C'est la raison d'être du mécanisme : ce qui a été qualifié une fois
        n'est plus une menace inconnue la fois suivante."""
        fiche = client.get("/api/v1/qualifications").json()["qualifications"][0]
        client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/adopt",
            json={"label": "Dépendance logicielle compromise"},
            headers=entetes,
        )

        charge = build_payload_inconnu("Z2")
        charge["agent"]["name"] = "srv-app-02"
        charge["agent"]["id"] = "042"
        suivant = platform.ingest_and_respond("wazuh", charge)

        classification = suivant.decision.classification
        assert classification["catalogued"] is True
        assert classification["label"] == "Dépendance logicielle compromise"
        assert suivant.qualification is None

    def test_reconnue_mais_toujours_sans_playbook(
        self, platform, client, entetes, incident_hors_catalogue
    ):
        """Savoir comment s'appelle une menace n'apprend pas comment y répondre.
        La réponse reste le confinement déduit des indicateurs."""
        fiche = client.get("/api/v1/qualifications").json()["qualifications"][0]
        client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/adopt",
            json={},
            headers=entetes,
        )
        charge = build_payload_inconnu("Z2")
        charge["agent"]["id"] = "042"
        suivant = platform.ingest_and_respond("wazuh", charge)
        assert suivant.decision.fallback, "la réponse doit rester un confinement de repli"
        assert not suivant.decision.trace.playbook_id

    def test_rejeter_conserve_la_fiche(self, client, entetes, incident_hors_catalogue):
        """Un rejet motivé documente ce que la plateforme a cru voir."""
        fiche = client.get("/api/v1/qualifications").json()["qualifications"][0]
        corps = client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/dismiss",
            json={"note": "faux positif : sauvegarde planifiée"},
            headers=entetes,
        ).json()
        assert corps["qualification"]["status"] == "rejected"
        assert client.get("/api/v1/qualifications?state=rejected").json()["count"] == 1

    def test_une_fiche_traitee_ne_se_rejoue_pas(self, client, entetes, incident_hors_catalogue):
        fiche = client.get("/api/v1/qualifications").json()["qualifications"][0]
        client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/adopt", json={}, headers=entetes
        )
        second = client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/dismiss", json={}, headers=entetes
        )
        assert second.status_code == 409

    def test_la_qualification_est_tracee(self, platform, client, entetes, incident_hors_catalogue):
        fiche = client.get("/api/v1/qualifications").json()["qualifications"][0]
        client.post(
            f"/api/v1/qualifications/{fiche['qualification_id']}/adopt", json={}, headers=entetes
        )
        assert platform.ledger.query(event_type="qualification.proposed")
        resolues = platform.ledger.query(event_type="qualification.resolved")
        assert resolues and resolues[0].actor.startswith("human:")
        assert platform.ledger.verify_chain().valid


class TestSignatureDeReconnaissance:
    def test_deux_formes_differentes_ne_se_confondent_pas(self, platform):
        """Z2 et Z3 n'exposent pas les mêmes indicateurs : les reconnaître
        comme un même type serait exactement l'erreur à éviter."""
        from cirtdefense.orchestration.qualifier import signature

        z2 = platform.adapter.ingest("wazuh", build_payload_inconnu("Z2")).event
        z3 = platform.adapter.ingest("wazuh", build_payload_inconnu("Z3")).event
        assert signature(z2) != signature(z3)

    def test_la_signature_ignore_les_valeurs_volatiles(self, platform):
        """Deux occurrences de la même menace n'ont pas les mêmes adresses ni
        les mêmes comptes. C'est la *forme* de l'observation qui se répète."""
        from cirtdefense.orchestration.qualifier import signature

        premier = platform.adapter.ingest("wazuh", build_payload_inconnu("Z2")).event
        charge = build_payload_inconnu("Z2")
        charge["data"]["dstip"] = "203.0.113.200"
        charge["data"]["dstuser"] = "svc-deploy"
        charge["agent"]["id"] = "099"
        second = platform.adapter.ingest("wazuh", charge).event
        assert signature(premier) == signature(second)


class TestIsolationApresExecution:
    """Le point de non-retour : une panne annexe ne doit jamais faire croire
    que la réponse n'a pas eu lieu.

    Sans cette isolation, un serveur de messagerie injoignable faisait remonter
    une exception à l'appelant *alors que les gestes étaient déjà posés sur les
    équipements*. Le journal disait vrai, l'appelant croyait le contraire.
    """

    def _casser(self, platform, methode: str):
        def tombe(*a, **k):
            raise RuntimeError(f"panne simulée de {methode}")

        setattr(platform.engine._notifier, methode, tombe)

    def test_une_notification_en_panne_n_annule_pas_la_reponse(self, platform):
        from cirtdefense.demo import build_payload, get_scenario

        self._casser(platform, "notify_actions")
        scenario = get_scenario("A1")
        resultat = platform.ingest_and_respond(scenario.source, build_payload("A1"))

        assert resultat is not None, "l'appel a échoué alors que les gestes ont eu lieu"
        assert resultat.execution.executed >= 1
        assert resultat.acted is True
        assert any("notification" in a for a in resultat.warnings)

    def test_l_incident_reste_enregistre(self, platform):
        from cirtdefense.demo import build_payload, get_scenario

        self._casser(platform, "notify_actions")
        scenario = get_scenario("A1")
        resultat = platform.ingest_and_respond(scenario.source, build_payload("A1"))
        assert platform.incidents.get(resultat.incident.incident_id) is not None

    def test_l_echec_est_remonte_et_non_masque(self, platform):
        """Isoler ne veut pas dire taire : l'échec doit être lisible dans le
        résultat et dans le journal applicatif."""
        from cirtdefense.demo import build_payload, get_scenario

        self._casser(platform, "notify_actions")
        scenario = get_scenario("A1")
        resultat = platform.ingest_and_respond(scenario.source, build_payload("A1"))
        assert resultat.warnings
        assert "RuntimeError" in resultat.warnings[0]
        assert resultat.to_dict()["warnings"] == resultat.warnings

    def test_une_panne_avant_execution_remonte_bien(self, platform):
        """La contrepartie : avant le point de non-retour, une exception
        signifie que l'événement n'a pas été traité, et l'appelant a raison
        de l'apprendre."""
        import pytest

        from cirtdefense.demo import build_payload, get_scenario

        def tombe(*a, **k):
            raise RuntimeError("fonds documentaire illisible")

        platform.engine._enrichment.enrich = tombe
        scenario = get_scenario("A1")
        with pytest.raises(RuntimeError):
            platform.ingest_and_respond(scenario.source, build_payload("A1"))

    def test_une_panne_du_registre_n_empeche_pas_le_confinement(self, platform):
        """L'inscription des gestes en attente est de la tenue de registre :
        son échec ne doit pas priver la cible de son confinement."""
        def tombe(*a, **k):
            raise RuntimeError("écriture impossible")

        platform.engine._pending.open = tombe
        resultat = platform.ingest_and_respond("wazuh", build_payload_inconnu("Z2"))
        assert resultat.execution.executed >= 1
        assert resultat.pending == []
        assert any("attente" in a for a in resultat.warnings)
