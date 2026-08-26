"""Interface applicative : contrat public et séparation des rôles."""

from __future__ import annotations


class TestIngestion:
    def test_ingestion_declenche_la_reponse(self, client, bruteforce_payload):
        response = client.post(
            "/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload}
        )
        body = response.json()

        assert response.status_code == 202
        assert body["decision"]["outcome"] == "autonomous_execution"
        assert body["execution"]["executed"] >= 1

    def test_source_inconnue_refusee(self, client):
        response = client.post("/api/v1/events", json={"source": "inexistant", "payload": {}})
        assert response.status_code == 400


class TestSeparationDesRoles:
    def test_rollback_exige_un_role(self, client, bruteforce_payload):
        body = client.post(
            "/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload}
        ).json()
        action_id = body["execution"]["results"][0]["action_id"]

        assert (
            client.post(
                f"/api/v1/actions/{action_id}/rollback", json={"reason": "test"}
            ).status_code
            == 403
        )

    def test_analyste_peut_annuler(self, client, analyst_headers, bruteforce_payload):
        body = client.post(
            "/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload}
        ).json()
        action_id = body["execution"]["results"][0]["action_id"]

        response = client.post(
            f"/api/v1/actions/{action_id}/rollback",
            json={"reason": "faux positif confirme"},
            headers=analyst_headers,
        )
        assert response.status_code == 200
        assert response.json()["success"]

    def test_coupe_circuit_reserve_a_l_administrateur(self, client, analyst_headers):
        assert (
            client.post(
                "/api/v1/admin/breaker/trip", json={"reason": "test"}, headers=analyst_headers
            ).status_code
            == 403
        )

    def test_jeton_invalide_rejete(self, client):
        assert (
            client.post(
                "/api/v1/admin/breaker/trip",
                json={"reason": "t"},
                headers={"Authorization": "Bearer faux"},
            ).status_code
            == 401
        )


class TestAbsenceDeValidationPrealable:
    def test_aucun_point_d_entree_de_validation(self, client):
        """Le pivot v3.0 doit se lire dans le contrat de l'API : exposer une
        route de validation retablirait l'EF-13 antérieure par la porte de
        derriere."""
        chemins = client.get("/openapi.json").json()["paths"]
        interdits = ("valider", "validate", "approve", "approuver", "reject", "rejeter")
        assert not [c for c in chemins if any(mot in c.lower() for mot in interdits)]

    def test_le_rollback_existe_bien_lui(self, client):
        chemins = client.get("/openapi.json").json()["paths"]
        assert any("rollback" in c for c in chemins)


class TestAdministration:
    def test_compilation_de_politique(self, client, admin_headers):
        response = client.post(
            "/api/v1/policy/compile",
            headers=admin_headers,
            json={"text": "Ne jamais bloquer une adresse interne", "version": "2"},
        )
        body = response.json()
        assert response.status_code == 200
        assert body["fully_compiled"]

    def test_les_consignes_non_compilees_sont_signalees(self, client, admin_headers):
        body = client.post(
            "/api/v1/policy/compile",
            headers=admin_headers,
            json={"text": "Faites au mieux selon les circonstances"},
        ).json()
        assert body["unparsed_sentences"]
        assert not body["fully_compiled"]

    def test_entree_de_catalogue_reversible_exige_une_annulation(self, client, admin_headers):
        response = client.post(
            "/api/v1/catalog",
            headers=admin_headers,
            json={
                "verb": "x",
                "actuator": "firewall",
                "reversibility": "reversible",
                "description": "test",
            },
        )
        assert response.status_code == 400
        assert "annulation" in response.json()["detail"]

    def test_cycle_du_coupe_circuit(self, client, admin_headers, bruteforce_payload):
        assert (
            client.post(
                "/api/v1/admin/breaker/trip", json={"reason": "anomalie"}, headers=admin_headers
            ).json()["state"]
            == "open"
        )

        body = client.post(
            "/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload}
        ).json()
        assert body["decision"]["outcome"] == "breaker_open"

        assert (
            client.post(
                "/api/v1/admin/breaker/reset", json={"reason": "traite"}, headers=admin_headers
            ).json()["state"]
            == "closed"
        )


class TestConsultation:
    def test_portefeuille_priorise(self, client, bruteforce_payload):
        client.post("/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload})
        body = client.get("/api/v1/incidents").json()
        assert body["count"] == 1
        assert body["incidents"][0]["risk_score"] > 0

    def test_chronologie_d_incident(self, client, bruteforce_payload):
        incident_id = client.post(
            "/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload}
        ).json()["incident_id"]

        body = client.get(f"/api/v1/incidents/{incident_id}").json()
        assert body["timeline"]
        assert body["decisions"]

    def test_verification_du_journal(self, client, bruteforce_payload):
        client.post("/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload})
        assert client.get("/api/v1/audit/verify").json()["valid"]

    def test_statut_expose_la_posture(self, client):
        body = client.get("/api/v1/status").json()
        assert "autonomy" in body
        assert "circuit_breaker" in body
        assert body["catalog"]["autonomously_executable"] < body["catalog"]["total"]

    def test_incident_inconnu(self, client):
        assert client.get("/api/v1/incidents/inc_inexistant").status_code == 404


class TestSurveillance:
    """EF-21 a EF-23 : la vue de surveillance rend compte du parc supervisé."""

    def test_le_parc_surveille_est_expose(self, client):
        body = client.get("/api/v1/monitoring").json()

        assert body["summary"]["total"] == len(body["targets"])
        assert body["summary"]["total"] > 0
        # Chaque ligne porte de quoi juger : mesure, seuil, verdict.
        ligne = body["targets"][0]
        assert {"health", "thresholds", "breaches", "state"} <= set(ligne)
        assert ligne["state"] in {"nominal", "degrade", "injoignable"}

    def test_l_incident_est_rattache_a_son_actif(self, client, bruteforce_payload):
        """Un incident traite doit apparaitre sur l'actif concerne, et non sur
        l'adresse de l'attaquant : c'est ce rattachement qui rend la vue
        exploitable."""
        client.post("/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload})

        cibles = {t["target"]: t for t in client.get("/api/v1/monitoring").json()["targets"]}

        assert cibles["srv-web-01"]["incidents"] >= 1
        assert "41.202.1.9" not in cibles

    def test_la_degradation_simulee_change_l_etat(self, client):
        """Le point d'entrée de simulation sert à éprouver la boucle EF-25 sans
        casser un service réel."""
        avant = client.get("/api/v1/monitoring").json()
        etats = {t["target"]: t["state"] for t in avant["targets"]}
        assert etats["srv-web-01"] != "injoignable"

        assert client.post("/api/v1/monitoring/simulate/srv-web-01").status_code == 200

        apres = client.get("/api/v1/monitoring").json()
        etats = {t["target"]: t["state"] for t in apres["targets"]}
        assert etats["srv-web-01"] == "injoignable"
        assert apres["summary"]["injoignable"] >= 1

    def test_la_simulation_refuse_une_cible_inconnue(self, client):
        assert client.post("/api/v1/monitoring/simulate/inexistant").status_code == 404


class TestDeclarationDePlateforme:
    """Le parc surveillé doit pouvoir s'étendre sans toucher au code."""

    CIBLE = {
        "label": "Serveur RH 01",
        "kind": "serveur applicatif",
        "ip": "10.0.3.60",
        "segment": "interne",
        "owner": "Direction des ressources humaines",
        "criticality": 4,
        "latitude": 3.8669,
        "longitude": 11.5187,
    }

    def test_declaration_puis_apparition_au_parc(self, client, admin_headers):
        reponse = client.post("/api/v1/monitoring/targets", json=self.CIBLE, headers=admin_headers)
        assert reponse.status_code == 201
        assert reponse.json()["target_id"] == "serveur-rh-01"

        cibles = {t["target"]: t for t in client.get("/api/v1/monitoring").json()["targets"]}
        assert "serveur-rh-01" in cibles
        assert cibles["serveur-rh-01"]["owner"] == "Direction des ressources humaines"
        assert cibles["serveur-rh-01"]["declared"] is True
        # Le parc de démonstration reste en place : la déclaration s'ajoute.
        assert "srv-web-01" in cibles

    def test_declaration_exige_le_role_administrateur(self, client):
        assert client.post("/api/v1/monitoring/targets", json=self.CIBLE).status_code == 403

    def test_doublon_refuse(self, client, admin_headers):
        client.post("/api/v1/monitoring/targets", json=self.CIBLE, headers=admin_headers)
        seconde = client.post("/api/v1/monitoring/targets", json=self.CIBLE, headers=admin_headers)
        assert seconde.status_code == 409

    def test_champs_obligatoires(self, client, admin_headers):
        incomplet = {"label": "X", "kind": "", "ip": "", "segment": "", "owner": ""}
        assert (
            client.post(
                "/api/v1/monitoring/targets", json=incomplet, headers=admin_headers
            ).status_code
            == 422
        )

    def test_declaration_journalisee(self, client, admin_headers):
        client.post("/api/v1/monitoring/targets", json=self.CIBLE, headers=admin_headers)
        journal = client.get("/api/v1/audit?limit=50").json()["entries"]
        types = [e["event_type"] for e in journal]
        assert "monitored_target_declared" in types

    def test_retrait(self, client, admin_headers):
        client.post("/api/v1/monitoring/targets", json=self.CIBLE, headers=admin_headers)
        assert (
            client.delete(
                "/api/v1/monitoring/targets/serveur-rh-01", headers=admin_headers
            ).status_code
            == 200
        )
        cibles = {t["target"] for t in client.get("/api/v1/monitoring").json()["targets"]}
        assert "serveur-rh-01" not in cibles

    def test_le_parc_de_demonstration_n_est_pas_retirable(self, client, admin_headers):
        """Il est porté par le code, pas par la base : le retirer laisserait
        une vue vide sans que rien ne l'explique."""
        reponse = client.delete("/api/v1/monitoring/targets/srv-web-01", headers=admin_headers)
        assert reponse.status_code == 404


class TestDetailDUnePlateforme:
    def test_le_detail_ne_porte_que_sur_sa_cible(self, client, bruteforce_payload):
        client.post("/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload})

        detail = client.get("/api/v1/monitoring/targets/srv-web-01").json()

        assert detail["target"] == "srv-web-01"
        assert detail["summary"]["incidents"] >= 1
        assert all(i["incident_id"] for i in detail["incidents"])
        # Aucune action ni chronologie venue d'un autre actif.
        for action in detail["actions"]:
            assert action["incident_id"] in {i["incident_id"] for i in detail["incidents"]}

    def test_une_plateforme_sans_incident_reste_consultable(self, client):
        detail = client.get("/api/v1/monitoring/targets/srv-mail-01").json()
        assert detail["summary"]["incidents"] == 0
        assert detail["state"] in {"nominal", "degrade", "injoignable"}

    def test_cible_inconnue(self, client):
        assert client.get("/api/v1/monitoring/targets/inexistant").status_code == 404


class TestBasculeDAutonomie:
    """EF-26 rendu accessible depuis l'interface, sans changer sa sémantique."""

    def test_suspension_puis_reactivation(self, client, admin_headers):
        arret = client.post(
            "/api/v1/admin/autonomy",
            json={"enabled": False, "reason": "test de bascule"},
            headers=admin_headers,
        ).json()
        assert arret["autonomy_active"] is False

        reprise = client.post(
            "/api/v1/admin/autonomy",
            json={"enabled": True, "reason": "test de bascule"},
            headers=admin_headers,
        ).json()
        assert reprise["autonomy_active"] is True

    def test_suspension_arrete_reellement_les_actions(
        self, client, admin_headers, bruteforce_payload
    ):
        """Suspendre doit cesser d'agir, pas se mettre à demander la permission."""
        client.post(
            "/api/v1/admin/autonomy",
            json={"enabled": False, "reason": "test"},
            headers=admin_headers,
        )
        corps = client.post(
            "/api/v1/events", json={"source": "wazuh", "payload": bruteforce_payload}
        ).json()

        assert corps["decision"]["outcome"] != "autonomous_execution"
        assert corps["execution"] is None or corps["execution"]["executed"] == 0

    def test_bascule_reservee_a_l_administrateur(self, client, analyst_headers):
        assert (
            client.post(
                "/api/v1/admin/autonomy", json={"enabled": False}, headers=analyst_headers
            ).status_code
            == 403
        )
