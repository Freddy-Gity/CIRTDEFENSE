"""Comptes, séparation des rôles et parcours de connexion (CDCF v3.0).

Le pivot v3.0 retire la validation d'une recommandation *avant* exécution
(EF-13). Il introduit en revanche une validation des *comptes* : ce sont deux
choses distinctes — l'une portait sur une action corrective, l'autre sur
l'accès d'une personne à la plateforme.
"""

from __future__ import annotations

from typing import Any

import pytest


def _analyste_id(client: Any, headers: dict[str, str]) -> str:
    postes = client.get("/api/v1/auth/postes").json()["postes"]
    client.post(
        "/api/v1/auth/register",
        json={
            "nom": "Mballa",
            "prenom": "Awa",
            "username": "awa",
            "email": "awa@antic.cm",
            "password": "analyste-fort-2026",
            "password_confirm": "analyste-fort-2026",
            "poste_id": postes[0]["poste_id"],
        },
    )
    users = client.get("/api/v1/admin/users", headers=headers).json()["users"]
    return next(u for u in users if u["username"] == "awa")["user_id"]


class TestInstallation:
    def test_me_demande_l_installation_sur_base_neuve(self, client: Any) -> None:
        assert client.get("/api/v1/auth/me").json() == {"setup_required": True}

    def test_setup_cree_le_super_admin_et_ouvre_une_session(self, client: Any) -> None:
        rep = client.post(
            "/api/v1/auth/setup",
            json={
                "nom": "Root",
                "prenom": "Sara",
                "username": "root",
                "email": "",
                "password": "installation-2026",
                "password_confirm": "installation-2026",
            },
        )
        assert rep.status_code == 201
        corps = rep.json()
        assert corps["role"] == "super_admin"
        assert "token" in corps
        me = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {corps['token']}"}
        ).json()
        assert me["setup_required"] is False
        assert "/demo" in me["allowed_routes"]

    def test_setup_refuse_une_seconde_fois(self, client: Any, superadmin_headers) -> None:
        rep = client.post(
            "/api/v1/auth/setup",
            json={
                "nom": "A",
                "prenom": "B",
                "username": "second",
                "email": "",
                "password": "installation-2026",
                "password_confirm": "installation-2026",
            },
        )
        assert rep.status_code == 409


class TestInscriptionAnalyste:
    def test_inscription_puis_validation_puis_connexion(
        self, client: Any, superadmin_headers
    ) -> None:
        uid = _analyste_id(client, superadmin_headers)

        refus = client.post(
            "/api/v1/auth/login", json={"username": "awa", "password": "analyste-fort-2026"}
        )
        assert refus.status_code == 403  # en attente

        admis = client.post(f"/api/v1/admin/users/{uid}/admit", headers=superadmin_headers)
        assert admis.status_code == 200 and admis.json()["status"] == "active"

        ok = client.post(
            "/api/v1/auth/login", json={"username": "awa", "password": "analyste-fort-2026"}
        )
        assert ok.status_code == 200
        assert "/demo" not in ok.json()["allowed_routes"]
        assert ok.json()["welcome"] == "Bienvenue Awa"

    def test_mots_de_passe_differents_refuses(self, client: Any, superadmin_headers) -> None:
        postes = client.get("/api/v1/auth/postes").json()["postes"]
        rep = client.post(
            "/api/v1/auth/register",
            json={
                "nom": "X",
                "prenom": "Y",
                "username": "zoe",
                "email": "zoe@antic.cm",
                "password": "aaaaaaaa",
                "password_confirm": "bbbbbbbb",
                "poste_id": postes[0]["poste_id"],
            },
        )
        assert rep.status_code == 422

    def test_nom_d_utilisateur_en_double_refuse(self, client: Any, superadmin_headers) -> None:
        _analyste_id(client, superadmin_headers)
        postes = client.get("/api/v1/auth/postes").json()["postes"]
        rep = client.post(
            "/api/v1/auth/register",
            json={
                "nom": "Autre",
                "prenom": "Awa",
                "username": "awa",
                "email": "autre@antic.cm",
                "password": "analyste-fort-2026",
                "password_confirm": "analyste-fort-2026",
                "poste_id": postes[0]["poste_id"],
            },
        )
        assert rep.status_code == 409


class TestPromotion:
    def test_la_promotion_debloque_les_vues_admin(self, client: Any, superadmin_headers) -> None:
        uid = _analyste_id(client, superadmin_headers)
        client.post(f"/api/v1/admin/users/{uid}/admit", headers=superadmin_headers)
        client.post(f"/api/v1/admin/users/{uid}/promote", headers=superadmin_headers)

        me = client.post(
            "/api/v1/auth/login", json={"username": "awa", "password": "analyste-fort-2026"}
        ).json()
        assert "/demo" in me["allowed_routes"]

    def test_seul_le_super_admin_promeut(self, client: Any, superadmin_headers) -> None:
        uid = _analyste_id(client, superadmin_headers)
        client.post(f"/api/v1/admin/users/{uid}/admit", headers=superadmin_headers)
        client.post(f"/api/v1/admin/users/{uid}/promote", headers=superadmin_headers)
        # se connecter en tant qu'admin (promu) et tenter de promouvoir quelqu'un
        jeton = client.post(
            "/api/v1/auth/login", json={"username": "awa", "password": "analyste-fort-2026"}
        ).json()["token"]
        autre = _second_analyste(client, superadmin_headers)
        rep = client.post(
            f"/api/v1/admin/users/{autre}/promote",
            headers={"Authorization": f"Bearer {jeton}"},
        )
        assert rep.status_code == 403


def _second_analyste(client: Any, headers: dict[str, str]) -> str:
    postes = client.get("/api/v1/auth/postes").json()["postes"]
    client.post(
        "/api/v1/auth/register",
        json={
            "nom": "Kamga",
            "prenom": "Eric",
            "username": "eric",
            "email": "eric@antic.cm",
            "password": "analyste-fort-2026",
            "password_confirm": "analyste-fort-2026",
            "poste_id": postes[0]["poste_id"],
        },
    )
    users = client.get("/api/v1/admin/users", headers=headers).json()["users"]
    return next(u for u in users if u["username"] == "eric")["user_id"]


class TestDecideur:
    def test_creation_connexion_et_message_personnalise(
        self, client: Any, superadmin_headers
    ) -> None:
        postes = client.get("/api/v1/admin/postes", headers=superadmin_headers).json()["postes"]
        dg = next(
            p for p in postes if p["kind"] == "decideur" and "Directeur Général" in p["label"]
        )
        rep = client.post(
            "/api/v1/admin/decideurs",
            headers=superadmin_headers,
            json={
                "poste_id": dg["poste_id"],
                "civility": "Monsieur",
                "username": "dg-antic",
                "password": "decideur-2026-fort",
            },
        )
        assert rep.status_code == 201

        me = client.post(
            "/api/v1/auth/login",
            json={"username": "dg-antic", "password": "decideur-2026-fort"},
        ).json()
        assert me["welcome"] == "Bienvenue Monsieur le Directeur Général de l'ANTIC"
        assert "/demo" not in me["allowed_routes"]
        assert "/monitoring" in me["allowed_routes"]

    def test_le_decideur_ne_peut_pas_agir(self, client: Any, superadmin_headers) -> None:
        postes = client.get("/api/v1/admin/postes", headers=superadmin_headers).json()["postes"]
        dg = next(p for p in postes if p["kind"] == "decideur")
        client.post(
            "/api/v1/admin/decideurs",
            headers=superadmin_headers,
            json={
                "poste_id": dg["poste_id"],
                "civility": "Madame",
                "username": "decideuse",
                "password": "decideur-2026-fort",
            },
        )
        jeton = client.post(
            "/api/v1/auth/login",
            json={"username": "decideuse", "password": "decideur-2026-fort"},
        ).json()["token"]
        h = {"Authorization": f"Bearer {jeton}"}

        assert client.get("/api/v1/audit?limit=5", headers=h).status_code == 200
        assert (
            client.post("/api/v1/admin/breaker/trip", json={"reason": "x"}, headers=h).status_code
            == 403
        )
        assert client.post("/api/v1/demo/run/A1", headers=h).status_code == 403


class TestSessions:
    def test_deconnexion_invalide_la_session(self, client: Any, superadmin_headers) -> None:
        assert client.post("/api/v1/auth/logout", headers=superadmin_headers).status_code == 204
        assert client.get("/api/v1/auth/me", headers=superadmin_headers).status_code == 401

    def test_jeton_inconnu_rejete_sur_route_gardee(
        self, client: Any, superadmin_headers
    ) -> None:
        rep = client.get(
            "/api/v1/admin/users", headers={"Authorization": "Bearer jeton-invente"}
        )
        assert rep.status_code == 401


class TestDemonstrationReservee:
    def test_demo_refuse_sans_role_admin(self, client: Any) -> None:
        assert client.post("/api/v1/demo/run/A1").status_code == 403

    def test_demo_ok_avec_super_admin(self, client: Any, superadmin_headers) -> None:
        assert client.post("/api/v1/demo/run/A1", headers=superadmin_headers).status_code == 202


@pytest.mark.parametrize(
    "chemin", ["valider", "validate", "approve", "approuver", "reject", "rejeter"]
)
def test_aucune_route_de_validation_d_action(client: Any, chemin: str) -> None:
    """La gestion des comptes ne réintroduit aucun mot interdit dans le contrat
    de l'API : « admit » / « decline » plutôt que « validate » / « reject »."""
    chemins = client.get("/openapi.json").json()["paths"]
    assert not [c for c in chemins if chemin in c.lower()]
