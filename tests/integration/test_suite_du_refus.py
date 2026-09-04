"""Ce que la plateforme fait d'une décision humaine.

Trois exigences, dans l'ordre où elles ont été demandées :

1. **Les boutons doivent fonctionner.** Ils reposaient sur `prompt()` ; quand
   le navigateur supprime les dialogues, l'appel rend ``null`` et le code
   sortait en silence — pas de requête, pas de message, rien. C'est le défaut
   qui a motivé cette série.
2. **Confirmer exécute, se charger engage, écarter n'abandonne pas.** Un refus
   laisse la menace entière : la plateforme doit chercher ce qu'elle sait
   encore faire.
3. **Le geste écarté n'est jamais rejoué.** Ni sous son nom, ni sous un autre.
   C'est l'invariant qui empêche « écarter » de devenir décoratif.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cirtdefense.orchestration.conseil import Conseil, Conseiller
from cirtdefense.orchestration.reversibility import ReversibilityCatalog
from cirtdefense.orchestration.substitution import Substitution, engagement

RACINE = Path(__file__).resolve().parents[2]

MENACE_INEDITE = {
    "timestamp": "2026-09-03T09:00:00Z",
    "source": "nids",
    "source_product": "sonde-scada",
    "title": "Anomalie protocolaire inedite sur bus industriel",
    "description": "Sequence Modbus non conforme suivie d'un transfert sortant",
    "severity": "critical",
    "confidence": 0.82,
    "asset": {
        "asset_id": "srv-scada-07",
        "hostname": "srv-scada-07",
        "ip": "10.20.4.7",
        "user": "operateur.scada",
        "criticality": 5,
        "zone": "ot",
    },
    "indicators": {
        "src_ip": "185.220.101.44",
        "dest_ip": "91.199.7.12",
        "dest_port": 502,
        "proto": "modbus",
        "user": "operateur.scada",
    },
}


@pytest.fixture
def attentes(platform):
    """Une menace hors catalogue : elle produit des gestes à effet durable."""
    platform.ingest_and_respond("generic_json", MENACE_INEDITE)
    ouvertes = platform.pending.pending(20)
    assert ouvertes, "la menace inédite doit ouvrir des attentes"
    return ouvertes


def _par_verbe(attentes, verbe: str) -> dict:
    for a in attentes:
        if a["verb"] == verbe:
            return a
    raise AssertionError(f"aucune attente pour « {verbe} »")


# ==========================================================================


class TestInterfaceSansDialogue:
    """Le défaut d'origine, figé pour qu'il ne revienne pas."""

    def test_l_interface_n_appelle_plus_prompt(self):
        """`prompt()` est supprimable par le navigateur, et son échec est muet.

        Un bouton dont l'action dépend d'un dialogue natif est un bouton qui
        peut cesser de fonctionner sans que rien ne l'indique — ni erreur, ni
        requête, ni message. C'est exactement ce qui s'est produit.
        """
        script = (RACINE / "web" / "static" / "app.js").read_text(encoding="utf-8")
        code = [
            ligne
            for ligne in script.splitlines()
            if "prompt(" in ligne and not ligne.strip().startswith("//")
        ]
        assert not code, f"appel à prompt() encore présent : {code}"

    def test_le_motif_se_saisit_dans_la_page(self):
        script = (RACINE / "web" / "static" / "app.js").read_text(encoding="utf-8")
        assert 'textarea[data-motif=' in script
        assert 'data-issue="substitute"' in script


class TestSubstitution:
    """La recherche d'un geste plus léger servant le même but."""

    @pytest.fixture
    def moteur(self):
        return Substitution(ReversibilityCatalog())

    def test_un_isolement_ecarte_propose_le_vlan_de_quarantaine(self, moteur):
        """Le cas qui a motivé la conception : les deux gestes coupent la
        machine du réseau, mais le second se défait entièrement."""
        alternatives = moteur.alternatives("edr", "isolate_host", "srv-scada-07")
        assert alternatives
        assert alternatives[0].entree.key == "network:move_to_vlan"
        assert alternatives[0].spec.target == "srv-scada-07"

    def test_toute_alternative_est_entierement_reversible(self, moteur):
        """Proposer un geste seulement partiellement réversible après un refus
        rendrait le refus vain : l'agent retrouverait un effet durable."""
        for actuator, verb in (
            ("edr", "isolate_host"),
            ("iam", "lock_account"),
            ("network", "cut_egress_connection"),
            ("edr", "wipe_disk"),
        ):
            for alt in moteur.alternatives(actuator, verb, "cible"):
                assert alt.entree.reversibility.value == "reversible", alt.entree.key
                assert alt.entree.rollback_verb, alt.entree.key

    def test_aucune_alternative_plus_engageante_que_le_geste_ecarte(self, moteur):
        catalogue = ReversibilityCatalog()
        for entree in catalogue.all():
            plafond = engagement(entree)
            for alt in moteur.alternatives(entree.actuator, entree.verb, "cible"):
                assert alt.engagement < plafond, f"{alt.entree.key} après {entree.key}"

    def test_le_geste_ecarte_n_est_jamais_sa_propre_alternative(self, moteur):
        for entree in ReversibilityCatalog().all():
            cles = {a.entree.key for a in moteur.alternatives(entree.actuator, entree.verb, "c")}
            assert entree.key not in cles

    def test_un_geste_deja_minimal_n_a_pas_d_alternative(self, moteur):
        """« Je ne sais pas faire moins » est une réponse. Elle vaut mieux
        qu'une proposition qui ne tiendrait pas."""
        assert moteur.alternatives("firewall", "block_ip", "185.220.101.44") == []

    def test_un_geste_inconnu_du_catalogue_ne_produit_rien(self, moteur):
        assert moteur.alternatives("inconnu", "verbe_imaginaire", "cible") == []


class TestEscaladeApresRefus:
    """Sous le seuil : surveillance. Au-dessus : confinement de substitution."""

    def test_sous_le_seuil_aucun_geste_n_est_pose(self, platform, attentes):
        platform.escalade._seuil = 9.9
        escalade = platform.escalade.apres_refus(
            _par_verbe(attentes, "isolate_host"), "human:analyst", "risque de production"
        )
        assert escalade.mesure == "surveillance"
        assert not escalade.a_agi, "le refus doit être appliqué tel quel"
        assert escalade.alternative is not None, "une proposition reste due à l'agent"

    def test_au_dessus_du_seuil_un_geste_de_substitution_est_applique(
        self, platform, attentes
    ):
        platform.escalade._seuil = 1.0
        escalade = platform.escalade.apres_refus(
            _par_verbe(attentes, "isolate_host"), "human:analyst", "risque de production"
        )
        assert escalade.mesure == "quarantaine"
        assert escalade.a_agi
        assert escalade.action.status.value == "executed"

    def test_le_geste_ecarte_n_est_jamais_rejoue(self, platform, attentes):
        """L'invariant central. Sans lui, « écarter » serait un bouton que la
        plateforme contourne."""
        platform.escalade._seuil = 1.0
        for attente in attentes:
            ecarte = f"{attente['actuator']}:{attente['verb']}"
            escalade = platform.escalade.apres_refus(attente, "human:analyst", "motif")
            if escalade.a_agi:
                assert escalade.action.spec.key != ecarte

    def test_le_substitut_applique_porte_un_jeton_d_annulation(self, platform, attentes):
        platform.escalade._seuil = 1.0
        escalade = platform.escalade.apres_refus(
            _par_verbe(attentes, "isolate_host"), "human:analyst", "motif"
        )
        assert escalade.action.rollback_token, "l'agent doit pouvoir défaire ce geste"

    def test_l_incident_porte_la_marque_de_surveillance(self, platform, attentes):
        platform.escalade._seuil = 9.9
        attente = _par_verbe(attentes, "isolate_host")
        platform.escalade.apres_refus(attente, "human:analyst", "motif")
        incident = platform.incidents.get(attente["incident_id"])
        assert incident.labels["surveillance"]["niveau"] == "renforcee"

    def test_la_suite_est_inscrite_au_journal(self, platform, attentes):
        avant = len(platform.ledger.query(limit=1000))
        platform.escalade.apres_refus(
            _par_verbe(attentes, "isolate_host"), "human:analyst", "motif"
        )
        assert len(platform.ledger.query(limit=1000)) > avant


class TestCascadeDIntelligence:
    """Le modèle enrichit ; il ne peut pas élargir le champ des gestes."""

    @pytest.fixture
    def candidats(self):
        return Substitution(ReversibilityCatalog())

    def test_sans_modele_le_socle_deterministe_repond(self, candidats, attentes):
        conseil = Conseiller(candidats, provider=None).conseiller(
            _par_verbe(attentes, "isolate_host")
        )
        assert conseil.niveau == "deterministe"
        assert conseil.retenue.entree.key == "network:move_to_vlan"

    def test_un_modele_ne_peut_pas_proposer_un_geste_hors_liste(
        self, candidats, attentes
    ):
        """La garantie qui rend le choix assisté acceptable. Un modèle qui
        désigne n'importe quoi ne peut pas faire sortir un geste dangereux :
        sa réponse est confrontée à la liste, et rejetée si elle n'y figure pas.
        """

        class Menteur:
            name = "menteur"

            def available(self):
                return True

            def render(self, question, facts, fallback):
                return "edr:wipe_disk\nEffacer le disque reglera le probleme."

        conseil = Conseiller(candidats, provider=Menteur()).conseiller(
            _par_verbe(attentes, "isolate_host")
        )
        assert conseil.retenue.entree.key == "network:move_to_vlan"
        assert conseil.niveau == "redige", "le choix déterministe doit tenir"

    def test_un_modele_qui_designe_un_candidat_valide_est_suivi(
        self, candidats, attentes
    ):
        class Conseillant:
            name = "conseillant"

            def available(self):
                return True

            def render(self, question, facts, fallback):
                return (
                    "network:block_lateral\n"
                    "Bloquer la propagation suffit ici, la machine reste jointe."
                )

        conseil = Conseiller(candidats, provider=Conseillant()).conseiller(
            _par_verbe(attentes, "isolate_host")
        )
        assert conseil.retenue.entree.key == "network:block_lateral"
        assert conseil.niveau == "choisi"

    def test_un_modele_en_panne_ne_prive_pas_du_conseil(self, candidats, attentes):
        class Casse:
            name = "casse"

            def available(self):
                return True

            def render(self, question, facts, fallback):
                raise RuntimeError("service indisponible")

        conseil = Conseiller(candidats, provider=Casse()).conseiller(
            _par_verbe(attentes, "isolate_host")
        )
        assert conseil.niveau == "deterministe"
        assert conseil.retenue is not None

    def test_le_niveau_employe_est_toujours_declare(self, candidats, attentes):
        """L'agent doit savoir si un modèle est intervenu dans ce qu'il lit."""
        conseil = Conseiller(candidats, provider=None).conseiller(
            _par_verbe(attentes, "isolate_host")
        )
        assert conseil.to_dict()["explication_niveau"]

    def test_un_conseil_vide_se_dit(self, candidats):
        conseil = Conseiller(candidats, provider=None).conseiller(
            {"actuator": "firewall", "verb": "block_ip", "target": "1.2.3.4"}
        )
        assert isinstance(conseil, Conseil)
        assert conseil.vide
        assert "aucun geste plus léger" in conseil.justification


class TestMachineAEtats:
    """Les trois issues, par l'API, telles que l'exploitant les déclenche."""

    def test_confirmer_execute_reellement(self, client, analyst_headers, attentes):
        attente = _par_verbe(attentes, "isolate_host")
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/confirm",
            json={"reason": "j assume l effet durable sur cette machine"},
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        corps = r.json()
        assert corps["pending"]["status"] == "confirmed"
        assert corps["action"]["status"] == "executed"

    def test_se_charger_n_est_pas_clore(self, client, analyst_headers, attentes):
        """« Je m'en charge » est un engagement, pas une clôture. Le faire
        disparaître au premier clic reproduirait le défaut que l'alerte
        persistante corrige."""
        attente = _par_verbe(attentes, "lock_account")
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/handled",
            json={"reason": "j interviens moi meme sur l annuaire"},
            headers=analyst_headers,
        )
        assert r.json()["pending"]["status"] == "taken_over"

        encore = client.get("/api/v1/pending").json()["pending"]
        assert attente["pending_id"] in {a["pending_id"] for a in encore}

    def test_rendre_compte_referme_la_prise_en_charge(
        self, client, analyst_headers, attentes
    ):
        attente = _par_verbe(attentes, "lock_account")
        client.post(
            f"/api/v1/pending/{attente['pending_id']}/handled",
            json={"reason": "je prends en charge"},
            headers=analyst_headers,
        )
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/resolved",
            json={"reason": "compte desactive a la main dans l annuaire a 09h42"},
            headers=analyst_headers,
        )
        assert r.json()["pending"]["status"] == "handled_by_human"
        restantes = {a["pending_id"] for a in client.get("/api/v1/pending").json()["pending"]}
        assert attente["pending_id"] not in restantes

    def test_on_ne_rend_pas_compte_de_ce_qu_on_n_a_pas_pris_en_charge(
        self, client, analyst_headers, attentes
    ):
        attente = _par_verbe(attentes, "lock_account")
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/resolved",
            json={"reason": "je clos sans avoir pris en charge"},
            headers=analyst_headers,
        )
        assert r.status_code == 409

    def test_ecarter_rend_la_suite_donnee_par_la_plateforme(
        self, client, analyst_headers, attentes
    ):
        attente = _par_verbe(attentes, "isolate_host")
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/decline",
            json={"reason": "risque de couper la production industrielle"},
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        escalade = r.json()["escalade"]
        assert escalade["mesure"] in ("surveillance", "quarantaine")
        assert escalade["motif"]
        assert r.json()["suite"]

    def test_une_proposition_peut_etre_acceptee(self, client, analyst_headers, attentes):
        """Une proposition qu'on ne peut pas accepter n'est pas une proposition."""
        attente = _par_verbe(attentes, "isolate_host")
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/decline",
            json={"reason": "trop brutal pour un automate en production"},
            headers=analyst_headers,
        )
        escalade = r.json()["escalade"]
        if escalade["action"]:
            pytest.skip("la plateforme avait déjà appliqué le substitut")
        suite = client.post(
            f"/api/v1/pending/{attente['pending_id']}/substitute",
            json={"reason": "j accepte le geste plus leger"},
            headers=analyst_headers,
        )
        assert suite.status_code == 200, suite.text
        assert suite.json()["action"]["status"] == "executed"

    def test_un_motif_trop_court_est_refuse(self, client, analyst_headers, attentes):
        attente = _par_verbe(attentes, "isolate_host")
        r = client.post(
            f"/api/v1/pending/{attente['pending_id']}/decline",
            json={"reason": "x"},
            headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_une_attente_close_ne_se_rejoue_pas(self, client, analyst_headers, attentes):
        attente = _par_verbe(attentes, "isolate_host")
        for _ in range(2):
            r = client.post(
                f"/api/v1/pending/{attente['pending_id']}/confirm",
                json={"reason": "clic repete de deux analystes"},
                headers=analyst_headers,
            )
        assert r.status_code == 409
