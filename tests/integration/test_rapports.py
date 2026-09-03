"""Édition des rapports d'opérations.

Trois exigences y sont vérifiées, dans cet ordre d'importance :

1. **Rien n'est produit sans demande.** L'écran des rapports s'ouvre vide ;
   c'est l'exploitant qui décide de ce qui sera couvert.
2. **Les quatre formats disent la même chose.** Un rapport officiel qui varie
   selon le fichier ouvert n'est plus opposable.
3. **Aucun terme technique n'atteint la page.** Un rapport est lu par un
   directeur ou un magistrat ; `firewall:block_ip` et `no_grounded_context`
   n'y ont pas leur place.
"""

from __future__ import annotations

import json
import re

import pytest

from cirtdefense.reporting import Editeur, Perimetre, Selection, langage
from cirtdefense.reporting.document import (
    Encadre,
    Graphique,
    Paragraphe,
    Tableau,
    Titre,
)
from cirtdefense.reporting.rendu_markdown import rendre as rendre_markdown


@pytest.fixture
def plateforme_active(platform, bruteforce_payload):
    """Une plateforme ayant réellement traité un incident."""
    platform.ingest_and_respond("wazuh", bruteforce_payload)
    return platform


@pytest.fixture
def editeur(plateforme_active):
    return Editeur(plateforme_active.compositeur)


def _incident(plateforme) -> str:
    return plateforme.portfolio.list(limit=1)[0].incident_id


# --------------------------------------------------------------------------


class TestChoixDuPerimetre:
    """L'exploitant choisit ; la plateforme ne choisit pas pour lui."""

    def test_les_cinq_perimetres_sont_proposes(self, client):
        options = client.get("/api/v1/rapports/options").json()
        proposes = {p["cle"] for p in options["perimetres"]}
        assert proposes == {"periode", "incident", "famille", "criticite", "type"}

    def test_les_quatre_formats_sont_proposes(self, client):
        options = client.get("/api/v1/rapports/options").json()
        assert {f["cle"] for f in options["formats"]} == {"pdf", "docx", "md", "json"}

    def test_les_libelles_viennent_du_serveur(self, client):
        """L'interface n'écrit aucun libellé métier : elle affiche ce qu'on
        lui sert. Une famille renommée dans le catalogue suit sans retouche."""
        options = client.get("/api/v1/rapports/options").json()
        for cle in ("familles", "criticites", "types", "fenetres"):
            assert options[cle], cle
            assert all(entree["libelle"] for entree in options[cle]), cle

    def test_un_perimetre_inconnu_est_refuse_en_clair(self, client):
        reponse = client.get("/api/v1/rapports/apercu?perimetre=au_pif")
        assert reponse.status_code == 400
        assert "périmètre" in reponse.json()["detail"]

    def test_une_intervention_sans_numero_est_refusee(self, client):
        reponse = client.get("/api/v1/rapports/apercu?perimetre=incident")
        assert reponse.status_code == 400
        assert "numéro" in reponse.json()["detail"]

    def test_une_intervention_inconnue_donne_un_404(self, client):
        reponse = client.get("/api/v1/rapports/apercu?perimetre=incident&valeur=inc_absent")
        assert reponse.status_code == 404

    def test_aucune_route_ne_produit_de_rapport_par_defaut(self):
        """Il n'existe pas de route qui rende un rapport sans périmètre :
        l'écran ne peut donc pas en afficher un à l'ouverture."""
        from cirtdefense.api.routes import rapports

        chemins = {r.path for r in rapports.router.routes}
        assert chemins == {
            "/api/v1/rapports/options",
            "/api/v1/rapports/apercu",
            "/api/v1/rapports/editer",
        }


class TestFiltrageDuPerimetre:
    def test_le_rapport_d_intervention_ne_couvre_que_celle_demandee(
        self, plateforme_active, editeur
    ):
        numero = _incident(plateforme_active)
        document = editeur.editer(
            Selection(perimetre=Perimetre.INCIDENT, valeur=numero), "md"
        ).document
        assert document.titre == "RAPPORT D'INTERVENTION"
        assert langage.numero_intervention(numero) in document.objet

    def test_une_famille_absente_rend_un_rapport_qui_le_dit(
        self, plateforme_active, editeur
    ):
        """Zéro intervention est un résultat, pas une erreur : le rapport doit
        l'écrire plutôt que d'échouer ou de rendre une page blanche."""
        rapport = editeur.editer(
            Selection(perimetre=Perimetre.FAMILLE, valeur="infrastructure", fenetre="7j"),
            "md",
        )
        assert "Aucune intervention" in rapport.texte

    def test_un_perimetre_thematique_annonce_ce_qu_il_omet(
        self, plateforme_active, editeur
    ):
        rapport = editeur.editer(
            Selection(perimetre=Perimetre.CRITICITE, valeur="high", fenetre="7j"), "md"
        )
        assert "n'y figurent pas" in rapport.texte

    def test_la_gravite_retient_aussi_les_niveaux_superieurs(self):
        """Demander les incidents graves en espérant que les plus graves en
        soient absents n'a aucun sens."""
        selection = Selection(perimetre=Perimetre.CRITICITE, valeur="high")
        assert selection.retient({"severity": "critical"})
        assert selection.retient({"severity": "high"})
        assert not selection.retient({"severity": "medium"})


class TestConcordanceDesFormats:
    """Un rapport qui ne dit pas la même chose selon le fichier ouvert n'est
    plus opposable. Les quatre rendus partagent donc la composition."""

    @pytest.mark.parametrize("format_", ["pdf", "docx", "md", "json"])
    def test_chaque_format_produit_un_fichier(self, editeur, format_):
        rapport = editeur.editer(Selection(fenetre="24h"), format_)
        assert len(rapport.contenu) > 500
        assert rapport.nom_de_fichier.endswith(f".{format_}")

    def test_le_pdf_est_un_pdf_et_le_docx_un_docx(self, editeur):
        assert editeur.editer(Selection(), "pdf").contenu.startswith(b"%PDF")
        # Un .docx est une archive ZIP : la signature en atteste.
        assert editeur.editer(Selection(), "docx").contenu.startswith(b"PK")

    def test_les_quatre_formats_portent_le_meme_contenu(self, editeur):
        """Comparaison sur la structure composée, seule chose que les quatre
        rendus partagent réellement."""
        selections = Selection(fenetre="24h")
        rendus = {f: editeur.editer(selections, f) for f in ("pdf", "docx", "md", "json")}
        titres = {f: r.document.titre for f, r in rendus.items()}
        objets = {f: r.document.objet for f, r in rendus.items()}
        assert len(set(titres.values())) == 1
        assert len(set(objets.values())) == 1

    def test_le_json_porte_les_tableaux_en_structure(self, editeur):
        """Le seul format destiné à une machine ne doit pas aplatir ses
        tableaux en texte : le destinataire aurait à analyser des phrases pour
        retrouver des chiffres."""
        corps = json.loads(editeur.editer(Selection(), "json").texte)
        tableaux = [b for b in corps["contenu"] if b["type"] == "tableau"]
        assert tableaux
        assert all(isinstance(t["lignes"], list) for t in tableaux)

    def test_le_nom_de_fichier_reste_en_ascii(self, editeur):
        """Un en-tête HTTP ne transporte que de l'ASCII ; le corps du rapport
        reste en UTF-8."""
        for perimetre, valeur in (
            (Perimetre.PERIODE, ""),
            (Perimetre.CRITICITE, "critical"),
            (Perimetre.FAMILLE, "network"),
        ):
            rapport = editeur.editer(
                Selection(perimetre=perimetre, valeur=valeur), "pdf"
            )
            rapport.nom_de_fichier.encode("ascii")

    def test_un_format_inconnu_est_refuse(self, editeur):
        with pytest.raises(ValueError, match="format"):
            editeur.editer(Selection(), "xlsx")


class TestTemplateAdministratif:
    def test_la_titulature_est_bilingue(self, editeur):
        document = editeur.editer(Selection(), "md").document
        gauche, droite = document.entete.colonnes()
        assert "RÉPUBLIQUE DU CAMEROUN" in gauche
        assert "REPUBLIC OF CAMEROON" in droite
        assert len(gauche) == len(droite), "les deux colonnes doivent s'aligner"

    def test_le_document_porte_une_reference_et_un_signataire(self, editeur):
        document = editeur.editer(Selection(), "md").document
        assert re.match(r"N° \d{4}/RAP/MINPOSTEL/ANTIC/CIRT/\d{4}", document.reference)
        assert document.signataire
        assert document.lieu == "Yaoundé"

    def test_deux_editions_du_meme_rapport_portent_le_meme_numero(self, editeur):
        """Ce qu'attend un service d'archives : rééditer un rapport ne crée
        pas une pièce nouvelle."""
        premier = editeur.editer(Selection(fenetre="7j"), "md").document
        second = editeur.editer(Selection(fenetre="7j"), "md").document
        assert premier.reference == second.reference

    def test_l_embleme_livre_avec_la_plateforme_existe(self, plateforme_active):
        """Le chemin par défaut doit pointer sur un fichier réel : sans lui,
        tous les rapports sortiraient avec un cartouche de réserve à la place
        du logo de l'Agence, et personne ne s'en apercevrait avant impression.
        """
        assert plateforme_active.settings.report_logo.is_file()

    def test_un_embleme_absent_ne_casse_pas_l_edition(
        self, plateforme_active, tmp_path, monkeypatch
    ):
        """Le document doit sortir même si le fichier d'emblème manque — un
        déploiement incomplet ne doit pas priver le Centre de ses rapports.
        Un cartouche de réserve tient alors la place du cachet.
        """
        from cirtdefense.reporting import rendu_docx, rendu_pdf

        introuvable = tmp_path / "absent.png"
        monkeypatch.setattr(rendu_pdf, "LOGO_PAR_DEFAUT", introuvable)
        monkeypatch.setattr(rendu_docx, "LOGO_PAR_DEFAUT", introuvable)
        editeur = Editeur(plateforme_active.compositeur, logo=introuvable)
        for format_ in ("pdf", "docx"):
            rapport = editeur.editer(Selection(fenetre="24h"), format_)
            assert len(rapport.contenu) > 500

    def test_deux_perimetres_differents_portent_des_numeros_differents(self, editeur):
        a = editeur.editer(Selection(fenetre="7j"), "md").document
        b = editeur.editer(Selection(fenetre="30j"), "md").document
        assert a.reference != b.reference

    def test_le_rapport_comporte_paragraphes_tableaux_et_graphiques(
        self, plateforme_active, editeur
    ):
        """La demande porte sur les trois : des explications, des résultats
        chiffrés, et de quoi les voir."""
        blocs = editeur.editer(Selection(fenetre="24h"), "md").document.blocs
        assert any(isinstance(b, Titre) for b in blocs)
        assert any(isinstance(b, Paragraphe) for b in blocs)
        assert any(isinstance(b, Tableau) for b in blocs)
        assert any(isinstance(b, Graphique) for b in blocs)

    def test_les_parties_sont_numerotees_a_la_romaine(self, editeur):
        document = editeur.editer(Selection(), "md").document
        numeros = [b.numero for b in document.blocs if isinstance(b, Titre) and b.numero]
        assert numeros[:3] == ["I", "II", "III"]

    def test_la_numerotation_ne_saute_aucun_numero(self, plateforme_active, editeur):
        """Certaines parties sont omises quand elles n'ont rien à dire ; la
        numérotation doit rester continue."""
        from cirtdefense.reporting.composer import ROMAINS

        document = editeur.editer(Selection(fenetre="24h"), "md").document
        numeros = [b.numero for b in document.blocs if isinstance(b, Titre) and b.numero]
        assert numeros == list(ROMAINS[: len(numeros)])


class TestLangageFamilier:
    """Aucune expression laissant penser à une commande d'ordinateur.

    C'est la contrainte la plus facile à perdre de vue : il suffit qu'un champ
    remonte brut d'un dépôt pour qu'un identifiant technique se retrouve dans
    un document officiel.
    """

    INTERDITS = (
        "firewall:", "edr:", "iam:", "waf:", "dns:", "network:", "edge:",
        "no_grounded_context", "policy_denied", "breaker_open", "out_of_catalog",
        "autonomous_execution", "rolled_back", "blocked_by_policy",
        "rollback_verb", "playbook", "actuator", "incident_id",
    )

    def _texte_du_rapport(self, editeur, selection: Selection) -> str:
        document = editeur.editer(selection, "md").document
        return rendre_markdown(document)

    def test_le_rapport_d_activite_ne_contient_aucun_identifiant_technique(
        self, plateforme_active, editeur
    ):
        texte = self._texte_du_rapport(editeur, Selection(fenetre="24h"))
        for interdit in self.INTERDITS:
            assert interdit not in texte, f"terme technique dans le rapport : {interdit}"

    def test_le_compte_rendu_d_intervention_non_plus(self, plateforme_active, editeur):
        numero = _incident(plateforme_active)
        texte = self._texte_du_rapport(
            editeur, Selection(perimetre=Perimetre.INCIDENT, valeur=numero)
        )
        for interdit in self.INTERDITS:
            if interdit == "incident_id":
                continue  # la fiche d'identification cite la référence interne
            assert interdit not in texte, f"terme technique dans le rapport : {interdit}"

    def test_tous_les_gestes_du_catalogue_sont_traduits(self, platform):
        """Un geste ajouté au catalogue sans traduction ferait apparaître son
        identifiant dans un document officiel. Le test le refuse d'avance."""
        manquants = [
            entree.key
            for entree in platform.catalog.all()
            if entree.key not in langage.GESTES
        ]
        assert not manquants, f"gestes sans traduction : {manquants}"

    def test_un_geste_inconnu_reste_lisible(self):
        """Repli plutôt qu'identifiant brut, si la table venait à prendre du
        retard sur le catalogue."""
        assert langage.geste("nouveau:couper_le_lien") == "Couper le lien"

    def test_les_issues_de_decision_sont_des_phrases(self):
        for cle, phrase in langage.ISSUES.items():
            assert "_" not in phrase, cle
            assert phrase[0].isupper(), cle

    def test_le_numero_d_intervention_est_un_numero_d_affaire(self):
        assert langage.numero_intervention("inc_f4c2f037a9fc46cd") == "INT-F4C2F037"

    def test_les_etats_s_accordent_avec_intervention(self):
        """« l'intervention est contenu » : l'accord au masculin sautait aux
        yeux du premier lecteur du rapport."""
        assert langage.etat_incident("contained") == "contenue"
        assert langage.etat_incident("closed") == "close"

    def test_le_pluriel_est_ecrit_et_non_parenthese(self):
        assert langage.nombre(1, "geste") == "1 geste"
        assert langage.nombre(3, "geste") == "3 gestes"
        assert "(s)" not in langage.nombre(0, "geste")

    def test_l_acteur_machine_est_nomme_en_clair(self):
        assert langage.acteur("system:orchestrator") == "la plateforme"
        assert langage.acteur("human:a.mbarga") == "l'agent a.mbarga"
        assert "generic_json" not in langage.acteur("adapter:generic_json")


class TestRoutesDEdition:
    def test_l_apercu_rend_le_document_structure(self, client, bruteforce_payload):
        client.post(
            "/api/v1/events/ingest?source=wazuh",
            json=bruteforce_payload,
            headers={"Authorization": "Bearer test-analyst"},
        )
        reponse = client.get("/api/v1/rapports/apercu?perimetre=periode&fenetre=24h")
        assert reponse.status_code == 200
        corps = reponse.json()
        assert corps["document"]["contenu"]
        assert corps["perimetre"]["perimetre"] == "periode"

    @pytest.mark.parametrize(
        ("format_", "type_attendu"),
        [
            ("pdf", "application/pdf"),
            ("docx", "application/vnd.openxmlformats-officedocument"),
            ("md", "text/markdown"),
            ("json", "application/json"),
        ],
    )
    def test_le_telechargement_sert_le_bon_type(self, client, format_, type_attendu):
        reponse = client.get(f"/api/v1/rapports/editer?perimetre=periode&format={format_}")
        assert reponse.status_code == 200
        assert type_attendu in reponse.headers["content-type"]
        assert "attachment" in reponse.headers["content-disposition"]

    def test_le_telechargement_n_est_pas_mis_en_cache(self, client):
        """Un rapport rejoué depuis le cache du navigateur afficherait des
        chiffres périmés sous un en-tête officiel."""
        reponse = client.get("/api/v1/rapports/editer?perimetre=periode&format=md")
        assert reponse.headers["cache-control"] == "no-store"

    def test_un_format_inconnu_est_refuse_en_clair(self, client):
        reponse = client.get("/api/v1/rapports/editer?perimetre=periode&format=xls")
        assert reponse.status_code == 400
        assert "format" in reponse.json()["detail"]

    def test_une_duree_inconnue_est_refusee_en_clair(self, client):
        reponse = client.get("/api/v1/rapports/apercu?perimetre=periode&fenetre=3siecles")
        assert reponse.status_code == 400
        assert "durée" in reponse.json()["detail"]


class TestMisesEnGarde:
    """Les avertissements que le rapport doit porter, sous peine d'induire
    son lecteur en erreur. Ils sont vérifiés sur les blocs composés plutôt
    que sur le texte rendu : la mise en page replie les lignes, et un test
    qui chercherait une phrase entière échouerait sur un retour à la ligne
    plutôt que sur une régression."""

    @staticmethod
    def _encadres(document) -> list[Encadre]:
        return [b for b in document.blocs if isinstance(b, Encadre)]

    def test_une_chaine_rompue_est_signalee(self, plateforme_active):
        """Le registre altéré est un incident de sécurité portant sur la
        plateforme : le rapport doit le dire, pas le taire.

        La base interdit toute mise à jour du journal — c'est précisément la
        garantie d'immuabilité — on ne peut donc pas falsifier une entrée
        pour éprouver ce chemin. On compose la section directement, avec des
        faits déclarant la chaîne rompue.
        """
        from cirtdefense.reporting.composer import _Numerotation
        from cirtdefense.reporting.document import Document

        faits = plateforme_active.compositeur._collector.collect(hours=24)
        faits.audit_chain_valid = False
        document = Document(titre="essai", objet="essai", reference="essai")
        plateforme_active.compositeur._section_tracabilite(
            document, faits, _Numerotation()
        )
        alertes = [e for e in self._encadres(document) if e.ton == "alerte"]
        assert alertes, "une chaîne rompue doit produire une alerte"
        assert "modifiée en dehors de la plateforme" in alertes[0].texte
        assert "ROMPUE" in str([b.to_dict() for b in document.blocs])

    def test_une_chaine_intacte_ne_declenche_aucune_alerte(self, plateforme_active, editeur):
        document = editeur.editer(Selection(fenetre="24h"), "md").document
        assert not [e for e in self._encadres(document) if e.ton == "alerte"]

    def test_le_mode_repetition_est_annonce(self, editeur):
        """Les chiffres d'une répétition ne mesurent pas une action réelle sur
        le réseau ; un rapport qui l'omettrait serait trompeur."""
        document = editeur.editer(Selection(fenetre="24h"), "md").document
        mises_en_garde = [
            e.texte for e in self._encadres(document) if e.ton == "attention"
        ]
        assert mises_en_garde
        assert any("aucun effet sur les équipements réels" in t for t in mises_en_garde)
