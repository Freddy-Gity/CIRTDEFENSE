"""Catalogue CIRT : conformité au document de référence."""

from __future__ import annotations

import pytest

from cirtdefense.domain import taxonomy as t
from cirtdefense.domain.enums import Reversibility


class TestCouvertureDuDocument:
    def test_les_22_lignes_sont_presentes(self):
        assert len(t.CATALOG) == 22

    @pytest.mark.parametrize("famille,attendu", [("A", 7), ("B", 7), ("C", 4), ("D", 4)])
    def test_effectif_par_famille(self, famille, attendu):
        codes = [a.code for a in t.CATALOG if a.family.code == famille]
        assert len(codes) == attendu

    def test_codes_conformes_et_uniques(self):
        codes = [a.code for a in t.CATALOG]
        assert len(codes) == len(set(codes))
        assert codes == sorted(codes, key=lambda c: (c[0], int(c[1:])))

    def test_une_categorie_par_type(self):
        """Deux types partageant une catégorie rendraient le playbook ambigu."""
        assert len(t.BY_CATEGORY) == len(t.CATALOG)


class TestPrincipeDeConception:
    def test_aucune_action_irreversible_au_catalogue(self):
        """Point de vigilance explicite du document : aucune ligne ne
        déclenche d'action irréversible en automatique. Ce test empêche une
        entrée ajoutee plus tard de franchir la limite en silence."""
        fautives = [a.code for a in t.CATALOG if a.reversibility is Reversibility.IRREVERSIBLE]
        assert not fautives, f"types déclarés irréversibles : {fautives}"

    def test_ransomware_se_limite_a_l_isolation(self):
        """A6 : la réponse automatique reste l'isolation réseau, jamais une
        remédiation complète."""
        a6 = t.get("A6")
        assert a6.reversibility is Reversibility.PARTIALLY_REVERSIBLE
        assert "jamais d'action irréversible" in a6.prescribed_actions

    def test_effet_residuel_documente_si_partiellement_reversible(self):
        for a in t.CATALOG:
            if a.reversibility is Reversibility.PARTIALLY_REVERSIBLE:
                assert a.residual_effect, f"{a.code} sans effet résiduel documente"

    def test_ligne_sans_action_corrective_signalee(self):
        """D1 dépend d'une autorité de certification externe : la plateforme
        ne peut pas agir, et cela doit être explicite."""
        d1 = t.get("D1")
        assert d1.no_direct_action
        assert not d1.autonomously_actionable


class TestCoherenceDesScores:
    def test_dangerosite_bornee(self):
        assert all(1 <= a.dangerousness <= 10 for a in t.CATALOG)

    def test_ransomware_et_rce_au_sommet(self):
        """Les deux compromissions les plus directes doivent dominer."""
        pires = sorted(t.CATALOG, key=lambda a: -a.dangerousness)[:3]
        assert {"A6", "B3"} <= {a.code for a in pires}

    def test_scan_est_le_moins_dangereux_des_attaques_reseau(self):
        reseau = t.by_family(t.AttackFamily.NETWORK)
        assert min(reseau, key=lambda a: a.dangerousness).code == "A3"

    def test_priorite_critique_reservee_aux_plus_graves(self):
        critiques = [a.code for a in t.CATALOG if a.priority is t.Priority.CRITICAL]
        assert set(critiques) == {"A6", "B3"}
