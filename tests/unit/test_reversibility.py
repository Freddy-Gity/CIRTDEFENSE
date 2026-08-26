"""Catalogue de réversibilité (EF-14) : la condition de l'autonomie."""

from __future__ import annotations

import pytest

from cirtdefense.domain.enums import Reversibility
from cirtdefense.orchestration.reversibility import (
    CatalogEntry,
    ReversibilityCatalog,
    UnknownActionError,
)


@pytest.fixture
def catalog() -> ReversibilityCatalog:
    return ReversibilityCatalog()


class TestPerimetreAutonome:
    def test_action_reversible_executable(self, catalog):
        assert catalog.is_autonomously_executable("firewall", "block_ip")

    @pytest.mark.parametrize(
        "actuator,verb", [("edr", "wipe_disk"), ("iam", "delete_account"), ("edr", "shutdown_host")]
    )
    def test_action_irreversible_exclue(self, catalog, actuator, verb):
        """Ces entrées figurent au catalogue pour rendre visible ce que
        l'autonomie ne couvre pas."""
        assert not catalog.is_autonomously_executable(actuator, verb)

    def test_action_hors_catalogue_refusee(self, catalog):
        assert not catalog.is_autonomously_executable("edr", "geste_inexistant")
        with pytest.raises(UnknownActionError, match="absente du catalogue"):
            catalog.require("edr", "geste_inexistant")

    def test_sous_ensemble_autonome_strictement_plus_petit(self, catalog):
        assert len(catalog.autonomous_subset()) < len(catalog.all())


class TestMetadonnees:
    def test_effet_residuel_documente_pour_le_partiellement_reversible(self, catalog):
        """L'analyste doit savoir ce qu'une annulation ne rendra pas."""
        for entry in catalog.all():
            if entry.reversibility is Reversibility.PARTIALLY_REVERSIBLE:
                assert entry.residual_effect, f"{entry.key} sans effet résiduel documente"

    def test_toute_entree_autonome_porte_un_verbe_d_annulation(self, catalog):
        for entry in catalog.autonomous_subset():
            assert entry.rollback_verb, f"{entry.key} sans verbe d'annulation"

    def test_delai_d_annulation_borne(self, catalog):
        """Un rollback sans délai maximal ne prouve rien (CDCF §5.3)."""
        for entry in catalog.autonomous_subset():
            assert 0 < entry.max_rollback_seconds <= 300


class TestGestionParAdministrateur:
    def test_ajout_et_retrait(self, catalog):
        entry = CatalogEntry(
            verb="custom_block",
            actuator="firewall",
            reversibility=Reversibility.REVERSIBLE,
            rollback_verb="custom_unblock",
            description="test",
        )
        catalog.add(entry)
        assert catalog.is_autonomously_executable("firewall", "custom_block")
        assert catalog.remove("firewall", "custom_block")
        assert not catalog.is_autonomously_executable("firewall", "custom_block")
