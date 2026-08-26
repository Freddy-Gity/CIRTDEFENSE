"""Garde de non-invention (EF-04) : le refus d'agir sans fondement."""

from __future__ import annotations

import pytest

from cirtdefense.config import get_settings
from cirtdefense.domain.events import Asset, DetectionEvent
from cirtdefense.enrichment.rag import EnrichmentService


@pytest.fixture(scope="module")
def service() -> EnrichmentService:
    return EnrichmentService.from_directory(get_settings().knowledge_dir)


CATEGORIES_DOCUMENTEES = [
    "bruteforce",
    "c2",
    "malware",
    "exfiltration",
    "lateral_movement",
    "web_attack",
    "scan",
    "dos",
    "privilege_escalation",
    "behaviour_anomaly",
    "infrastructure_degradation",
]


class TestContexteFonde:
    @pytest.mark.parametrize("categorie", CATEGORIES_DOCUMENTEES)
    def test_categorie_documentee_donne_un_contexte_utilisable(self, service, categorie):
        context = service.enrich(
            DetectionEvent(category=categorie, title=categorie, asset=Asset(asset_id="a"))
        )
        assert context.is_usable
        assert context.sources

    def test_sources_citees_pour_l_audit(self, service):
        context = service.enrich(
            DetectionEvent(category="bruteforce", title="brute force", asset=Asset(asset_id="a"))
        )
        assert any("bruteforce.md" in s for s in context.sources)


class TestContexteNonFonde:
    @pytest.mark.parametrize(
        "categorie", ["unknown", "menace_inconnue_xyz", "zzz_quantum_flux", ""]
    )
    def test_categorie_hors_catalogue_bloque_l_action(self, service, categorie):
        """C'est la limite assumee du CDCF §1.4.3 : l'autonomie ne couvre pas
        ce qui n'est pas documente."""
        context = service.enrich(
            DetectionEvent(category=categorie, title="signal opaque", asset=Asset(asset_id="a"))
        )
        assert not context.is_usable

    def test_le_motif_du_refus_est_explicite(self, service):
        context = service.enrich(
            DetectionEvent(category="menace_inconnue", title="x", asset=Asset(asset_id="a"))
        )
        assert context.grounding is not None
        assert context.grounding.reason

    def test_les_mots_de_liaison_ne_suffisent_pas(self, service):
        """Régression : une première version validait une menace inconnue
        parce que les mots de liaison de la phrase de contrôle figuraient
        dans le corpus."""
        context = service.enrich(
            DetectionEvent(
                category="categorie_menace_documentee_inventee",
                title="menace catégorie documentée réponse definie",
                description="menace catégorie documentée",
                asset=Asset(asset_id="a"),
            )
        )
        assert not context.is_usable
