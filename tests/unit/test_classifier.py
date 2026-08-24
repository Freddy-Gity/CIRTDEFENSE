"""Classification : type, famille, criticite, dangerosite."""

from __future__ import annotations

import pytest

from cirtdefense.domain.enums import Severity
from cirtdefense.domain.events import Asset, DetectionEvent
from cirtdefense.domain.taxonomy import CATALOG, AttackFamily, Priority
from cirtdefense.orchestration.classifier import Classifier


@pytest.fixture
def classifier() -> Classifier:
    return Classifier()


def _event(category, severity=Severity.MEDIUM, confidence=0.7, criticality=3, **kw):
    return DetectionEvent(
        category=category,
        severity=severity,
        confidence=confidence,
        asset=Asset(asset_id="srv-01", criticality=criticality),
        **kw,
    )


class TestResolutionDuType:
    @pytest.mark.parametrize("attack", CATALOG, ids=lambda a: a.code)
    def test_chaque_type_du_catalogue_est_reconnu(self, classifier, attack):
        result = classifier.classify(_event(attack.category))
        assert result.is_catalogued
        assert result.code == attack.code

    def test_categorie_hors_catalogue_reste_qualifiee(self, classifier):
        """Un type inconnu doit etre declare tel quel, pas laisse sans
        qualification : le portefeuille doit pouvoir l'afficher."""
        result = classifier.classify(_event("menace_inedite"))
        assert not result.is_catalogued
        assert result.code == "?"
        assert result.dangerousness > 0

    def test_categorie_heritee_rapprochee_et_signalee(self, classifier):
        """Le rapprochement est trace : un lecteur doit savoir que la source
        n'avait pas qualifie plus finement."""
        result = classifier.classify(_event("malware"))
        assert result.code == "A6"
        assert result.aliased_from == "malware"
        assert any("rapprochee" in f for f in result.factors)


class TestCriticite:
    def test_le_catalogue_impose_un_plancher(self, classifier):
        """Une source ne peut pas remonter moins grave que le type ne vaut."""
        result = classifier.classify(_event("ransomware", severity=Severity.LOW))
        assert result.severity is Severity.CRITICAL

    def test_la_source_peut_remonter_plus_grave(self, classifier):
        result = classifier.classify(_event("scan", severity=Severity.HIGH))
        assert result.severity >= Severity.HIGH

    def test_actif_vital_releve_la_criticite(self, classifier):
        normal = classifier.classify(_event("xss", criticality=3))
        vital = classifier.classify(_event("xss", criticality=5))
        assert vital.severity > normal.severity


class TestDangerosite:
    def test_distincte_de_la_criticite(self, classifier):
        """Un scan est de criticite basse mais pas de dangerosite nulle ; une
        panne de service est l'inverse."""
        scan = classifier.classify(_event("scan", severity=Severity.LOW))
        panne = classifier.classify(_event("service_unavailable", criticality=5))
        assert scan.severity < panne.severity
        assert scan.dangerousness < panne.dangerousness
        assert scan.dangerousness > 0

    def test_croit_avec_la_criticite_de_l_actif(self, classifier):
        faible = classifier.classify(_event("sql_injection", criticality=1))
        fort = classifier.classify(_event("sql_injection", criticality=5))
        assert fort.dangerousness > faible.dangerousness

    def test_la_confiance_module_sans_annuler(self, classifier):
        """Une detection incertaine de rancongiciel reste plus dangereuse
        qu'un scan certain."""
        incertain = classifier.classify(_event("ransomware", confidence=0.3))
        certain = classifier.classify(_event("scan", confidence=1.0))
        assert incertain.dangerousness > certain.dangerousness

    def test_bornee_a_dix(self, classifier):
        result = classifier.classify(
            _event("rce", severity=Severity.CRITICAL, confidence=1.0, criticality=5)
        )
        assert result.dangerousness <= 10.0

    def test_chaque_score_est_explique(self, classifier):
        """Sans validation humaine en amont, une qualification qu'on ne sait
        pas justifier ne vaut rien."""
        result = classifier.classify(_event("ransomware", criticality=5))
        assert result.factors
        assert any("dangerosite de base" in f for f in result.factors)
        assert any("confiance" in f for f in result.factors)


class TestPriorite:
    def test_issue_du_catalogue(self, classifier):
        assert classifier.classify(_event("ransomware")).priority is Priority.CRITICAL
        assert classifier.classify(_event("scan")).priority is Priority.LOW

    def test_actif_vital_porte_la_priorite_a_critique(self, classifier):
        """Le document laisse des priorites conditionnelles (« haute si
        service critique ») : l'actif tranche ce qui reste ouvert."""
        normal = classifier.classify(_event("exfiltration", criticality=3))
        vital = classifier.classify(_event("exfiltration", criticality=5))
        assert normal.priority is Priority.HIGH
        assert vital.priority is Priority.CRITICAL


class TestFamille:
    @pytest.mark.parametrize(
        "categorie,famille",
        [
            ("ddos_volumetric", AttackFamily.NETWORK),
            ("sql_injection", AttackFamily.APPLICATION),
            ("compromised_account", AttackFamily.INSIDER),
            ("config_drift", AttackFamily.INFRASTRUCTURE),
        ],
    )
    def test_rattachement(self, classifier, categorie, famille):
        assert classifier.classify(_event(categorie)).family is famille
