"""Invariants du domaine : ce qui doit rester vrai quel que soit le chemin."""

from __future__ import annotations

import pytest

from cirtdefense.domain.action import ActionSpec
from cirtdefense.domain.enums import Reversibility, Severity
from cirtdefense.domain.events import Asset, DetectionEvent
from cirtdefense.domain.incident import Incident


class TestSeverity:
    def test_ordre_total(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_comparaison_avec_autre_type_non_supportee(self):
        with pytest.raises(TypeError):
            _ = Severity.HIGH > 3


class TestActionSpec:
    def test_action_reversible_exige_un_verbe_d_annulation(self):
        """Sans verbe d'annulation, EF-25 ne pourrait pas retirer l'action."""
        with pytest.raises(ValueError, match="rollback_verb"):
            ActionSpec(
                verb="block_ip",
                actuator="firewall",
                target="1.2.3.4",
                reversibility=Reversibility.REVERSIBLE,
            )

    def test_action_irreversible_n_exige_rien(self):
        spec = ActionSpec(verb="wipe_disk", actuator="edr", target="h1")
        assert spec.reversibility is Reversibility.IRREVERSIBLE

    def test_rayon_d_impact_minimal(self):
        with pytest.raises(ValueError, match="blast_radius"):
            ActionSpec(verb="notify", actuator="notify", target="x", blast_radius=0)


class TestDetectionEvent:
    def test_confiance_bornee(self):
        with pytest.raises(ValueError, match="confidence"):
            DetectionEvent(confidence=1.5)

    def test_empreinte_stable_pour_la_meme_observation(self):
        """Deux collecteurs remontant la même observation ne doivent pas
        provoquer deux actions."""
        args = {
            "category": "bruteforce",
            "asset": Asset(asset_id="srv-01"),
            "indicators": {"srcip": "41.202.1.9"},
        }
        assert DetectionEvent(**args).fingerprint() == DetectionEvent(**args).fingerprint()

    def test_empreinte_differente_si_la_cible_change(self):
        base = {"category": "bruteforce", "indicators": {"srcip": "41.202.1.9"}}
        a = DetectionEvent(asset=Asset(asset_id="srv-01"), **base)
        b = DetectionEvent(asset=Asset(asset_id="srv-02"), **base)
        assert a.fingerprint() != b.fingerprint()

    def test_aller_retour_serialisation(self):
        event = DetectionEvent(
            category="c2",
            severity=Severity.HIGH,
            asset=Asset(asset_id="srv-01", user="jdupont", criticality=5),
            indicators={"dest_ip": "185.1.1.1"},
            mitre_techniques=("T1071",),
        )
        restored = DetectionEvent.from_dict(event.to_dict())
        assert restored.category == event.category
        assert restored.severity is event.severity
        assert restored.asset.user == "jdupont"
        assert restored.mitre_techniques == ("T1071",)


class TestIncident:
    def test_correlation_par_categorie_et_cible(self):
        event = DetectionEvent(category="bruteforce", asset=Asset(asset_id="srv-01"))
        incident = Incident.from_event(event)
        assert incident.accepts(
            DetectionEvent(category="bruteforce", asset=Asset(asset_id="srv-01"))
        )
        assert not incident.accepts(
            DetectionEvent(category="malware", asset=Asset(asset_id="srv-01"))
        )

    def test_gravite_prend_le_maximum_observe(self):
        incident = Incident.from_event(
            DetectionEvent(
                category="bruteforce", severity=Severity.LOW, asset=Asset(asset_id="srv-01")
            )
        )
        incident.absorb(
            DetectionEvent(
                category="bruteforce", severity=Severity.CRITICAL, asset=Asset(asset_id="srv-01")
            )
        )
        assert incident.severity is Severity.CRITICAL

    def test_score_de_risque_croit_avec_l_enjeu(self):
        faible = Incident.from_event(
            DetectionEvent(
                category="scan",
                severity=Severity.LOW,
                asset=Asset(asset_id="poste-01", criticality=1),
            )
        )
        fort = Incident.from_event(
            DetectionEvent(
                category="malware",
                severity=Severity.CRITICAL,
                confidence=0.9,
                asset=Asset(asset_id="srv-01", criticality=5),
            )
        )
        assert fort.risk_score() > faible.risk_score()

    def test_incident_clos_n_absorbe_plus_rien(self):
        incident = Incident.from_event(
            DetectionEvent(category="bruteforce", asset=Asset(asset_id="srv-01"))
        )
        incident.close()
        assert not incident.accepts(
            DetectionEvent(category="bruteforce", asset=Asset(asset_id="srv-01"))
        )
