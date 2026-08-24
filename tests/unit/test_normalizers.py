"""Normalisation multi-sources (EF-18 a EF-20)."""

from __future__ import annotations

from cirtdefense.domain.enums import Severity, SourceKind
from cirtdefense.ingestion import registry
from cirtdefense.ingestion.normalizers.mapping import classify_category


class TestClassification:
    def test_correspondance_la_plus_specifique_l_emporte(self):
        """« command and control » doit primer sur « trojan » : sinon le
        classement dependrait de l'ordre du dictionnaire."""
        assert classify_category("ET TROJAN Beacon", "command and control") == "c2"

    def test_repli_explicite_sur_inconnu(self):
        assert classify_category("evenement sans rapport") == "unknown"

    def test_deterministe(self):
        libelle = "SQL injection attempt detected"
        assert {classify_category(libelle) for _ in range(20)} == {"web_attack"}


class TestWazuh:
    def test_normalisation_complete(self):
        event = registry.get("wazuh")(
            {
                "timestamp": "2026-08-24T10:00:00Z",
                "rule": {
                    "level": 12,
                    "description": "Multiple failed password",
                    "groups": ["auth"],
                },
                "agent": {"id": "003", "name": "srv-web-01", "ip": "10.0.0.5"},
                "data": {"srcip": "41.202.1.9", "dstuser": "admin"},
            }
        )
        assert event.source is SourceKind.EDR
        assert event.category == "bruteforce"
        assert event.severity is Severity.CRITICAL
        assert event.indicators["srcip"] == "41.202.1.9"

    def test_confiance_plafonnee(self):
        """Une source ne s'auto-declare jamais certaine a 100 %."""
        event = registry.get("wazuh")({"rule": {"level": 15, "description": "x"}, "agent": {}})
        assert event.confidence <= 0.9


class TestSuricata:
    def test_echelle_de_gravite_inversee(self):
        """Chez Suricata, 1 est le plus grave."""
        grave = registry.get("suricata")({"alert": {"signature": "x", "severity": 1}})
        benin = registry.get("suricata")({"alert": {"signature": "x", "severity": 4}})
        assert grave.severity > benin.severity


class TestSyslog:
    def test_extraction_du_compte_reel(self):
        """« for user root » doit rendre root, pas le mot « user »."""
        event = registry.get("syslog")(
            {
                "line": "<131>1 2026-08-24T10:05:00Z fw-01 sshd 1 ID47 "
                "Failed password for user root from 41.202.1.9"
            }
        )
        assert event.asset.user == "root"
        assert event.indicators["srcip"] == "41.202.1.9"

    def test_ligne_non_conforme_reste_exploitable(self):
        event = registry.get("syslog")({"line": "texte libre sans en-tete"})
        assert event.category == "unknown"
        assert event.confidence < 0.5


class TestRegistre:
    def test_toutes_les_sources_produisent_un_evenement_valide(self):
        echantillons = {
            "wazuh": {"rule": {"level": 5, "description": "test"}, "agent": {"id": "a"}},
            "suricata": {"alert": {"signature": "test", "severity": 3}},
            "syslog": {"line": "<134>1 - host app - - message"},
            "generic_json": {"category": "scan", "severity": "low", "asset_id": "srv-01"},
        }
        for source, payload in echantillons.items():
            event = registry.get(source)(payload)
            assert event.event_id
            assert 0.0 <= event.confidence <= 1.0

    def test_source_inconnue(self):
        assert registry.get("produit-inexistant") is None
