"""Mode degrade (Axe 5) : agir sans voir serait pire que ne pas agir."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cirtdefense.degraded.queue import DegradedSpool, SpoolFullError


class TestComportementEnModeDegrade:
    def test_aucune_action_pendant_la_coupure(self, platform, bruteforce_payload):
        """La boucle EF-25 ne pourrait pas constater les degats : le systeme
        observe et met en file, il n'agit pas."""
        platform.enter_degraded_mode("perte de connectivite avec les equipements")

        assert platform.ingest_and_respond("wazuh", bruteforce_payload) is None
        assert platform.spool.size() == 1
        assert not platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

    def test_rejeu_a_la_reprise(self, platform, bruteforce_payload):
        platform.enter_degraded_mode("coupure")
        platform.ingest_and_respond("wazuh", bruteforce_payload)

        report = platform.leave_degraded_mode()

        assert report["replayed"] == 1
        assert platform.spool.size() == 0
        assert platform.registry.require("firewall").is_applied("block_ip", "41.202.1.9")

    def test_le_rejeu_emprunte_la_chaine_nominale(self, platform, bruteforce_payload):
        """Un chemin de rejeu parallele finirait par diverger de l'ingestion
        normale."""
        platform.enter_degraded_mode("coupure")
        platform.ingest_and_respond("wazuh", bruteforce_payload)
        platform.leave_degraded_mode()

        types = [e.event_type for e in platform.ledger.query(limit=50)]
        assert "event.ingested" in types
        assert "decision.made" in types


class TestFileDeSynchronisation:
    def test_persistance_sur_disque(self, tmp_path):
        """Une coupure prolongee ne doit pas faire perdre ce qui s'est produit
        pendant."""
        spool = DegradedSpool(tmp_path / "spool")
        spool.enqueue("wazuh", {"a": 1})

        assert DegradedSpool(tmp_path / "spool").size() == 1

    def test_ordre_d_arrivee_respecte(self, tmp_path):
        spool = DegradedSpool(tmp_path / "spool")
        for i in range(5):
            spool.enqueue("wazuh", {"i": i})

        assert [i.payload["i"] for i in spool.items()] == [0, 1, 2, 3, 4]

    def test_file_pleine_conserve_les_plus_anciens(self, tmp_path):
        """Les plus anciens portent le debut de l'incident."""
        spool = DegradedSpool(tmp_path / "spool", max_items=2)
        spool.enqueue("wazuh", {"i": 0})
        spool.enqueue("wazuh", {"i": 1})

        with pytest.raises(SpoolFullError):
            spool.enqueue("wazuh", {"i": 2})
        assert [i.payload["i"] for i in spool.items()] == [0, 1]

    def test_evenement_perime_n_est_pas_rejoue(self, tmp_path):
        """La situation qu'il decrit a probablement change ; agir dessus
        serait agir sur une photographie ancienne."""
        spool = DegradedSpool(tmp_path / "spool")
        item = spool.enqueue("wazuh", {"a": 1})

        perime = item.to_dict()
        perime["queued_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
        (tmp_path / "spool" / f"{item.item_id}.json").write_text(
            __import__("json").dumps(perime)
        )

        report = spool.replay(lambda source, payload: None)
        assert report.skipped_stale == 1
        assert report.replayed == 0

    def test_echec_de_rejeu_conserve_l_element(self, tmp_path):
        spool = DegradedSpool(tmp_path / "spool")
        spool.enqueue("wazuh", {"a": 1})

        def handler(source, payload):
            raise RuntimeError("equipement toujours injoignable")

        report = spool.replay(handler)
        assert report.failed == 1
        assert spool.size() == 1
        assert spool.items()[0].attempts == 1
