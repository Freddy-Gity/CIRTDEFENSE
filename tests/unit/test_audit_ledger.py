"""Journal d'audit : la seule trace de ce que le systeme a fait seul."""

from __future__ import annotations

import pytest
from cirtdefense.audit.ledger import GENESIS_HASH, AuditLedger
from cirtdefense.persistence.db import connect, init_schema


@pytest.fixture
def ledger() -> AuditLedger:
    conn = connect(":memory:")
    init_schema(conn)
    return AuditLedger(conn)


class TestChainage:
    def test_premiere_entree_chainee_a_la_genese(self, ledger):
        assert ledger.record("action.executed", {"a": 1}).prev_hash == GENESIS_HASH

    def test_chaque_entree_pointe_vers_la_precedente(self, ledger):
        first = ledger.record("action.executed", {"a": 1})
        second = ledger.record("action.executed", {"a": 2})
        assert second.prev_hash == first.entry_hash

    def test_chaine_valide_apres_ecritures(self, ledger):
        for i in range(20):
            ledger.record("action.executed", {"i": i})
        verification = ledger.verify_chain()
        assert verification.valid
        assert verification.entries_checked == 20


class TestImmuabilite:
    def test_suppression_interdite_par_la_base(self, ledger):
        ledger.record("action.executed", {"a": 1})
        with pytest.raises(Exception, match="immuable"):
            ledger._conn.execute("DELETE FROM audit_log")

    def test_modification_interdite_par_la_base(self, ledger):
        ledger.record("action.executed", {"a": 1})
        with pytest.raises(Exception, match="immuable"):
            ledger._conn.execute("UPDATE audit_log SET actor = 'pirate'")

    def test_alteration_detectee_si_les_declencheurs_sont_contournes(self, ledger):
        """Defense en profondeur : meme avec un acces direct au fichier de
        base, l'alteration reste detectable."""
        for i in range(3):
            ledger.record("action.executed", {"i": i})
        ledger._conn.execute("DROP TRIGGER audit_log_no_update")
        ledger._conn.execute("UPDATE audit_log SET payload = '{\"i\": 99}' WHERE seq = 2")

        verification = ledger.verify_chain()
        assert not verification.valid
        assert verification.first_broken_seq == 2


class TestConsultation:
    def test_chronologie_d_un_incident(self, ledger):
        ledger.record("event.ingested", {}, incident_id="inc_1")
        ledger.record("decision.made", {}, incident_id="inc_1")
        ledger.record("action.executed", {}, incident_id="inc_2")

        timeline = ledger.incident_timeline("inc_1")
        assert [e.event_type for e in timeline] == ["event.ingested", "decision.made"]

    def test_filtrage_par_type(self, ledger):
        ledger.record("action.executed", {})
        ledger.record("rollback.completed", {})
        assert len(ledger.query(event_type="rollback.completed")) == 1
