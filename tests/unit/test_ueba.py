"""UEBA : detection d'ecart comportemental (EF-08 a EF-10)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cirtdefense.detection.ueba.baseline import BaselineStore, RunningStat
from cirtdefense.detection.ueba.scorer import UebaScorer
from cirtdefense.domain.events import Asset, DetectionEvent


@pytest.fixture
def scorer(tmp_path) -> UebaScorer:
    return UebaScorer(BaselineStore(tmp_path / "baselines.json"))


BASE = datetime(2026, 8, 24, 10, 0, tzinfo=UTC)


def journee(n: int, category="auth", hour=10, ip="10.0.0.9", user="jdupont"):
    return [
        DetectionEvent(
            occurred_at=BASE.replace(hour=hour) + timedelta(minutes=i),
            category=category,
            asset=Asset(asset_id="srv-01", user=user),
            indicators={"srcip": ip},
        )
        for i in range(n)
    ]


class TestStatistiques:
    def test_welford_equivaut_au_calcul_direct(self):
        valeurs = [10, 11, 9, 10, 12, 10, 9]
        stat = RunningStat()
        for v in valeurs:
            stat.update(v)
        moyenne = sum(valeurs) / len(valeurs)
        assert stat.mean == pytest.approx(moyenne)
        assert stat.stddev == pytest.approx(
            (sum((v - moyenne) ** 2 for v in valeurs) / (len(valeurs) - 1)) ** 0.5
        )

    def test_dispersion_nulle_ne_sature_pas_le_score(self):
        stat = RunningStat()
        for _ in range(10):
            stat.update(5.0)
        assert stat.zscore(5.0) == 0.0
        assert stat.zscore(500.0) <= 3.0


class TestDetection:
    def test_pas_d_alerte_sans_profil_etabli(self, scorer):
        """On ne qualifie pas d'anormal ce qu'on n'a jamais observe."""
        assert scorer.evaluate(journee(200, category="bruteforce", hour=3)) is None

    def test_comportement_habituel_n_alerte_pas(self, scorer):
        for _ in range(10):
            scorer.evaluate(journee(3))
        assert scorer.evaluate(journee(3)) is None

    def test_ecart_marque_declenche_une_alerte(self, scorer):
        for _ in range(10):
            scorer.evaluate(journee(3))
        anormal = []
        for i in range(40):
            anormal += journee(1, category="bruteforce", hour=3, ip=f"41.202.1.{i}")

        alerte = scorer.evaluate(anormal)
        assert alerte is not None
        assert alerte.category == "behaviour_anomaly"
        assert alerte.confidence <= 0.85

    def test_l_alerte_porte_son_explication(self, scorer):
        """Une action fondee sur ce score devra etre justifiee a posteriori."""
        for _ in range(10):
            scorer.evaluate(journee(3))
        anormal = []
        for i in range(40):
            anormal += journee(1, category="bruteforce", hour=3, ip=f"41.202.1.{i}")

        alerte = scorer.evaluate(anormal)
        assert "ecart" in alerte.description.lower()
        assert alerte.indicators["contributions"]


class TestEmpoisonnementDuProfil:
    def test_un_comportement_anormal_n_est_pas_appris(self, scorer):
        """Sinon une attaque prolongee deviendrait la nouvelle normale."""
        for _ in range(10):
            scorer.evaluate(journee(3))
        anormal = []
        for i in range(40):
            anormal += journee(1, category="bruteforce", hour=3, ip=f"41.202.1.{i}")

        observations_avant = scorer._store.get("jdupont").observations
        scorer.evaluate(anormal)
        assert scorer._store.get("jdupont").observations == observations_avant
        assert scorer.evaluate(anormal) is not None
