"""Fixtures partagees.

Chaque test recoit une plateforme isolee, en base memoire et en mode
simulation. C'est deliberé : une suite de tests qui partagerait une base
laisserait le coupe-circuit d'un test ouvert pour le suivant, et les echecs
seraient impossibles a interpreter.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cirtdefense.config import AutonomySettings, Settings  # noqa: E402
from cirtdefense.detection.infra.health import HealthSnapshot, StaticProbe  # noqa: E402
from cirtdefense.platform import Platform, build_platform  # noqa: E402


@pytest.fixture
def probe() -> StaticProbe:
    """Sonde alimentee a la main : l'etat de sante est un parametre du test."""
    p = StaticProbe()
    p.set(
        HealthSnapshot(
            target="srv-web-01", reachable=True, latency_ms=100,
            error_rate=0.01, throughput=500, active_sessions=20,
        )
    )
    return p


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        env="test",
        db_path=tmp_path / "cirt.db",
        degraded_spool=tmp_path / "spool",
        admin_token="test-admin",
        analyst_token="test-analyst",
        autonomy=AutonomySettings(
            enabled=True,
            actuation_mode="simulation",
            circuit_breaker_enabled=True,
            breaker_rollback_threshold=3,
            breaker_error_threshold=5,
        ),
    )


@pytest.fixture
def platform(settings: Settings, probe: StaticProbe) -> Any:
    p = build_platform(settings, probe=probe)
    yield p
    p.close()


@pytest.fixture
def client(platform: Platform):
    from fastapi.testclient import TestClient

    from cirtdefense.api.deps import set_platform
    from cirtdefense.main import create_app

    set_platform(platform)
    with TestClient(create_app()) as test_client:
        yield test_client
    set_platform(None)


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-admin"}


@pytest.fixture
def analyst_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-analyst"}


@pytest.fixture
def bruteforce_payload() -> dict[str, Any]:
    """Alerte Wazuh de force brute avec source externe et compte cible."""
    return {
        "timestamp": "2026-08-24T10:00:00Z",
        "rule": {
            "level": 10,
            "description": "Multiple failed password attempts",
            "groups": ["authentication_failed"],
        },
        "agent": {"id": "srv-web-01", "name": "srv-web-01", "ip": "10.0.0.5"},
        "data": {"srcip": "41.202.1.9", "dstuser": "jdupont"},
    }
