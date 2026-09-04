"""Configuration d'exécution, lue une fois au démarrage.

Les valeurs qui touchent à la posture d'autonomie (EF-07, EF-25, EF-26) sont
regroupées ici et journalisées au démarrage : un auditeur doit pouvoir dire,
pour un incident donne, sous quelle configuration le système a agi.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "oui")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True, slots=True)
class AutonomySettings:
    """Posture d'autonomie - CDCF v3.0 §1.4.3."""

    enabled: bool = True
    """EF-07 : exécution sans validation humaine préalable."""
    actuation_mode: str = "simulation"
    """simulation | live. En simulation les actuateurs n'ont aucun effet réel."""
    post_action_watch_seconds: int = 120
    """EF-25 : durée de surveillance post-action avant cloture de la boucle."""
    rollback_max_latency_seconds: int = 180
    """CR de non-régression : délai borne d'annulation d'une action erronée."""
    circuit_breaker_enabled: bool = True
    """EF-26 : coupe-circuit global actionnable par l'administrateur."""
    breaker_rollback_threshold: int = 3
    breaker_error_threshold: int = 5
    breaker_window_seconds: int = 600
    decline_quarantine_threshold: float = 7.0
    """Dangerosité à partir de laquelle un geste écarté par un agent déclenche
    tout de même un confinement — posé par substitution réversible, jamais avec
    le geste refusé. En deçà, l'actif passe seulement sous surveillance
    rapprochée et le refus s'applique tel quel."""

    @property
    def is_live(self) -> bool:
        return self.actuation_mode == "live"


@dataclass(frozen=True, slots=True)
class Settings:
    env: str = "dev"
    site_id: str = "cirt-cm-01"
    site_lat: float = 3.8747
    """Latitude du siège (par défaut : ANTIC, Nlongkak, Yaoundé). Sert de
    centre géographique au balayage radar de l'onglet Surveillance."""
    site_lon: float = 11.5203
    """Longitude du siège."""
    db_path: Path = field(default_factory=lambda: PROJECT_ROOT / "data" / "cirtdefense.db")
    knowledge_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "src" / "cirtdefense" / "enrichment" / "knowledge"
    )
    playbook_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / "src" / "cirtdefense" / "orchestration" / "playbooks"
    )
    grounding_min_score: float = 0.15
    """EF-04 : sous ce seuil, le contexte est jugé non fondé et le moteur
    refuse d'agir plutôt que d'agir sur une hypothèse."""
    llm_provider: str = "offline"
    llm_model: str = "claude-opus-5"
    llm_api_key: str = ""
    degraded_spool: Path = field(default_factory=lambda: PROJECT_ROOT / "data" / "spool")
    degraded_max_items: int = 10000
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    admin_token: str = "change-me-admin"
    analyst_token: str = "change-me-analyst"
    session_ttl_hours: int = 12
    """Durée de vie d'une session ouverte à la connexion (onglet Comptes)."""
    report_logo: Path = field(
        default_factory=lambda: PROJECT_ROOT / "web" / "static" / "logo-antic.png"
    )
    """Emblème imprimé au centre de la titulature des rapports officiels.

    Configurable : un autre site du CIRT, ou une autre administration
    utilisant la plateforme, imprime son propre emblème sans toucher au code.
    """
    autonomy: AutonomySettings = field(default_factory=AutonomySettings)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            env=os.getenv("CIRT_ENV", "dev"),
            site_id=os.getenv("CIRT_SITE_ID", "cirt-cm-01"),
            site_lat=_float("CIRT_SITE_LAT", 3.8747),
            site_lon=_float("CIRT_SITE_LON", 11.5203),
            db_path=Path(os.getenv("CIRT_DB_PATH", str(PROJECT_ROOT / "data" / "cirtdefense.db"))),
            knowledge_dir=Path(
                os.getenv(
                    "CIRT_KNOWLEDGE_DIR",
                    str(PROJECT_ROOT / "src" / "cirtdefense" / "enrichment" / "knowledge"),
                )
            ),
            grounding_min_score=_float("CIRT_GROUNDING_MIN_SCORE", 0.15),
            llm_provider=os.getenv("CIRT_LLM_PROVIDER", "offline"),
            llm_model=os.getenv("CIRT_LLM_MODEL", "claude-opus-5"),
            llm_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            degraded_spool=Path(
                os.getenv("CIRT_DEGRADED_SPOOL", str(PROJECT_ROOT / "data" / "spool"))
            ),
            degraded_max_items=_int("CIRT_DEGRADED_MAX_ITEMS", 10000),
            api_host=os.getenv("CIRT_API_HOST", "0.0.0.0"),
            api_port=_int("CIRT_API_PORT", 8000),
            admin_token=os.getenv("CIRT_ADMIN_TOKEN", "change-me-admin"),
            analyst_token=os.getenv("CIRT_ANALYST_TOKEN", "change-me-analyst"),
            session_ttl_hours=_int("CIRT_SESSION_TTL_HOURS", 12),
            report_logo=Path(
                os.getenv(
                    "CIRT_REPORT_LOGO", str(PROJECT_ROOT / "web" / "static" / "logo-antic.png")
                )
            ),
            autonomy=AutonomySettings(
                enabled=_flag("CIRT_AUTONOMY_ENABLED", True),
                actuation_mode=os.getenv("CIRT_ACTUATION_MODE", "simulation"),
                post_action_watch_seconds=_int("CIRT_POST_ACTION_WATCH_SECONDS", 120),
                rollback_max_latency_seconds=_int("CIRT_ROLLBACK_MAX_LATENCY_SECONDS", 180),
                circuit_breaker_enabled=_flag("CIRT_CIRCUIT_BREAKER_ENABLED", True),
                breaker_rollback_threshold=_int("CIRT_BREAKER_ROLLBACK_THRESHOLD", 3),
                breaker_error_threshold=_int("CIRT_BREAKER_ERROR_THRESHOLD", 5),
                breaker_window_seconds=_int("CIRT_BREAKER_WINDOW_SECONDS", 600),
                decline_quarantine_threshold=_float(
                    "CIRT_DECLINE_QUARANTINE_THRESHOLD", 7.0
                ),
            ),
        )

    def summary(self) -> dict:
        data = asdict(self)
        data["db_path"] = str(self.db_path)
        data["knowledge_dir"] = str(self.knowledge_dir)
        data["playbook_dir"] = str(self.playbook_dir)
        data["degraded_spool"] = str(self.degraded_spool)
        for secret in ("admin_token", "analyst_token", "llm_api_key"):
            data[secret] = "***" if data[secret] else ""
        return data


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()


def reset_settings_cache() -> None:
    """Utilise par les tests pour recharger l'environnement."""
    get_settings.cache_clear()
