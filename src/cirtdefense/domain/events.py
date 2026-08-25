"""Schema pivot `DetectionEvent` (EF-18 a EF-20).

Toute source, quelle que soit sa technologie, est ramenee à cette forme par
l'adaptateur d'ingestion. Le reste de la plateforme ne connaît que ce type :
c'est ce qui permet d'ajouter une source sans toucher a l'orchestration.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from .enums import Severity, SourceKind


def utcnow() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True, slots=True)
class Asset:
    """Cible concernee par un événement. Sert de clé de correlation."""

    asset_id: str
    hostname: str | None = None
    ip: str | None = None
    user: str | None = None
    criticality: int = 3  # 1 (accessoire) a 5 (vital)
    zone: str = "unknown"

    def correlation_key(self) -> str:
        return self.asset_id or self.hostname or self.ip or "unknown"


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """Événement normalise. Immuable : c'est une observation, pas un état."""

    event_id: str = field(default_factory=lambda: _new_id("evt"))
    occurred_at: datetime = field(default_factory=utcnow)
    received_at: datetime = field(default_factory=utcnow)
    source: SourceKind = SourceKind.SIEM
    source_product: str = "unknown"
    category: str = "unknown"
    """Famille de menace normalisee : bruteforce, exfiltration, lateral_movement..."""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    """Confiance de la source dans sa propre détection, 0.0 a 1.0."""
    asset: Asset = field(default_factory=lambda: Asset(asset_id="unknown"))
    title: str = ""
    description: str = ""
    indicators: dict[str, Any] = field(default_factory=dict)
    """IOC et attributs libres : ip_src, hash, port, process, user_agent..."""
    raw: dict[str, Any] = field(default_factory=dict)
    """Charge utile d'origine, conservee pour l'audit et le rejeu."""
    mitre_techniques: tuple[str, ...] = ()
    site_id: str = "cirt-cm-01"

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence hors bornes : {self.confidence}")
        if self.asset.criticality not in range(1, 6):
            raise ValueError(f"criticality hors bornes : {self.asset.criticality}")

    def fingerprint(self) -> str:
        """Empreinte stable servant à la deduplication et a l'idempotence.

        Deux remontees de la même observation par deux collecteurs differents
        doivent produire la même empreinte, sinon le moteur agirait deux fois.
        """
        payload = "|".join(
            [
                self.category,
                self.asset.correlation_key(),
                str(sorted(self.indicators.items())),
                self.occurred_at.replace(second=0, microsecond=0).isoformat(),
            ]
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["occurred_at"] = self.occurred_at.isoformat()
        data["received_at"] = self.received_at.isoformat()
        data["source"] = self.source.value
        data["severity"] = self.severity.value
        data["mitre_techniques"] = list(self.mitre_techniques)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectionEvent:
        payload = dict(data)
        asset = payload.pop("asset", {}) or {}
        for key in ("occurred_at", "received_at"):
            value = payload.get(key)
            if isinstance(value, str):
                payload[key] = datetime.fromisoformat(value)
        if "source" in payload:
            payload["source"] = SourceKind(payload["source"])
        if "severity" in payload:
            payload["severity"] = Severity(payload["severity"])
        if "mitre_techniques" in payload:
            payload["mitre_techniques"] = tuple(payload["mitre_techniques"])
        known = {f for f in DetectionEvent.__dataclass_fields__ if f != "asset"}
        payload = {k: v for k, v in payload.items() if k in known}
        return cls(asset=Asset(**asset), **payload)
