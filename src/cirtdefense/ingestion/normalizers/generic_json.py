"""Normaliseur pivot : accepte déjà la forme `DetectionEvent`.

Sert de porte d'entrée aux sources maison et au rejeu du mode dégrade.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ...domain.enums import Severity, SourceKind
from ...domain.events import Asset, DetectionEvent
from .mapping import classify_category, severity_from_level


def normalize(payload: dict[str, Any]) -> DetectionEvent:
    asset_data = payload.get("asset") or {}
    occurred = payload.get("occurred_at") or payload.get("timestamp")
    return DetectionEvent(
        occurred_at=_parse_time(occurred),
        source=_parse_source(payload.get("source")),
        source_product=str(payload.get("source_product", "generic")),
        category=payload.get("category")
        or classify_category(str(payload.get("title", "")), str(payload.get("description", ""))),
        severity=_parse_severity(payload.get("severity")),
        confidence=float(payload.get("confidence", 0.5)),
        asset=Asset(
            asset_id=str(asset_data.get("asset_id") or payload.get("asset_id") or "unknown"),
            hostname=asset_data.get("hostname") or payload.get("hostname"),
            ip=asset_data.get("ip") or payload.get("ip"),
            user=asset_data.get("user") or payload.get("user"),
            criticality=int(asset_data.get("criticality", 3)),
            zone=str(asset_data.get("zone", "unknown")),
        ),
        title=str(payload.get("title", "")),
        description=str(payload.get("description", "")),
        indicators=dict(payload.get("indicators") or {}),
        mitre_techniques=tuple(payload.get("mitre_techniques") or ()),
        raw=payload,
        site_id=str(payload.get("site_id", "cirt-cm-01")),
    )


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _parse_source(value: Any) -> SourceKind:
    if isinstance(value, SourceKind):
        return value
    try:
        return SourceKind(str(value).lower())
    except ValueError:
        return SourceKind.SIEM


def _parse_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.lower())
        except ValueError:
            return severity_from_level(value)
    return severity_from_level(value)
