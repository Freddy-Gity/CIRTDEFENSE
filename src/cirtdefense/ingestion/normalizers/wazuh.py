"""Normaliseur Wazuh (alertes JSON du gestionnaire)."""

from __future__ import annotations

from typing import Any

from ...domain.enums import SourceKind
from ...domain.events import Asset, DetectionEvent
from .generic_json import _parse_time
from .mapping import classify_category, severity_from_level


def normalize(payload: dict[str, Any]) -> DetectionEvent:
    rule = payload.get("rule") or {}
    agent = payload.get("agent") or {}
    data = payload.get("data") or {}
    description = str(rule.get("description", ""))
    groups = " ".join(rule.get("groups") or [])

    indicators: dict[str, Any] = {}
    for key in ("srcip", "dstip", "srcport", "dstport", "srcuser", "dstuser"):
        if data.get(key):
            indicators[key] = data[key]
    if payload.get("full_log"):
        indicators["full_log"] = str(payload["full_log"])[:500]

    return DetectionEvent(
        occurred_at=_parse_time(payload.get("timestamp")),
        source=SourceKind.EDR,
        source_product="wazuh",
        category=classify_category(description, groups),
        severity=severity_from_level(rule.get("level")),
        confidence=_confidence_from_level(rule.get("level")),
        asset=Asset(
            asset_id=str(agent.get("id") or agent.get("name") or "unknown"),
            hostname=agent.get("name"),
            ip=agent.get("ip") or data.get("dstip"),
            user=data.get("dstuser") or data.get("srcuser"),
            criticality=int((payload.get("cirt") or {}).get("criticality", 3)),
            zone=str((payload.get("cirt") or {}).get("zone", "unknown")),
        ),
        title=description or f"Regle Wazuh {rule.get('id', '?')}",
        description=description,
        indicators=indicators,
        mitre_techniques=tuple((rule.get("mitre") or {}).get("id") or ()),
        raw=payload,
    )


def _confidence_from_level(level: Any) -> float:
    """Wazuh n'exprime pas de confiance : on la derive du niveau de regle.

    Volontairement plafonnee a 0.9 — une source ne s'auto-declare jamais
    certaine a 100 % dans cette plateforme.
    """
    try:
        value = int(level)
    except (TypeError, ValueError):
        return 0.5
    return round(min(0.9, 0.3 + value * 0.05), 2)
