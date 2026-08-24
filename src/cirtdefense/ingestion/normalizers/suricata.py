"""Normaliseur Suricata (EVE JSON, evenements de type `alert`)."""

from __future__ import annotations

from typing import Any

from ...domain.enums import Severity, SourceKind
from ...domain.events import Asset, DetectionEvent
from .generic_json import _parse_time
from .mapping import classify_category

# Suricata : 1 = le plus grave.
_SIGNATURE_SEVERITY = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM, 4: Severity.LOW}


def normalize(payload: dict[str, Any]) -> DetectionEvent:
    alert = payload.get("alert") or {}
    signature = str(alert.get("signature", ""))
    class_type = str(alert.get("category", ""))

    indicators = {
        k: payload[k]
        for k in ("src_ip", "dest_ip", "src_port", "dest_port", "proto", "app_proto")
        if payload.get(k)
    }
    if alert.get("signature_id"):
        indicators["signature_id"] = alert["signature_id"]

    # Le nom de domaine interroge est l'indicateur decisif d'un canal de
    # commande et controle : sans lui, la reponse prescrite par le catalogue
    # (sinkhole DNS) ne peut pas etre ciblee et le playbook retombe sur le
    # seul blocage d'adresse, moins efficace contre une infrastructure a
    # resolution dynamique.
    domain = (
        (payload.get("dns") or {}).get("rrname")
        or (payload.get("tls") or {}).get("sni")
        or (payload.get("http") or {}).get("hostname")
    )
    if domain:
        indicators["domain"] = str(domain).rstrip(".")

    return DetectionEvent(
        occurred_at=_parse_time(payload.get("timestamp")),
        source=SourceKind.NIDS,
        source_product="suricata",
        category=classify_category(signature, class_type),
        severity=_SIGNATURE_SEVERITY.get(int(alert.get("severity", 3)), Severity.MEDIUM),
        confidence=0.6,
        asset=Asset(
            asset_id=str(payload.get("dest_ip") or payload.get("host") or "unknown"),
            ip=payload.get("dest_ip"),
            hostname=payload.get("host"),
            zone=str(payload.get("in_iface", "unknown")),
        ),
        title=signature or "Alerte Suricata",
        description=f"{class_type} — {signature}".strip(" —"),
        indicators=indicators,
        raw=payload,
    )
