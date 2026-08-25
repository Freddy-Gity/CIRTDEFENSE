"""Normaliseur syslog RFC 5424 / RFC 3164 (ligne de texte brute)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from ...domain.enums import Severity, SourceKind
from ...domain.events import Asset, DetectionEvent
from .mapping import classify_category

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$"
)
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)

_SEVERITY_BY_SYSLOG = {
    0: Severity.CRITICAL,
    1: Severity.CRITICAL,
    2: Severity.CRITICAL,
    3: Severity.HIGH,
    4: Severity.MEDIUM,
    5: Severity.LOW,
    6: Severity.INFO,
    7: Severity.INFO,
}
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# `for user root` doit rendre "root" et non "user" : la forme longue passe en premier.
_USER = re.compile(r"(?:for\s+user|user|for)\s+(?P<user>[\w.\-\\]+)", re.IGNORECASE)


def normalize(payload: dict[str, Any]) -> DetectionEvent:
    """Accepte {"line": "<134>1 ..."} ou directement une chaîne sous `message`."""
    line = str(payload.get("line") or payload.get("message") or "")
    match = _RFC5424.match(line) or _RFC3164.match(line)
    fields: dict[str, str] = match.groupdict() if match else {}
    message = fields.get("rest", line)

    priority = int(fields.get("pri", 13))
    severity = _SEVERITY_BY_SYSLOG.get(priority % 8, Severity.MEDIUM)

    ips = _IP.findall(message)
    user_match = _USER.search(message)
    indicators: dict[str, Any] = {}
    if ips:
        indicators["srcip"] = ips[0]
    if user_match:
        indicators["user"] = user_match.group("user")

    return DetectionEvent(
        occurred_at=_parse_syslog_time(fields.get("ts")),
        source=SourceKind.SIEM,
        source_product=fields.get("app") or "syslog",
        category=classify_category(message),
        severity=severity,
        confidence=0.4,  # une ligne de journal est une observation faible
        asset=Asset(
            asset_id=fields.get("host") or "unknown",
            hostname=fields.get("host"),
            ip=ips[0] if ips else None,
            user=user_match.group("user") if user_match else None,
        ),
        title=message[:120],
        description=message,
        indicators=indicators,
        raw={"line": line},
    )


def _parse_syslog_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)
