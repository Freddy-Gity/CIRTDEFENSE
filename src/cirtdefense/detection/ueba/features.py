"""Extraction des attributs comportementaux d'une entité.

Les attributs sont volontairement peu nombreux et interpretables : en
autonomie totale, un score qu'on ne sait pas expliquer est un score qu'on ne
peut pas defendre devant l'analyste après coup.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ...domain.events import DetectionEvent


@dataclass(slots=True)
class BehaviourFeatures:
    entity: str
    event_count: int = 0
    distinct_hours: set[int] = field(default_factory=set)
    distinct_sources_ips: set[str] = field(default_factory=set)
    distinct_categories: Counter = field(default_factory=Counter)
    off_hours_count: int = 0
    failed_auth_count: int = 0
    volume_bytes: float = 0.0
    last_seen: datetime | None = None

    def as_vector(self) -> dict[str, float]:
        """Représentation numérique stable, utilisée par le scoreur."""
        return {
            "event_rate": float(self.event_count),
            "hour_spread": float(len(self.distinct_hours)),
            "ip_spread": float(len(self.distinct_sources_ips)),
            "category_spread": float(len(self.distinct_categories)),
            "off_hours_ratio": (self.off_hours_count / self.event_count)
            if self.event_count
            else 0.0,
            "failed_auth": float(self.failed_auth_count),
            "volume_bytes": float(self.volume_bytes),
        }


OFF_HOURS = set(range(0, 6)) | {22, 23}
"""Plage considérée hors heures ouvrables (UTC). à ajuster au fuseau du site."""


def extract(entity: str, events: list[DetectionEvent]) -> BehaviourFeatures:
    features = BehaviourFeatures(entity=entity)
    for event in events:
        features.event_count += 1
        hour = event.occurred_at.hour
        features.distinct_hours.add(hour)
        if hour in OFF_HOURS:
            features.off_hours_count += 1
        features.distinct_categories[event.category] += 1
        src = event.indicators.get("srcip") or event.indicators.get("src_ip")
        if src:
            features.distinct_sources_ips.add(str(src))
        if event.category == "bruteforce":
            features.failed_auth_count += 1
        volume = event.indicators.get("bytes") or event.indicators.get("bytes_out")
        if isinstance(volume, int | float):
            features.volume_bytes += float(volume)
        if features.last_seen is None or event.occurred_at > features.last_seen:
            features.last_seen = event.occurred_at
    return features


def entity_of(event: DetectionEvent) -> str:
    """Entité observée : l'utilisateur si connu, sinon la machine."""
    return event.asset.user or event.asset.correlation_key()


def summarize(features: BehaviourFeatures) -> dict[str, Any]:
    return {
        "entity": features.entity,
        "event_count": features.event_count,
        "distinct_hours": sorted(features.distinct_hours),
        "distinct_source_ips": sorted(features.distinct_sources_ips),
        "top_categories": features.distinct_categories.most_common(3),
        "off_hours_count": features.off_hours_count,
        "failed_auth_count": features.failed_auth_count,
        "volume_bytes": features.volume_bytes,
        "last_seen": features.last_seen.isoformat() if features.last_seen else None,
    }
