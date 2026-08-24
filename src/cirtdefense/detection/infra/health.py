"""Sondes de sante : mesure de l'etat d'un service ou d'une machine.

Ces mesures ont deux usages distincts qu'il faut garder separes :
detecter une degradation *subie* (EF-21) et detecter une degradation
*provoquee par nos propres actions* (EF-25). Le mecanisme de mesure est le
meme, l'interpretation ne l'est pas.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """Photographie instantanee de l'etat d'une cible."""

    target: str
    taken_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    reachable: bool = True
    latency_ms: float = 0.0
    error_rate: float = 0.0
    """Part de requetes en erreur, 0.0 a 1.0."""
    throughput: float = 0.0
    active_sessions: int = 0
    metrics: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "taken_at": self.taken_at.isoformat(),
            "reachable": self.reachable,
            "latency_ms": self.latency_ms,
            "error_rate": self.error_rate,
            "throughput": self.throughput,
            "active_sessions": self.active_sessions,
            "metrics": self.metrics,
        }


class HealthProbe(ABC):
    """Contrat d'une sonde. L'implantation reelle (ICMP, HTTP, SNMP, agent)
    depend du site ; la plateforme ne connait que cette interface."""

    name: str = "probe"

    @abstractmethod
    def measure(self, target: str) -> HealthSnapshot: ...


class StaticProbe(HealthProbe):
    """Sonde alimentee par un dictionnaire : recette, tests et demonstration.

    C'est aussi le point d'injection utilise pour rejouer un scenario de
    degradation post-action sans casser un service reel.
    """

    name = "static"

    def __init__(self, snapshots: dict[str, HealthSnapshot] | None = None) -> None:
        self._snapshots: dict[str, HealthSnapshot] = snapshots or {}

    def set(self, snapshot: HealthSnapshot) -> None:
        self._snapshots[snapshot.target] = snapshot

    def measure(self, target: str) -> HealthSnapshot:
        return self._snapshots.get(target, HealthSnapshot(target=target))


class CompositeProbe(HealthProbe):
    """Agrege plusieurs sondes : la cible est saine si toutes la disent saine."""

    name = "composite"

    def __init__(self, probes: list[HealthProbe]) -> None:
        self._probes = probes

    def measure(self, target: str) -> HealthSnapshot:
        snapshots = [p.measure(target) for p in self._probes]
        if not snapshots:
            return HealthSnapshot(target=target)
        merged: dict[str, float] = {}
        for snapshot in snapshots:
            merged.update(snapshot.metrics)
        return HealthSnapshot(
            target=target,
            reachable=all(s.reachable for s in snapshots),
            latency_ms=max(s.latency_ms for s in snapshots),
            error_rate=max(s.error_rate for s in snapshots),
            throughput=min(s.throughput for s in snapshots),
            active_sessions=max(s.active_sessions for s in snapshots),
            metrics=merged,
        )
