"""Détection de dégradation subie (EF-21 a EF-23).

Produit un `DetectionEvent` de catégorie `infrastructure_degradation` quand
une cible sort de ses seuils de service. Ces événements empruntent la même
chaîne que les alertes de sécurité : l'indisponibilité est traitée comme un
incident a part entière, ce qui est le sens de l'Axe 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...domain.enums import Severity, SourceKind
from ...domain.events import Asset, DetectionEvent
from .health import HealthProbe, HealthSnapshot


@dataclass(frozen=True, slots=True)
class ServiceThresholds:
    """Seuils de service par cible. Renseignes par l'administrateur."""

    max_latency_ms: float = 1000.0
    max_error_rate: float = 0.05
    min_throughput: float = 0.0
    criticality: int = 3

    def breaches(self, snapshot: HealthSnapshot) -> list[str]:
        problems: list[str] = []
        if not snapshot.reachable:
            problems.append("cible injoignable")
        if snapshot.latency_ms > self.max_latency_ms:
            problems.append(
                f"latence {snapshot.latency_ms:.0f} ms > seuil {self.max_latency_ms:.0f} ms"
            )
        if snapshot.error_rate > self.max_error_rate:
            problems.append(
                f"taux d'erreur {snapshot.error_rate:.1%} > seuil {self.max_error_rate:.1%}"
            )
        if self.min_throughput and snapshot.throughput < self.min_throughput:
            problems.append(f"débit {snapshot.throughput:.1f} < seuil {self.min_throughput:.1f}")
        return problems


class InfrastructureMonitor:
    def __init__(
        self,
        probe: HealthProbe,
        thresholds: dict[str, ServiceThresholds] | None = None,
        default_thresholds: ServiceThresholds | None = None,
    ) -> None:
        self._probe = probe
        self._thresholds = thresholds or {}
        self._default = default_thresholds or ServiceThresholds()

    def thresholds_for(self, target: str) -> ServiceThresholds:
        return self._thresholds.get(target, self._default)

    def check(self, target: str) -> DetectionEvent | None:
        snapshot = self._probe.measure(target)
        thresholds = self.thresholds_for(target)
        problems = thresholds.breaches(snapshot)
        if not problems:
            return None
        return DetectionEvent(
            occurred_at=snapshot.taken_at,
            source=SourceKind.INFRASTRUCTURE,
            source_product="cirtdefense-monitor",
            category="infrastructure_degradation",
            severity=_severity_for(snapshot, thresholds),
            confidence=0.9,  # une mesure directe, pas une inférence
            asset=Asset(asset_id=target, hostname=target, criticality=thresholds.criticality),
            title=f"Dégradation de service sur {target}",
            description="; ".join(problems),
            indicators={"health": snapshot.to_dict(), "breaches": problems},
            raw=snapshot.to_dict(),
        )

    def sweep(self, targets: list[str]) -> list[DetectionEvent]:
        return [e for e in (self.check(t) for t in targets) if e is not None]

    def register(self, target: str, thresholds: ServiceThresholds) -> None:
        self._thresholds[target] = thresholds

    def describe(self) -> dict[str, Any]:
        return {
            "probe": self._probe.name,
            "targets": sorted(self._thresholds),
            "default_thresholds": {
                "max_latency_ms": self._default.max_latency_ms,
                "max_error_rate": self._default.max_error_rate,
                "min_throughput": self._default.min_throughput,
            },
        }


def _severity_for(snapshot: HealthSnapshot, thresholds: ServiceThresholds) -> Severity:
    if not snapshot.reachable:
        return Severity.CRITICAL if thresholds.criticality >= 4 else Severity.HIGH
    if snapshot.error_rate > thresholds.max_error_rate * 4:
        return Severity.HIGH
    return Severity.MEDIUM
