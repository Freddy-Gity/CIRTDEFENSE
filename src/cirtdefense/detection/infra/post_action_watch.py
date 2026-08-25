"""Boucle de contrôle fermée post-action (EF-25).

C'est la contrepartie technique de l'abandon de la validation humaine
préalable : puisque personne ne relit l'action avant, le système doit relire
son propre effet après. Le principe est celui d'un `commit` à l'essai —
l'action est confirmée seulement si la cible ne s'est pas dégradée.

Point de methode important : la comparaison se fait contre une mesure prise
*avant* l'action. Sans cette référence, on attribuerait à notre action une
dégradation causee par l'attaque elle-même, et le système annulerait
précisément les confinements qui fonctionnent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ...logging_setup import log_with
from .health import HealthProbe, HealthSnapshot

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DegradationThresholds:
    """Écarts au-delà desquels l'action est jugee nuisible.

    Les valeurs sont relatives à l'état d'avant : ce qui compte n'est pas la
    valeur absolue de la latence mais le fait que *nous* l'ayons aggravee.
    """

    latency_increase_factor: float = 2.0
    error_rate_increase: float = 0.15
    throughput_drop_ratio: float = 0.5
    reachability_loss_is_fatal: bool = True


@dataclass(slots=True)
class WatchVerdict:
    target: str
    degraded: bool
    reasons: list[str] = field(default_factory=list)
    before: HealthSnapshot | None = None
    after: HealthSnapshot | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    latency_seconds: float = 0.0
    """Délai ecoule entre l'action et le verdict — borne par le CR de
    non-régression securitaire (CDCF 5.3)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "degraded": self.degraded,
            "reasons": self.reasons,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "observed_at": self.observed_at.isoformat(),
            "latency_seconds": round(self.latency_seconds, 3),
        }


class PostActionWatcher:
    """Retient l'état d'avant, puis juge l'état d'après."""

    def __init__(
        self,
        probe: HealthProbe,
        thresholds: DegradationThresholds | None = None,
    ) -> None:
        self._probe = probe
        self._thresholds = thresholds or DegradationThresholds()
        self._baselines: dict[str, tuple[HealthSnapshot, datetime]] = {}

    def capture_baseline(self, action_id: str, target: str) -> HealthSnapshot:
        """à appeler juste avant l'exécution, jamais après."""
        snapshot = self._probe.measure(target)
        self._baselines[action_id] = (snapshot, datetime.now(UTC))
        return snapshot

    def has_baseline(self, action_id: str) -> bool:
        return action_id in self._baselines

    def evaluate(self, action_id: str, target: str | None = None) -> WatchVerdict:
        """Juge l'état d'après.

        La cible est celle sur laquelle la référence a été prise, et non celle
        que l'appelant croit surveiller. Une première version acceptait la
        cible de l'appelant : la référence était alors mesuree sur la machine
        (`srv-web-01`) et la mesure d'après sur la cible de l'action
        (`41.202.1.9`, `jdupont`), deux grandeurs sans rapport. La comparaison
        rendait « dégrade » a peu pres à chaque fois, et le système annulait
        des actions parfaitement saines.
        """
        entry = self._baselines.get(action_id)
        if entry is None:
            # Sans référence, on ne peut pas imputer une dégradation a
            # l'action. On s'abstient plutôt que d'annuler a tort un
            # confinement qui protege peut-être la cible.
            log_with(
                logger,
                logging.WARNING,
                "verdict post-action impossible : aucune mesure de référence",
                action_id=action_id,
                target=target,
            )
            return WatchVerdict(
                target=target or "?",
                degraded=False,
                reasons=["aucune mesure de référence prise avant l'action"],
            )

        before, captured_at = entry
        watched = before.target
        if target is not None and target != watched:
            log_with(
                logger,
                logging.WARNING,
                "cible d'évaluation differente de la cible de référence : "
                "la cible de référence fait foi",
                action_id=action_id,
                requested=target,
                watched=watched,
            )
        after = self._probe.measure(watched)
        reasons = self._compare(before, after)
        verdict = WatchVerdict(
            target=watched,
            degraded=bool(reasons),
            reasons=reasons,
            before=before,
            after=after,
            latency_seconds=(datetime.now(UTC) - captured_at).total_seconds(),
        )
        if verdict.degraded:
            log_with(
                logger,
                logging.ERROR,
                "dégradation imputee à une action autonome",
                action_id=action_id,
                target=watched,
                reasons=reasons,
            )
        return verdict

    def release(self, action_id: str) -> None:
        """Libere la référence une fois la boucle refermee."""
        self._baselines.pop(action_id, None)

    def _compare(self, before: HealthSnapshot, after: HealthSnapshot) -> list[str]:
        reasons: list[str] = []
        t = self._thresholds

        if t.reachability_loss_is_fatal and before.reachable and not after.reachable:
            reasons.append("la cible était joignable avant l'action et ne l'est plus")

        if (
            before.latency_ms > 0
            and after.latency_ms > before.latency_ms * t.latency_increase_factor
        ):
            reasons.append(
                f"latence multipliee par {after.latency_ms / before.latency_ms:.1f} "
                f"({before.latency_ms:.0f} ms -> {after.latency_ms:.0f} ms)"
            )

        if after.error_rate - before.error_rate > t.error_rate_increase:
            reasons.append(
                f"taux d'erreur en hausse de {(after.error_rate - before.error_rate):.1%} "
                f"({before.error_rate:.1%} -> {after.error_rate:.1%})"
            )

        if before.throughput > 0 and after.throughput < before.throughput * t.throughput_drop_ratio:
            reasons.append(
                f"débit divise par {before.throughput / max(after.throughput, 0.01):.1f} "
                f"({before.throughput:.1f} -> {after.throughput:.1f})"
            )
        return reasons
