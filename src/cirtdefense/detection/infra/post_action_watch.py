"""Boucle de controle fermee post-action (EF-25).

C'est la contrepartie technique de l'abandon de la validation humaine
prealable : puisque personne ne relit l'action avant, le systeme doit relire
son propre effet apres. Le principe est celui d'un `commit` a l'essai —
l'action est confirmee seulement si la cible ne s'est pas degradee.

Point de methode important : la comparaison se fait contre une mesure prise
*avant* l'action. Sans cette reference, on attribuerait a notre action une
degradation causee par l'attaque elle-meme, et le systeme annulerait
precisement les confinements qui fonctionnent.
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
    """Ecarts au-dela desquels l'action est jugee nuisible.

    Les valeurs sont relatives a l'etat d'avant : ce qui compte n'est pas la
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
    """Delai ecoule entre l'action et le verdict — borne par le CR de
    non-regression securitaire (CDCF 5.3)."""

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
    """Retient l'etat d'avant, puis juge l'etat d'apres."""

    def __init__(
        self,
        probe: HealthProbe,
        thresholds: DegradationThresholds | None = None,
    ) -> None:
        self._probe = probe
        self._thresholds = thresholds or DegradationThresholds()
        self._baselines: dict[str, tuple[HealthSnapshot, datetime]] = {}

    def capture_baseline(self, action_id: str, target: str) -> HealthSnapshot:
        """A appeler juste avant l'execution, jamais apres."""
        snapshot = self._probe.measure(target)
        self._baselines[action_id] = (snapshot, datetime.now(UTC))
        return snapshot

    def has_baseline(self, action_id: str) -> bool:
        return action_id in self._baselines

    def evaluate(self, action_id: str, target: str | None = None) -> WatchVerdict:
        """Juge l'etat d'apres.

        La cible est celle sur laquelle la reference a ete prise, et non celle
        que l'appelant croit surveiller. Une premiere version acceptait la
        cible de l'appelant : la reference etait alors mesuree sur la machine
        (`srv-web-01`) et la mesure d'apres sur la cible de l'action
        (`41.202.1.9`, `jdupont`), deux grandeurs sans rapport. La comparaison
        rendait « degrade » a peu pres a chaque fois, et le systeme annulait
        des actions parfaitement saines.
        """
        entry = self._baselines.get(action_id)
        if entry is None:
            # Sans reference, on ne peut pas imputer une degradation a
            # l'action. On s'abstient plutot que d'annuler a tort un
            # confinement qui protege peut-etre la cible.
            log_with(
                logger,
                logging.WARNING,
                "verdict post-action impossible : aucune mesure de reference",
                action_id=action_id,
                target=target,
            )
            return WatchVerdict(
                target=target or "?",
                degraded=False,
                reasons=["aucune mesure de reference prise avant l'action"],
            )

        before, captured_at = entry
        watched = before.target
        if target is not None and target != watched:
            log_with(
                logger,
                logging.WARNING,
                "cible d'evaluation differente de la cible de reference : "
                "la cible de reference fait foi",
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
                "degradation imputee a une action autonome",
                action_id=action_id,
                target=watched,
                reasons=reasons,
            )
        return verdict

    def release(self, action_id: str) -> None:
        """Libere la reference une fois la boucle refermee."""
        self._baselines.pop(action_id, None)

    def _compare(self, before: HealthSnapshot, after: HealthSnapshot) -> list[str]:
        reasons: list[str] = []
        t = self._thresholds

        if t.reachability_loss_is_fatal and before.reachable and not after.reachable:
            reasons.append("la cible etait joignable avant l'action et ne l'est plus")

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
                f"debit divise par {before.throughput / max(after.throughput, 0.01):.1f} "
                f"({before.throughput:.1f} -> {after.throughput:.1f})"
            )
        return reasons
