"""Scoreur UEBA : transforme un écart au profil en `DetectionEvent` (EF-09/EF-10).

Deux garde-fous, directement lies a l'autonomie totale :
- une entité sans profil etabli ne produit jamais d'alerte (on ne qualifie pas
  d'anormal ce qu'on n'a jamais observe) ;
- le score est accompagne des attributs qui l'ont produit, pour que l'action
  qui en decoulera reste explicable a posteriori.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...domain.enums import Severity, SourceKind
from ...domain.events import Asset, DetectionEvent
from .baseline import BaselineStore
from .features import BehaviourFeatures, entity_of, extract, summarize

ALERT_THRESHOLD = 3.0
"""Écart-type cumule au-delà duquel un comportement est signalé."""

_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (8.0, Severity.CRITICAL),
    (6.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)


@dataclass(slots=True)
class AnomalyScore:
    entity: str
    score: float
    contributions: dict[str, float]
    established: bool
    features: BehaviourFeatures

    @property
    def is_anomalous(self) -> bool:
        return self.established and self.score >= ALERT_THRESHOLD

    @property
    def severity(self) -> Severity:
        for threshold, severity in _SEVERITY_BANDS:
            if self.score >= threshold:
                return severity
        return Severity.LOW

    @property
    def confidence(self) -> float:
        """Croit avec le score mais reste plafonnee : l'UEBA propose une
        presomption, jamais une certitude."""
        return round(min(0.85, 0.35 + (self.score - ALERT_THRESHOLD) * 0.06), 2)

    def explain(self) -> list[str]:
        ordered = sorted(self.contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)
        return [
            f"{name} s'écarte de {deviation:+.1f} écart-type du profil habituel"
            for name, deviation in ordered[:4]
            if abs(deviation) >= 1.0
        ]


class UebaScorer:
    def __init__(self, store: BaselineStore) -> None:
        self._store = store

    def score(self, entity: str, events: list[DetectionEvent]) -> AnomalyScore:
        features = extract(entity, events)
        baseline = self._store.get(entity)
        deviations = baseline.deviations(features)
        # Seuls les ecarts positifs comptent : un utilisateur moins actif que
        # d'habitude n'est pas une menace.
        total = sum(max(0.0, d) for d in deviations.values())
        return AnomalyScore(
            entity=entity,
            score=round(total, 2),
            contributions=deviations,
            established=baseline.is_established,
            features=features,
        )

    def learn(self, entity: str, events: list[DetectionEvent]) -> None:
        self._store.get(entity).learn(extract(entity, events))

    def evaluate(self, events: list[DetectionEvent]) -> DetectionEvent | None:
        """Produit un événement UEBA si le lot observe sort du profil.

        Le profil est mis à jour *seulement* quand le comportement est juge
        normal : sinon une attaque prolongee deviendrait progressivement la
        nouvelle référence de l'entité (empoisonnement de la ligne de base).
        """
        if not events:
            return None
        entity = entity_of(events[0])
        result = self.score(entity, events)

        if not result.is_anomalous:
            self.learn(entity, events)
            return None

        reference = events[-1]
        explanation = result.explain()
        return DetectionEvent(
            occurred_at=reference.occurred_at,
            source=SourceKind.UEBA,
            source_product="cirtdefense-ueba",
            category="behaviour_anomaly",
            severity=result.severity,
            confidence=result.confidence,
            asset=Asset(
                asset_id=reference.asset.asset_id,
                hostname=reference.asset.hostname,
                ip=reference.asset.ip,
                user=reference.asset.user,
                criticality=reference.asset.criticality,
                zone=reference.asset.zone,
            ),
            title=f"Comportement inhabituel de {entity} (score {result.score})",
            description="; ".join(explanation) or "Écart global au profil de référence",
            indicators={
                "ueba_score": result.score,
                "ueba_threshold": ALERT_THRESHOLD,
                "contributions": {k: round(v, 2) for k, v in result.contributions.items()},
                "observations": self._store.get(entity).observations,
            },
            raw={"ueba_features": summarize(result.features)},
            site_id=reference.site_id,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "entities": len(self._store.all()),
            "established": sum(1 for b in self._store.all().values() if b.is_established),
            "threshold": ALERT_THRESHOLD,
        }
