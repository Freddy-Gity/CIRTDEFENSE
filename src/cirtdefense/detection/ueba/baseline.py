"""Profil de reference par entite : moyenne et ecart-type glissants.

Un modele statistique simple est retenu a dessein. Il est reproductible d'une
execution a l'autre, ce qu'un modele reentraine en continu ne garantit pas —
propriete indispensable pour rejuger une action apres coup.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .features import BehaviourFeatures

MIN_OBSERVATIONS = 7
"""En deca, l'entite est declaree « sans reference » : le scoreur s'abstient
plutot que de qualifier d'anormal ce qu'il n'a simplement jamais vu."""


@dataclass(slots=True)
class RunningStat:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        """Algorithme de Welford : une seule passe, pas d'historique conserve."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def stddev(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))

    def zscore(self, value: float) -> float:
        deviation = self.stddev
        if deviation == 0:
            # Sans dispersion, tout ecart non nul est signale, mais avec une
            # amplitude bornee pour ne pas saturer le score sur du bruit.
            return 0.0 if value == self.mean else min(abs(value - self.mean), 3.0)
        return (value - self.mean) / deviation

    def to_dict(self) -> dict[str, float]:
        return {"count": self.count, "mean": self.mean, "m2": self.m2}


@dataclass(slots=True)
class EntityBaseline:
    entity: str
    stats: dict[str, RunningStat] = field(default_factory=dict)
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def observations(self) -> int:
        return max((s.count for s in self.stats.values()), default=0)

    @property
    def is_established(self) -> bool:
        return self.observations >= MIN_OBSERVATIONS

    def learn(self, features: BehaviourFeatures) -> None:
        for name, value in features.as_vector().items():
            self.stats.setdefault(name, RunningStat()).update(value)
        self.updated_at = datetime.now(UTC)

    def deviations(self, features: BehaviourFeatures) -> dict[str, float]:
        return {
            name: self.stats[name].zscore(value)
            for name, value in features.as_vector().items()
            if name in self.stats
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "observations": self.observations,
            "established": self.is_established,
            "updated_at": self.updated_at.isoformat(),
            "stats": {k: v.to_dict() for k, v in self.stats.items()},
        }


class BaselineStore:
    """Stockage fichier des profils. Suffisant a l'echelle d'un CIRT national
    sur le perimetre du projet, et trivialement inspectable pendant la recette."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._baselines: dict[str, EntityBaseline] = {}
        self._load()

    def get(self, entity: str) -> EntityBaseline:
        return self._baselines.setdefault(entity, EntityBaseline(entity=entity))

    def all(self) -> dict[str, EntityBaseline]:
        return dict(self._baselines)

    def _load(self) -> None:
        if not self._path.exists():
            return
        data = json.loads(self._path.read_text())
        for entity, payload in data.items():
            baseline = EntityBaseline(
                entity=entity,
                updated_at=datetime.fromisoformat(payload["updated_at"]),
            )
            for name, stat in payload.get("stats", {}).items():
                baseline.stats[name] = RunningStat(**stat)
            self._baselines[entity] = baseline

    def persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {e: b.to_dict() for e, b in self._baselines.items()}
        self._path.write_text(json.dumps(payload, indent=2, default=str))
