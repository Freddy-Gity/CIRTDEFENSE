"""Incident : agregat de correlation et unité de priorisation (Axe 4).

Un incident regroupe les événements qui portent sur la même cible et la même
famille de menace dans une fenêtre de temps. C'est l'objet que le décideur
consulte dans le portefeuille, et celui auquel toutes les actions sont
rattachées pour la traçabilité.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .action import ActionResult
from .enums import ActionStatus, IncidentStatus, Severity
from .events import DetectionEvent

CORRELATION_WINDOW = timedelta(minutes=15)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass(slots=True)
class Incident:
    incident_id: str = field(default_factory=lambda: _new_id("inc"))
    correlation_key: str = ""
    category: str = "unknown"
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    opened_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    closed_at: datetime | None = None
    events: list[DetectionEvent] = field(default_factory=list)
    actions: list[ActionResult] = field(default_factory=list)
    asset_criticality: int = 3
    site_id: str = "cirt-cm-01"
    labels: dict[str, Any] = field(default_factory=dict)

    # Classification au catalogue CIRT (voir domain/taxonomy.py). Renseignee
    # par le moteur des la premiere qualification de l'incident.
    attack_code: str = ""
    attack_label: str = ""
    family: str = ""
    family_label: str = ""
    dangerousness: float = 0.0
    priority: str = ""
    priority_rank: int = 0

    @classmethod
    def from_event(cls, event: DetectionEvent) -> Incident:
        return cls(
            correlation_key=cls.key_for(event),
            category=event.category,
            severity=event.severity,
            opened_at=event.received_at,
            updated_at=event.received_at,
            events=[event],
            asset_criticality=event.asset.criticality,
            site_id=event.site_id,
        )

    @staticmethod
    def key_for(event: DetectionEvent) -> str:
        return f"{event.category}::{event.asset.correlation_key()}"

    def accepts(self, event: DetectionEvent, now: datetime | None = None) -> bool:
        """Un événement rejoint l'incident s'il partage la clé et la fenêtre."""
        if self.status in (IncidentStatus.CLOSED, IncidentStatus.ROLLED_BACK):
            return False
        if self.key_for(event) != self.correlation_key:
            return False
        reference = now or datetime.now(UTC)
        return reference - self.updated_at <= CORRELATION_WINDOW

    def absorb(self, event: DetectionEvent) -> None:
        self.events.append(event)
        self.updated_at = event.received_at
        if event.severity > self.severity:
            self.severity = event.severity
        self.asset_criticality = max(self.asset_criticality, event.asset.criticality)

    # -- Axe 4 : priorisation du portefeuille ------------------------------

    def risk_score(self, now: datetime | None = None) -> float:
        """Score 0-100 arbitrant l'ordre de traitement (Axe 4).

        Volontairement déterministe et explicable : le décideur doit pouvoir
        justifier l'ordre du portefeuille sans lire les poids d'un modèle.

        Six composantes, dont deux issues du catalogue CIRT quand l'incident a
        été classifie. La priorité du catalogue et la dangerosité y ont un
        poids deliberement fort : c'est le document métier qui arbitre l'ordre,
        pas la seule gravité remontee par la source.
        """
        reference = now or datetime.now(UTC)
        severity_part = self.severity.rank / 4 * 30
        criticality_part = (self.asset_criticality - 1) / 4 * 20
        volume_part = min(len(self.events), 10) / 10 * 10
        mean_confidence = (
            sum(e.confidence for e in self.events) / len(self.events) if self.events else 0.0
        )
        confidence_part = mean_confidence * 5
        age_minutes = max((reference - self.updated_at).total_seconds() / 60, 0)
        freshness_part = max(0.0, 1 - age_minutes / 120) * 5

        # Sans classification, ces deux parts valent zero : un incident non
        # qualifie ne doit pas passer devant un incident qualifie critique.
        priority_part = self.priority_rank / 4 * 20
        danger_part = self.dangerousness / 10 * 10

        return round(
            severity_part
            + criticality_part
            + volume_part
            + confidence_part
            + freshness_part
            + priority_part
            + danger_part,
            2,
        )

    def apply_classification(self, classification: Any) -> None:
        """Rattache la qualification du catalogue a l'incident."""
        self.attack_code = classification.code
        self.attack_label = classification.label
        self.family = classification.family.value if classification.family else ""
        self.family_label = classification.family.label if classification.family else ""
        # Arrondi a la source : la valeur est affichee, comparee et exportee
        # en rapport ; un bruit de virgule flottante y serait visible.
        self.dangerousness = round(classification.dangerousness, 1)
        self.priority = classification.priority.value
        self.priority_rank = classification.priority.rank
        if classification.severity > self.severity:
            self.severity = classification.severity

    @property
    def executed_actions(self) -> list[ActionResult]:
        return [a for a in self.actions if a.status is ActionStatus.EXECUTED]

    @property
    def has_active_containment(self) -> bool:
        return any(a.status is ActionStatus.EXECUTED for a in self.actions)

    def register_action(self, result: ActionResult) -> None:
        result.incident_id = self.incident_id
        self.actions.append(result)
        self.updated_at = datetime.now(UTC)
        if result.status is ActionStatus.EXECUTED:
            self.status = IncidentStatus.CONTAINED
        elif result.status is ActionStatus.ROLLED_BACK and not self.has_active_containment:
            self.status = IncidentStatus.ROLLED_BACK

    def close(self) -> None:
        self.status = IncidentStatus.CLOSED
        self.closed_at = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "correlation_key": self.correlation_key,
            "category": self.category,
            "severity": self.severity.value,
            "status": self.status.value,
            "risk_score": self.risk_score(),
            "opened_at": self.opened_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "event_count": len(self.events),
            "asset_criticality": self.asset_criticality,
            "site_id": self.site_id,
            "actions": [a.to_dict() for a in self.actions],
            "labels": self.labels,
            "attack_code": self.attack_code,
            "attack_label": self.attack_label,
            "family": self.family,
            "family_label": self.family_label,
            "dangerousness": self.dangerousness,
            "priority": self.priority,
            "priority_rank": self.priority_rank,
        }
