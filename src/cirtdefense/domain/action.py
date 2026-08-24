"""Actions correctives : specification, resultat, catalogue de reversibilite.

En v3.0 une action n'est plus une *proposition* soumise a l'analyste (EF-13
ancienne version) mais un ordre que le moteur execute lui-meme. Le garde-fou
n'est donc plus humain : il est porte par les invariants de ce module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .enums import ActionStatus, Reversibility


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass(frozen=True, slots=True)
class ActionSpec:
    """Description declarative d'une action executable par un actuateur.

    `rollback_verb` est obligatoire des lors que l'action se dit reversible :
    c'est la contrepartie technique de l'autonomie totale (CDCF 1.4.3).
    """

    verb: str
    """Identifiant du geste : block_ip, isolate_host, disable_account..."""
    actuator: str
    """Nom du connecteur qui sait executer ce verbe : firewall, edr, iam..."""
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    reversibility: Reversibility = Reversibility.IRREVERSIBLE
    rollback_verb: str | None = None
    blast_radius: int = 1
    """Nombre approximatif d'entites impactees. Sert a la politique (EF-15)."""
    expected_effect: str = ""
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.reversibility is not Reversibility.IRREVERSIBLE and not self.rollback_verb:
            raise ValueError(
                f"action '{self.verb}' declaree {self.reversibility.value} "
                "sans rollback_verb : le rollback autonome (EF-25) serait impossible"
            )
        if self.blast_radius < 1:
            raise ValueError("blast_radius doit valoir au moins 1")

    @property
    def key(self) -> str:
        return f"{self.actuator}:{self.verb}"


@dataclass(slots=True)
class ActionResult:
    """Trace d'execution d'une ActionSpec. Muable : son statut evolue."""

    action_id: str = field(default_factory=lambda: _new_id("act"))
    spec: ActionSpec | None = None
    incident_id: str = ""
    decision_id: str = ""
    status: ActionStatus = ActionStatus.PLANNED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    rollback_token: str | None = None
    """Jeton rendu par l'actuateur, nécessaire pour annuler precisement."""
    rolled_back_at: datetime | None = None
    rollback_reason: str | None = None
    rollback_actor: str = ""

    @property
    def duration_ms(self) -> int | None:
        if not self.started_at or not self.finished_at:
            return None
        return int((self.finished_at - self.started_at).total_seconds() * 1000)

    @property
    def is_reversible(self) -> bool:
        return (
            self.spec is not None
            and self.spec.reversibility is not Reversibility.IRREVERSIBLE
            and self.rollback_token is not None
        )

    def mark_started(self) -> None:
        self.status = ActionStatus.EXECUTING
        self.started_at = datetime.now(UTC)

    def mark_executed(self, output: dict[str, Any], rollback_token: str | None) -> None:
        self.status = ActionStatus.EXECUTED
        self.finished_at = datetime.now(UTC)
        self.output = output
        self.rollback_token = rollback_token

    def mark_failed(self, error: str) -> None:
        self.status = ActionStatus.FAILED
        self.finished_at = datetime.now(UTC)
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "decision_id": self.decision_id,
            "verb": self.spec.verb if self.spec else None,
            "actuator": self.spec.actuator if self.spec else None,
            "target": self.spec.target if self.spec else None,
            "parameters": self.spec.parameters if self.spec else {},
            "reversibility": self.spec.reversibility.value if self.spec else None,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": self.duration_ms,
            "output": self.output,
            "error": self.error,
            "rollback_token": self.rollback_token,
            "rolled_back_at": self.rolled_back_at.isoformat() if self.rolled_back_at else None,
            "rollback_reason": self.rollback_reason,
            "rollback_actor": self.rollback_actor,
        }
