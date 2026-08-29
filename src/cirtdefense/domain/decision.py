"""Décision du moteur d'orchestration et sa trace explicative.

L'autonomie totale supprime le point de contrôle humain *avant* l'action.
La contrepartie exigee par le CDCF 1.4.3 est que chaque décision porte, en
elle-même, de quoi être rejugee après coup : contexte source, règles de
politique appliquées, alternatives écartées.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .action import ActionSpec
from .enums import DecisionOutcome


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass(slots=True)
class PolicyVerdict:
    """Résultat de l'évaluation d'une action face à la politique compilée."""

    allowed: bool
    rule_id: str | None = None
    rule_text: str | None = None
    reason: str = ""


@dataclass(slots=True)
class DecisionTrace:
    """Le « pourquoi » d'une décision, lisible par un humain non technicien."""

    playbook_id: str = ""
    playbook_version: str = ""
    matched_conditions: list[str] = field(default_factory=list)
    grounding_score: float = 0.0
    context_sources: list[str] = field(default_factory=list)
    """Chemins ou identifiants des documents ayant fondé la décision (EF-04)."""
    considered_actions: list[str] = field(default_factory=list)
    rejected_actions: list[dict[str, str]] = field(default_factory=list)
    policy_verdicts: list[dict[str, Any]] = field(default_factory=list)
    engine_version: str = "3.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "playbook_version": self.playbook_version,
            "matched_conditions": self.matched_conditions,
            "grounding_score": self.grounding_score,
            "context_sources": self.context_sources,
            "considered_actions": self.considered_actions,
            "rejected_actions": self.rejected_actions,
            "policy_verdicts": self.policy_verdicts,
            "engine_version": self.engine_version,
        }


@dataclass(slots=True)
class Decision:
    decision_id: str = field(default_factory=lambda: _new_id("dec"))
    incident_id: str = ""
    event_id: str = ""
    outcome: DecisionOutcome = DecisionOutcome.NO_ACTION_NEEDED
    actions: list[ActionSpec] = field(default_factory=list)
    trace: DecisionTrace = field(default_factory=DecisionTrace)
    rationale: str = ""
    decided_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    classification: dict[str, Any] = field(default_factory=dict)
    """Qualification au catalogue CIRT : type, famille, criticité, dangerosité."""
    fallback: dict[str, Any] = field(default_factory=dict)
    """Plan de repli, quand la menace n'est pas catalogüée : les gestes déduits
    des indicateurs observés, et ceux qui attendent une confirmation humaine."""

    @property
    def is_actionable(self) -> bool:
        return self.outcome is DecisionOutcome.AUTONOMOUS_EXECUTION and bool(self.actions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "incident_id": self.incident_id,
            "event_id": self.event_id,
            "outcome": self.outcome.value,
            "rationale": self.rationale,
            "decided_at": self.decided_at.isoformat(),
            "classification": self.classification,
            "fallback": self.fallback,
            "actions": [
                {
                    "verb": a.verb,
                    "actuator": a.actuator,
                    "target": a.target,
                    "parameters": a.parameters,
                    "reversibility": a.reversibility.value,
                    "rollback_verb": a.rollback_verb,
                    "blast_radius": a.blast_radius,
                }
                for a in self.actions
            ],
            "trace": self.trace.to_dict(),
        }
