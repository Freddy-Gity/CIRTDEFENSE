"""Vocabulaire ferme du domaine.

Les valeurs sont serialisees telles quelles dans le journal d'audit : elles
font partie du contrat de tracabilite et ne doivent pas etre renommees sans
une entree d'historique de version (CDCF 7.3).
"""

from enum import StrEnum


class Severity(StrEnum):
    """Gravite d'un evenement de detection, echelle normalisee de l'adaptateur."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class SourceKind(StrEnum):
    """Origine d'un DetectionEvent (CDCF 3.2)."""

    UEBA = "ueba"
    INFRASTRUCTURE = "infrastructure"
    EDR = "edr"
    NIDS = "nids"
    SIEM = "siem"
    MANUAL = "manual"
    REPLAY = "replay"


class Reversibility(StrEnum):
    """Catalogue de reversibilite (EF-14).

    En v3.0 cette metadonnee n'est plus un simple support de priorisation :
    c'est la condition operationnelle qui autorise le moteur a agir seul.
    """

    REVERSIBLE = "reversible"
    """Annulation automatique complete, sans perte d'etat."""

    PARTIALLY_REVERSIBLE = "partially_reversible"
    """Annulation automatique possible mais avec effet residuel (session coupee...)."""

    IRREVERSIBLE = "irreversible"
    """Aucun retour arriere automatique (effacement, reinitialisation materielle)."""


class ActionStatus(StrEnum):
    PLANNED = "planned"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_BY_BREAKER = "blocked_by_breaker"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class IncidentStatus(StrEnum):
    OPEN = "open"
    CONTAINED = "contained"
    ROLLED_BACK = "rolled_back"
    CLOSED = "closed"


class DecisionOutcome(StrEnum):
    """Issue du moteur d'orchestration pour un evenement donne."""

    AUTONOMOUS_EXECUTION = "autonomous_execution"
    NO_ACTION_NEEDED = "no_action_needed"
    NO_GROUNDED_CONTEXT = "no_grounded_context"
    POLICY_DENIED = "policy_denied"
    BREAKER_OPEN = "breaker_open"
    OUT_OF_CATALOG = "out_of_catalog"


class AuditEventType(StrEnum):
    EVENT_INGESTED = "event.ingested"
    CONTEXT_ENRICHED = "context.enriched"
    DECISION_MADE = "decision.made"
    ACTION_EXECUTED = "action.executed"
    ACTION_FAILED = "action.failed"
    ROLLBACK_TRIGGERED = "rollback.triggered"
    ROLLBACK_COMPLETED = "rollback.completed"
    ROLLBACK_FAILED = "rollback.failed"
    ANALYST_NOTIFIED = "analyst.notified"
    MANUAL_ROLLBACK = "manual.rollback"
    BREAKER_TRIPPED = "breaker.tripped"
    BREAKER_RESET = "breaker.reset"
    POLICY_COMPILED = "policy.compiled"
    DEGRADED_ENTER = "degraded.enter"
    DEGRADED_REPLAY = "degraded.replay"
