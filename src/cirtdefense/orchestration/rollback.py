"""Annulation d'action : autonome (EF-25) et manuelle a posteriori (Analyste).

EF-25 ferme la boucle : la surveillance observe la cible apres l'action et,
si l'etat s'est degrade par rapport a la mesure prise avant, l'action est
annulee sans intervention humaine.

Le delai d'annulation est **borne et mesure**. C'est l'objet du critere de
recette de non-regression securitaire (CDCF §5.3) : demontrer qu'une action
erronee est detectee et annulee dans un delai connu. Un rollback qui
fonctionne mais dont personne ne sait combien de temps il prend ne prouve rien.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..actuators.base import ActuatorRegistry
from ..audit.ledger import AuditLedger
from ..detection.infra.post_action_watch import PostActionWatcher, WatchVerdict
from ..domain.action import ActionResult
from ..domain.enums import ActionStatus, AuditEventType
from ..logging_setup import log_with
from ..persistence.repositories import ActionRepository
from .reversibility import ReversibilityCatalog, get_catalog

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RollbackOutcome:
    action_id: str
    success: bool
    reason: str
    actor: str
    latency_seconds: float = 0.0
    within_bound: bool = True
    """Faux si l'annulation a depasse le delai maximal admis pour cette action."""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "success": self.success,
            "reason": self.reason,
            "actor": self.actor,
            "latency_seconds": round(self.latency_seconds, 3),
            "within_bound": self.within_bound,
            "detail": self.detail,
        }


@dataclass(slots=True)
class ControlLoopReport:
    """Bilan d'un passage de la boucle de controle."""

    checked: int = 0
    degraded: int = 0
    rolled_back: int = 0
    rollback_failures: int = 0
    outcomes: list[RollbackOutcome] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "degraded": self.degraded,
            "rolled_back": self.rolled_back,
            "rollback_failures": self.rollback_failures,
            "outcomes": [o.to_dict() for o in self.outcomes],
            "verdicts": self.verdicts,
        }


class RollbackService:
    def __init__(
        self,
        registry: ActuatorRegistry,
        actions: ActionRepository,
        ledger: AuditLedger,
        watcher: PostActionWatcher,
        catalog: ReversibilityCatalog | None = None,
        *,
        max_latency_seconds: int = 180,
    ) -> None:
        self._registry = registry
        self._actions = actions
        self._ledger = ledger
        self._watcher = watcher
        self._catalog = catalog or get_catalog()
        self._max_latency = max_latency_seconds

    # -- EF-25 : boucle de controle fermee ---------------------------------

    def run_control_loop(self, results: list[ActionResult] | None = None) -> ControlLoopReport:
        """Examine les actions executees et annule celles qui ont nui.

        Sans argument, la boucle balaye les actions reversibles encore
        actives : c'est le mode d'appel du planificateur periodique.
        """
        report = ControlLoopReport()
        candidates = results if results is not None else self._actions.executed_reversible()

        for result in candidates:
            if result.status is not ActionStatus.EXECUTED or result.spec is None:
                continue
            if not self._watcher.has_baseline(result.action_id):
                # Sans reference, la boucle s'abstient : voir PostActionWatcher.
                continue

            report.checked += 1
            # La cible surveillee est celle de la mesure de reference, pas la
            # cible de l'action : bloquer une adresse se mesure sur la sante du
            # service protege, pas sur celle de l'adresse bloquee.
            verdict = self._watcher.evaluate(result.action_id)
            report.verdicts.append(verdict.to_dict())
            if not verdict.degraded:
                self._watcher.release(result.action_id)
                continue

            report.degraded += 1
            outcome = self.rollback(
                result,
                reason=self._format_reason(verdict),
                actor="system:control-loop",
                audit_type=AuditEventType.ROLLBACK_TRIGGERED,
            )
            report.outcomes.append(outcome)
            if outcome.success:
                report.rolled_back += 1
            else:
                report.rollback_failures += 1
        return report

    # -- annulation unitaire, autonome ou manuelle -------------------------

    def rollback(
        self,
        result: ActionResult,
        reason: str,
        actor: str,
        audit_type: AuditEventType = AuditEventType.MANUAL_ROLLBACK,
    ) -> RollbackOutcome:
        started = datetime.now(UTC)

        if result.spec is None:
            return self._refuse(result, "action sans specification : annulation impossible", actor)
        if result.status is ActionStatus.ROLLED_BACK:
            # Idempotence : la boucle et l'analyste peuvent viser la meme action.
            return RollbackOutcome(
                action_id=result.action_id, success=True,
                reason="action deja annulee", actor=actor, detail="aucune operation necessaire",
            )
        if result.status is not ActionStatus.EXECUTED:
            return self._refuse(
                result, f"action au statut '{result.status.value}' : rien a annuler", actor
            )
        if not result.is_reversible:
            return self._refuse(
                result,
                "action non reversible ou jeton d'annulation absent : "
                "aucune annulation automatique possible",
                actor,
            )

        entry = self._catalog.get(result.spec.actuator, result.spec.verb)
        bound = entry.max_rollback_seconds if entry else self._max_latency

        self._ledger.record(
            audit_type,
            {"action_id": result.action_id, "reason": reason,
             "verb": result.spec.verb, "target": result.spec.target},
            actor=actor, incident_id=result.incident_id, action_id=result.action_id,
        )

        actuator = self._registry.require(result.spec.actuator)
        try:
            outcome = actuator.rollback(
                result.spec.verb,
                result.spec.target,
                result.rollback_token or "",
                result.spec.parameters,
            )
        except Exception as exc:  # noqa: BLE001
            return self._fail(result, f"exception pendant l'annulation : {exc}", actor, started, bound)

        latency = (datetime.now(UTC) - started).total_seconds()
        if not outcome.success:
            return self._fail(result, outcome.message, actor, started, bound)

        result.status = ActionStatus.ROLLED_BACK
        result.rolled_back_at = datetime.now(UTC)
        result.rollback_reason = reason
        result.rollback_actor = actor
        self._actions.save(result)

        within_bound = latency <= bound
        self._ledger.record(
            AuditEventType.ROLLBACK_COMPLETED,
            {
                "action_id": result.action_id,
                "reason": reason,
                "latency_seconds": round(latency, 3),
                "max_allowed_seconds": bound,
                "within_bound": within_bound,
                "detail": outcome.message,
            },
            actor=actor, incident_id=result.incident_id, action_id=result.action_id,
        )
        self._watcher.release(result.action_id)

        if not within_bound:
            log_with(logger, logging.ERROR,
                     "annulation reussie mais hors du delai admis",
                     action_id=result.action_id, latency=latency, bound=bound)
        else:
            log_with(logger, logging.WARNING, "action autonome annulee",
                     action_id=result.action_id, actor=actor, latency=latency)

        return RollbackOutcome(
            action_id=result.action_id, success=True, reason=reason, actor=actor,
            latency_seconds=latency, within_bound=within_bound, detail=outcome.message,
        )

    def rollback_by_id(self, action_id: str, reason: str, actor: str) -> RollbackOutcome:
        """Porte de sortie humaine (Analyste), toujours a posteriori."""
        result = self._actions.get(action_id)
        if result is None:
            return RollbackOutcome(
                action_id=action_id, success=False,
                reason=f"action '{action_id}' inconnue", actor=actor,
            )
        return self.rollback(result, reason, actor, AuditEventType.MANUAL_ROLLBACK)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _format_reason(verdict: WatchVerdict) -> str:
        return (
            f"degradation constatee sur {verdict.target} apres l'action : "
            + " ; ".join(verdict.reasons)
        )

    def _refuse(self, result: ActionResult, reason: str, actor: str) -> RollbackOutcome:
        log_with(logger, logging.WARNING, "annulation refusee",
                 action_id=result.action_id, reason=reason)
        return RollbackOutcome(
            action_id=result.action_id, success=False, reason=reason, actor=actor
        )

    def _fail(
        self, result: ActionResult, message: str, actor: str,
        started: datetime, bound: int,
    ) -> RollbackOutcome:
        """Echec d'annulation : l'etat le plus grave que le systeme puisse
        atteindre, puisqu'une action reste appliquee sans moyen de la retirer."""
        latency = (datetime.now(UTC) - started).total_seconds()
        result.status = ActionStatus.ROLLBACK_FAILED
        result.rollback_reason = message
        result.rollback_actor = actor
        self._actions.save(result)
        self._ledger.record(
            AuditEventType.ROLLBACK_FAILED,
            {"action_id": result.action_id, "error": message,
             "latency_seconds": round(latency, 3), "max_allowed_seconds": bound},
            actor=actor, incident_id=result.incident_id, action_id=result.action_id,
        )
        log_with(logger, logging.CRITICAL,
                 "ECHEC D'ANNULATION : une action reste appliquee sans retour arriere",
                 action_id=result.action_id, error=message)
        return RollbackOutcome(
            action_id=result.action_id, success=False, reason=message, actor=actor,
            latency_seconds=latency, within_bound=latency <= bound,
        )
