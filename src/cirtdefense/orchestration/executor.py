"""Executeur : application effective des actions (EF-07 revisee).

C'est le point exact ou la v3.0 se separe de la v2.1. Il n'y a plus d'etape
d'attente : une action validee par la politique, presente au catalogue de
reversibilite et autorisee par le coupe-circuit part immediatement.

Ordre des operations, non negociable :

1. mesure de reference de la cible (sans elle, EF-25 est aveugle) ;
2. execution ;
3. journalisation ;
4. notification a posteriori de l'analyste (EF-13 revisee).

La mesure de reference precede l'execution. Inverser 1 et 2 rendrait toute
imputation de degradation impossible, et donc le rollback autonome arbitraire.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..actuators.base import ActuatorRegistry
from ..audit.ledger import AuditLedger
from ..detection.infra.post_action_watch import PostActionWatcher
from ..domain.action import ActionResult, ActionSpec
from ..domain.enums import ActionStatus, AuditEventType
from ..logging_setup import log_with
from ..persistence.repositories import ActionRepository
from .reversibility import ReversibilityCatalog, get_catalog

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ExecutionReport:
    results: list[ActionResult] = field(default_factory=list)
    executed: int = 0
    failed: int = 0
    blocked: int = 0

    @property
    def all_succeeded(self) -> bool:
        return self.failed == 0 and self.blocked == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed": self.executed,
            "failed": self.failed,
            "blocked": self.blocked,
            "results": [r.to_dict() for r in self.results],
        }


class Executor:
    def __init__(
        self,
        registry: ActuatorRegistry,
        actions: ActionRepository,
        ledger: AuditLedger,
        watcher: PostActionWatcher | None = None,
        catalog: ReversibilityCatalog | None = None,
        *,
        actuation_mode: str = "simulation",
    ) -> None:
        self._registry = registry
        self._actions = actions
        self._ledger = ledger
        self._watcher = watcher
        self._catalog = catalog or get_catalog()
        self._mode = actuation_mode

    def execute(
        self,
        spec: ActionSpec,
        incident_id: str,
        decision_id: str,
        watch_target: str | None = None,
    ) -> ActionResult:
        result = ActionResult(spec=spec, incident_id=incident_id, decision_id=decision_id)

        guard = self._preflight(spec)
        if guard is not None:
            result.status = ActionStatus.BLOCKED_BY_POLICY
            result.error = guard
            self._actions.save(result)
            self._ledger.record(
                AuditEventType.ACTION_FAILED,
                {**result.to_dict(), "blocked_reason": guard, "actuation_mode": self._mode},
                incident_id=incident_id, decision_id=decision_id, action_id=result.action_id,
            )
            log_with(logger, logging.ERROR, "action refusee avant execution",
                     action=spec.key, reason=guard)
            return result

        # (1) Reference AVANT l'action : condition de possibilite d'EF-25.
        if self._watcher is not None:
            self._watcher.capture_baseline(result.action_id, watch_target or spec.target)

        # (2) Execution.
        result.mark_started()
        actuator = self._registry.require(spec.actuator)
        try:
            outcome = actuator.execute(spec.verb, spec.target, spec.parameters)
        except Exception as exc:  # noqa: BLE001
            result.mark_failed(f"exception de l'actuateur : {exc}")
            log_with(logger, logging.ERROR, "exception pendant l'execution",
                     action=spec.key, target=spec.target, error=str(exc))
        else:
            if outcome.success:
                result.mark_executed(
                    output={
                        "message": outcome.message,
                        "details": outcome.details,
                        "already_applied": outcome.already_applied,
                        "actuation_mode": self._mode,
                    },
                    rollback_token=outcome.rollback_token,
                )
            else:
                result.mark_failed(outcome.message or "echec sans motif fourni")

        # (3) Journalisation : reussite comme echec.
        self._actions.save(result)
        self._ledger.record(
            AuditEventType.ACTION_EXECUTED
            if result.status is ActionStatus.EXECUTED
            else AuditEventType.ACTION_FAILED,
            {**result.to_dict(), "actuation_mode": self._mode,
             "expected_effect": spec.expected_effect},
            incident_id=incident_id, decision_id=decision_id, action_id=result.action_id,
        )

        level = logging.INFO if result.status is ActionStatus.EXECUTED else logging.ERROR
        log_with(logger, level, "action autonome executee" if result.status is ActionStatus.EXECUTED
                 else "action autonome en echec",
                 action=spec.key, target=spec.target, mode=self._mode,
                 status=result.status.value, duration_ms=result.duration_ms)
        return result

    def execute_all(
        self,
        specs: list[ActionSpec],
        incident_id: str,
        decision_id: str,
        watch_target: str | None = None,
    ) -> ExecutionReport:
        report = ExecutionReport()
        for spec in specs:
            result = self.execute(spec, incident_id, decision_id, watch_target)
            report.results.append(result)
            match result.status:
                case ActionStatus.EXECUTED:
                    report.executed += 1
                case ActionStatus.BLOCKED_BY_POLICY | ActionStatus.BLOCKED_BY_BREAKER:
                    report.blocked += 1
                case _:
                    report.failed += 1
        return report

    def _preflight(self, spec: ActionSpec) -> str | None:
        """Derniere verification avant le point de non-retour.

        Elle double celle du planificateur a dessein : une action peut avoir
        ete construite ailleurs (rejeu du mode degrade, appel direct de l'API),
        et le catalogue est le garde-fou qu'on ne veut pas pouvoir contourner.
        """
        entry = self._catalog.get(spec.actuator, spec.verb)
        if entry is None:
            return f"action '{spec.key}' absente du catalogue de reversibilite"
        if not entry.autonomously_executable:
            return (
                f"action '{spec.key}' declaree {entry.reversibility.value} : "
                "hors du perimetre de l'execution autonome"
            )
        if not self._registry.can_handle(spec.actuator, spec.verb):
            return f"actuateur '{spec.actuator}' ne supporte pas le verbe '{spec.verb}'"
        actuator = self._registry.require(spec.actuator)
        if not actuator.health():
            return f"actuateur '{spec.actuator}' indisponible"
        return None
