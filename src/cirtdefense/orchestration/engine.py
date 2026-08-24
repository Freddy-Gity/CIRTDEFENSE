"""Moteur d'orchestration autonome : la chaine complete.

Enchainement, pour tout evenement, sans aucune interruption humaine :

    ingestion -> enrichissement -> planification -> politique -> coupe-circuit
      -> execution -> notification a posteriori -> surveillance -> rollback

Le moteur ne connait pas les details de chaque etape ; il en connait l'ordre
et les conditions d'arret. Quatre motifs peuvent interrompre la chaine avant
l'execution, et chacun est journalise avec son motif :

- contexte non fonde (EF-04) ;
- aucune action au catalogue de reversibilite (EF-14) ;
- politique de l'administrateur (EF-15) ;
- coupe-circuit ouvert (EF-26).

Aucun de ces motifs n'est une attente de validation : ce sont des refus. Le
systeme n'a pas d'etat « en attente d'un humain ».
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..audit.ledger import AuditLedger
from ..domain.action import ActionSpec
from ..domain.decision import Decision, DecisionTrace
from ..domain.enums import AuditEventType, DecisionOutcome
from ..domain.events import DetectionEvent
from ..domain.incident import Incident
from ..domain.policy import ResponsePolicy
from ..enrichment.rag import EnrichedContext, EnrichmentService
from ..logging_setup import log_with
from ..persistence.repositories import (
    ActionRepository,
    DecisionRepository,
    IncidentRepository,
)
from .circuit_breaker import CircuitBreaker
from .executor import ExecutionReport, Executor
from .planner import Planner
from .rollback import ControlLoopReport, RollbackService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class OrchestrationResult:
    """Ce qui s'est passe pour un evenement, de bout en bout."""

    event: DetectionEvent
    incident: Incident
    decision: Decision
    execution: ExecutionReport | None = None
    control_loop: ControlLoopReport | None = None
    notifications: list[str] = field(default_factory=list)

    @property
    def acted(self) -> bool:
        return self.execution is not None and self.execution.executed > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event.event_id,
            "incident_id": self.incident.incident_id,
            "decision": self.decision.to_dict(),
            "execution": self.execution.to_dict() if self.execution else None,
            "control_loop": self.control_loop.to_dict() if self.control_loop else None,
            "notifications": self.notifications,
            "acted": self.acted,
        }


class OrchestrationEngine:
    def __init__(
        self,
        *,
        enrichment: EnrichmentService,
        planner: Planner,
        executor: Executor,
        rollback: RollbackService,
        breaker: CircuitBreaker,
        policy: ResponsePolicy,
        incidents: IncidentRepository,
        decisions: DecisionRepository,
        actions: ActionRepository,
        ledger: AuditLedger,
        notifier: Any = None,
        autonomy_enabled: bool = True,
    ) -> None:
        self._enrichment = enrichment
        self._planner = planner
        self._executor = executor
        self._rollback = rollback
        self._breaker = breaker
        self._policy = policy
        self._incidents = incidents
        self._decisions = decisions
        self._actions = actions
        self._ledger = ledger
        self._notifier = notifier
        self._autonomy_enabled = autonomy_enabled

    def set_policy(self, policy: ResponsePolicy) -> None:
        """Rechargement a chaud d'une politique recompilee."""
        self._policy = policy

    @property
    def policy(self) -> ResponsePolicy:
        return self._policy

    # -- chaine principale --------------------------------------------------

    def handle(self, event: DetectionEvent, incident: Incident) -> OrchestrationResult:
        context = self._enrichment.enrich(event)
        self._ledger.record(
            AuditEventType.CONTEXT_ENRICHED,
            {"event_id": event.event_id, **context.to_dict()},
            incident_id=incident.incident_id,
        )

        decision = self._decide(event, incident, context)
        self._decisions.save(decision)
        self._ledger.record(
            AuditEventType.DECISION_MADE,
            decision.to_dict(),
            incident_id=incident.incident_id,
            decision_id=decision.decision_id,
        )

        result = OrchestrationResult(event=event, incident=incident, decision=decision)
        if not decision.is_actionable:
            log_with(
                logger,
                logging.INFO,
                "aucune action autonome engagee",
                event_id=event.event_id,
                outcome=decision.outcome.value,
                rationale=decision.rationale,
            )
            self._incidents.save(incident)
            return result

        # EF-07 : execution immediate, sans validation prealable.
        report = self._executor.execute_all(
            decision.actions,
            incident_id=incident.incident_id,
            decision_id=decision.decision_id,
            watch_target=event.asset.correlation_key(),
        )
        result.execution = report
        for action_result in report.results:
            incident.register_action(action_result)
        self._incidents.save(incident)

        # EF-13 revisee : l'analyste est informe apres coup, sans rien bloquer.
        result.notifications = self._notify_after_the_fact(incident, decision, report)

        # Un echec d'actuateur peut annoncer une panne en serie : on laisse le
        # coupe-circuit en juger immediatement plutot qu'au prochain incident.
        if report.failed:
            self._breaker.evaluate_auto_trip()

        return result

    def run_control_loop(self) -> ControlLoopReport:
        """EF-25. A appeler periodiquement, apres le delai de surveillance."""
        report = self._rollback.run_control_loop()
        if report.rolled_back or report.rollback_failures:
            self._breaker.evaluate_auto_trip()
        return report

    # -- decision -----------------------------------------------------------

    def _decide(
        self, event: DetectionEvent, incident: Incident, context: EnrichedContext
    ) -> Decision:
        trace = DecisionTrace(
            grounding_score=context.grounding.score if context.grounding else 0.0,
            context_sources=context.sources,
        )
        decision = Decision(incident_id=incident.incident_id, event_id=event.event_id, trace=trace)

        if not self._autonomy_enabled:
            decision.outcome = DecisionOutcome.POLICY_DENIED
            decision.rationale = (
                "autonomie desactivee par configuration (CIRT_AUTONOMY_ENABLED=false) : "
                "le systeme raisonne et journalise mais n'execute pas"
            )
            return decision

        if not self._breaker.allows_execution():
            status = self._breaker.status()
            decision.outcome = DecisionOutcome.BREAKER_OPEN
            decision.rationale = (
                f"coupe-circuit ouvert (EF-26) : {status.reason}. "
                "Aucune action n'est executee jusqu'au rearmement par l'administrateur."
            )
            return decision

        # EF-04 : sans contexte fonde, pas d'action. C'est le refus le plus
        # important du systeme, et celui qui couvre les menaces inconnues.
        if not context.is_usable:
            decision.outcome = DecisionOutcome.NO_GROUNDED_CONTEXT
            decision.rationale = (
                "contexte non fonde documentairement : "
                f"{context.grounding.reason if context.grounding else 'aucune source'}. "
                "Agir reviendrait a agir sur une hypothese."
            )
            return decision

        plan = self._planner.plan(event)
        trace.playbook_id = plan.playbook_id
        trace.playbook_version = plan.playbook_version
        trace.matched_conditions = plan.matched_rules
        trace.considered_actions = [a.spec.key for a in plan.actions]
        trace.rejected_actions = list(plan.skipped)

        if not plan.actions:
            decision.outcome = (
                DecisionOutcome.OUT_OF_CATALOG if plan.skipped else DecisionOutcome.NO_ACTION_NEEDED
            )
            decision.rationale = "aucune action executable : " + (
                "; ".join(s["reason"] for s in plan.skipped)
                if plan.skipped
                else "aucune regle de playbook ne correspond a cet evenement"
            )
            return decision

        allowed, verdicts = self._apply_policy(plan.specs, event, incident)
        trace.policy_verdicts = verdicts

        if not allowed:
            decision.outcome = DecisionOutcome.POLICY_DENIED
            denied = [v["rule_text"] or v["reason"] for v in verdicts if not v["allowed"]]
            decision.rationale = (
                "toutes les actions candidates sont refusees par la politique de "
                f"reponse : {'; '.join(denied)}"
            )
            return decision

        decision.outcome = DecisionOutcome.AUTONOMOUS_EXECUTION
        decision.actions = allowed
        decision.rationale = (
            f"playbook {plan.playbook_id} v{plan.playbook_version}, "
            f"regles {', '.join(plan.matched_rules)} ; "
            f"{len(allowed)} action(s) autorisee(s) par la politique "
            f"{self._policy.policy_id} v{self._policy.version} "
            f"(empreinte {self._policy.checksum()})"
        )
        return decision

    def _apply_policy(
        self, specs: list[ActionSpec], event: DetectionEvent, incident: Incident
    ) -> tuple[list[ActionSpec], list[dict[str, Any]]]:
        context = {
            "incident.severity": incident.severity.value,
            "incident.category": incident.category,
            "asset.criticality": event.asset.criticality,
            "asset.zone": event.asset.zone,
        }
        allowed: list[ActionSpec] = []
        verdicts: list[dict[str, Any]] = []
        for spec in specs:
            verdict = self._policy.evaluate(spec, context)
            verdicts.append(
                {
                    "action": spec.key,
                    "target": spec.target,
                    "allowed": verdict.allowed,
                    "rule_id": verdict.rule_id,
                    "rule_text": verdict.rule_text,
                    "reason": verdict.reason,
                }
            )
            if verdict.allowed:
                allowed.append(spec)
        return allowed, verdicts

    # -- EF-13 revisee ------------------------------------------------------

    def _notify_after_the_fact(
        self, incident: Incident, decision: Decision, report: ExecutionReport
    ) -> list[str]:
        """Informe l'analyste de ce qui a ete fait, sans jamais l'attendre."""
        if self._notifier is None:
            return []
        sent = self._notifier.notify_actions(incident, decision, report)
        for notification_id in sent:
            self._ledger.record(
                AuditEventType.ANALYST_NOTIFIED,
                {
                    "notification_id": notification_id,
                    "incident_id": incident.incident_id,
                    "actions_executed": report.executed,
                    "actions_failed": report.failed,
                },
                incident_id=incident.incident_id,
                decision_id=decision.decision_id,
            )
        return sent
