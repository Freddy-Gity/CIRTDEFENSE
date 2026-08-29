"""Moteur d'orchestration autonome : la chaîne complète.

Enchainement, pour tout événement, sans aucune interruption humaine :

    ingestion -> enrichissement -> planification -> politique -> coupe-circuit
      -> exécution -> notification a posteriori -> surveillance -> rollback

Le moteur ne connaît pas les détails de chaque étape ; il en connaît l'ordre
et les conditions d'arrêt. Quatre motifs peuvent interrompre la chaîne avant
l'exécution, et chacun est journalisé avec son motif :

- contexte non fondé (EF-04) ;
- aucune action au catalogue de réversibilité (EF-14) ;
- politique de l'administrateur (EF-15) ;
- coupe-circuit ouvert (EF-26).

Aucun de ces motifs n'est une attente de validation : ce sont des refus. Le
système n'a pas d'état « en attente d'un humain ».
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
from .classifier import Classification, Classifier
from .executor import ExecutionReport, Executor
from .fallback import FallbackPlanner
from .planner import Planner
from .rollback import ControlLoopReport, RollbackService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class OrchestrationResult:
    """Ce qui s'est passe pour un événement, de bout en bout."""

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
        classifier: Classifier | None = None,
        fallback: FallbackPlanner | None = None,
        autonomy_enabled: bool = True,
    ) -> None:
        self._enrichment = enrichment
        self._planner = planner
        self._fallback = fallback
        self._executor = executor
        self._rollback = rollback
        self._breaker = breaker
        self._policy = policy
        self._incidents = incidents
        self._decisions = decisions
        self._actions = actions
        self._ledger = ledger
        self._notifier = notifier
        self._classifier = classifier or Classifier()
        self._autonomy_enabled = autonomy_enabled

    def set_policy(self, policy: ResponsePolicy) -> None:
        """Rechargement à chaud d'une politique recompilee."""
        self._policy = policy

    @property
    def policy(self) -> ResponsePolicy:
        return self._policy

    # -- chaîne principale --------------------------------------------------

    def handle(self, event: DetectionEvent, incident: Incident) -> OrchestrationResult:
        # La classification precede l'enrichissement : elle qualifie ce qui est
        # observe, independamment de ce que la base documentaire contient. Un
        # type hors catalogue doit pouvoir être qualifie « non catalogue »
        # plutôt que de rester sans qualification du tout.
        classification = self._classifier.classify(event)
        incident.apply_classification(classification)

        context = self._enrichment.enrich(event)
        self._ledger.record(
            AuditEventType.CONTEXT_ENRICHED,
            {"event_id": event.event_id, **context.to_dict()},
            incident_id=incident.incident_id,
        )

        decision = self._decide(event, incident, context, classification)
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
            # S'abstenir n'est pas rassurant : la menace reste entiere. Le
            # silence sur une abstention est pire que sur une action, puisque
            # l'action, elle, a au moins contenu quelque chose.
            result.notifications = self._notify_abstention(incident, decision)
            return result

        # EF-07 : exécution immédiate, sans validation préalable.
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

        # EF-13 revisee : l'analyste est informé après coup, sans rien bloquer.
        result.notifications = self._notify_after_the_fact(incident, decision, report)

        # Un échec d'actuateur peut annoncer une panne en série : on laisse le
        # coupe-circuit en juger immédiatement plutôt qu'au prochain incident.
        if report.failed:
            self._breaker.evaluate_auto_trip()

        return result

    def run_control_loop(self) -> ControlLoopReport:
        """EF-25. à appeler periodiquement, après le délai de surveillance."""
        report = self._rollback.run_control_loop()
        if report.rolled_back or report.rollback_failures:
            self._breaker.evaluate_auto_trip()
        return report

    # -- décision -----------------------------------------------------------

    def _decide(
        self,
        event: DetectionEvent,
        incident: Incident,
        context: EnrichedContext,
        classification: Classification,
    ) -> Decision:
        trace = DecisionTrace(
            grounding_score=context.grounding.score if context.grounding else 0.0,
            context_sources=context.sources,
        )
        decision = Decision(
            incident_id=incident.incident_id,
            event_id=event.event_id,
            trace=trace,
            classification=classification.to_dict(),
        )

        if not self._autonomy_enabled:
            decision.outcome = DecisionOutcome.POLICY_DENIED
            decision.rationale = (
                "autonomie désactivée par configuration (CIRT_AUTONOMY_ENABLED=false) : "
                "le système raisonne et journalise mais n'exécute pas"
            )
            return decision

        if not self._breaker.allows_execution():
            status = self._breaker.status()
            decision.outcome = DecisionOutcome.BREAKER_OPEN
            decision.rationale = (
                f"coupe-circuit ouvert (EF-26) : {status.reason}. "
                "Aucune action n'est exécutée jusqu'au réarmement par l'administrateur."
            )
            return decision

        # EF-04 : sans contexte fondé, aucun playbook n'est choisi. C'est le
        # refus le plus important du système, et il tient : on ne devine pas
        # un type d'attaque pour en déduire une réponse.
        #
        # Le repli qui suit ne lève pas cette garde, il change de fondement.
        # Il ne déduit rien du type — il part des indicateurs *observés* et
        # n'engage que des gestes réversibles, à rayon contenu, annulables.
        # Bloquer une adresse hostile protège quelle que soit l'attaque
        # qu'elle porte ; c'est un fait constaté, pas une hypothèse.
        if not context.is_usable:
            repli = self._fallback.plan(event) if self._fallback else None
            if repli is None or repli.empty:
                decision.outcome = DecisionOutcome.NO_GROUNDED_CONTEXT
                decision.rationale = (
                    "contexte non fondé documentairement : "
                    f"{context.grounding.reason if context.grounding else 'aucune source'}. "
                    "Agir reviendrait a agir sur une hypothèse."
                )
                return decision

            decision.fallback = repli.to_dict()
            trace.considered_actions = [
                s.spec.key for s in (*repli.autonomous, *repli.requires_confirmation)
            ]
            trace.rejected_actions = [
                {
                    "action": s.spec.key,
                    "reason": (
                        f"effet durable ({s.spec.reversibility.value}) : "
                        f"{s.residual_effect or 'annulation partielle'} — "
                        "confirmation humaine requise"
                    ),
                }
                for s in repli.requires_confirmation
            ]

            # La politique s'applique au repli comme au reste : une consigne
            # « ne jamais bloquer une adresse » vaut aussi pour une menace
            # inconnue. Contourner la politique au motif de l'urgence serait
            # exactement ce que la compilation a priori (EF-15) interdit.
            autorisees, verdicts = self._apply_policy(
                [s.spec for s in repli.autonomous], event, incident
            )
            trace.policy_verdicts = verdicts

            if not autorisees:
                decision.outcome = DecisionOutcome.POLICY_DENIED
                decision.rationale = (
                    "menace non catalogüée : le confinement de repli a été refusé "
                    "par la politique de réponse. Aucune action n'est engagée."
                )
                return decision

            decision.outcome = DecisionOutcome.AUTONOMOUS_EXECUTION
            decision.actions = autorisees
            decision.rationale = (
                "contexte non fondé documentairement : aucun playbook n'est applicable. "
                "Confinement de repli engagé sur les seuls indicateurs observés "
                f"({'; '.join(repli.observations[:3])}) — "
                f"{len(autorisees)} geste(s) réversible(s), annulables. "
                f"{len(repli.requires_confirmation)} geste(s) à effet durable attendent "
                "une confirmation humaine. Le type d'attaque reste à qualifier."
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
            decision.rationale = "aucune action exécutable : " + (
                "; ".join(s["reason"] for s in plan.skipped)
                if plan.skipped
                else "aucune règle de playbook ne correspond à cet événement"
            )
            return decision

        allowed, verdicts = self._apply_policy(plan.specs, event, incident)
        trace.policy_verdicts = verdicts

        if not allowed:
            decision.outcome = DecisionOutcome.POLICY_DENIED
            denied = [v["rule_text"] or v["reason"] for v in verdicts if not v["allowed"]]
            decision.rationale = (
                "toutes les actions candidates sont refusées par la politique de "
                f"réponse : {'; '.join(denied)}"
            )
            return decision

        decision.outcome = DecisionOutcome.AUTONOMOUS_EXECUTION
        decision.actions = allowed
        qualification = (
            f"{classification.code} — {classification.label} "
            f"[{classification.family_label_or_blank()}] ; "
            f"criticité {classification.severity.value}, "
            f"dangerosité {classification.dangerousness:.1f}/10 "
            f"({classification.danger_band}), priorité {classification.priority.value}"
        )
        decision.rationale = (
            f"{qualification}. Playbook {plan.playbook_id} v{plan.playbook_version}, "
            f"règles {', '.join(plan.matched_rules)} ; "
            f"{len(allowed)} action(s) autorisée(s) par la politique "
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

    def _notify_abstention(self, incident: Incident, decision: Decision) -> list[str]:
        if self._notifier is None:
            return []
        sent = self._notifier.notify_abstention(incident, decision)
        for notification_id in sent:
            self._ledger.record(
                AuditEventType.ANALYST_NOTIFIED,
                {
                    "notification_id": notification_id,
                    "incident_id": incident.incident_id,
                    "abstention": True,
                    "outcome": decision.outcome.value,
                    "rationale": decision.rationale,
                },
                incident_id=incident.incident_id,
                decision_id=decision.decision_id,
            )
        return sent

    def _notify_after_the_fact(
        self, incident: Incident, decision: Decision, report: ExecutionReport
    ) -> list[str]:
        """Informe l'analyste de ce qui a été fait, sans jamais l'attendre."""
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
