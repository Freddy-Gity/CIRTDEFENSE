"""Notification a posteriori de l'analyste (EF-13, version v3.0).

L'analyste ne valide plus rien en amont : son rôle devient celui d'un
superviseur qui constate, vérifie et peut annuler après coup. Cette
notification est donc son unique point d'entrée dans la boucle, ce qui impose
qu'elle soit exploitable telle quelle : ce qui a été fait, sur quoi, pourquoi,
et comment l'annuler.

Une notification qui obligerait à ouvrir trois ecrans pour comprendre serait
un échec fonctionnel, pas un détail de presentation.
"""

from __future__ import annotations

import logging
from typing import Any

from ..domain.action import ActionResult
from ..domain.decision import Decision
from ..domain.enums import ActionStatus, Severity
from ..domain.incident import Incident
from ..logging_setup import log_with

logger = logging.getLogger(__name__)


class AnalystNotifier:
    def __init__(self, notification_actuator: Any, default_recipient: str = "analyste") -> None:
        self._actuator = notification_actuator
        self._recipient = default_recipient

    def notify_actions(self, incident: Incident, decision: Decision, report: Any) -> list[str]:
        if not report.results:
            return []

        severity = self._severity_of(incident, report)
        outcome = self._actuator.execute(
            "notify",
            self._recipient,
            {
                "channel": "analyst",
                "severity": severity,
                "subject": self._subject(incident, report),
                "body": self.render(incident, decision, report),
                "incident_id": incident.incident_id,
                "action_id": report.results[0].action_id,
            },
        )
        if not outcome.success:
            log_with(
                logger,
                logging.ERROR,
                "la notification a posteriori a echoue : l'action reste exécutée",
                incident_id=incident.incident_id,
                error=outcome.message,
            )
            return []
        return [outcome.rollback_token] if outcome.rollback_token else []

    def notify_rollback(self, incident_id: str, outcome: Any) -> list[str]:
        result = self._actuator.execute(
            "notify",
            self._recipient,
            {
                "channel": "analyst",
                "severity": "high" if not outcome.success else "medium",
                "subject": (
                    "Annulation automatique effectuee"
                    if outcome.success
                    else "ÉCHEC d'annulation automatique"
                ),
                "body": (
                    f"Action {outcome.action_id}\n"
                    f"Motif : {outcome.reason}\n"
                    f"Délai d'annulation : {outcome.latency_seconds:.1f} s "
                    f"({'dans' if outcome.within_bound else 'HORS'} le délai admis)\n"
                    + (
                        ""
                        if outcome.success
                        else "\nATTENTION : l'action reste appliquée. Une intervention "
                        "manuelle sur l'équipement est nécessaire."
                    )
                ),
                "incident_id": incident_id,
                "action_id": outcome.action_id,
            },
        )
        return [result.rollback_token] if result.success and result.rollback_token else []

    # -- rédaction ----------------------------------------------------------

    def render(self, incident: Incident, decision: Decision, report: Any) -> str:
        lines: list[str] = [
            "Le système a exécuté une réponse automatique. Cette notification "
            "vous informe après coup : aucune validation n'était requise.",
            "",
            f"Incident   : {incident.incident_id}",
            f"Catégorie  : {incident.category} (gravité {incident.severity.value})",
            f"Cible      : {incident.correlation_key}",
            f"Score de risque : {incident.risk_score()}",
            "",
            "MOTIF DE LA DÉCISION",
            f"  {decision.rationale}",
        ]

        if decision.trace.context_sources:
            lines.append(
                "  Sources documentaires : "
                + ", ".join(s.split("/")[-1] for s in decision.trace.context_sources)
            )

        lines += ["", "ACTIONS EXÉCUTÉES"]
        for result in report.results:
            lines.append(f"  {self._describe(result)}")

        if decision.trace.rejected_actions:
            lines += ["", "ACTIONS ENVISAGÉES PUIS ÉCARTÉES"]
            for skipped in decision.trace.rejected_actions:
                lines.append(f"  - {skipped.get('action')} : {skipped.get('reason')}")

        reversible = [
            r for r in report.results if r.status is ActionStatus.EXECUTED and r.is_reversible
        ]
        if reversible:
            lines += [
                "",
                "POUR ANNULER (annulation manuelle a posteriori)",
                *[f"  POST /api/v1/actions/{r.action_id}/rollback" for r in reversible],
            ]

        irreversible_note = [
            r
            for r in report.results
            if r.status is ActionStatus.EXECUTED
            and r.spec
            and r.spec.reversibility.value == "partially_reversible"
        ]
        if irreversible_note:
            lines += [
                "",
                "EFFETS RÉSIDUELS APRÈS ANNULATION",
                "  Certaines actions ne sont que partiellement réversibles : les "
                "sessions et états en mémoire perdus ne seront pas restaurés.",
            ]
        return "\n".join(lines)

    @staticmethod
    def _describe(result: ActionResult) -> str:
        spec = result.spec
        head = (
            f"[{result.status.value}] {spec.key if spec else '?'} -> {spec.target if spec else '?'}"
        )
        if result.status is ActionStatus.EXECUTED:
            return (
                f"{head} ({result.duration_ms} ms) — {spec.expected_effect if spec else ''}".rstrip(
                    " —"
                )
            )
        return f"{head} — {result.error or 'sans detail'}"

    @staticmethod
    def _subject(incident: Incident, report: Any) -> str:
        if report.failed or report.blocked:
            return (
                f"Réponse automatique partielle sur {incident.correlation_key} "
                f"({report.executed} exécutée(s), {report.failed} échec(s), "
                f"{report.blocked} refusée(s))"
            )
        return (
            f"Réponse automatique exécutée sur {incident.correlation_key} "
            f"({report.executed} action(s))"
        )

    @staticmethod
    def _severity_of(incident: Incident, report: Any) -> str:
        if report.failed or report.blocked:
            return Severity.HIGH.value
        return incident.severity.value
