"""Notification a posteriori de l'analyste (EF-13, version v3.0).

L'analyste ne valide plus rien en amont : son role devient celui d'un
superviseur qui constate, verifie et peut annuler apres coup. Cette
notification est donc son unique point d'entree dans la boucle, ce qui impose
qu'elle soit exploitable telle quelle : ce qui a ete fait, sur quoi, pourquoi,
et comment l'annuler.

Une notification qui obligerait a ouvrir trois ecrans pour comprendre serait
un echec fonctionnel, pas un detail de presentation.
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

    def notify_actions(
        self, incident: Incident, decision: Decision, report: Any
    ) -> list[str]:
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
            log_with(logger, logging.ERROR,
                     "la notification a posteriori a echoue : l'action reste executee",
                     incident_id=incident.incident_id, error=outcome.message)
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
                    else "ECHEC d'annulation automatique"
                ),
                "body": (
                    f"Action {outcome.action_id}\n"
                    f"Motif : {outcome.reason}\n"
                    f"Delai d'annulation : {outcome.latency_seconds:.1f} s "
                    f"({'dans' if outcome.within_bound else 'HORS'} le delai admis)\n"
                    + ("" if outcome.success else
                       "\nATTENTION : l'action reste appliquee. Une intervention "
                       "manuelle sur l'equipement est necessaire.")
                ),
                "incident_id": incident_id,
                "action_id": outcome.action_id,
            },
        )
        return [result.rollback_token] if result.success and result.rollback_token else []

    # -- redaction ----------------------------------------------------------

    def render(self, incident: Incident, decision: Decision, report: Any) -> str:
        lines: list[str] = [
            "Le systeme a execute une reponse automatique. Cette notification "
            "vous informe apres coup : aucune validation n'etait requise.",
            "",
            f"Incident   : {incident.incident_id}",
            f"Categorie  : {incident.category} (gravite {incident.severity.value})",
            f"Cible      : {incident.correlation_key}",
            f"Score de risque : {incident.risk_score()}",
            "",
            "MOTIF DE LA DECISION",
            f"  {decision.rationale}",
        ]

        if decision.trace.context_sources:
            lines.append("  Sources documentaires : " + ", ".join(
                s.split("/")[-1] for s in decision.trace.context_sources
            ))

        lines += ["", "ACTIONS EXECUTEES"]
        for result in report.results:
            lines.append(f"  {self._describe(result)}")

        if decision.trace.rejected_actions:
            lines += ["", "ACTIONS ENVISAGEES PUIS ECARTEES"]
            for skipped in decision.trace.rejected_actions:
                lines.append(f"  - {skipped.get('action')} : {skipped.get('reason')}")

        reversible = [r for r in report.results if r.status is ActionStatus.EXECUTED and r.is_reversible]
        if reversible:
            lines += [
                "",
                "POUR ANNULER (annulation manuelle a posteriori)",
                *[f"  POST /api/v1/actions/{r.action_id}/rollback" for r in reversible],
            ]

        irreversible_note = [
            r for r in report.results
            if r.status is ActionStatus.EXECUTED and r.spec and r.spec.reversibility.value
            == "partially_reversible"
        ]
        if irreversible_note:
            lines += [
                "",
                "EFFETS RESIDUELS APRES ANNULATION",
                "  Certaines actions ne sont que partiellement reversibles : les "
                "sessions et etats en memoire perdus ne seront pas restaures.",
            ]
        return "\n".join(lines)

    @staticmethod
    def _describe(result: ActionResult) -> str:
        spec = result.spec
        head = f"[{result.status.value}] {spec.key if spec else '?'} -> {spec.target if spec else '?'}"
        if result.status is ActionStatus.EXECUTED:
            return f"{head} ({result.duration_ms} ms) — {spec.expected_effect if spec else ''}".rstrip(" —")
        return f"{head} — {result.error or 'sans detail'}"

    @staticmethod
    def _subject(incident: Incident, report: Any) -> str:
        if report.failed or report.blocked:
            return (
                f"Reponse automatique partielle sur {incident.correlation_key} "
                f"({report.executed} executee(s), {report.failed} echec(s), "
                f"{report.blocked} refusee(s))"
            )
        return (
            f"Reponse automatique executee sur {incident.correlation_key} "
            f"({report.executed} action(s))"
        )

    @staticmethod
    def _severity_of(incident: Incident, report: Any) -> str:
        if report.failed or report.blocked:
            return Severity.HIGH.value
        return incident.severity.value
