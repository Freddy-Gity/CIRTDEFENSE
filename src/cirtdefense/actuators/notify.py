"""Actuateur de notification (EF-13 v3.0 : information a posteriori).

La notification est traitée comme une action a part entiere : elle est
planifiée, exécutée, journalisée et annulable comme les autres. Ce choix n'est
pas cosmetique — en v3.0 la notification est la seule chose que l'analyste
reçoit avant que l'action ne soit déjà faite, et elle doit donc être aussi
tracable que l'action elle-même.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from .base import ActuationOutcome, Actuator

VERBS: tuple[str, ...] = ("notify", "retract_notification")


class NotificationActuator(Actuator):
    """Depose les notifications dans un dépôt ; la remise effective (courriel,
    messagerie instantanee, SMS) est branchee par `sinks`."""

    name = "notify"
    supported_verbs = VERBS

    def __init__(self, repository: Any = None) -> None:
        self._repository = repository
        self._sent: dict[str, dict[str, Any]] = {}
        self.sinks: list[Any] = []

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if verb != "notify":
            return ActuationOutcome(success=False, message=f"verbe non supporte : {verb}")

        notification_id = f"ntf_{uuid.uuid4().hex[:12]}"
        payload = {
            "notification_id": notification_id,
            "created_at": datetime.now(UTC).isoformat(),
            "channel": parameters.get("channel", "analyst"),
            "recipient": target,
            "severity": parameters.get("severity", "medium"),
            "subject": parameters.get("subject", "Action autonome exécutée"),
            "body": parameters.get("body", ""),
            "incident_id": parameters.get("incident_id"),
            "action_id": parameters.get("action_id"),
            "acknowledged_at": None,
        }
        self._sent[notification_id] = payload
        if self._repository is not None:
            self._repository.save(payload)
        for sink in self.sinks:
            # Un canal de remise indisponible ne doit pas faire echouer
            # l'action : la notification reste consultable dans l'interface.
            try:
                sink(payload)
            except Exception as exc:  # noqa: BLE001
                payload.setdefault("delivery_errors", []).append(str(exc))

        return ActuationOutcome(
            success=True,
            rollback_token=notification_id,
            details=payload,
            message=f"notification {notification_id} deposee pour {target}",
        )

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        payload = self._sent.get(token)
        if payload is None:
            return ActuationOutcome(success=False, message=f"notification inconnue : {token}")
        payload["retracted_at"] = datetime.now(UTC).isoformat()
        if self._repository is not None:
            self._repository.save(payload)
        return ActuationOutcome(
            success=True,
            details={"notification_id": token},
            message="notification marquee comme retirée",
        )

    def sent(self) -> list[dict[str, Any]]:
        return list(self._sent.values())


def build(mode: str = "simulation", repository: Any = None) -> Actuator:
    return NotificationActuator(repository)
