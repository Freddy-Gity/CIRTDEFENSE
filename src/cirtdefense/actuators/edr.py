"""Actuateur EDR : isolement de machine, arrêt de processus, quarantaine.

L'isolement est l'action la plus lourde du catalogue autonome : elle coupe
une machine du réseau. Elle n'est que *partiellement* réversible (les sessions
en cours sont perdues), ce que le catalogue documente explicitement.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "isolate_host",
    "release_host",
    "kill_process",
    "restart_process",
    "quarantine_file",
    "restore_file",
)


class SimulatedEdr(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("edr", VERBS)


class LiveEdr(Actuator):
    """Squelette d'intégration (Wazuh, CrowdStrike, Defender, Harfanglab...)."""

    name = "edr"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur EDR en mode réel sans client configure")
        if verb == "isolate_host" and not parameters.get("keep_agent_channel", True):
            # Isoler sans conserver le canal de l'agent rendrait la levée de
            # quarantaine impossible à distance : ce serait une action
            # irréversible deguisee en action réversible.
            return ActuationOutcome(
                success=False,
                message="isolement refusé : le canal de l'agent doit rester ouvert "
                "pour que la levée de quarantaine reste possible",
            )
        raise NotImplementedError("LiveEdr.exécute : brancher le client EDR du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur EDR en mode réel sans client configure")
        raise NotImplementedError("LiveEdr.rollback : lever l'action identifiée par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedEdr() if mode != "live" else LiveEdr(client)
