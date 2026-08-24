"""Actuateur EDR : isolement de machine, arret de processus, quarantaine.

L'isolement est l'action la plus lourde du catalogue autonome : elle coupe
une machine du reseau. Elle n'est que *partiellement* reversible (les sessions
en cours sont perdues), ce que le catalogue documente explicitement.
"""

from __future__ import annotations

from typing import Any

from .base import Actuator, ActuationOutcome
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "isolate_host", "release_host",
    "kill_process", "restart_process",
    "quarantine_file", "restore_file",
)


class SimulatedEdr(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("edr", VERBS)


class LiveEdr(Actuator):
    """Squelette d'integration (Wazuh, CrowdStrike, Defender, Harfanglab...)."""

    name = "edr"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur EDR en mode reel sans client configure")
        if verb == "isolate_host" and not parameters.get("keep_agent_channel", True):
            # Isoler sans conserver le canal de l'agent rendrait la levee de
            # quarantaine impossible a distance : ce serait une action
            # irreversible deguisee en action reversible.
            return ActuationOutcome(
                success=False,
                message="isolement refuse : le canal de l'agent doit rester ouvert "
                "pour que la levee de quarantaine reste possible",
            )
        raise NotImplementedError("LiveEdr.execute : brancher le client EDR du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur EDR en mode reel sans client configure")
        raise NotImplementedError("LiveEdr.rollback : lever l'action identifiee par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedEdr() if mode != "live" else LiveEdr(client)
