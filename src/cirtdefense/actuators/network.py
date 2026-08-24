"""Actuateur reseau : limitation de debit sortant, bascule de VLAN."""

from __future__ import annotations

from typing import Any

from .base import Actuator, ActuationOutcome
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "throttle_egress", "clear_egress_throttle",
    "move_to_vlan", "restore_vlan",
)


class SimulatedNetwork(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("network", VERBS)


class LiveNetwork(Actuator):
    """Squelette d'integration (commutateur, controleur SDN, NAC)."""

    name = "network"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur reseau en mode reel sans client configure")
        if verb == "move_to_vlan" and not parameters.get("previous_vlan"):
            # Sans le VLAN d'origine, `restore_vlan` ne saurait pas quoi
            # retablir. On refuse plutot que de rendre l'action irreversible.
            return ActuationOutcome(
                success=False,
                message="bascule refusee : le VLAN d'origine doit etre releve "
                "avant la bascule pour que le retour arriere soit possible",
            )
        raise NotImplementedError("LiveNetwork.execute : brancher le client reseau du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur reseau en mode reel sans client configure")
        raise NotImplementedError("LiveNetwork.rollback : retablir l'etat memorise sous `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedNetwork() if mode != "live" else LiveNetwork(client)
