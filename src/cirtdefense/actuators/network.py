"""Actuateur réseau : limitation de débit sortant, bascule de VLAN."""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "throttle_egress",
    "clear_egress_throttle",
    "move_to_vlan",
    "restore_vlan",
    # Coupure d'une connexion sortante précise (A5) : plus chirurgical qu'une
    # limitation de débit, qui laisse le transfert aboutir plus lentement.
    "cut_egress_connection",
    "restore_egress_connection",
    # Blocage des protocoles de propagation latérale (A6) : SMB, RDP, WinRM.
    # Distinct de l'isolement complet, qui coupe aussi le trafic légitime.
    "block_lateral",
    "unblock_lateral",
)


class SimulatedNetwork(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("network", VERBS)


class LiveNetwork(Actuator):
    """Squelette d'intégration (commutateur, contrôleur SDN, NAC)."""

    name = "network"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur réseau en mode réel sans client configure")
        if verb == "move_to_vlan" and not parameters.get("previous_vlan"):
            # Sans le VLAN d'origine, `restore_vlan` ne saurait pas quoi
            # rétablir. On refuse plutôt que de rendre l'action irréversible.
            return ActuationOutcome(
                success=False,
                message="bascule refusée : le VLAN d'origine doit être releve "
                "avant la bascule pour que le retour arrière soit possible",
            )
        raise NotImplementedError("LiveNetwork.exécute : brancher le client réseau du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur réseau en mode réel sans client configure")
        raise NotImplementedError("LiveNetwork.rollback : rétablir l'état memorise sous `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedNetwork() if mode != "live" else LiveNetwork(client)
