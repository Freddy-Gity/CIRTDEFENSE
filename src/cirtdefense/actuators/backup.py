"""Actuateur de sauvegarde : declenchement de snapshot (A6).

Face a un rancongiciel, le catalogue prescrit le declenchement d'un
snapshot « si disponible ». C'est la seule action du catalogue qui *cree*
quelque chose au lieu de restreindre, et sa reversibilite est particuliere :
annuler revient a supprimer le snapshot, ce qu'on ne fait jamais
automatiquement. L'annulation est donc un simple demarquage — le snapshot
reste, il cesse seulement d'etre rattache a l'incident.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = ("trigger_snapshot", "unlink_snapshot")


class SimulatedBackup(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("backup", VERBS)


class LiveBackup(Actuator):
    """Squelette d'integration (Veeam, Bacula, snapshots LVM/ZFS, API du
    fournisseur de virtualisation)."""

    name = "backup"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de sauvegarde en mode reel sans client configure")
        raise NotImplementedError("LiveBackup.execute : brancher le client de sauvegarde.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de sauvegarde en mode reel sans client configure")
        # Volontairement : on ne supprime jamais un snapshot automatiquement.
        raise NotImplementedError(
            "LiveBackup.rollback : detacher le snapshot de l'incident SANS le supprimer."
        )

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedBackup() if mode != "live" else LiveBackup(client)
