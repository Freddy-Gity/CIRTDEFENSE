"""Actuateur de configuration : restauration d'une reference (D4).

Le catalogue conditionne la restauration automatique a un delta **mineur**.
Cette condition n'est pas decorative : restaurer une configuration de
reference obsolete ecraserait un changement legitime recent. L'actuateur
refuse donc au-dela d'un seuil de delta, et l'incident part alors en
notification.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "restore_baseline",
    "revert_restore",
    "close_port",
    "reopen_port",
)

MAX_MINOR_DELTA = 5
"""Nombre d'ecarts au-dela duquel la derive cesse d'etre « mineure »."""


class SimulatedConfiguration(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("config", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if verb == "restore_baseline":
            delta = int(parameters.get("delta_count", 0))
            if delta > MAX_MINOR_DELTA:
                return ActuationOutcome(
                    success=False,
                    message=f"restauration refusee : {delta} ecarts constates, "
                    f"au-dela du seuil de {MAX_MINOR_DELTA} qui definit une derive "
                    "mineure ; un changement legitime recent serait ecrase",
                )
        return super().execute(verb, target, parameters)


class LiveConfiguration(Actuator):
    """Squelette d'integration (Ansible, Puppet, SaltStack, gestionnaire de
    configuration reseau du site)."""

    name = "config"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de configuration en mode reel sans client configure")
        if verb == "restore_baseline" and int(parameters.get("delta_count", 0)) > MAX_MINOR_DELTA:
            return ActuationOutcome(
                success=False, message="restauration refusee : derive non mineure"
            )
        raise NotImplementedError(
            "LiveConfiguration.execute : brancher le gestionnaire de configuration. "
            "Relever imperativement la configuration courante AVANT restauration, "
            "faute de quoi `revert_restore` n'aurait rien a retablir."
        )

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de configuration en mode reel sans client configure")
        raise NotImplementedError(
            "LiveConfiguration.rollback : retablir la configuration relevee sous `token`."
        )

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedConfiguration() if mode != "live" else LiveConfiguration(client)
