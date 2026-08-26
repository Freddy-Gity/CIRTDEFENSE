"""Actuateur de service : redémarrage et bascule (D3).

Le redémarrage est la seule action du catalogue dont la réversibilité est
paradoxale : on ne « derredemarre » pas un service. Ce qui est réversible,
c'est la bascule vers un nœud de secours — on rebascule. Pour le
redémarrage, l'annulation consiste à marquer l'opération comme annulée dans
la trace, le service restant demarre, ce qui est l'état souhaite de toute
façon. L'effet résiduel — l'interruption pendant le redémarrage — est
documenté au catalogue de réversibilité.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "restart_service",
    "cancel_restart",
    "failover",
    "failback",
    "close_idle_connections",
    "restore_connections",
)


class SimulatedService(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("service", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if verb == "failover" and not parameters.get("standby_node"):
            # Basculer sans savoir vers ou aggraverait l'indisponibilité.
            return ActuationOutcome(
                success=False,
                message="bascule refusée : aucun nœud de secours déclare",
            )
        return super().execute(verb, target, parameters)


class LiveService(Actuator):
    """Squelette d'intégration (systemd, orchestrateur de conteneurs,
    equilibreur de charge)."""

    name = "service"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de service en mode réel sans client configure")
        if verb == "failover" and not parameters.get("standby_node"):
            return ActuationOutcome(
                success=False, message="bascule refusée : aucun nœud de secours déclare"
            )
        raise NotImplementedError("LiveService.exécute : brancher le gestionnaire de services.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de service en mode réel sans client configure")
        raise NotImplementedError("LiveService.rollback : rebasculer vers le nœud nominal.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedService() if mode != "live" else LiveService(client)
