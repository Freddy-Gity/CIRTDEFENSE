"""Actuateur de service : redemarrage et bascule (D3).

Le redemarrage est la seule action du catalogue dont la reversibilite est
paradoxale : on ne « derredemarre » pas un service. Ce qui est reversible,
c'est la bascule vers un noeud de secours — on rebascule. Pour le
redemarrage, l'annulation consiste a marquer l'operation comme annulee dans
la trace, le service restant demarre, ce qui est l'etat souhaite de toute
facon. L'effet residuel — l'interruption pendant le redemarrage — est
documente au catalogue de reversibilite.
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
            # Basculer sans savoir vers ou aggraverait l'indisponibilite.
            return ActuationOutcome(
                success=False,
                message="bascule refusee : aucun noeud de secours declare",
            )
        return super().execute(verb, target, parameters)


class LiveService(Actuator):
    """Squelette d'integration (systemd, orchestrateur de conteneurs,
    equilibreur de charge)."""

    name = "service"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de service en mode reel sans client configure")
        if verb == "failover" and not parameters.get("standby_node"):
            return ActuationOutcome(
                success=False, message="bascule refusee : aucun noeud de secours declare"
            )
        raise NotImplementedError("LiveService.execute : brancher le gestionnaire de services.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de service en mode reel sans client configure")
        raise NotImplementedError("LiveService.rollback : rebasculer vers le noeud nominal.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedService() if mode != "live" else LiveService(client)
