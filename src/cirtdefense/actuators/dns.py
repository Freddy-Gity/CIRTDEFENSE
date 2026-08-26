"""Actuateur DNS : sinkhole et blocage de résolution.

Le sinkhole (A7) redirige la résolution d'un domaine de commande et contrôle
vers une adresse contrôlée. Il coupe le canal tout en permettant d'observer
quels hôtes tentent encore de le joindre — ce qui vaut mieux qu'un blocage
aveugle pour l'investigation qui suivra.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "sinkhole_domain",
    "release_domain",
    "block_resolution",
    "unblock_resolution",
)

PROTECTED_DOMAINS = frozenset(
    {
        "localhost",
        "gov.cm",
        "antic.cm",
        "cirt.cm",
    }
)
"""Domaines dont le détournement automatique paralyserait l'administration
ou couperait des services de l'État."""


class SimulatedDns(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("dns", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._is_protected(target):
            return ActuationOutcome(
                success=False,
                message=f"domaine '{target}' protege : détournement automatique refuse",
            )
        return super().execute(verb, target, parameters)

    @staticmethod
    def _is_protected(domain: str) -> bool:
        lowered = domain.lower().strip(".")
        return any(lowered == p or lowered.endswith(f".{p}") for p in PROTECTED_DOMAINS)


class LiveDns(Actuator):
    """Squelette d'intégration (BIND RPZ, Unbound, Pi-hole, resolveur du site)."""

    name = "dns"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur DNS en mode réel sans client configure")
        if SimulatedDns._is_protected(target):
            return ActuationOutcome(success=False, message=f"domaine '{target}' protege : refus")
        raise NotImplementedError("LiveDns.exécute : brancher le resolveur du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur DNS en mode réel sans client configure")
        raise NotImplementedError("LiveDns.rollback : retirer l'entrée identifiée par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedDns() if mode != "live" else LiveDns(client)
