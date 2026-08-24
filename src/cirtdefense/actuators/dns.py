"""Actuateur DNS : sinkhole et blocage de resolution.

Le sinkhole (A7) redirige la resolution d'un domaine de commande et controle
vers une adresse controlee. Il coupe le canal tout en permettant d'observer
quels hotes tentent encore de le joindre — ce qui vaut mieux qu'un blocage
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
"""Domaines dont le detournement automatique paralyserait l'administration
ou couperait des services de l'Etat."""


class SimulatedDns(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("dns", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._is_protected(target):
            return ActuationOutcome(
                success=False,
                message=f"domaine '{target}' protege : detournement automatique refuse",
            )
        return super().execute(verb, target, parameters)

    @staticmethod
    def _is_protected(domain: str) -> bool:
        lowered = domain.lower().strip(".")
        return any(lowered == p or lowered.endswith(f".{p}") for p in PROTECTED_DOMAINS)


class LiveDns(Actuator):
    """Squelette d'integration (BIND RPZ, Unbound, Pi-hole, resolveur du site)."""

    name = "dns"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur DNS en mode reel sans client configure")
        if SimulatedDns._is_protected(target):
            return ActuationOutcome(success=False, message=f"domaine '{target}' protege : refus")
        raise NotImplementedError("LiveDns.execute : brancher le resolveur du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur DNS en mode reel sans client configure")
        raise NotImplementedError("LiveDns.rollback : retirer l'entree identifiee par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedDns() if mode != "live" else LiveDns(client)
