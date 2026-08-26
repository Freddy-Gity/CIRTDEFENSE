"""Actuateur pare-feu : blocage et limitation de débit par adresse ou domaine.

Deux implantations coexistent : une simulation fidele au contrat et un
squelette d'intégration réelle. Le choix est fait par la configuration, jamais
par le code appelant — le moteur ne doit pas savoir s'il agit pour de vrai.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "block_ip",
    "unblock_ip",
    "rate_limit_ip",
    "clear_rate_limit",
    "block_domain",
    "unblock_domain",
)

PRIVATE_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")


def is_private(address: str) -> bool:
    """Une adresse interne demande davantage de prudence : le blocage y coupe
    un usage légitime plus souvent qu'il n'arrête un attaquant."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(r) for r in PRIVATE_RANGES)


class SimulatedFirewall(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("firewall", VERBS)


class LiveFirewall(Actuator):
    """Squelette d'intégration. à compléter avec le client de l'équipement du
    site (API REST du pare-feu, `nft`, `pf`, contrôleur SDN).

    Les vérifications faites ici — validite de l'adresse, refus des verbes non
    supportes — restent valables quel que soit l'équipement retenu et sont
    donc conservees dans le squelette.
    """

    name = "firewall"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        self._require_client()
        if not self.supports(verb):
            return ActuationOutcome(success=False, message=f"verbe non supporte : {verb}")
        if verb in ("block_ip", "rate_limit_ip"):
            try:
                ipaddress.ip_address(target)
            except ValueError:
                return ActuationOutcome(
                    success=False, message=f"cible '{target}' n'est pas une adresse IP valide"
                )
        raise NotImplementedError(
            "LiveFirewall.exécute : brancher ici le client du pare-feu du site. "
            "Le retour doit imperativement porter un rollback_token identifiant "
            "la règle créée, sans quoi la boucle EF-25 ne peut pas l'annuler."
        )

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        self._require_client()
        raise NotImplementedError(
            "LiveFirewall.rollback : supprimer la règle identifiée par `token`."
        )

    def health(self) -> bool:
        return self._client is not None

    def _require_client(self) -> None:
        if self._client is None:
            raise RuntimeError(
                "actuateur pare-feu en mode réel sans client configure ; "
                "vérifier CIRT_ACTUATION_MODE et l'injection du client"
            )


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedFirewall() if mode != "live" else LiveFirewall(client)
