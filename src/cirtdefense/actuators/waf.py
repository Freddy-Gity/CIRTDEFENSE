"""Actuateur pare-feu applicatif (WAF).

Couvre les réponses applicatives du catalogue : blocage de motif (B1, B4),
blocage de requête (B2), limitation de débit par IP ou session (A2, B6).

Une règle WAF est toujours réversible — elle se retire — mais son rayon
d'impact est plus large qu'une règle réseau : un motif trop général bloque du
trafic légitime. Le rayon déclare dans les playbooks doit le refleter.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "block_pattern",
    "unblock_pattern",
    "block_request",
    "unblock_request",
    "rate_limit_rule",
    "clear_rate_limit_rule",
    "sanitize_field",
    "clear_sanitize_field",
)


class SimulatedWaf(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("waf", VERBS)


class LiveWaf(Actuator):
    """Squelette d'intégration (ModSecurity, Cloudflare, AWS WAF, NAXSI)."""

    name = "waf"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur WAF en mode réel sans client configure")
        if verb == "block_pattern" and len(target) < 4:
            # Un motif trop court bloquerait une part enorme du trafic
            # legitime. Le refus est prefere a une coupure de service.
            return ActuationOutcome(
                success=False,
                message=f"motif '{target}' trop général : blocage refuse, "
                "le rayon d'impact serait indetermine",
            )
        raise NotImplementedError("LiveWaf.exécute : brancher le client WAF du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur WAF en mode réel sans client configure")
        raise NotImplementedError("LiveWaf.rollback : retirer la règle identifiée par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedWaf() if mode != "live" else LiveWaf(client)
