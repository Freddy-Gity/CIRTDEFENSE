"""Actuateur pare-feu applicatif (WAF).

Couvre les reponses applicatives du catalogue : blocage de motif (B1, B4),
blocage de requete (B2), limitation de debit par IP ou session (A2, B6).

Une regle WAF est toujours reversible — elle se retire — mais son rayon
d'impact est plus large qu'une regle reseau : un motif trop general bloque du
trafic legitime. Le rayon declare dans les playbooks doit le refleter.
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
    """Squelette d'integration (ModSecurity, Cloudflare, AWS WAF, NAXSI)."""

    name = "waf"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur WAF en mode reel sans client configure")
        if verb == "block_pattern" and len(target) < 4:
            # Un motif trop court bloquerait une part enorme du trafic
            # legitime. Le refus est prefere a une coupure de service.
            return ActuationOutcome(
                success=False,
                message=f"motif '{target}' trop general : blocage refuse, "
                "le rayon d'impact serait indetermine",
            )
        raise NotImplementedError("LiveWaf.execute : brancher le client WAF du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur WAF en mode reel sans client configure")
        raise NotImplementedError("LiveWaf.rollback : retirer la regle identifiee par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedWaf() if mode != "live" else LiveWaf(client)
