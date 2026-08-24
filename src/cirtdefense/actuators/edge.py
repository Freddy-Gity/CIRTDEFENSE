"""Actuateur de bordure : attenuation volumetrique en amont (A1).

Contre un DDoS volumetrique, aucune action locale ne suffit : le lien est
sature avant d'atteindre nos equipements. L'attenuation se joue chez
l'operateur de transit ou le fournisseur de scrubbing.

Cet actuateur est donc, plus encore que les autres, un **point d'integration**
avec un tiers. Les regles qu'il pose portent une duree de vie courte (TTL),
conformement au catalogue qui qualifie l'action de reversible precisement
parce qu'elle expire d'elle-meme.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "enable_scrubbing",
    "disable_scrubbing",
    "blackhole_ip",
    "release_blackhole",
    "edge_rate_limit",
    "clear_edge_rate_limit",
)

DEFAULT_TTL_SECONDS = 900
"""Duree de vie par defaut d'une regle de bordure. Une regle qui n'expire pas
cesserait d'etre reversible en pratique : personne ne penserait a la retirer."""


class SimulatedEdge(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("edge", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        enriched = dict(parameters)
        enriched.setdefault("ttl_seconds", DEFAULT_TTL_SECONDS)
        return super().execute(verb, target, enriched)


class LiveEdge(Actuator):
    """Squelette d'integration (operateur de transit, Cloudflare Magic Transit,
    OVH VAC, annonce BGP FlowSpec)."""

    name = "edge"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de bordure en mode reel sans client configure")
        if verb == "blackhole_ip" and not parameters.get("ttl_seconds"):
            # Un blackhole sans expiration devient un blocage definitif que
            # personne ne retire : ce serait une action irreversible deguisee.
            return ActuationOutcome(
                success=False,
                message="blackhole refuse sans duree de vie : une regle qui "
                "n'expire pas n'est pas reversible en pratique",
            )
        raise NotImplementedError("LiveEdge.execute : brancher l'API de l'operateur.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de bordure en mode reel sans client configure")
        raise NotImplementedError("LiveEdge.rollback : retirer l'annonce identifiee par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedEdge() if mode != "live" else LiveEdge(client)
