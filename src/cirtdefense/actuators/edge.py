"""Actuateur de bordure : attenuation volumétrique en amont (A1).

Contre un DDoS volumétrique, aucune action locale ne suffit : le lien est
sature avant d'atteindre nos équipements. L'attenuation se joue chez
l'opérateur de transit ou le fournisseur de scrubbing.

Cet actuateur est donc, plus encore que les autres, un **point d'intégration**
avec un tiers. Les règles qu'il pose portent une durée de vie courte (TTL),
conformement au catalogue qui qualifie l'action de réversible précisément
parce qu'elle expire d'elle-même.
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
"""Durée de vie par défaut d'une règle de bordure. Une règle qui n'expire pas
cesserait d'être réversible en pratique : personne ne penserait à la retirer."""


class SimulatedEdge(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("edge", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        enriched = dict(parameters)
        enriched.setdefault("ttl_seconds", DEFAULT_TTL_SECONDS)
        return super().execute(verb, target, enriched)


class LiveEdge(Actuator):
    """Squelette d'intégration (opérateur de transit, Cloudflare Magic Transit,
    OVH VAC, annonce BGP FlowSpec)."""

    name = "edge"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de bordure en mode réel sans client configure")
        if verb == "blackhole_ip" and not parameters.get("ttl_seconds"):
            # Un blackhole sans expiration devient un blocage definitif que
            # personne ne retire : ce serait une action irreversible deguisee.
            return ActuationOutcome(
                success=False,
                message="blackhole refuse sans durée de vie : une règle qui "
                "n'expire pas n'est pas réversible en pratique",
            )
        raise NotImplementedError("LiveEdge.exécute : brancher l'API de l'opérateur.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur de bordure en mode réel sans client configure")
        raise NotImplementedError("LiveEdge.rollback : retirer l'annonce identifiée par `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedEdge() if mode != "live" else LiveEdge(client)
