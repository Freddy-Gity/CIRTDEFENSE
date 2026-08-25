"""Actuateur de simulation : applique l'état en mémoire, sans effet réel.

Sert à trois choses, toutes indispensables au projet :
- la recette et la démonstration en soutenance, ou aucun équipement réel
  n'est mobilise ;
- les tests automatises de la boucle EF-25 ;
- l'exploitation en mode `simulation`, ou la plateforme raisonne et journalise
  exactement comme en production mais n'agit pas.

Le mode d'actionnement est une donnée de configuration journalisée : un
auditeur doit pouvoir dire si une action tracee a réellement eu lieu.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .base import ActuationOutcome, Actuator


@dataclass(slots=True)
class AppliedState:
    token: str
    verb: str
    target: str
    parameters: dict[str, Any]
    applied_at: datetime
    rolled_back_at: datetime | None = None
    previous_state: dict[str, Any] = field(default_factory=dict)
    """État d'avant, memorise pour permettre une annulation exacte."""


class SimulatedActuator(Actuator):
    """Implantation de référence du contrat, tenant un état cohérent."""

    def __init__(self, name: str, verbs: tuple[str, ...], healthy: bool = True) -> None:
        self.name = name
        self.supported_verbs = verbs
        self._healthy = healthy
        self._state: dict[str, AppliedState] = {}
        self._by_key: dict[str, str] = {}
        self.failure_verbs: set[str] = set()
        """Verbes forces en échec : sert à éprouver le traitement d'erreur."""
        self.rollback_failure_verbs: set[str] = set()

    # -- contrat ------------------------------------------------------------

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if verb in self.failure_verbs:
            return ActuationOutcome(success=False, message=f"échec simule de '{verb}' sur {target}")

        key = f"{verb}:{target}"
        existing_token = self._by_key.get(key)
        if existing_token and self._state[existing_token].rolled_back_at is None:
            # Idempotence : l'état cible est déjà en place, on rend le même
            # jeton plutôt que d'empiler une seconde application.
            return ActuationOutcome(
                success=True,
                rollback_token=existing_token,
                already_applied=True,
                message=f"'{verb}' déjà appliqué sur {target}",
                details={"target": target, "verb": verb},
            )

        token = f"tok_{uuid.uuid4().hex[:12]}"
        self._state[token] = AppliedState(
            token=token,
            verb=verb,
            target=target,
            parameters=dict(parameters),
            applied_at=datetime.now(UTC),
            previous_state=self._capture_previous(verb, target, parameters),
        )
        self._by_key[key] = token
        return ActuationOutcome(
            success=True,
            rollback_token=token,
            details={"target": target, "verb": verb, "parameters": parameters},
            message=f"'{verb}' applique sur {target} (simulation)",
        )

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if verb in self.rollback_failure_verbs:
            return ActuationOutcome(success=False, message=f"échec simule d'annulation de '{verb}'")

        state = self._state.get(token)
        if state is None:
            return ActuationOutcome(success=False, message=f"jeton d'annulation inconnu : {token}")
        if state.rolled_back_at is not None:
            # Idempotence de l'annulation : la boucle EF-25 et un rollback
            # manuel de l'analyste peuvent viser la même action.
            return ActuationOutcome(
                success=True,
                already_applied=True,
                message="action déjà annulée",
                details={"token": token},
            )
        state.rolled_back_at = datetime.now(UTC)
        self._by_key.pop(f"{state.verb}:{state.target}", None)
        return ActuationOutcome(
            success=True,
            details={"token": token, "restored": state.previous_state},
            message=f"'{state.verb}' annule sur {state.target} (simulation)",
        )

    def health(self) -> bool:
        return self._healthy

    # -- introspection, utilisée par les tests et l'interface ---------------

    def set_healthy(self, healthy: bool) -> None:
        self._healthy = healthy

    def active_states(self) -> list[AppliedState]:
        return [s for s in self._state.values() if s.rolled_back_at is None]

    def is_applied(self, verb: str, target: str) -> bool:
        token = self._by_key.get(f"{verb}:{target}")
        return token is not None and self._state[token].rolled_back_at is None

    def _capture_previous(
        self, verb: str, target: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        """Memorise ce qu'il faudra rétablir. Une annulation qui ne sait pas
        d'ou elle vient n'est pas une annulation."""
        if verb == "move_to_vlan":
            return {"vlan": parameters.get("previous_vlan", "vlan-production")}
        if verb == "throttle_egress":
            return {"bandwidth_mbps": parameters.get("previous_bandwidth_mbps", 1000)}
        return {}
