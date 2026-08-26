"""Contrat commun des actuateurs."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..logging_setup import log_with

logger = logging.getLogger(__name__)


class ActuatorError(RuntimeError):
    """Échec d'exécution cote équipement."""


class RollbackError(RuntimeError):
    """Échec d'annulation. Situation la plus grave du système : une action a
    été appliquée sans pouvoir être retirée."""


@dataclass(slots=True)
class ActuationOutcome:
    """Ce que rend un actuateur après exécution."""

    success: bool
    rollback_token: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    already_applied: bool = False
    """Vrai si l'état cible était déjà en place (idempotence)."""


class Actuator(ABC):
    """Un connecteur vers un équipement ou un service."""

    name: str = "abstract"
    supported_verbs: tuple[str, ...] = ()

    def supports(self, verb: str) -> bool:
        return verb in self.supported_verbs

    @abstractmethod
    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        """Applique le verbe. Doit être idempotent."""

    @abstractmethod
    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        """Annule une exécution identifiée par son jeton."""

    def health(self) -> bool:
        """L'équipement répond-il ? Un actuateur en panne doit être connu du
        moteur *avant* qu'il ne planifie une action qui en dépend."""
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verbs": list(self.supported_verbs),
            "healthy": self.health(),
        }


class ActuatorRegistry:
    def __init__(self) -> None:
        self._actuators: dict[str, Actuator] = {}

    def register(self, actuator: Actuator) -> None:
        self._actuators[actuator.name] = actuator
        log_with(
            logger,
            logging.INFO,
            "actuateur enregistre",
            actuator=actuator.name,
            verbs=list(actuator.supported_verbs),
        )

    def get(self, name: str) -> Actuator | None:
        return self._actuators.get(name)

    def require(self, name: str) -> Actuator:
        actuator = self._actuators.get(name)
        if actuator is None:
            raise ActuatorError(f"actuateur '{name}' non enregistré")
        return actuator

    def names(self) -> list[str]:
        return sorted(self._actuators)

    def can_handle(self, actuator_name: str, verb: str) -> bool:
        actuator = self._actuators.get(actuator_name)
        return actuator is not None and actuator.supports(verb)

    def describe(self) -> list[dict[str, Any]]:
        return [a.describe() for a in self._actuators.values()]
