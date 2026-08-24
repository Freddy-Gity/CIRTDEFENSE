"""Coupe-circuit global de l'autonomie (EF-26).

**Ce mecanisme ne reintroduit aucune validation par action.** C'est un
interrupteur systeme, a l'echelle de la plateforme entiere, pas un point de
controle sur le chemin d'une action donnee : quand il est ferme, chaque action
part sans qu'aucun humain ne l'ait vue ; quand il est ouvert, plus aucune ne
part du tout. L'autonomie totale est donc preservee au sens du CDCF §1.4.3.

Il repond a la question que la soutenance posera : « comment arretez-vous le
systeme s'il se trompe en boucle ? ». Sans lui, la seule reponse serait
d'eteindre le service, ce qui ferait aussi perdre la journalisation et la
capacite d'annuler les actions deja engagees — c'est-a-dire exactement les
moyens dont on a besoin au pire moment.

Deux voies de declenchement :

- **manuelle** : l'administrateur actionne l'interrupteur ;
- **automatique** : le systeme se coupe lui-meme quand il constate qu'il se
  trompe de facon repetee (annulations en rafale, echecs d'actuateurs en
  serie). Cette seconde voie est celle qui compte reellement, l'humain
  n'etant par construction pas devant l'ecran.

L'etat est persistant : un redemarrage ne doit pas relancer l'autonomie que
l'on venait d'interrompre.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from ..audit.ledger import AuditLedger
from ..domain.enums import ActionStatus, AuditEventType
from ..logging_setup import log_with
from ..persistence.repositories import ActionRepository, BreakerRepository

logger = logging.getLogger(__name__)


class BreakerState(StrEnum):
    CLOSED = "closed"
    """Autonomie active : les actions partent sans validation prealable."""
    OPEN = "open"
    """Autonomie suspendue : plus aucune action n'est executee."""


@dataclass(slots=True)
class BreakerStatus:
    state: BreakerState
    reason: str
    actor: str
    changed_at: str | None
    rollbacks_in_window: int = 0
    failures_in_window: int = 0
    rollback_threshold: int = 3
    failure_threshold: int = 5
    window_seconds: int = 600

    @property
    def autonomy_active(self) -> bool:
        return self.state is BreakerState.CLOSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "autonomy_active": self.autonomy_active,
            "reason": self.reason,
            "actor": self.actor,
            "changed_at": self.changed_at,
            "observations": {
                "rollbacks_in_window": self.rollbacks_in_window,
                "failures_in_window": self.failures_in_window,
                "rollback_threshold": self.rollback_threshold,
                "failure_threshold": self.failure_threshold,
                "window_seconds": self.window_seconds,
            },
        }


class CircuitBreaker:
    def __init__(
        self,
        repository: BreakerRepository,
        actions: ActionRepository,
        ledger: AuditLedger,
        *,
        enabled: bool = True,
        rollback_threshold: int = 3,
        failure_threshold: int = 5,
        window_seconds: int = 600,
    ) -> None:
        self._repository = repository
        self._actions = actions
        self._ledger = ledger
        self._enabled = enabled
        self._rollback_threshold = rollback_threshold
        self._failure_threshold = failure_threshold
        self._window = timedelta(seconds=window_seconds)

    @property
    def enabled(self) -> bool:
        """Si le coupe-circuit est desactive par configuration, l'exclusion du
        perimetre doit etre explicite et journalisee, jamais implicite."""
        return self._enabled

    def status(self) -> BreakerStatus:
        stored = self._repository.read()
        since = datetime.now(UTC) - self._window
        return BreakerStatus(
            state=BreakerState(stored.get("state", "closed")),
            reason=stored.get("reason", ""),
            actor=stored.get("actor", ""),
            changed_at=stored.get("changed_at"),
            rollbacks_in_window=self._actions.count_since(
                (ActionStatus.ROLLED_BACK.value, ActionStatus.ROLLBACK_FAILED.value), since
            ),
            failures_in_window=self._actions.count_since((ActionStatus.FAILED.value,), since),
            rollback_threshold=self._rollback_threshold,
            failure_threshold=self._failure_threshold,
            window_seconds=int(self._window.total_seconds()),
        )

    def allows_execution(self) -> bool:
        if not self._enabled:
            return True
        return self.status().autonomy_active

    # -- declenchement ------------------------------------------------------

    def trip(self, reason: str, actor: str = "system:breaker") -> BreakerStatus:
        """Ouvre le circuit. Idempotent : re-declencher n'ecrase pas le motif
        d'origine, qui est celui qui interesse l'enquete."""
        current = self.status()
        if current.state is BreakerState.OPEN:
            return current
        self._repository.write(BreakerState.OPEN.value, reason, actor)
        self._ledger.record(
            AuditEventType.BREAKER_TRIPPED,
            {
                "reason": reason,
                "rollbacks_in_window": current.rollbacks_in_window,
                "failures_in_window": current.failures_in_window,
                "window_seconds": current.window_seconds,
            },
            actor=actor,
        )
        log_with(
            logger,
            logging.CRITICAL,
            "COUPE-CIRCUIT OUVERT : execution autonome suspendue",
            reason=reason,
            actor=actor,
        )
        return self.status()

    def reset(self, actor: str, reason: str = "") -> BreakerStatus:
        """Referme le circuit. Reservee a l'administrateur : le systeme ne se
        readmet jamais tout seul, faute de pouvoir juger que la cause a
        disparu."""
        self._repository.write(BreakerState.CLOSED.value, reason or "rearmement manuel", actor)
        self._ledger.record(AuditEventType.BREAKER_RESET, {"reason": reason}, actor=actor)
        log_with(
            logger,
            logging.WARNING,
            "coupe-circuit referme : autonomie retablie",
            actor=actor,
            reason=reason,
        )
        return self.status()

    def evaluate_auto_trip(self) -> BreakerStatus:
        """A appeler apres chaque annulation ou echec.

        C'est la voie qui protege reellement : elle constate que le systeme se
        trompe en rafale et l'arrete, sans attendre qu'un humain s'en apercoive.
        """
        status = self.status()
        if not self._enabled or not status.autonomy_active:
            return status

        if status.rollbacks_in_window >= self._rollback_threshold:
            return self.trip(
                f"{status.rollbacks_in_window} annulations automatiques en "
                f"{status.window_seconds} s : le moteur produit des actions "
                "que la surveillance annule aussitot",
                actor="system:breaker",
            )
        if status.failures_in_window >= self._failure_threshold:
            return self.trip(
                f"{status.failures_in_window} echecs d'execution en "
                f"{status.window_seconds} s : les actuateurs ne repondent pas "
                "de facon fiable",
                actor="system:breaker",
            )
        return status
