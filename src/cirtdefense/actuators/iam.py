"""Actuateur annuaire : désactivation de compte, révocation de sessions.

Ces actions touchent des personnes. Le rayon d'impact déclare doit refleter
le nombre d'utilisateurs affectes : désactiver un compte de service utilise
par plusieurs traitements ne vaut pas désactiver un compte nominatif.
"""

from __future__ import annotations

from typing import Any

from .base import ActuationOutcome, Actuator
from .simulation import SimulatedActuator

VERBS: tuple[str, ...] = (
    "disable_account",
    "enable_account",
    "revoke_sessions",
    "noop_restore_sessions",
    "force_password_reset",
    "cancel_password_reset",
    # Verrouillage temporaire (A4) : distinct de la désactivation, il expire
    # de lui-même et gêne moins l'utilisateur légitime.
    "lock_account",
    "unlock_account",
    # Forçage MFA à la prochaine connexion (A4, C4)
    "force_mfa",
    "clear_mfa_requirement",
    # Jeton d'API (B6)
    "revoke_token",
    "reissue_token",
    # Privilège accorde hors processus (C1)
    "revoke_privilege",
    "restore_privilege",
    # Accès à une ressource hors profil (C2)
    "block_resource_access",
    "restore_resource_access",
    # Droits d'écriture/export (C3)
    "restrict_export",
    "restore_export",
)

PROTECTED_ACCOUNTS = frozenset({"administrator", "root", "admin", "krbtgt", "svc-backup"})
"""Comptes dont la désactivation automatique paralyserait l'administration —
y compris celle qui permettrait de reparer une erreur du système."""


class SimulatedIam(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("iam", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if verb == "disable_account" and target.lower() in PROTECTED_ACCOUNTS:
            return ActuationOutcome(
                success=False,
                message=f"compte '{target}' protege : désactivation automatique refusée, "
                "sous peine de perdre le moyen de corriger une erreur du système",
            )
        return super().execute(verb, target, parameters)


class LiveIam(Actuator):
    """Squelette d'intégration (LDAP, Active Directory, Keycloak, Entra ID)."""

    name = "iam"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur IAM en mode réel sans client configure")
        if verb == "disable_account" and target.lower() in PROTECTED_ACCOUNTS:
            return ActuationOutcome(
                success=False, message=f"compte '{target}' protege : désactivation refusée"
            )
        raise NotImplementedError("LiveIam.exécute : brancher le client d'annuaire du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur IAM en mode réel sans client configure")
        raise NotImplementedError("LiveIam.rollback : rétablir l'état memorise sous `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedIam() if mode != "live" else LiveIam(client)
