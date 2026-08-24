"""Actuateur annuaire : desactivation de compte, revocation de sessions.

Ces actions touchent des personnes. Le rayon d'impact declare doit refleter
le nombre d'utilisateurs affectes : desactiver un compte de service utilise
par plusieurs traitements ne vaut pas desactiver un compte nominatif.
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
    # Verrouillage temporaire (A4) : distinct de la desactivation, il expire
    # de lui-meme et gene moins l'utilisateur legitime.
    "lock_account",
    "unlock_account",
    # Forcage MFA a la prochaine connexion (A4, C4)
    "force_mfa",
    "clear_mfa_requirement",
    # Jeton d'API (B6)
    "revoke_token",
    "reissue_token",
    # Privilege accorde hors processus (C1)
    "revoke_privilege",
    "restore_privilege",
    # Acces a une ressource hors profil (C2)
    "block_resource_access",
    "restore_resource_access",
    # Droits d'ecriture/export (C3)
    "restrict_export",
    "restore_export",
)

PROTECTED_ACCOUNTS = frozenset({"administrator", "root", "admin", "krbtgt", "svc-backup"})
"""Comptes dont la desactivation automatique paralyserait l'administration —
y compris celle qui permettrait de reparer une erreur du systeme."""


class SimulatedIam(SimulatedActuator):
    def __init__(self) -> None:
        super().__init__("iam", VERBS)

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if verb == "disable_account" and target.lower() in PROTECTED_ACCOUNTS:
            return ActuationOutcome(
                success=False,
                message=f"compte '{target}' protege : desactivation automatique refusee, "
                "sous peine de perdre le moyen de corriger une erreur du systeme",
            )
        return super().execute(verb, target, parameters)


class LiveIam(Actuator):
    """Squelette d'integration (LDAP, Active Directory, Keycloak, Entra ID)."""

    name = "iam"
    supported_verbs = VERBS

    def __init__(self, client: Any = None) -> None:
        self._client = client

    def execute(self, verb: str, target: str, parameters: dict[str, Any]) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur IAM en mode reel sans client configure")
        if verb == "disable_account" and target.lower() in PROTECTED_ACCOUNTS:
            return ActuationOutcome(
                success=False, message=f"compte '{target}' protege : desactivation refusee"
            )
        raise NotImplementedError("LiveIam.execute : brancher le client d'annuaire du site.")

    def rollback(
        self, verb: str, target: str, token: str, parameters: dict[str, Any]
    ) -> ActuationOutcome:
        if self._client is None:
            raise RuntimeError("actuateur IAM en mode reel sans client configure")
        raise NotImplementedError("LiveIam.rollback : retablir l'etat memorise sous `token`.")

    def health(self) -> bool:
        return self._client is not None


def build(mode: str = "simulation", client: Any = None) -> Actuator:
    return SimulatedIam() if mode != "live" else LiveIam(client)
