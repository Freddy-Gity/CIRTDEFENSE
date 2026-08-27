"""Dépendances partagees : instance de plateforme et contrôle de rôle."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status

from ..platform import Platform, build_platform
from ..security.access import is_admin
from ..security.tokens import token_fingerprint

_platform: Platform | None = None


def get_platform() -> Platform:
    global _platform
    if _platform is None:
        _platform = build_platform()
    return _platform


def set_platform(platform: Platform | None) -> None:
    """Injection utilisée par les tests."""
    global _platform
    _platform = platform


class Role(StrEnum):
    VIEWER = "viewer"
    DECIDEUR = "decideur"
    ANALYST = "analyst"
    ADMIN = "admin"


# Rôle stocké sur le compte → rôle effectif de contrôle d'accès de l'API.
_ROLE_DE_COMPTE = {
    "super_admin": Role.ADMIN,
    "admin": Role.ADMIN,
    "analyste": Role.ANALYST,
    "decideur": Role.DECIDEUR,
}


def _bearer(authorization: str | None) -> str:
    return (authorization or "").removeprefix("Bearer ").strip()


def current_user(
    platform: Annotated[Platform, Depends(get_platform)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any] | None:
    """Compte rattaché à la session porteuse, ou None (jeton de service, absent).

    Les jetons de service (``CIRT_ADMIN_TOKEN`` / ``CIRT_ANALYST_TOKEN``) ne
    portent pas de compte : ils restent réservés au déploiement et aux tests.
    """
    token = _bearer(authorization)
    if not token or token in (platform.settings.admin_token, platform.settings.analyst_token):
        return None
    user_id = platform.sessions.resolve(token_fingerprint(token))
    if user_id is None:
        return None
    user = platform.users.get(user_id)
    if user is None or user["status"] != "active":
        return None
    return user


def resolve_role(
    platform: Annotated[Platform, Depends(get_platform)],
    user: Annotated[dict[str, Any] | None, Depends(current_user)],
    authorization: Annotated[str | None, Header()] = None,
) -> Role:
    """Authentification par jeton porteur.

    Deux sources : (1) un jeton de service lu sur la plateforme active — la
    même instance qui porte la posture d'autonomie, la politique et les
    dépôts ; (2) une session ouverte à la connexion, rattachée à un compte.

    Sans jeton, le rôle est ``VIEWER`` (lecture seule). Un jeton présent mais
    inconnu est un 401 : mieux vaut un refus franc qu'une dégradation
    silencieuse en lecture seule.
    """
    settings = platform.settings
    token = _bearer(authorization)
    if not token:
        return Role.VIEWER
    if token == settings.admin_token:
        return Role.ADMIN
    if token == settings.analyst_token:
        return Role.ANALYST
    if user is not None:
        return _ROLE_DE_COMPTE.get(user["role"], Role.VIEWER)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="session invalide ou expirée"
    )


def require_admin(role: Annotated[Role, Depends(resolve_role)]) -> Role:
    if role is not Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="opération réservée à l'administrateur",
        )
    return role


def require_analyst(role: Annotated[Role, Depends(resolve_role)]) -> Role:
    if role not in (Role.ANALYST, Role.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="opération réservée à l'analyste ou à l'administrateur",
        )
    return role


def require_user(
    user: Annotated[dict[str, Any] | None, Depends(current_user)],
) -> dict[str, Any]:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="connexion requise")
    return user


def require_admin_user(
    user: Annotated[dict[str, Any], Depends(require_user)],
) -> dict[str, Any]:
    """Comme ``require_admin`` mais renvoie le compte — pour journaliser l'acteur
    et pour les gestes qui ne s'appuient pas sur un jeton de service."""
    if not is_admin(user["role"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="opération réservée à l'administrateur",
        )
    return user


def require_super_admin(
    user: Annotated[dict[str, Any], Depends(require_user)],
) -> dict[str, Any]:
    if user["role"] != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="opération réservée au super-administrateur",
        )
    return user


PlatformDep = Annotated[Platform, Depends(get_platform)]
AdminDep = Annotated[Role, Depends(require_admin)]
AnalystDep = Annotated[Role, Depends(require_analyst)]
RoleDep = Annotated[Role, Depends(resolve_role)]
CurrentUserDep = Annotated["dict[str, Any] | None", Depends(current_user)]
UserDep = Annotated["dict[str, Any]", Depends(require_user)]
AdminUserDep = Annotated["dict[str, Any]", Depends(require_admin_user)]
SuperAdminDep = Annotated["dict[str, Any]", Depends(require_super_admin)]
