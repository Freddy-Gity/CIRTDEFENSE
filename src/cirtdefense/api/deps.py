"""Dependances partagees : instance de plateforme et contrôle de rôle."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from ..platform import Platform, build_platform

_platform: Platform | None = None


def get_platform() -> Platform:
    global _platform
    if _platform is None:
        _platform = build_platform()
    return _platform


def set_platform(platform: Platform | None) -> None:
    """Injection utilisee par les tests."""
    global _platform
    _platform = platform


class Role(StrEnum):
    ANALYST = "analyst"
    ADMIN = "admin"
    VIEWER = "viewer"


def resolve_role(
    platform: Annotated[Platform, Depends(get_platform)],
    authorization: Annotated[str | None, Header()] = None,
) -> Role:
    """Authentification par jeton porteur.

    Les jetons sont lus sur la plateforme active, et non sur la configuration
    globale : c'est la même instance qui porte la posture d'autonomie, la
    politique et les dépôts. Deux sources de configuration distinctes
    finiraient par diverger, et l'écart porterait précisément sur qui à le
    droit d'arrêter le système.

    Volontairement minimale par ailleurs : l'intégration a l'annuaire du CIRT
    releve du déploiement et non du prototype. Ce qui compte ici est que la
    separation des rôles existe et soit vérifiée à chaque appel sensible.
    """
    settings = platform.settings
    if not authorization:
        return Role.VIEWER
    token = authorization.removeprefix("Bearer ").strip()
    if token == settings.admin_token:
        return Role.ADMIN
    if token == settings.analyst_token:
        return Role.ANALYST
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="jeton d'authentification invalide"
    )


def require_admin(role: Annotated[Role, Depends(resolve_role)]) -> Role:
    if role is not Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="opération reservee a l'administrateur",
        )
    return role


def require_analyst(role: Annotated[Role, Depends(resolve_role)]) -> Role:
    if role not in (Role.ANALYST, Role.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="opération reservee a l'analyste ou a l'administrateur",
        )
    return role


PlatformDep = Annotated[Platform, Depends(get_platform)]
AdminDep = Annotated[Role, Depends(require_admin)]
AnalystDep = Annotated[Role, Depends(require_analyst)]
