"""Administration des comptes et des postes (réservé aux administrateurs).

Validation des inscriptions d'analystes, promotion analyste → administrateur,
suspension, et gestion des postes ouverts au sein du CIRT/ANTIC (dont la
création des identifiants d'un décideur).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from ...security.passwords import hash_password
from ..deps import AdminUserDep, PlatformDep, SuperAdminDep
from ..schemas import DecideurRequest, PosteRequest, PosteUpdateRequest

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])


def _public_user(u: dict[str, Any]) -> dict[str, Any]:
    return {
        k: u[k]
        for k in (
            "user_id",
            "username",
            "email",
            "nom",
            "prenom",
            "civility",
            "poste",
            "kind",
            "role",
            "status",
            "created_at",
            "validated_by",
            "validated_at",
            "last_login_at",
        )
    }


def _acteur(admin: dict[str, Any]) -> str:
    return f"human:{admin['role']}:{admin['username']}"


# --------------------------------------------------------------- comptes


@router.get("/users")
def list_users(
    platform: PlatformDep, _: AdminUserDep, status_filter: str = "", role: str = ""
) -> dict[str, Any]:
    users = platform.users.list(status=status_filter, role=role)
    return {
        "users": [_public_user(u) for u in users],
        "pending": sum(1 for u in users if u["status"] == "pending"),
    }


def _get_or_404(platform: PlatformDep, user_id: str) -> dict[str, Any]:
    user = platform.users.get(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "compte inconnu")
    return user


@router.post("/users/{user_id}/admit")
def admit(platform: PlatformDep, admin: AdminUserDep, user_id: str) -> dict[str, Any]:
    """Admet une inscription d'analyste en attente (le compte devient actif)."""
    user = _get_or_404(platform, user_id)
    if user["status"] != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "ce compte n'est pas en attente")
    platform.users.set_status(user_id, "active", by=admin["username"])
    platform.ledger.record(
        "account.admit",
        {"username": user["username"], "poste": user["poste"]},
        actor=_acteur(admin),
    )
    return _public_user(_get_or_404(platform, user_id))


@router.post("/users/{user_id}/decline")
def decline(platform: PlatformDep, admin: AdminUserDep, user_id: str) -> dict[str, Any]:
    """Écarte une inscription en attente."""
    user = _get_or_404(platform, user_id)
    if user["status"] != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "ce compte n'est pas en attente")
    platform.users.set_status(user_id, "refused", by=admin["username"])
    platform.ledger.record("account.decline", {"username": user["username"]}, actor=_acteur(admin))
    return _public_user(_get_or_404(platform, user_id))


@router.post("/users/{user_id}/suspend")
def suspend(platform: PlatformDep, admin: AdminUserDep, user_id: str) -> dict[str, Any]:
    user = _get_or_404(platform, user_id)
    if user["user_id"] == admin["user_id"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "vous ne pouvez pas suspendre votre propre compte"
        )
    if user["role"] == "super_admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "le super-administrateur ne se suspend pas")
    platform.users.set_status(user_id, "suspended", by=admin["username"])
    platform.sessions.close_all_for(user_id)
    platform.ledger.record("auth.suspend", {"username": user["username"]}, actor=_acteur(admin))
    return _public_user(_get_or_404(platform, user_id))


@router.post("/users/{user_id}/reactivate")
def reactivate(platform: PlatformDep, admin: AdminUserDep, user_id: str) -> dict[str, Any]:
    user = _get_or_404(platform, user_id)
    if user["status"] not in ("suspended", "refused"):
        raise HTTPException(status.HTTP_409_CONFLICT, "ce compte est déjà actif ou en attente")
    platform.users.set_status(user_id, "active", by=admin["username"])
    platform.ledger.record("auth.reactivate", {"username": user["username"]}, actor=_acteur(admin))
    return _public_user(_get_or_404(platform, user_id))


@router.post("/users/{user_id}/promote")
def promote(platform: PlatformDep, admin: SuperAdminDep, user_id: str) -> dict[str, Any]:
    """Promeut un analyste au rôle d'administrateur (débloque les vues admin)."""
    user = _get_or_404(platform, user_id)
    if user["role"] != "analyste":
        raise HTTPException(status.HTTP_409_CONFLICT, "seul un analyste peut être promu")
    platform.users.set_role(user_id, "admin")
    platform.ledger.record("auth.promote", {"username": user["username"]}, actor=_acteur(admin))
    return _public_user(_get_or_404(platform, user_id))


@router.post("/users/{user_id}/demote")
def demote(platform: PlatformDep, admin: SuperAdminDep, user_id: str) -> dict[str, Any]:
    user = _get_or_404(platform, user_id)
    if user["role"] != "admin":
        raise HTTPException(status.HTTP_409_CONFLICT, "ce compte n'est pas administrateur")
    platform.users.set_role(user_id, "analyste")
    platform.ledger.record("auth.demote", {"username": user["username"]}, actor=_acteur(admin))
    return _public_user(_get_or_404(platform, user_id))


@router.post("/users/{user_id}/transfer-superadmin")
def transfer_superadmin(
    platform: PlatformDep, admin: SuperAdminDep, user_id: str
) -> dict[str, Any]:
    """Transfère le rôle de super-administrateur à un autre **administrateur**.

    L'ancien super-administrateur redevient administrateur : il reste un seul
    super-administrateur à tout instant.
    """
    cible = _get_or_404(platform, user_id)
    if cible["user_id"] == admin["user_id"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "vous êtes déjà super-administrateur")
    if cible["role"] != "admin":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "seul un administrateur peut recevoir le rôle de super-administrateur",
        )
    platform.users.set_role(cible["user_id"], "super_admin")
    platform.users.set_role(admin["user_id"], "admin")
    platform.ledger.record(
        "account.transfer_superadmin",
        {"de": admin["username"], "vers": cible["username"]},
        actor=_acteur(admin),
    )
    return {
        "nouveau_super_admin": cible["username"],
        "votre_role": "admin",
    }


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(platform: PlatformDep, admin: SuperAdminDep, user_id: str) -> None:
    """Suppression définitive d'un compte — réservée au super-administrateur."""
    user = _get_or_404(platform, user_id)
    if user["user_id"] == admin["user_id"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "vous ne pouvez pas supprimer votre propre compte"
        )
    if user["role"] == "super_admin":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "le compte super-administrateur ne se supprime pas"
        )
    platform.sessions.close_all_for(user_id)
    platform.users.delete(user_id)
    platform.ledger.record(
        "account.delete",
        {"username": user["username"], "role": user["role"], "poste": user["poste"]},
        actor=_acteur(admin),
    )


# ---------------------------------------------------------------- postes


@router.get("/postes")
def list_postes(platform: PlatformDep, _: AdminUserDep, kind: str = "") -> dict[str, Any]:
    return {"postes": platform.postes.list(kind=kind)}


@router.post("/postes", status_code=status.HTTP_201_CREATED)
def create_poste(body: PosteRequest, platform: PlatformDep, admin: AdminUserDep) -> dict[str, Any]:
    if platform.postes.label_taken(body.kind, body.label):
        raise HTTPException(status.HTTP_409_CONFLICT, "un poste porte déjà ce libellé")
    poste = platform.postes.create(
        kind=body.kind, label=body.label, civility=body.civility, by=admin["username"]
    )
    platform.ledger.record(
        "poste.create", {"kind": body.kind, "label": body.label}, actor=_acteur(admin)
    )
    return poste


@router.patch("/postes/{poste_id}")
def update_poste(
    poste_id: str, body: PosteUpdateRequest, platform: PlatformDep, admin: AdminUserDep
) -> dict[str, Any]:
    if platform.postes.get(poste_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "poste inconnu")
    platform.postes.update(poste_id, label=body.label, civility=body.civility, active=body.active)
    platform.ledger.record("poste.update", {"poste_id": poste_id}, actor=_acteur(admin))
    poste = platform.postes.get(poste_id)
    assert poste is not None
    return poste


@router.delete("/postes/{poste_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_poste(poste_id: str, platform: PlatformDep, admin: AdminUserDep) -> None:
    if not platform.postes.delete(poste_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "poste inconnu")
    platform.ledger.record("poste.delete", {"poste_id": poste_id}, actor=_acteur(admin))


@router.post("/decideurs", status_code=status.HTTP_201_CREATED)
def create_decideur(
    body: DecideurRequest, platform: PlatformDep, admin: AdminUserDep
) -> dict[str, Any]:
    """Crée le compte d'un poste de décideur (identifiants remis en main propre)."""
    poste = platform.postes.get(body.poste_id)
    if poste is None or poste["kind"] != "decideur":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "poste de décideur inconnu")
    if platform.users.list(kind="decideur", status="active"):
        deja = {u["poste"] for u in platform.users.list(kind="decideur")}
        if poste["label"] in deja:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "ce poste a déjà un compte ; suspendez l'ancien d'abord"
            )
    if platform.users.username_taken(body.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "nom d'utilisateur déjà pris")

    user = platform.users.create(
        username=body.username,
        password_hash=hash_password(body.password),
        kind="decideur",
        role="decideur",
        status="active",
        nom=body.nom,
        prenom=body.prenom,
        civility=body.civility,
        poste=poste["label"],
        validated_by=admin["username"],
    )
    platform.ledger.record(
        "auth.decideur_create",
        {"username": user["username"], "poste": poste["label"]},
        actor=_acteur(admin),
    )
    return _public_user(user)
