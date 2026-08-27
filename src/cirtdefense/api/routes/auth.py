"""Authentification et parcours de connexion (CDCF v3.0 — séparation des rôles).

La plateforme distingue quatre rôles : super-administrateur, administrateur,
analyste, décideur. Le super-administrateur est créé au tout premier lancement
par l'écran d'installation ; les analystes s'inscrivent et attendent une
validation ; les décideurs reçoivent des identifiants remis par un
administrateur.

Chaque geste sensible est inscrit au journal d'audit : c'est la seule trace
opposable de qui a ouvert une session, validé un compte ou promu un analyste.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from ...security.access import allowed_routes, display_name, welcome_message
from ...security.passwords import hash_password, needs_rehash, verify_password
from ...security.tokens import new_session_token, token_fingerprint
from ..deps import CurrentUserDep, PlatformDep, UserDep
from ..schemas import LoginRequest, RegisterRequest, SetupRequest

router = APIRouter(prefix="/api/v1/auth", tags=["authentification"])


def _me_payload(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "kind": user["kind"],
        "status": user["status"],
        "nom": user["nom"],
        "prenom": user["prenom"],
        "civility": user["civility"],
        "poste": user["poste"],
        "email": user["email"],
        "display_name": display_name(user),
        "welcome": welcome_message(user),
        "allowed_routes": allowed_routes(user["role"]),
    }


def _ouvrir_session(platform: PlatformDep, user_id: str, request: Request) -> str:
    token = new_session_token()
    platform.sessions.open(
        user_id,
        token_fingerprint(token),
        ttl_hours=platform.settings.session_ttl_hours,
        user_agent=request.headers.get("user-agent", ""),
    )
    return token


@router.get("/me")
def me(platform: PlatformDep, user: CurrentUserDep) -> dict[str, Any]:
    """État de session pour l'amorçage de l'interface.

    - ``setup_required`` : aucun super-administrateur, l'écran d'installation
      doit s'afficher ;
    - sinon, session absente/expirée → 401 ;
    - sinon, la charge utile du compte connecté.
    """
    if not platform.users.has_super_admin():
        return {"setup_required": True}
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "connexion requise")
    return {"setup_required": False, **_me_payload(user)}


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def setup(body: SetupRequest, platform: PlatformDep, request: Request) -> dict[str, Any]:
    """Crée le compte super-administrateur. N'est acceptée qu'une seule fois."""
    if platform.users.has_super_admin():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "un super-administrateur existe déjà ; passez par la connexion",
        )
    if body.password != body.password_confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "mots de passe différents")
    if platform.users.username_taken(body.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "nom d'utilisateur déjà pris")

    user = platform.users.create(
        username=body.username,
        password_hash=hash_password(body.password),
        kind="admin",
        role="super_admin",
        status="active",
        email=body.email,
        nom=body.nom,
        prenom=body.prenom,
    )
    platform.ledger.record(
        "auth.setup",
        {"username": user["username"], "user_id": user["user_id"]},
        actor=f"human:super_admin:{user['username']}",
    )
    token = _ouvrir_session(platform, user["user_id"], request)
    platform.users.touch_login(user["user_id"])
    return {"token": token, **_me_payload(user)}


@router.post("/login")
def login(body: LoginRequest, platform: PlatformDep, request: Request) -> dict[str, Any]:
    user = platform.users.by_username(body.username)
    invalides = HTTPException(status.HTTP_401_UNAUTHORIZED, "identifiants incorrects")
    if user is None or not verify_password(body.password, user["password_hash"]):
        raise invalides
    if user["status"] == "pending":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "compte en attente de validation par l'administrateur",
        )
    if user["status"] != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "compte suspendu ou refusé")

    if needs_rehash(user["password_hash"]):
        platform.users.set_password(user["user_id"], hash_password(body.password))

    token = _ouvrir_session(platform, user["user_id"], request)
    platform.users.touch_login(user["user_id"])
    platform.ledger.record(
        "auth.login",
        {"username": user["username"], "role": user["role"]},
        actor=f"human:{user['role']}:{user['username']}",
    )
    return {"token": token, **_me_payload(user)}


@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
def register(body: RegisterRequest, platform: PlatformDep) -> dict[str, Any]:
    """Inscription d'un analyste. Le compte reste ``pending`` jusqu'à validation."""
    if body.password != body.password_confirm:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "mots de passe différents")
    if platform.users.username_taken(body.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "nom d'utilisateur déjà pris")
    if platform.users.email_taken(body.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "adresse e-mail déjà utilisée")

    poste = platform.postes.get(body.poste_id)
    if poste is None or poste["kind"] != "analyste" or not poste["active"]:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "poste inconnu ou fermé")

    user = platform.users.create(
        username=body.username,
        password_hash=hash_password(body.password),
        kind="analyste",
        role="analyste",
        status="pending",
        email=body.email,
        nom=body.nom,
        prenom=body.prenom,
        poste=poste["label"],
    )
    platform.ledger.record(
        "auth.register",
        {"username": user["username"], "poste": poste["label"]},
        actor=f"human:analyste:{user['username']}",
    )
    return {
        "status": "pending",
        "message": "Compte créé — en attente de validation par l'administrateur.",
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(platform: PlatformDep, user: UserDep, request: Request) -> None:
    token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if token:
        platform.sessions.close(token_fingerprint(token))
    platform.ledger.record(
        "auth.logout",
        {"username": user["username"]},
        actor=f"human:{user['role']}:{user['username']}",
    )


@router.get("/postes")
def postes_ouverts(platform: PlatformDep) -> dict[str, Any]:
    """Postes d'analyste ouverts à l'inscription (menu déroulant du formulaire)."""
    postes = platform.postes.list(kind="analyste", active_only=True)
    return {"postes": [{"poste_id": p["poste_id"], "label": p["label"]} for p in postes]}
