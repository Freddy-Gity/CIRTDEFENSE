"""Jetons de session opaques.

Le client reçoit un jeton aléatoire ; la base ne stocke que son empreinte
SHA-256. Une fuite de la table ``user_sessions`` ne permet donc pas de rejouer
une session — il faudrait inverser le SHA-256 du jeton.
"""

from __future__ import annotations

import hashlib
import secrets

_TOKEN_BYTES = 32


def new_session_token() -> str:
    """Jeton porteur à remettre au client (URL-safe, ~43 caractères)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def token_fingerprint(token: str) -> str:
    """Empreinte stockée en base pour un jeton donné."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
