"""Primitives de sécurité : hachage des mots de passe, jetons de session.

Rien ici ne dépend d'une bibliothèque tierce : la plateforme doit rester
installable et exécutable hors connexion (mode dégradé, Axe 5).
"""

from .passwords import hash_password, needs_rehash, verify_password
from .tokens import new_session_token, token_fingerprint

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
    "new_session_token",
    "token_fingerprint",
]
