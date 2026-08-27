"""Hachage des mots de passe — PBKDF2-HMAC-SHA256, bibliothèque standard.

Le format stocké est ``pbkdf2_sha256$<itérations>$<sel_b64>$<hachage_b64>``.
Il porte son propre paramètre d'itérations : le jour où on l'augmente, les
comptes existants restent vérifiables et se re-hachent à la connexion suivante
(``needs_rehash``).

Aucune dépendance externe : ni ``bcrypt``, ni ``argon2``, ni ``passlib``. Le
coût CPU de PBKDF2 à 600 000 itérations est de l'ordre de 0,3 s, acceptable
pour une plateforme interne au CIRT et cohérent avec la contrainte hors-ligne.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 600_000
_SALT_BYTES = 16


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    """Retourne l'empreinte encodée d'un mot de passe en clair."""
    if not password:
        raise ValueError("mot de passe vide")
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGO}${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """Vérifie un mot de passe contre une empreinte stockée, en temps constant."""
    try:
        algo, iter_txt, salt_txt, digest_txt = encoded.split("$", 3)
        if algo != _ALGO:
            return False
        iterations = int(iter_txt)
        salt = _unb64(salt_txt)
        expected = _unb64(digest_txt)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def needs_rehash(encoded: str, *, iterations: int = _ITERATIONS) -> bool:
    """Vrai si l'empreinte a été produite avec un paramétrage plus faible."""
    try:
        algo, iter_txt, _, _ = encoded.split("$", 3)
    except ValueError:
        return True
    return algo != _ALGO or int(iter_txt) < iterations
