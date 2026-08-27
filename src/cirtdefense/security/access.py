"""Séparation des rôles : qui voit quoi (CDCF v3.0).

Un seul fichier porte la matrice rôle → vues, pour qu'un auditeur puisse la
relire d'un coup d'œil. Elle est déduite du diagramme de cas d'utilisation
``docs/diagrams/cas-utilisation-v3.mmd`` :

- **analyste** — superviseur a posteriori : rollback manuel (UC6), journal
  d'audit (UC7), portefeuille (UC8), file du mode dégradé (UC12) ;
- **décideur** — lecture stratégique stricte : mêmes vues que l'analyste
  hormis la Démonstration, mais aucune action ;
- **administrateur / super-administrateur** — rôle renforcé : politique (UC9),
  catalogue de réversibilité (UC10), coupe-circuit (UC11), gestion des
  comptes et des postes, plus tout le reste.

Le filtrage des vues se fait ici et est renvoyé par ``GET /api/v1/auth/me``.
Le filtrage des *actions* reste porté par les garde-fous de ``api/deps.py``.
"""

from __future__ import annotations

from typing import Any

# Ordre = ordre d'affichage dans la navigation et sur la page d'accueil.
_COMMUN = [
    "/dashboard",
    "/incidents/portfolio",
    "/monitoring",
    "/reversibility-catalog",
    "/reports",
    "/assistant",
    "/audit-log",
    "/settings",
]

ROLE_ROUTES: dict[str, list[str]] = {
    "analyste": list(_COMMUN),
    "decideur": list(_COMMUN),
    "admin": [*_COMMUN[:4], "/demo", *_COMMUN[4:]],
    "super_admin": [*_COMMUN[:4], "/demo", *_COMMUN[4:]],
}

# Rôles autorisés à ouvrir les sections d'administration des Réglages
# (validation des inscriptions, promotion, gestion des postes).
ADMIN_ROLES = frozenset({"admin", "super_admin"})


def allowed_routes(role: str) -> list[str]:
    return ROLE_ROUTES.get(role, ["/dashboard", "/audit-log", "/settings"])


def is_admin(role: str) -> bool:
    return role in ADMIN_ROLES


def display_name(user: dict[str, Any]) -> str:
    """Nom court pour l'en-tête : prénom si connu, sinon poste, sinon identifiant."""
    return (user.get("prenom") or user.get("poste") or user.get("username") or "").strip()


def welcome_message(user: dict[str, Any]) -> str:
    """« Bienvenue Monsieur le Directeur Général de l'ANTIC » / « Bienvenue Awa »."""
    civ = (user.get("civility") or "").strip()
    poste = (user.get("poste") or "").strip()
    prenom = (user.get("prenom") or "").strip()
    role = user.get("role", "")

    if role == "decideur" and poste:
        article = "" if not civ else " le" if civ == "Monsieur" else " la"
        tete = f"{civ}{article} {poste}".strip() if civ else poste
        return f"Bienvenue {tete}"
    if prenom:
        return f"Bienvenue {prenom}"
    if civ and poste:
        return f"Bienvenue {civ} — {poste}"
    return f"Bienvenue {user.get('username', '')}".rstrip()


# Postes semés au premier démarrage : le CIRT peut ensuite les modifier ou en
# ajouter depuis les Réglages. (kind, label, civility)
POSTES_PAR_DEFAUT: list[tuple[str, str, str]] = [
    ("analyste", "Analyste SOC — quart de jour", ""),
    ("analyste", "Analyste SOC — quart de nuit", ""),
    ("analyste", "Analyste réponse à incident", ""),
    ("analyste", "Analyste renseignement sur la menace", ""),
    ("analyste", "Ingénieur détection", ""),
    ("decideur", "Sous-Directeur du CIRT", "Monsieur"),
    ("decideur", "Directeur du CIRT", "Monsieur"),
    ("decideur", "Directeur Général de l'ANTIC", "Monsieur"),
    ("decideur", "Président du Conseil d'Administration de l'ANTIC", "Monsieur"),
]

CIVILITES = ("Monsieur", "Madame")
