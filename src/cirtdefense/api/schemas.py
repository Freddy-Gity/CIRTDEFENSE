"""Schémas d'entrée et de sortie de l'API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class IngestRequest(BaseModel):
    source: str = Field(
        description="Normaliseur à utiliser : wazuh, suricata, syslog, generic_json"
    )
    payload: dict[str, Any] = Field(description="Charge brute telle que produite par la source")


class IngestBatchRequest(BaseModel):
    source: str
    payloads: list[dict[str, Any]]


class PendingResolutionRequest(BaseModel):
    """Motif obligatoire : une décision humaine sans motif ne se rejuge pas."""

    reason: str = Field(min_length=3, description="Motif de la décision, consigné au journal")


class QualificationDecisionRequest(BaseModel):
    """Corrections apportées par l'humain à la proposition de la plateforme.

    Tous les champs sont optionnels : valider sans rien corriger est le cas
    nominal quand la proposition tombe juste.
    """

    label: str | None = Field(default=None, description="Nom retenu pour ce type d'attaque")
    family: str | None = Field(
        default=None, description="network | application | insider | infrastructure"
    )
    category: str | None = Field(
        default=None,
        description="Clé de reconnaissance ; à ne changer qu'en connaissance de cause",
    )
    severity: str | None = Field(default=None, description="info | low | medium | high | critical")
    dangerousness: float | None = Field(default=None, ge=0, le=10)
    signal: str | None = Field(default=None, description="Signal caractéristique, en clair")
    note: str = Field(default="", description="Commentaire libre, consigné au journal")

    def corrections(self) -> dict[str, object]:
        champs = ("label", "family", "category", "severity", "dangerousness", "signal")
        return {c: getattr(self, c) for c in champs if getattr(self, c) not in (None, "")}


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=3, description="Motif de l'annulation, consigne au journal")


class PolicyCompileRequest(BaseModel):
    text: str = Field(
        min_length=3,
        description="Politique de réponse en langage naturel, une consigne par phrase",
    )
    version: str = "1"
    activate: bool = True
    default_effect: str = Field(
        default="allow",
        description="'allow' : tout ce qui n'est pas refuse est exécuté ; "
        "'deny' : liste blanche stricte",
    )


class BreakerRequest(BaseModel):
    reason: str = Field(min_length=3)


class AutonomyRequest(BaseModel):
    """Bascule du mode autonomie depuis l'interface."""

    enabled: bool
    reason: str = Field(default="", max_length=300)


class CatalogEntryRequest(BaseModel):
    verb: str
    actuator: str
    reversibility: str
    rollback_verb: str | None = None
    description: str
    rollback_description: str = ""
    residual_effect: str = ""
    typical_blast_radius: int = 1
    max_rollback_seconds: int = 60


class HealthReportRequest(BaseModel):
    """Alimentation de la sonde de santé depuis l'extérieur (recette, demo)."""

    target: str
    reachable: bool = True
    latency_ms: float = 0.0
    error_rate: float = 0.0
    throughput: float = 0.0
    active_sessions: int = 0


class MonitoredTargetRequest(BaseModel):
    """Declaration manuelle d'une plateforme à surveiller.

    Les cinq premiers champs sont ceux que l'administrateur doit renseigner :
    sans propriétaire ni segment, une alerte sur cette machine n'aurait
    personne à qui être adressee ni de contexte réseau pour être jugee.
    """

    label: str = Field(min_length=2, max_length=80, description="Nom ou libellé de la plateforme")
    kind: str = Field(min_length=2, max_length=40, description="Type : serveur web, pare-feu, …")
    ip: str = Field(description="Adresse IP de la plateforme")
    segment: str = Field(min_length=1, max_length=60, description="Segment réseau ou zone")
    owner: str = Field(min_length=2, max_length=80, description="Propriétaire ou responsable")
    criticality: int = Field(default=3, ge=1, le=5)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)


# ---------------------------------------------------------------------------
# Comptes et séparation des rôles
# ---------------------------------------------------------------------------

_MDP = Field(min_length=8, max_length=200, description="Mot de passe (8 caractères minimum)")
_NOM = Field(min_length=1, max_length=80)
_USER = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")


def _valide_email(v: str) -> str:
    v = v.strip()
    if v and ("@" not in v or "." not in v.split("@")[-1] or " " in v):
        raise ValueError("adresse e-mail invalide")
    return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class SetupRequest(BaseModel):
    """Création du compte super-administrateur au premier lancement."""

    nom: str = _NOM
    prenom: str = _NOM
    username: str = _USER
    email: str = Field(default="", max_length=120)
    password: str = _MDP
    password_confirm: str = Field(min_length=1, max_length=200)

    _v_email = field_validator("email")(_valide_email)


class RegisterRequest(BaseModel):
    """Inscription d'un analyste — en attente de validation par l'administrateur."""

    nom: str = _NOM
    prenom: str = _NOM
    username: str = _USER
    email: str = Field(min_length=3, max_length=120)
    password: str = _MDP
    password_confirm: str = Field(min_length=1, max_length=200)
    poste_id: str = Field(min_length=1, description="Poste choisi parmi la liste ouverte")

    _v_email = field_validator("email")(_valide_email)


class PosteRequest(BaseModel):
    kind: Literal["analyste", "decideur"]
    label: str = Field(min_length=2, max_length=120)
    civility: Literal["Monsieur", "Madame", ""] = ""


class PosteUpdateRequest(BaseModel):
    label: str | None = Field(default=None, min_length=2, max_length=120)
    civility: Literal["Monsieur", "Madame", ""] | None = None
    active: bool | None = None


class DecideurRequest(BaseModel):
    """Création par l'administrateur du compte d'un poste de décideur."""

    poste_id: str = Field(min_length=1)
    civility: Literal["Monsieur", "Madame"]
    nom: str = Field(default="", max_length=80)
    prenom: str = Field(default="", max_length=80)
    username: str = _USER
    password: str = _MDP
