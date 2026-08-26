"""Schémas d'entrée et de sortie de l'API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    source: str = Field(
        description="Normaliseur à utiliser : wazuh, suricata, syslog, generic_json"
    )
    payload: dict[str, Any] = Field(description="Charge brute telle que produite par la source")


class IngestBatchRequest(BaseModel):
    source: str
    payloads: list[dict[str, Any]]


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
