"""Adaptateur d'ingestion : normalisation, deduplication, correlation (EF-18/19/20).

L'adaptateur ne decide de rien. Il produit un `DetectionEvent` rattache a un
incident et le remet au moteur. Cette separation compte : en autonomie totale,
le point ou une observation devient un ordre doit rester unique et identifiable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..audit.ledger import AuditLedger
from ..domain.enums import AuditEventType
from ..domain.events import DetectionEvent
from ..domain.incident import Incident
from ..logging_setup import log_with
from ..persistence.repositories import EventRepository, IncidentRepository
from . import registry

logger = logging.getLogger(__name__)


class UnknownSourceError(ValueError):
    """Aucun normaliseur enregistre pour la source demandee."""


@dataclass(slots=True)
class IngestionResult:
    event: DetectionEvent | None
    incident: Incident | None
    duplicate: bool = False
    reason: str = ""

    @property
    def accepted(self) -> bool:
        return self.event is not None and not self.duplicate


class IngestionAdapter:
    def __init__(
        self,
        events: EventRepository,
        incidents: IncidentRepository,
        ledger: AuditLedger,
    ) -> None:
        self._events = events
        self._incidents = incidents
        self._ledger = ledger

    def ingest(self, source: str, payload: dict[str, Any]) -> IngestionResult:
        normalizer = registry.get(source)
        if normalizer is None:
            raise UnknownSourceError(
                f"source '{source}' inconnue ; sources disponibles : {registry.available()}"
            )

        event = normalizer(payload)
        fingerprint = event.fingerprint()

        # EF-19 : la deduplication precede toute correlation. En autonomie
        # totale, une meme observation comptee deux fois declencherait deux
        # actions sur la meme cible.
        if self._events.exists_fingerprint(fingerprint):
            log_with(
                logger, logging.INFO, "evenement duplique ignore",
                fingerprint=fingerprint, source=source,
            )
            return IngestionResult(
                event=event, incident=None, duplicate=True,
                reason="empreinte deja connue (deduplication EF-19)",
            )

        incident = self._correlate(event)
        self._events.save(event, incident.incident_id)
        self._incidents.save(incident)

        self._ledger.record(
            AuditEventType.EVENT_INGESTED,
            {
                "event_id": event.event_id,
                "fingerprint": fingerprint,
                "source": source,
                "source_product": event.source_product,
                "category": event.category,
                "severity": event.severity.value,
                "confidence": event.confidence,
                "asset": event.asset.correlation_key(),
            },
            actor=f"adapter:{source}",
            incident_id=incident.incident_id,
        )
        return IngestionResult(event=event, incident=incident)

    def ingest_batch(self, source: str, payloads: list[dict[str, Any]]) -> list[IngestionResult]:
        return [self.ingest(source, p) for p in payloads]

    def _correlate(self, event: DetectionEvent) -> Incident:
        """EF-20 : rattache l'evenement a un incident ouvert ou en cree un."""
        key = Incident.key_for(event)
        existing = self._incidents.find_open_by_key(key)
        now = datetime.now(UTC)
        if existing and existing.accepts(event, now=now):
            existing.absorb(event)
            return existing
        return Incident.from_event(event)
