"""File de synchronisation persistante du mode dégrade."""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..logging_setup import log_with

logger = logging.getLogger(__name__)

STALE_AFTER = timedelta(hours=6)
"""Au-delà, un événement en file est trop ancien pour justifier une action :
la situation qu'il decrit a probablement change."""


@dataclass(slots=True)
class SpoolItem:
    item_id: str
    source: str
    payload: dict[str, Any]
    queued_at: datetime
    attempts: int = 0
    last_error: str = ""

    @property
    def is_stale(self) -> bool:
        return datetime.now(UTC) - self.queued_at > STALE_AFTER

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "source": self.source,
            "payload": self.payload,
            "queued_at": self.queued_at.isoformat(),
            "attempts": self.attempts,
            "last_error": self.last_error,
            "stale": self.is_stale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SpoolItem:
        return cls(
            item_id=data["item_id"],
            source=data["source"],
            payload=data["payload"],
            queued_at=datetime.fromisoformat(data["queued_at"]),
            attempts=data.get("attempts", 0),
            last_error=data.get("last_error", ""),
        )


@dataclass(slots=True)
class ReplayReport:
    replayed: int = 0
    skipped_stale: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "replayed": self.replayed,
            "skipped_stale": self.skipped_stale,
            "failed": self.failed,
            "errors": self.errors,
        }


class DegradedSpool:
    """File sur disque : elle doit survivre à un redémarrage, faute de quoi une
    coupure prolongee ferait perdre tout ce qui s'est produit pendant."""

    def __init__(self, directory: Path | str, max_items: int = 10000) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_items = max_items

    def enqueue(self, source: str, payload: dict[str, Any]) -> SpoolItem:
        if self.size() >= self._max_items:
            # File pleine : on refuse le plus recent plutôt que d'écraser le
            # plus ancien, qui porte le debut de l'incident.
            raise SpoolFullError(
                f"file du mode dégrade pleine ({self._max_items} éléments) ; "
                "les plus anciens événements sont conserves"
            )
        item = SpoolItem(
            item_id=f"spl_{uuid.uuid4().hex[:12]}",
            source=source,
            payload=payload,
            queued_at=datetime.now(UTC),
        )
        self._path(item.item_id).write_text(json.dumps(item.to_dict(), default=str))
        log_with(
            logger,
            logging.INFO,
            "événement mis en file (mode dégrade)",
            item_id=item.item_id,
            source=source,
        )
        return item

    def items(self) -> list[SpoolItem]:
        result: list[SpoolItem] = []
        for path in sorted(self._dir.glob("spl_*.json")):
            try:
                result.append(SpoolItem.from_dict(json.loads(path.read_text())))
            except (json.JSONDecodeError, KeyError) as exc:
                log_with(
                    logger,
                    logging.ERROR,
                    "élément de file illisible, ignore",
                    path=str(path),
                    error=str(exc),
                )
        return sorted(result, key=lambda i: i.queued_at)

    def size(self) -> int:
        return len(list(self._dir.glob("spl_*.json")))

    def remove(self, item_id: str) -> None:
        self._path(item_id).unlink(missing_ok=True)

    def replay(self, handler: Any, drop_stale: bool = True) -> ReplayReport:
        """Rejoue la file dans l'ordre d'arrivee.

        `handler(source, payload)` doit se comporter exactement comme
        l'ingestion nominale : le rejeu n'est pas un chemin de code parallele,
        sans quoi les deux divergeraient avec le temps.
        """
        report = ReplayReport()
        for item in self.items():
            if item.is_stale:
                report.skipped_stale += 1
                if drop_stale:
                    self.remove(item.item_id)
                log_with(
                    logger,
                    logging.WARNING,
                    "événement trop ancien : rejeu abandonne",
                    item_id=item.item_id,
                    queued_at=item.queued_at.isoformat(),
                )
                continue
            try:
                handler(item.source, item.payload)
            except Exception as exc:  # noqa: BLE001
                report.failed += 1
                report.errors.append(f"{item.item_id}: {exc}")
                item.attempts += 1
                item.last_error = str(exc)
                self._path(item.item_id).write_text(json.dumps(item.to_dict(), default=str))
            else:
                report.replayed += 1
                self.remove(item.item_id)
        return report

    def _path(self, item_id: str) -> Path:
        return self._dir / f"{item_id}.json"


class SpoolFullError(RuntimeError):
    """File pleine : la plateforme ne peut plus mémoriser ce qu'elle observe."""
