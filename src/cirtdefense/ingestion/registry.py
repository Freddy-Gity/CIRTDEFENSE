"""Registre des normaliseurs disponibles.

Ajouter une source = déposer un normaliseur et l'enregistrer ici. Aucun autre
fichier de la plateforme n'a besoin de le savoir (EF-20).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..domain.events import DetectionEvent

Normalizer = Callable[[dict[str, Any]], DetectionEvent]

_REGISTRY: dict[str, Normalizer] = {}


def register(name: str, normalizer: Normalizer) -> None:
    _REGISTRY[name] = normalizer


def get(name: str) -> Normalizer | None:
    return _REGISTRY.get(name)


def available() -> list[str]:
    return sorted(_REGISTRY)


def load_builtin() -> None:
    """Enregistre les normaliseurs livres avec la plateforme."""
    from .normalizers import generic_json, suricata, syslog, wazuh

    register("generic_json", generic_json.normalize)
    register("wazuh", wazuh.normalize)
    register("suricata", suricata.normalize)
    register("syslog", syslog.normalize)


load_builtin()
