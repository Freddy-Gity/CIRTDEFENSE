"""Mémoire d'une conversation et trace du raisonnement.

Deux besoins distincts, servis ici.

**Le fil.** Sans mémoire, « et sur sept jours ? » n'a aucun sens : il faut
savoir de quoi on parlait. L'assistant garde donc les derniers tours, avec
l'intention et la période retenues, pour qu'une question de suivi se rattache
à la précédente plutôt que d'être déclarée incomprise.

**La trace.** Un assistant qui affirme sans montrer comment il conclut demande
qu'on lui fasse confiance. Celui-ci expose chaque étape : ce qu'il a reconnu
dans la question, sur quel indice, quelle période il a retenue et pourquoi,
quelles sources il a lues, ce qu'il a écarté. Dans un contexte où la réponse
peut déclencher une action réelle, ce détail n'est pas un ornement : c'est ce
qui rend la réponse contestable, donc vérifiable.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

MEMOIRE = 12
"""Tours conservés par conversation. Au-delà, le contexte utile est éteint et
garder davantage ne ferait que consommer de la mémoire."""


@dataclass(slots=True)
class Etape:
    """Une étape du raisonnement, telle qu'elle sera montrée à l'utilisateur."""

    label: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "detail": self.detail}


@dataclass(slots=True)
class Raisonnement:
    etapes: list[Etape] = field(default_factory=list)

    def ajouter(self, label: str, detail: str = "") -> Raisonnement:
        self.etapes.append(Etape(label, detail))
        return self

    def to_list(self) -> list[dict[str, str]]:
        return [e.to_dict() for e in self.etapes]

    def __bool__(self) -> bool:
        return bool(self.etapes)


@dataclass(slots=True)
class Tour:
    role: str
    """`humain` ou `assistant`."""
    texte: str
    intent: str = ""
    hours: int = 0
    label: str = ""
    incident_id: str = ""
    at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "texte": self.texte,
            "intent": self.intent,
            "at": self.at.isoformat(),
        }


@dataclass(slots=True)
class Conversation:
    """Le fil d'une séance. Ce qu'on en retient sert aux questions de suivi."""

    identifiant: str
    tours: deque[Tour] = field(default_factory=lambda: deque(maxlen=MEMOIRE))
    debut: datetime = field(default_factory=lambda: datetime.now(UTC))

    def ajouter(self, tour: Tour) -> None:
        self.tours.append(tour)

    @property
    def vide(self) -> bool:
        return not self.tours

    def dernier_assistant(self) -> Tour | None:
        for tour in reversed(self.tours):
            if tour.role == "assistant":
                return tour
        return None

    def derniere_intention(self) -> str:
        tour = self.dernier_assistant()
        return tour.intent if tour else ""

    def derniere_periode(self) -> tuple[int, str] | None:
        """Période du dernier tour, quand il en portait une.

        C'est elle que reprend une question de suivi : « et les annulations ? »
        après un bilan sur sept jours parle bien de ces sept jours.
        """
        tour = self.dernier_assistant()
        if tour and tour.hours:
            return tour.hours, tour.label
        return None

    def dernier_incident(self) -> str:
        for tour in reversed(self.tours):
            if tour.incident_id:
                return tour.incident_id
        return ""

    def nombre_echanges(self) -> int:
        return sum(1 for t in self.tours if t.role == "humain")


class MemoireDesConversations:
    """Conserve les fils en cours, en mémoire vive uniquement.

    Rien n'est persisté : une conversation est un confort d'usage, pas une
    trace opposable. Ce qui doit survivre — les actions, les décisions — est
    déjà au journal d'audit, qui lui est immuable.
    """

    def __init__(self, maximum: int = 64) -> None:
        self._fils: dict[str, Conversation] = {}
        self._maximum = maximum

    def obtenir(self, identifiant: str | None) -> Conversation:
        cle = identifiant or "defaut"
        fil = self._fils.get(cle)
        if fil is None:
            if len(self._fils) >= self._maximum:
                # Le plus ancien cède la place : un poste de supervision ouvert
                # longtemps ne doit pas faire enfler la memoire indefiniment.
                self._fils.pop(next(iter(self._fils)))
            fil = Conversation(identifiant=cle)
            self._fils[cle] = fil
        return fil

    def oublier(self, identifiant: str) -> bool:
        return self._fils.pop(identifiant, None) is not None
