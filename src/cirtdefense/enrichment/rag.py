"""Module d'enrichissement (EF-03) : contexte documente pour la decision.

Le contrat est strict et volontairement pauvre : le module rend des extraits
sourc..es et un verdict de fondement. Il ne resume pas, ne conclut pas, ne
recommande pas. Le choix de l'action revient au planificateur, a partir de
playbooks ecrits par des humains — pas d'un texte genere.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..domain.events import DetectionEvent
from ..logging_setup import log_with
from .grounding import GroundingGuard, GroundingReport
from .vector_store import LexicalIndex, SearchHit

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EnrichedContext:
    event_id: str
    query: str
    hits: list[SearchHit] = field(default_factory=list)
    grounding: GroundingReport | None = None
    relevance: float = 0.0
    threat_notes: list[str] = field(default_factory=list)

    @property
    def is_usable(self) -> bool:
        """Seul un contexte fonde autorise une action autonome (EF-04)."""
        return bool(self.hits) and self.grounding is not None and self.grounding.grounded

    @property
    def sources(self) -> list[str]:
        return [h.document.source_path for h in self.hits]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "query": self.query,
            "relevance": self.relevance,
            "usable": self.is_usable,
            "sources": self.sources,
            "documents": [
                {
                    "doc_id": h.document.doc_id,
                    "title": h.document.title,
                    "score": round(h.score, 3),
                    "matched_terms": h.matched_terms,
                    "excerpt": _excerpt(h),
                }
                for h in self.hits
            ],
            "grounding": self.grounding.to_dict() if self.grounding else None,
            "threat_notes": self.threat_notes,
        }


def _excerpt(hit: SearchHit, width: int = 320) -> str:
    """Extrait centre sur le premier terme retrouve, pour que l'analyste voie
    le passage qui a reellement pese et non le debut du document."""
    text = hit.document.text
    lowered = text.lower()
    position = min(
        (lowered.find(term) for term in hit.matched_terms if lowered.find(term) >= 0),
        default=0,
    )
    start = max(0, position - width // 3)
    return text[start : start + width].strip().replace("\n", " ")


class EnrichmentService:
    def __init__(
        self,
        index: LexicalIndex,
        guard: GroundingGuard | None = None,
        top_k: int = 4,
    ) -> None:
        self._index = index
        self._guard = guard or GroundingGuard()
        self._top_k = top_k

    @classmethod
    def from_directory(cls, directory: Path | str, min_score: float = 0.15) -> EnrichmentService:
        return cls(LexicalIndex.from_directory(directory), GroundingGuard(min_score))

    def enrich(self, event: DetectionEvent) -> EnrichedContext:
        query = self._build_query(event)
        hits = self._index.search(query, top_k=self._top_k)

        # La recherche lexicale peut manquer le document de reference d'une
        # categorie quand le code technique et la redaction n'ont pas de mots
        # en commun. La couverture declaree comble cet ecart, sans jamais
        # inventer un document : si aucun ne declare la categorie, il n'y en a
        # pas, et le contexte sera juge non fonde.
        declared = self._index.covering(event.category)
        known = {h.document.doc_id for h in hits}
        for document in declared:
            if document.doc_id not in known:
                hits.append(SearchHit(document=document, score=0.0, matched_terms=[event.category]))

        # Les affirmations soumises au controle sont celles qui, si elles
        # etaient fausses, rendraient l'action injustifiee. Elles sont
        # formulees autour des termes propres a l'evenement : la garde ne
        # retient de toute facon que les termes discriminants du corpus.
        claims = [f"menace de type {event.category}"]
        if event.mitre_techniques:
            claims.append(f"techniques {' '.join(event.mitre_techniques)}")

        report = self._guard.check(claims, hits, corpus=self._index)
        context = EnrichedContext(
            event_id=event.event_id,
            query=query,
            hits=hits,
            grounding=report,
            relevance=self._guard.check_score(hits),
            threat_notes=[h.document.title for h in hits],
        )

        if not context.is_usable:
            log_with(
                logger,
                logging.WARNING,
                "contexte non fonde : aucune action autonome ne sera engagee",
                event_id=event.event_id,
                category=event.category,
                reason=report.reason,
            )
        return context

    def _build_query(self, event: DetectionEvent) -> str:
        parts = [event.category, event.title, event.description, *event.mitre_techniques]
        indicators = " ".join(str(v) for v in event.indicators.values() if isinstance(v, str))
        return " ".join(p for p in (*parts, indicators) if p)

    def corpus_size(self) -> int:
        return len(self._index)
