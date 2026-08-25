"""Index documentaire lexical (BM25), sans dependance externe.

Un index lexical est prefere ici à un index vectoriel dense : il est
déterministe, inspectable et n'exige aucun modèle d'embarquement, ce qui
compte pour le mode dégrade (Axe 5) ou la plateforme doit rester operante
hors connexion.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9_\-]{2,}")

_STOPWORDS = frozenset(
    """le la les de des du un une et ou a au aux en dans par pour sur avec sans
    est sont ce cette ces qui que quoi dont il elle ils elles se sa son ses
    the of and to in for on with is are be as at by from that this it its""".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS]


@dataclass(slots=True)
class Document:
    doc_id: str
    title: str
    text: str
    source_path: str
    metadata: dict[str, str] = field(default_factory=dict)
    tokens: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.tokens:
            self.tokens = tokenize(f"{self.title} {self.text}")


@dataclass(slots=True)
class SearchHit:
    document: Document
    score: float
    matched_terms: list[str]


class LexicalIndex:
    """BM25 Okapi. k1 et b aux valeurs usuelles de la litterature."""

    K1 = 1.5
    B = 0.75

    def __init__(self) -> None:
        self._documents: dict[str, Document] = {}
        self._df: Counter[str] = Counter()
        self._avg_len: float = 0.0

    def add(self, document: Document) -> None:
        self._documents[document.doc_id] = document
        for term in set(document.tokens):
            self._df[term] += 1
        self._recompute_avg()

    def add_many(self, documents: list[Document]) -> None:
        for document in documents:
            self._documents[document.doc_id] = document
            for term in set(document.tokens):
                self._df[term] += 1
        self._recompute_avg()

    def _recompute_avg(self) -> None:
        if not self._documents:
            self._avg_len = 0.0
            return
        self._avg_len = sum(len(d.tokens) for d in self._documents.values()) / len(self._documents)

    def __len__(self) -> int:
        return len(self._documents)

    @property
    def documents(self) -> list[Document]:
        return list(self._documents.values())

    def search(self, query: str, top_k: int = 5) -> list[SearchHit]:
        terms = tokenize(query)
        if not terms or not self._documents:
            return []
        total = len(self._documents)
        hits: list[SearchHit] = []
        for document in self._documents.values():
            counts = Counter(document.tokens)
            length = len(document.tokens) or 1
            score = 0.0
            matched: list[str] = []
            for term in set(terms):
                frequency = counts.get(term, 0)
                if frequency == 0:
                    continue
                matched.append(term)
                df = self._df.get(term, 0)
                idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
                denominator = frequency + self.K1 * (
                    1 - self.B + self.B * length / (self._avg_len or 1)
                )
                score += idf * (frequency * (self.K1 + 1)) / denominator
            if score > 0:
                hits.append(
                    SearchHit(document=document, score=score, matched_terms=sorted(matched))
                )
        hits.sort(key=lambda h: (-h.score, h.document.doc_id))
        return hits[:top_k]

    @classmethod
    def from_directory(cls, directory: Path | str, pattern: str = "*.md") -> LexicalIndex:
        index = cls()
        base = Path(directory)
        if not base.exists():
            return index
        documents: list[Document] = []
        for path in sorted(base.rglob(pattern)):
            raw = path.read_text(encoding="utf-8")
            metadata, body = parse_front_matter(raw)
            metadata["filename"] = path.name
            title = next(
                (line.lstrip("# ").strip() for line in body.splitlines() if line.startswith("#")),
                path.stem,
            )
            documents.append(
                Document(
                    doc_id=path.stem,
                    title=title,
                    text=raw,
                    source_path=str(path),
                    metadata=metadata,
                )
            )
        index.add_many(documents)
        return index

    # -- statistiques exposees a la garde de non-invention -------------------

    def document_frequency(self, term: str) -> int:
        return self._df.get(term, 0)

    def ubiquity(self, term: str) -> float:
        """Part des documents contenant le terme, 0.0 à 1.0.

        Un terme present partout ne discrimine rien : il ne peut pas servir à
        prouver qu'une affirmation précise est documentée.
        """
        if not self._documents:
            return 0.0
        return self._df.get(term, 0) / len(self._documents)

    def covering(self, category: str) -> list[Document]:
        """Documents declarant explicitement couvrir cette catégorie.

        La couverture est déclarée dans l'en-tête du document, pas deduite du
        texte : un code technique (`behaviour_anomaly`) n'à aucune raison
        d'apparaitre dans une rédaction en francais, et faire dependre la
        garde EF-04 d'une telle coincidence la rendrait ininterpretable.
        """
        return [
            d
            for d in self._documents.values()
            if category in d.metadata.get("categories", "").split()
        ]


def parse_front_matter(raw: str) -> tuple[dict[str, str], str]:
    """Lit un en-tête `---` clé: valeur `---` en tête de document."""
    if not raw.startswith("---"):
        return {}, raw
    parts = raw.split("---", 2)
    if len(parts) < 3:
        return {}, raw
    metadata: dict[str, str] = {}
    for line in parts[1].strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            metadata[key.strip()] = value.strip()
    return metadata, parts[2]
