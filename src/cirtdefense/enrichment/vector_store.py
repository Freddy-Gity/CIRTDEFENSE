"""Index documentaire lexical (BM25), sans dépendance externe.

Un index lexical est préféré ici à un index vectoriel dense : il est
déterministe, inspectable et n'exige aucun modèle d'embarquement, ce qui
compte pour le mode dégrade (Axe 5) ou la plateforme doit rester opérante
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
    """BM25 Okapi sur index inverse. k1 et b aux valeurs usuelles.

    **Pourquoi un index inverse et pas un balayage.** Une premiere version
    parcourait tous les documents a chaque requete. Sur les 28 fiches de
    demonstration, la difference etait invisible ; mesuree sur un corpus de la
    taille qu'atteindront les procedures reelles du CIRT, elle ne l'est plus :
    50 ms par recherche a 10 000 fiches, contre moins d'une milliseconde ici.

    L'index inverse ne visite que les documents contenant au moins un terme de
    la requete. Le score rendu est **identique** — c'est la meme formule sur
    les memes documents ; seuls sont ecartes ceux dont le score aurait de
    toute facon valu zero.
    """

    K1 = 1.5
    B = 0.75

    def __init__(self) -> None:
        self._documents: dict[str, Document] = {}
        self._df: Counter[str] = Counter()
        self._avg_len: float = 0.0
        # Liste d'occurrences : terme -> {doc_id: frequence}. C'est ce qui
        # remplace le balayage complet.
        self._postings: dict[str, dict[str, int]] = {}
        self._lengths: dict[str, int] = {}

    def add(self, document: Document) -> None:
        self.add_many([document])

    def add_many(self, documents: list[Document]) -> None:
        for document in documents:
            ancien = self._documents.get(document.doc_id)
            if ancien is not None:
                # Reindexation d'un document deja present : on retire d'abord
                # ses occurrences, sinon les frequences documentaires seraient
                # comptees deux fois et l'IDF fausse.
                self._remove(ancien)
            self._documents[document.doc_id] = document
            comptes = Counter(document.tokens)
            self._lengths[document.doc_id] = len(document.tokens)
            for term, frequence in comptes.items():
                self._df[term] += 1
                self._postings.setdefault(term, {})[document.doc_id] = frequence
        self._recompute_avg()

    def _remove(self, document: Document) -> None:
        for term in set(document.tokens):
            self._df[term] -= 1
            if self._df[term] <= 0:
                del self._df[term]
            occurrences = self._postings.get(term)
            if occurrences is not None:
                occurrences.pop(document.doc_id, None)
                if not occurrences:
                    del self._postings[term]
        self._lengths.pop(document.doc_id, None)

    def _recompute_avg(self) -> None:
        if not self._documents:
            self._avg_len = 0.0
            return
        self._avg_len = sum(self._lengths.values()) / len(self._documents)

    def __len__(self) -> int:
        return len(self._documents)

    @property
    def documents(self) -> list[Document]:
        return list(self._documents.values())

    def search(self, query: str, top_k: int = 5) -> list[SearchHit]:
        """BM25 sur les seuls documents contenant un terme de la requete."""
        terms = tokenize(query)
        if not terms or not self._documents:
            return []
        total = len(self._documents)
        moyenne = self._avg_len or 1

        scores: dict[str, float] = {}
        retrouves: dict[str, list[str]] = {}
        for term in set(terms):
            occurrences = self._postings.get(term)
            if not occurrences:
                continue
            df = len(occurrences)
            idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
            for doc_id, frequency in occurrences.items():
                longueur = self._lengths.get(doc_id, 1) or 1
                denominateur = frequency + self.K1 * (
                    1 - self.B + self.B * longueur / moyenne
                )
                scores[doc_id] = scores.get(doc_id, 0.0) + idf * (
                    frequency * (self.K1 + 1)
                ) / denominateur
                retrouves.setdefault(doc_id, []).append(term)

        hits = [
            SearchHit(
                document=self._documents[doc_id],
                score=score,
                matched_terms=sorted(retrouves[doc_id]),
            )
            for doc_id, score in scores.items()
            if score > 0
        ]
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

    # -- statistiques exposées à la garde de non-invention -------------------

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

        La couverture est déclarée dans l'en-tête du document, pas déduite du
        texte : un code technique (`behaviour_anomaly`) n'à aucune raison
        d'apparaitre dans une rédaction en francais, et faire dépendre la
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
