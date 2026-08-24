"""Garde de non-invention (EF-04).

Une seule question est tranchee ici : le contexte remonte est-il *reellement*
soutenu par des documents, ou est-il une reconstruction plausible ?

Le controle porte exclusivement sur les termes **discriminants** d'une
affirmation. C'est le point delicat : une premiere version comparait tous les
mots, si bien que les mots de liaison de la phrase de controle
(« categorie », « menace », « documentee ») suffisaient a la valider — une
menace parfaitement inconnue passait pour documentee. Un terme present dans
la moitie des documents ne prouve rien ; seuls les termes rares le peuvent.

Le controle reste deliberement lexical. Une verification par un modele
reintroduirait le probleme qu'elle est censee resoudre : un modele peut
halluciner la justification de sa propre hallucination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .vector_store import SearchHit, tokenize

UBIQUITY_LIMIT = 0.5
"""Au-dela de cette part de documents, un terme est juge non discriminant."""


class CorpusStats(Protocol):
    """Ce dont la garde a besoin du corpus, et rien de plus."""

    def ubiquity(self, term: str) -> float: ...


@dataclass(slots=True)
class ClaimCheck:
    claim: str
    discriminating_terms: list[str]
    found_terms: list[str]
    coverage: float
    supported: bool
    note: str = ""


@dataclass(slots=True)
class GroundingReport:
    grounded: bool
    score: float
    supported_claims: list[str] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    reason: str = ""
    checks: list[ClaimCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "grounded": self.grounded,
            "score": round(self.score, 3),
            "supported_claims": self.supported_claims,
            "unsupported_claims": self.unsupported_claims,
            "sources": self.sources,
            "reason": self.reason,
            "checks": [
                {
                    "claim": c.claim,
                    "discriminating_terms": c.discriminating_terms,
                    "found_terms": c.found_terms,
                    "coverage": round(c.coverage, 3),
                    "supported": c.supported,
                    "note": c.note,
                }
                for c in self.checks
            ],
        }


class GroundingGuard:
    def __init__(self, min_score: float = 0.15, ubiquity_limit: float = UBIQUITY_LIMIT) -> None:
        self._min_score = min_score
        self._ubiquity_limit = ubiquity_limit

    def check(
        self,
        statements: list[str],
        hits: list[SearchHit],
        corpus: CorpusStats | None = None,
    ) -> GroundingReport:
        if not hits:
            return GroundingReport(
                grounded=False,
                score=0.0,
                unsupported_claims=list(statements),
                reason="aucun document pertinent : le contexte serait entierement suppose",
            )

        corpus_terms: set[str] = set()
        for hit in hits:
            corpus_terms.update(hit.document.tokens)

        checks: list[ClaimCheck] = []
        for statement in statements:
            checks.append(self._check_one(statement, corpus_terms, corpus))

        verifiable = [c for c in checks if c.discriminating_terms]
        supported = [c for c in checks if c.supported]
        unsupported = [c for c in checks if not c.supported]
        score = sum(c.coverage for c in verifiable) / len(verifiable) if verifiable else 0.0

        # Une affirmation invérifiable ne vaut pas une affirmation verifiee :
        # s'il ne reste aucun terme discriminant, le contexte n'est pas fonde.
        grounded = bool(verifiable) and not unsupported

        return GroundingReport(
            grounded=grounded,
            score=score,
            supported_claims=[c.claim for c in supported],
            unsupported_claims=[c.claim for c in unsupported],
            sources=[h.document.source_path for h in hits],
            reason=self._explain(verifiable, unsupported, grounded),
            checks=checks,
        )

    def _check_one(
        self,
        statement: str,
        corpus_terms: set[str],
        corpus: CorpusStats | None,
    ) -> ClaimCheck:
        terms = set(tokenize(statement))
        discriminating = sorted(
            t for t in terms
            if corpus is None or corpus.ubiquity(t) <= self._ubiquity_limit
        )
        if not discriminating:
            return ClaimCheck(
                claim=statement,
                discriminating_terms=[],
                found_terms=[],
                coverage=0.0,
                supported=False,
                note="aucun terme discriminant : affirmation invérifiable en l'etat",
            )
        found = sorted(set(discriminating) & corpus_terms)
        coverage = len(found) / len(discriminating)
        return ClaimCheck(
            claim=statement,
            discriminating_terms=discriminating,
            found_terms=found,
            coverage=coverage,
            supported=coverage >= self._min_score,
            note="" if found else "aucun terme discriminant retrouve dans les sources",
        )

    @staticmethod
    def _explain(verifiable: list[ClaimCheck], unsupported: list[ClaimCheck], grounded: bool) -> str:
        if grounded:
            return "toutes les affirmations verifiables sont couvertes par au moins une source"
        if not verifiable:
            return "aucune affirmation ne comporte de terme discriminant : rien n'est verifiable"
        missing = ", ".join(
            t for c in unsupported for t in c.discriminating_terms if t not in c.found_terms
        )
        return f"{len(unsupported)} affirmation(s) sans appui documentaire (termes absents : {missing})"

    def check_score(self, hits: list[SearchHit], normalizer: float = 6.0) -> float:
        """Score de pertinence brut de la recherche, normalise sur [0, 1].

        `normalizer` correspond a un score BM25 deja franchement bon ; au-dela
        on plafonne, la distinction n'ayant plus d'utilite decisionnelle.
        """
        if not hits:
            return 0.0
        return round(min(1.0, hits[0].score / normalizer), 3)
