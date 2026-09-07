"""Index inversé : la recherche doit être plus rapide *sans* changer un score.

Une optimisation de la recherche documentaire n'est pas anodine ici : c'est
elle qui alimente la garde d'ancrage (EF-04), donc l'autorisation d'agir. Un
score qui bougerait, même à la marge, pourrait faire basculer un contexte de
« fondé » à « non fondé » — et changer la réponse du système à une menace.

Ces tests fixent donc l'équivalence, pas la performance : ils comparent
l'index inversé à l'implantation par balayage complet, terme à terme.
"""

from __future__ import annotations

import math
import random
from collections import Counter

from cirtdefense.enrichment.vector_store import Document, LexicalIndex, tokenize


def bm25_par_balayage(index: LexicalIndex, query: str, top_k: int = 5) -> list[tuple[str, float]]:
    """Implantation de référence : visite tous les documents.

    C'est le code qui précédait l'index inversé, conservé ici comme témoin.
    Il n'a aucune vocation à être rapide ; il sert à prouver que le nouveau
    calcul rend exactement la même chose.
    """
    terms = tokenize(query)
    if not terms or not index.documents:
        return []
    total = len(index.documents)
    resultats: list[tuple[str, float]] = []
    for document in index.documents:
        comptes = Counter(document.tokens)
        longueur = len(document.tokens) or 1
        score = 0.0
        for term in set(terms):
            frequence = comptes.get(term, 0)
            if frequence == 0:
                continue
            df = index.document_frequency(term)
            idf = math.log(1 + (total - df + 0.5) / (df + 0.5))
            denominateur = frequence + index.K1 * (
                1 - index.B + index.B * longueur / (index._avg_len or 1)
            )
            score += idf * (frequence * (index.K1 + 1)) / denominateur
        if score > 0:
            resultats.append((document.doc_id, score))
    resultats.sort(key=lambda r: (-r[1], r[0]))
    return resultats[:top_k]


def _corpus(n: int, graine: int = 3) -> LexicalIndex:
    """Corpus synthétique où les termes métier apparaissent dans une fraction
    des fiches, comme dans un fonds documentaire réel."""
    alea = random.Random(graine)
    metier = "exfiltration donnees tunnel dns bruteforce ransomware isolation waf".split()
    bruit = [f"terme{i}" for i in range(600)]
    index = LexicalIndex()
    index.add_many(
        [
            Document(
                doc_id=f"d{i}",
                title=f"Fiche {i}",
                text=" ".join(
                    alea.choices(bruit, k=60)
                    + (alea.choices(metier, k=8) if alea.random() < 0.2 else [])
                ),
                source_path=f"/k/d{i}.md",
            )
            for i in range(n)
        ]
    )
    return index


class TestEquivalenceAvecLeBalayage:
    def test_scores_identiques_sur_le_corpus_reel(self):
        index = LexicalIndex.from_directory("src/cirtdefense/enrichment/knowledge")
        assert len(index) > 0, "corpus documentaire introuvable"
        requetes = [
            "exfiltration de donnees transfert sortant",
            "bruteforce ssh authentication failure",
            "ransomware chiffrement isolation",
            "ddos volumetrique scrubbing",
            "injection sql waf",
            "commande et controle sinkhole dns",
        ]
        for requete in requetes:
            obtenu = [(h.document.doc_id, h.score) for h in index.search(requete, top_k=5)]
            attendu = bm25_par_balayage(index, requete, top_k=5)
            assert [d for d, _ in obtenu] == [d for d, _ in attendu], requete
            for (_, a), (_, b) in zip(obtenu, attendu, strict=True):
                assert a == b, f"score divergent sur « {requete} »"

    def test_scores_identiques_sur_corpus_large(self):
        index = _corpus(800)
        alea = random.Random(17)
        vocabulaire = "exfiltration donnees tunnel dns bruteforce ransomware isolation waf".split()
        for _ in range(30):
            requete = " ".join(alea.choices(vocabulaire, k=4))
            obtenu = [(h.document.doc_id, h.score) for h in index.search(requete, top_k=4)]
            attendu = bm25_par_balayage(index, requete, top_k=4)
            assert obtenu == attendu

    def test_les_termes_retrouves_sont_les_memes(self):
        index = LexicalIndex.from_directory("src/cirtdefense/enrichment/knowledge")
        for hit in index.search("exfiltration tunnel dns sortant", top_k=4):
            attendus = sorted(
                t
                for t in set(tokenize("exfiltration tunnel dns sortant"))
                if t in hit.document.tokens
            )
            assert hit.matched_terms == attendus


class TestIntegriteDeLIndex:
    def test_seuls_les_documents_pertinents_sont_visites(self):
        """C'est tout l'intérêt : ne pas toucher un document qui aurait de
        toute façon obtenu un score nul."""
        index = _corpus(400)
        vus = {
            doc_id
            for terme in set(tokenize("exfiltration tunnel"))
            for doc_id in index._postings.get(terme, {})
        }
        assert 0 < len(vus) < len(index), "l'index inversé ne restreint rien"

    def test_reindexer_un_document_ne_fausse_pas_les_frequences(self):
        """Ajouter deux fois le même identifiant doit remplacer, pas cumuler :
        des fréquences comptées deux fois fausseraient l'IDF, donc les scores,
        donc la garde d'ancrage."""
        index = LexicalIndex()
        index.add(Document(doc_id="a", title="A", text="exfiltration dns", source_path="/a"))
        avant = index.document_frequency("exfiltration")
        index.add(Document(doc_id="a", title="A", text="exfiltration dns", source_path="/a"))
        assert index.document_frequency("exfiltration") == avant
        assert len(index) == 1

    def test_reindexer_retire_les_termes_disparus(self):
        index = LexicalIndex()
        index.add(Document(doc_id="a", title="A", text="ransomware isolation", source_path="/a"))
        index.add(Document(doc_id="a", title="A", text="bruteforce", source_path="/a"))
        assert index.document_frequency("ransomware") == 0
        assert index.search("ransomware") == []
        assert index.search("bruteforce")

    def test_longueur_moyenne_coherente(self):
        index = LexicalIndex()
        index.add(Document(doc_id="a", title="A", text="un deux trois", source_path="/a"))
        index.add(Document(doc_id="b", title="B", text="quatre cinq", source_path="/b"))
        assert index._avg_len == sum(len(d.tokens) for d in index.documents) / 2

    def test_requete_sans_correspondance_rend_une_liste_vide(self):
        index = _corpus(50)
        assert index.search("motabsolumentabsentducorpus") == []

    def test_index_vide(self):
        assert LexicalIndex().search("quoi que ce soit") == []
