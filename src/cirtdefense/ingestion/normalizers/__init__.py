"""Normaliseurs par produit source.

Chacun expose `normalize(payload: dict) -> DetectionEvent` et ne fait *que*
de la traduction : aucune décision, aucun appel réseau, aucun effet de bord.
Cela les rend testables à l'unité avec un simple echantillon de journal.
"""
