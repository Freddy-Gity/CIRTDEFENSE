"""Normaliseurs par produit source.

Chacun expose `normalize(payload: dict) -> DetectionEvent` et ne fait *que*
de la traduction : aucune decision, aucun appel reseau, aucun effet de bord.
Cela les rend testables a l'unite avec un simple echantillon de journal.
"""
