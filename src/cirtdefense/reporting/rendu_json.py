"""Rendu JSON : le rapport tel qu'un autre système le lira.

C'est le seul format destiné à une machine, et il n'y a donc qu'une exigence :
qu'il porte la même information que les trois autres, structurée plutôt que
mise en page. Un tableau y reste un tableau, un graphique y reste une série de
valeurs — rien n'est aplati en texte, sans quoi le destinataire devrait
analyser des phrases pour retrouver des chiffres.
"""

from __future__ import annotations

import json

from .document import Document


def rendre(document: Document, selection: dict | None = None) -> dict:
    corps = document.to_dict()
    if selection is not None:
        corps["perimetre_demande"] = selection
    return corps


def serialiser(document: Document, selection: dict | None = None) -> str:
    return json.dumps(rendre(document, selection), ensure_ascii=False, indent=2)
