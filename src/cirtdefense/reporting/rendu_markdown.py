"""Rendu Markdown : la version texte, lisible sans aucun outil.

Le Markdown reste le format de repli : il s'ouvre dans n'importe quel
éditeur, se relit dans un terminal, se colle dans un courriel. Il porte donc
exactement le même contenu que le PDF, en-tête administratif compris — sous
une forme dégradée mais complète.
"""

from __future__ import annotations

from datetime import datetime

from .document import (
    Document,
    Encadre,
    Graphique,
    Liste,
    Paragraphe,
    SautDePage,
    Tableau,
    Titre,
)

LARGEUR_BARRE = 32


def rendre(document: Document) -> str:
    lignes: list[str] = []
    lignes += _entete(document)
    for bloc in document.blocs:
        lignes += _bloc(bloc)
    lignes += _pied(document)
    return "\n".join(lignes).rstrip() + "\n"


def _entete(document: Document) -> list[str]:
    gauche, droite = document.entete.colonnes()
    lignes = ["<!-- En-tête administratif -->", ""]
    for fr, en in zip(gauche, droite, strict=True):
        if fr.startswith("*"):
            continue
        lignes.append(f"**{fr}** — *{en}*  ")
    lignes += [
        "",
        "---",
        "",
        f"# {document.titre}",
        "",
        f"**Référence** : {document.reference}  ",
        f"**Objet** : {document.objet}  ",
        f"**Établi le** : {_date(document.etabli_le)}  ",
        f"**Établi par** : {document.etabli_par}",
        "",
        "---",
        "",
    ]
    return lignes


def _bloc(bloc: object) -> list[str]:
    match bloc:
        case Titre():
            diese = "#" * min(bloc.niveau + 1, 6)
            return [f"{diese} {bloc.intitule}", ""]
        case Paragraphe():
            texte = f"**{bloc.texte}**" if bloc.accent else bloc.texte
            return [texte, ""]
        case Liste():
            puce = (
                [f"{i}. {e}" for i, e in enumerate(bloc.elements, 1)]
                if bloc.numerotee
                else [f"- {e}" for e in bloc.elements]
            )
            return [*puce, ""]
        case Tableau():
            return _tableau(bloc)
        case Graphique():
            return _graphique(bloc)
        case Encadre():
            marque = {"alerte": "🛑", "attention": "⚠️"}.get(bloc.ton, "ℹ️")
            corps = [f"> {ligne}" for ligne in _replier(bloc.texte, 78)]
            return [f"> {marque} **{bloc.titre}**", ">", *corps, ""]
        case SautDePage():
            return ["---", ""]
        case _:
            return []


def _tableau(bloc: Tableau) -> list[str]:
    if not bloc.entetes:
        return []
    separateur = [
        "---:" if bloc.alignement(i) == "droite" else "---"
        for i in range(len(bloc.entetes))
    ]
    lignes = [
        "| " + " | ".join(_echapper(e) for e in bloc.entetes) + " |",
        "|" + "|".join(separateur) + "|",
    ]
    lignes += [
        "| " + " | ".join(_echapper(str(c)) for c in ligne) + " |" for ligne in bloc.lignes
    ]
    if bloc.legende:
        lignes += ["", f"*{bloc.legende}*"]
    return [*lignes, ""]


def _graphique(bloc: Graphique) -> list[str]:
    """Le diagramme en barres, dessiné en caractères pleins.

    C'est volontairement rustique : un graphique en Markdown suppose un outil
    de rendu, et le format doit rester lisible sans aucun outil.
    """
    if not bloc.valeurs:
        return []
    maximum = bloc.maximum
    largeur_libelle = max(len(k) for k, _ in bloc.valeurs)
    lignes = [f"**{bloc.titre}**", "", "```"]
    for libelle, valeur in bloc.valeurs:
        pleins = int(round(valeur / maximum * LARGEUR_BARRE))
        barre = "█" * pleins + "·" * (LARGEUR_BARRE - pleins)
        lignes.append(f"{libelle.ljust(largeur_libelle)} │{barre}│ {_nombre(valeur)}")
    lignes += ["```", ""]
    return lignes


def _pied(document: Document) -> list[str]:
    lignes = ["---", ""]
    if document.mention_finale:
        lignes += [f"*{document.mention_finale}*", ""]
    lignes += [
        f"{document.lieu}, le {_date(document.etabli_le)}",
        "",
        document.signataire,
        "",
    ]
    return lignes


def _echapper(texte: str) -> str:
    """Une barre verticale dans une cellule casserait le tableau."""
    return texte.replace("|", "\\|").replace("\n", " ")


def _replier(texte: str, largeur: int) -> list[str]:
    mots = texte.split()
    lignes: list[str] = []
    courante = ""
    for mot in mots:
        if courante and len(courante) + 1 + len(mot) > largeur:
            lignes.append(courante)
            courante = mot
        else:
            courante = f"{courante} {mot}".strip()
    if courante:
        lignes.append(courante)
    return lignes


def _nombre(valeur: float) -> str:
    return str(int(valeur)) if valeur == int(valeur) else f"{valeur:.1f}"


def _date(valeur: datetime | None) -> str:
    return valeur.strftime("%d/%m/%Y à %H h %M") if valeur else "—"
