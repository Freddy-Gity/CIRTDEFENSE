"""Édition des rapports d'opérations.

Un seul chemin, quel que soit le format demandé :

    périmètre choisi  →  faits collectés  →  document composé  →  rendu

Le document composé est le pivot. Les quatre rendus n'ont aucun accès aux
dépôts et ne décident de rien : ils mettent en page une structure qu'on leur
donne. C'est ce qui garantit qu'un rapport dit la même chose en PDF, en Word,
en Markdown et en JSON — et le service qui l'archive n'a pas à se demander
laquelle des quatre versions fait foi.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import rendu_docx, rendu_json, rendu_markdown, rendu_pdf
from .composer import Compositeur
from .document import Document
from .selection import Perimetre, Selection, choix_possibles

FORMATS: dict[str, tuple[str, str]] = {
    "pdf": ("application/pdf", "pdf"),
    "docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docx",
    ),
    "md": ("text/markdown; charset=utf-8", "md"),
    "json": ("application/json; charset=utf-8", "json"),
}


@dataclass(slots=True)
class Rapport:
    """Un rapport édité : ses octets, son type, le nom sous lequel l'enregistrer."""

    contenu: bytes
    media_type: str
    nom_de_fichier: str
    document: Document

    @property
    def texte(self) -> str:
        return self.contenu.decode("utf-8")


class Editeur:
    """Point d'entrée unique de l'édition d'un rapport."""

    def __init__(self, compositeur: Compositeur, logo: str | Path = "") -> None:
        self._compositeur = compositeur
        self._logo = str(logo)

    def formats(self) -> list[str]:
        return list(FORMATS)

    def editer(
        self, selection: Selection, format_: str = "pdf", etabli_par: str = ""
    ) -> Rapport:
        if format_ not in FORMATS:
            raise ValueError(
                f"format « {format_} » inconnu ; choisir parmi : {', '.join(FORMATS)}"
            )
        document = self._compositeur.composer(selection, etabli_par=etabli_par)
        media_type, extension = FORMATS[format_]
        contenu = self._rendre(document, format_, selection)
        return Rapport(
            contenu=contenu,
            media_type=media_type,
            # Un en-tête HTTP ne transporte que de l'ASCII : le nom reste
            # sans accent, le contenu du rapport est en UTF-8.
            nom_de_fichier=f"rapport-{selection.suffixe_de_fichier()}.{extension}",
            document=document,
        )

    def _rendre(self, document: Document, format_: str, selection: Selection) -> bytes:
        match format_:
            case "pdf":
                return rendu_pdf.rendre(document, logo=self._logo or None)
            case "docx":
                return rendu_docx.rendre(document, logo=self._logo or None)
            case "md":
                return rendu_markdown.rendre(document).encode("utf-8")
            case _:
                return rendu_json.serialiser(document, selection.to_dict()).encode("utf-8")


def apercu(compositeur: Compositeur, selection: Selection) -> dict[str, Any]:
    """Le rapport rendu pour l'écran, avant tout téléchargement.

    L'exploitant lit d'abord, télécharge ensuite s'il est satisfait. Servir
    le document structuré évite de produire quatre fichiers pour un seul
    regard.
    """
    document = compositeur.composer(selection)
    return {
        "perimetre": selection.to_dict(),
        "document": document.to_dict(),
        "markdown": rendu_markdown.rendre(document),
    }


__all__ = [
    "FORMATS",
    "Compositeur",
    "Document",
    "Editeur",
    "Perimetre",
    "Rapport",
    "Selection",
    "apercu",
    "choix_possibles",
]
