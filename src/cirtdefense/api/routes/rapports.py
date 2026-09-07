"""Édition des rapports d'opérations.

Trois routes seulement, et l'ordre dans lequel on les appelle décrit
l'usage : on demande d'abord ce qu'il est possible de couvrir, on prévisualise
ensuite, on télécharge enfin — et seulement si l'aperçu convient.

Rien n'est produit à l'ouverture de l'écran. C'est délibéré : un rapport que
personne n'a demandé n'a pas d'objet, et en produire un d'office fait croire
que la plateforme n'en sait pas faire d'autre.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from ...reporting import Editeur, Perimetre, Selection, apercu, choix_possibles
from ..deps import PlatformDep

router = APIRouter(prefix="/api/v1/rapports", tags=["rapports"])


@router.get("/options")
def options() -> dict:
    """Ce que l'interface propose dans ses menus.

    Les libellés viennent du serveur, pas du code de l'interface : une famille
    renommée dans le catalogue métier se répercute sans retoucher l'écran.
    """
    return choix_possibles()


@router.get("/apercu")
def previsualiser(
    platform: PlatformDep,
    perimetre: str = "periode",
    fenetre: str = "24h",
    valeur: str = "",
) -> dict:
    """Le rapport composé, rendu à l'écran avant tout téléchargement."""
    selection = _selection(perimetre, fenetre, valeur)
    try:
        return apercu(platform.compositeur, selection)
    except ValueError as erreur:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(erreur)) from erreur
    except LookupError as erreur:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(erreur)) from erreur


@router.get("/editer", response_class=Response)
def editer(
    platform: PlatformDep,
    perimetre: str = "periode",
    fenetre: str = "24h",
    valeur: str = "",
    format: str = "pdf",  # noqa: A002 - nom porté par l'URL, pas par le code appelant
) -> Response:
    """Le rapport téléchargeable, dans l'un des quatre formats."""
    selection = _selection(perimetre, fenetre, valeur)
    editeur = Editeur(platform.compositeur, logo=platform.settings.report_logo)
    try:
        rapport = editeur.editer(selection, format)
    except ValueError as erreur:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(erreur)) from erreur
    except LookupError as erreur:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(erreur)) from erreur
    return Response(
        content=rapport.contenu,
        media_type=rapport.media_type,
        headers={
            # Un en-tête HTTP ne transporte que de l'ASCII : le nom du fichier
            # reste sans accent, le contenu du rapport est en UTF-8.
            "Content-Disposition": f'attachment; filename="{rapport.nom_de_fichier}"',
            "Cache-Control": "no-store",
        },
    )


def _selection(perimetre: str, fenetre: str, valeur: str) -> Selection:
    try:
        cadre = Perimetre(perimetre)
    except ValueError as erreur:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"périmètre « {perimetre} » inconnu ; choisir parmi : "
            f"{', '.join(p.value for p in Perimetre)}",
        ) from erreur
    selection = Selection(perimetre=cadre, fenetre=fenetre, valeur=valeur)
    erreur_de_saisie = selection.valider()
    if erreur_de_saisie:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, erreur_de_saisie)
    return selection
