"""Rendu PDF : le document officiel, prêt à être signé et classé.

C'est le format qui sort de l'imprimante et qui part en courrier. Il porte
donc la titulature administrative camerounaise en trois colonnes — français
à gauche, emblème au centre, anglais à droite — la référence du document, le
lieu et la date, et le bloc de signature.

Le rendu s'appuie sur ReportLab, bibliothèque en Python pur : aucune dépendance
système, rien à installer sur le poste, et la génération reste possible sur un
site coupé d'Internet. C'est une contrainte du Centre, pas une préférence.

Le diagramme en barres est tracé en primitives géométriques plutôt qu'en
caractères pleins : à l'impression, une barre dessinée reste nette là où une
suite de blocs typographiques dépend des polices installées.
"""

from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

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

VERT_ADMIN = colors.HexColor("#1b5e3a")
"""Le vert du drapeau : la seule couleur de marque du document."""
GRIS_TRAIT = colors.HexColor("#9aa3a8")
GRIS_FOND = colors.HexColor("#f0f2f3")
ROUGE_ALERTE = colors.HexColor("#a02020")
ORANGE_ATTENTION = colors.HexColor("#a06a10")

LOGO_PAR_DEFAUT = Path("web/static/logo-antic.png")


def rendre(document: Document, logo: str | Path | None = None) -> bytes:
    """Rend le document en PDF et renvoie les octets du fichier."""
    tampon = io.BytesIO()
    styles = _styles()
    modele = SimpleDocTemplate(
        tampon,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=15 * mm,
        bottomMargin=20 * mm,
        title=document.titre,
        author=document.etabli_par,
        subject=document.objet,
    )
    contenu: list[Flowable] = []
    contenu += _titulature(document, styles, _chemin_logo(logo, document))
    contenu += _cartouche(document, styles)
    for bloc in document.blocs:
        contenu += _bloc(bloc, styles, modele.width)
    contenu += _signature(document, styles)

    modele.build(contenu, onFirstPage=_pied_de_page, onLaterPages=_pied_de_page)
    return tampon.getvalue()


# ---------------------------------------------------------------- styles


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    normal = ParagraphStyle(
        "corps",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        alignment=TA_JUSTIFY,
        spaceAfter=5,
    )
    return {
        "corps": normal,
        "accent": ParagraphStyle(
            "accent", parent=normal, fontName="Helvetica-Bold", textColor=VERT_ADMIN
        ),
        "titulature": ParagraphStyle(
            "titulature",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.6,
            leading=8.6,
            alignment=TA_CENTER,
        ),
        "titre_doc": ParagraphStyle(
            "titre_doc",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            alignment=TA_CENTER,
            textColor=VERT_ADMIN,
            spaceBefore=6,
            spaceAfter=4,
        ),
        "partie": ParagraphStyle(
            "partie",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=VERT_ADMIN,
            spaceBefore=11,
            spaceAfter=5,
        ),
        "sous_partie": ParagraphStyle(
            "sous_partie",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.8,
            leading=13,
            spaceBefore=7,
            spaceAfter=3,
        ),
        "cellule": ParagraphStyle(
            "cellule",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10.4,
        ),
        "cellule_titre": ParagraphStyle(
            "cellule_titre",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.2,
            leading=10.4,
            textColor=colors.white,
        ),
        "cellule_droite": ParagraphStyle(
            "cellule_droite",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10.4,
            alignment=TA_RIGHT,
        ),
        "legende": ParagraphStyle(
            "legende",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=7.8,
            leading=10,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#555b5e"),
            spaceAfter=8,
        ),
        "cartouche": ParagraphStyle(
            "cartouche", parent=normal, fontSize=9, leading=12.5, alignment=0
        ),
    }


# ------------------------------------------------------------ titulature


def _chemin_logo(logo: str | Path | None, document: Document) -> Path | None:
    for candidat in (logo, document.entete.logo, LOGO_PAR_DEFAUT):
        if candidat and Path(candidat).is_file():
            return Path(candidat)
    return None


def _titulature(
    document: Document, styles: dict[str, ParagraphStyle], logo: Path | None
) -> list[Flowable]:
    gauche, droite = document.entete.colonnes()
    style = styles["titulature"]
    colonne_fr = [Paragraph(_texte(ligne), style) for ligne in gauche]
    colonne_en = [Paragraph(_texte(ligne), style) for ligne in droite]

    emblème: Flowable
    if logo is not None:
        emblème = Image(str(logo), width=26 * mm, height=26 * mm, kind="proportional")
        emblème.hAlign = "CENTER"
    else:
        # Sans fichier d'emblème, on réserve l'espace plutôt que de décaler la
        # mise en page : le document reste conforme, il attend son cachet.
        emblème = _CartoucheVide(26 * mm, 26 * mm)

    tableau = Table(
        [[colonne_fr, emblème, colonne_en]],
        colWidths=[62 * mm, 46 * mm, 62 * mm],
    )
    tableau.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return [tableau, Spacer(1, 5 * mm), _Filet(VERT_ADMIN, 1.1), Spacer(1, 4 * mm)]


def _cartouche(document: Document, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Titre, référence, objet : le bloc que lit un service d'archives."""
    lignes = [
        Paragraph(_texte(document.titre), styles["titre_doc"]),
        Paragraph(f"<b>Référence :</b> {_texte(document.reference)}", styles["cartouche"]),
        Paragraph(f"<b>Objet :</b> {_texte(document.objet)}", styles["cartouche"]),
        Paragraph(
            f"<b>Établi le :</b> {_date(document.etabli_le)} — "
            f"<b>par :</b> {_texte(document.etabli_par)}",
            styles["cartouche"],
        ),
    ]
    encadre = Table([[lignes]], colWidths=[170 * mm])
    encadre.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, GRIS_TRAIT),
                ("BACKGROUND", (0, 0), (-1, -1), GRIS_FOND),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return [encadre, Spacer(1, 6 * mm)]


# ----------------------------------------------------------------- blocs


def _bloc(bloc: object, styles: dict[str, ParagraphStyle], largeur: float) -> list[Flowable]:
    match bloc:
        case Titre():
            style = styles["partie"] if bloc.niveau <= 1 else styles["sous_partie"]
            return [Paragraph(_texte(bloc.intitule.upper() if bloc.niveau <= 1
                                     else bloc.intitule), style)]
        case Paragraphe():
            style = styles["accent"] if bloc.accent else styles["corps"]
            return [Paragraph(_texte(bloc.texte), style)]
        case Liste():
            return _liste(bloc, styles)
        case Tableau():
            return _tableau(bloc, styles, largeur)
        case Graphique():
            return _graphique(bloc, styles, largeur)
        case Encadre():
            return _encadre(bloc, styles, largeur)
        case SautDePage():
            return [PageBreak()]
        case _:
            return []


def _liste(bloc: Liste, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    sortie: list[Flowable] = []
    for index, element in enumerate(bloc.elements, 1):
        puce = f"{index}." if bloc.numerotee else "•"
        ligne = Table(
            [[Paragraph(puce, styles["corps"]), Paragraph(_texte(element), styles["corps"])]],
            colWidths=[7 * mm, 163 * mm],
        )
        ligne.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        sortie.append(ligne)
    sortie.append(Spacer(1, 3 * mm))
    return sortie


def _tableau(
    bloc: Tableau, styles: dict[str, ParagraphStyle], largeur: float
) -> list[Flowable]:
    if not bloc.entetes:
        return []
    # L'alignement se pose sur le paragraphe : une consigne ALIGN de tableau
    # cadre la cellule, pas le texte qu'elle contient, et laisserait les
    # nombres collés à gauche.
    par_colonne = [
        styles["cellule_droite"] if bloc.alignement(i) == "droite" else styles["cellule"]
        for i in range(len(bloc.entetes))
    ]
    donnees = [[Paragraph(_texte(e), styles["cellule_titre"]) for e in bloc.entetes]]
    donnees += [
        [
            Paragraph(_texte(str(c)), par_colonne[min(i, len(par_colonne) - 1)])
            for i, c in enumerate(ligne)
        ]
        for ligne in bloc.lignes
    ]
    largeurs = _largeurs(bloc, largeur)
    tableau = Table(donnees, colWidths=largeurs, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), VERT_ADMIN),
        ("GRID", (0, 0), (-1, -1), 0.4, GRIS_TRAIT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        # Une ligne sur deux grisée : sur un tableau de trente lignes
        # photocopié, c'est ce qui empêche de sauter d'une ligne à l'autre.
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GRIS_FOND]),
    ]
    tableau.setStyle(TableStyle(style))

    sortie: list[Flowable] = [tableau]
    if bloc.legende:
        sortie += [Spacer(1, 1.5 * mm), Paragraph(_texte(bloc.legende), styles["legende"])]
    else:
        sortie.append(Spacer(1, 4 * mm))
    return sortie


def _largeurs(bloc: Tableau, largeur: float) -> list[float]:
    """Répartit la largeur au prorata du contenu réel de chaque colonne.

    Des colonnes égales donnent des tableaux illisibles dès qu'une colonne
    porte une phrase et une autre un nombre à deux chiffres.
    """
    poids: list[float] = []
    planchers: list[float] = []
    for index, entete in enumerate(bloc.entetes):
        cellules = [str(ligne[index]) for ligne in bloc.lignes if index < len(ligne)]
        moyenne = sum(len(c) for c in cellules) / len(cellules) if cellules else 0
        # +2 pour la marge intérieure : sans elle, un intitulé comme
        # « Annulés » se coupe entre le « é » et le « s ».
        poids.append(max(len(entete) + 2, moyenne, 6))
        # Un nom de machine ou une adresse IP ne se coupe pas : la colonne
        # qui les porte doit tenir le plus long mot qu'elle contient, sans
        # quoi « srv-db-01 » s'affiche sur deux lignes.
        insecable = max(
            (len(mot) for texte in [entete, *cellules] for mot in texte.split()),
            default=6,
        )
        planchers.append(min(_mesure(insecable) + 3 * mm, largeur * 0.3))
    total = sum(poids)
    brut = [largeur * p / total for p in poids]
    ajustees = [max(v, plancher) for v, plancher in zip(brut, planchers, strict=True)]
    exces = sum(ajustees) - largeur
    if exces > 0:
        # On reprend la largeur en trop aux seules colonnes qui ont de la
        # marge au-dessus de leur plancher, au prorata de cette marge.
        marge = [max(v - p, 0) for v, p in zip(ajustees, planchers, strict=True)]
        disponible = sum(marge)
        if disponible > 0:
            ajustees = [
                v - exces * m / disponible for v, m in zip(ajustees, marge, strict=True)
            ]
        else:
            ajustees = [largeur * v / sum(ajustees) for v in ajustees]
    return ajustees


def _mesure(caracteres: int) -> float:
    """Largeur approchée d'un mot de N caractères en Helvetica 8,2 pt."""
    return caracteres * 8.2 * 0.52


def _graphique(
    bloc: Graphique, styles: dict[str, ParagraphStyle], largeur: float
) -> list[Flowable]:
    if not bloc.valeurs:
        return []
    dessin = _Barres(bloc, largeur)
    return [
        KeepTogether(
            [
                Paragraph(_texte(bloc.titre), styles["sous_partie"]),
                dessin,
                Spacer(1, 4 * mm),
            ]
        )
    ]


def _encadre(
    bloc: Encadre, styles: dict[str, ParagraphStyle], largeur: float
) -> list[Flowable]:
    teinte = {
        "alerte": ROUGE_ALERTE,
        "attention": ORANGE_ATTENTION,
    }.get(bloc.ton, VERT_ADMIN)
    titre_style = ParagraphStyle(
        "encadre_titre",
        parent=styles["corps"],
        fontName="Helvetica-Bold",
        textColor=teinte,
        spaceAfter=2,
    )
    contenu = [
        Paragraph(_texte(bloc.titre), titre_style),
        Paragraph(_texte(bloc.texte), styles["corps"]),
    ]
    cadre = Table([[contenu]], colWidths=[largeur])
    cadre.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, teinte),
                ("LINEBEFORE", (0, 0), (0, -1), 2.4, teinte),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fbfaf6")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return [Spacer(1, 2 * mm), cadre, Spacer(1, 4 * mm)]


def _signature(document: Document, styles: dict[str, ParagraphStyle]) -> list[Flowable]:
    sortie: list[Flowable] = [Spacer(1, 6 * mm)]
    if document.mention_finale:
        mention = ParagraphStyle(
            "mention", parent=styles["corps"], fontName="Helvetica-Oblique", fontSize=8.5
        )
        sortie.append(Paragraph(_texte(document.mention_finale), mention))
    sortie.append(Spacer(1, 8 * mm))

    droite = ParagraphStyle(
        "signature", parent=styles["corps"], alignment=TA_CENTER, fontSize=9.5
    )
    bloc = [
        Paragraph(
            f"{_texte(document.lieu)}, le {_date(document.etabli_le)}", droite
        ),
        Spacer(1, 3 * mm),
        Paragraph(f"<b>{_texte(document.signataire)}</b>", droite),
        Spacer(1, 18 * mm),
    ]
    tableau = Table([["", bloc]], colWidths=[85 * mm, 85 * mm])
    tableau.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    sortie.append(tableau)
    return sortie


# -------------------------------------------------------------- flowables


class _Filet(Flowable):
    """Trait de séparation pleine largeur."""

    def __init__(self, couleur: colors.Color, epaisseur: float = 0.8) -> None:
        super().__init__()
        self._couleur = couleur
        self._epaisseur = epaisseur
        self.width = 0.0
        self.height = epaisseur

    def wrap(self, largeur_disponible: float, hauteur_disponible: float):
        self.width = largeur_disponible
        return largeur_disponible, self._epaisseur

    def draw(self) -> None:
        self.canv.setStrokeColor(self._couleur)
        self.canv.setLineWidth(self._epaisseur)
        self.canv.line(0, 0, self.width, 0)


class _CartoucheVide(Flowable):
    """Emplacement réservé à l'emblème, quand le fichier n'est pas fourni."""

    def __init__(self, largeur: float, hauteur: float) -> None:
        super().__init__()
        self.width = largeur
        self.height = hauteur

    def draw(self) -> None:
        self.canv.setStrokeColor(GRIS_TRAIT)
        self.canv.setDash(2, 2)
        self.canv.rect(0, 0, self.width, self.height)
        self.canv.setDash()
        self.canv.setFillColor(GRIS_TRAIT)
        self.canv.setFont("Helvetica", 6)
        self.canv.drawCentredString(self.width / 2, self.height / 2 - 2, "EMBLÈME")


class _Barres(Flowable):
    """Diagramme en barres horizontales, tracé en primitives.

    Les libellés occupent le tiers gauche, les barres les deux tiers restants,
    la valeur chiffrée s'inscrit au bout de la barre. Une seule teinte : le
    document doit rester lisible photocopié en noir et blanc.
    """

    HAUTEUR_BARRE = 6.5 * mm
    ECART = 2.2 * mm

    def __init__(self, graphique: Graphique, largeur: float) -> None:
        super().__init__()
        self._g = graphique
        self.width = largeur
        self.height = len(graphique.valeurs) * (self.HAUTEUR_BARRE + self.ECART)

    def wrap(self, largeur_disponible: float, hauteur_disponible: float):
        self.width = largeur_disponible
        return self.width, self.height

    def draw(self) -> None:
        canevas = self.canv
        colonne_libelle = self.width * 0.34
        piste = self.width * 0.52
        maximum = self._g.maximum
        y = self.height - self.HAUTEUR_BARRE

        for libelle, valeur in self._g.valeurs:
            canevas.setFillColor(colors.HexColor("#2b3134"))
            canevas.setFont("Helvetica", 7.6)
            canevas.drawString(
                0,
                y + self.HAUTEUR_BARRE / 2 - 2.6,
                _tronquer(libelle, colonne_libelle, 7.6),
            )

            canevas.setFillColor(GRIS_FOND)
            canevas.rect(colonne_libelle, y, piste, self.HAUTEUR_BARRE, stroke=0, fill=1)

            longueur = max(piste * (valeur / maximum), 0.6 * mm)
            canevas.setFillColor(VERT_ADMIN)
            canevas.rect(colonne_libelle, y, longueur, self.HAUTEUR_BARRE, stroke=0, fill=1)

            canevas.setFillColor(colors.HexColor("#2b3134"))
            canevas.setFont("Helvetica-Bold", 7.6)
            canevas.drawString(
                colonne_libelle + piste + 2.5 * mm,
                y + self.HAUTEUR_BARRE / 2 - 2.6,
                _nombre(valeur),
            )
            y -= self.HAUTEUR_BARRE + self.ECART


def _pied_de_page(canevas, modele) -> None:
    """Numérotation et rappel de la nature du document sur chaque page."""
    canevas.saveState()
    canevas.setStrokeColor(GRIS_TRAIT)
    canevas.setLineWidth(0.4)
    canevas.line(20 * mm, 14 * mm, A4[0] - 20 * mm, 14 * mm)
    canevas.setFont("Helvetica", 7)
    canevas.setFillColor(colors.HexColor("#666c6f"))
    canevas.drawString(
        20 * mm, 10 * mm, "Centre de réponse aux incidents informatiques — ANTIC"
    )
    canevas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {canevas.getPageNumber()}")
    canevas.restoreState()


# ------------------------------------------------------------------ outils


def _texte(valeur: str) -> str:
    """ReportLab lit un mini-langage balisé : les chevrons doivent être neutralisés.

    Un nom de machine du genre ``<srv-01>`` remonté par un capteur ferait
    autrement échouer la génération du document — au pire moment, celui où on
    l'imprime.
    """
    return (
        str(valeur)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _tronquer(texte: str, largeur: float, taille: float) -> str:
    # Approximation suffisante : Helvetica tourne autour de 0,5 em par
    # caractère en moyenne sur du français.
    maximum = max(int(largeur / (taille * 0.5)), 4)
    return texte if len(texte) <= maximum else texte[: maximum - 1] + "…"


def _nombre(valeur: float) -> str:
    return str(int(valeur)) if valeur == int(valeur) else f"{valeur:.1f}"


def _date(valeur: datetime | None) -> str:
    return valeur.strftime("%d/%m/%Y à %H h %M") if valeur else "—"
