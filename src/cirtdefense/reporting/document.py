"""Modèle neutre d'un rapport, indépendant du format de sortie.

Un rapport est composé **une fois**, sous forme de blocs, puis rendu en PDF,
en Word, en Markdown ou en JSON. C'est ce qui garantit que les quatre versions
disent exactement la même chose : elles partagent la composition, elles ne se
partagent que la mise en forme.

L'alternative — écrire quatre générateurs — produit immanquablement des écarts
entre les formats, et un rapport officiel qui ne dit pas la même chose selon
le fichier ouvert n'est plus opposable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Bloc:
    """Élément de contenu. Chaque rendu sait traiter les six sous-types."""

    def to_dict(self) -> dict[str, Any]:  # pragma: no cover - redéfini
        raise NotImplementedError


@dataclass(slots=True)
class Titre(Bloc):
    texte: str
    niveau: int = 1
    numero: str = ""
    """Numérotation administrative : « I », « II.1 »… Vide si non numéroté."""

    @property
    def intitule(self) -> str:
        return f"{self.numero}. {self.texte}" if self.numero else self.texte

    def to_dict(self) -> dict[str, Any]:
        return {"type": "titre", "niveau": self.niveau, "numero": self.numero,
                "texte": self.texte}


@dataclass(slots=True)
class Paragraphe(Bloc):
    texte: str
    accent: bool = False
    """Vrai pour une phrase que le lecteur ne doit pas manquer."""

    def to_dict(self) -> dict[str, Any]:
        return {"type": "paragraphe", "texte": self.texte, "accent": self.accent}


@dataclass(slots=True)
class Liste(Bloc):
    elements: list[str] = field(default_factory=list)
    numerotee: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"type": "liste", "elements": self.elements, "numerotee": self.numerotee}


@dataclass(slots=True)
class Tableau(Bloc):
    entetes: list[str] = field(default_factory=list)
    lignes: list[list[str]] = field(default_factory=list)
    legende: str = ""
    alignements: list[str] = field(default_factory=list)
    """« gauche » ou « droite » par colonne. Les nombres s'alignent à droite."""

    def alignement(self, colonne: int) -> str:
        if colonne < len(self.alignements):
            return self.alignements[colonne]
        return "gauche"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "tableau",
            "entetes": self.entetes,
            "lignes": self.lignes,
            "legende": self.legende,
        }


@dataclass(slots=True)
class Graphique(Bloc):
    """Diagramme en barres horizontales.

    Volontairement limité à cette forme : elle se dessine dans les quatre
    formats sans image externe ni bibliothèque de tracé, et reste lisible en
    noir et blanc — un rapport officiel finit souvent photocopié.
    """

    titre: str
    valeurs: list[tuple[str, float]] = field(default_factory=list)
    unite: str = ""

    @property
    def maximum(self) -> float:
        return max((v for _, v in self.valeurs), default=0.0) or 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "graphique",
            "titre": self.titre,
            "unite": self.unite,
            "valeurs": [{"libelle": k, "valeur": v} for k, v in self.valeurs],
        }


@dataclass(slots=True)
class Encadre(Bloc):
    """Mention à détacher du corps : avertissement, précision de méthode."""

    titre: str
    texte: str
    ton: str = "neutre"
    """neutre | attention | alerte"""

    def to_dict(self) -> dict[str, Any]:
        return {"type": "encadre", "titre": self.titre, "texte": self.texte, "ton": self.ton}


@dataclass(slots=True)
class SautDePage(Bloc):
    def to_dict(self) -> dict[str, Any]:
        return {"type": "saut_de_page"}


# --------------------------------------------------------------- en-tête


@dataclass(slots=True)
class EnTeteAdministratif:
    """Bloc de titulature des documents officiels camerounais.

    Disposition en trois colonnes : la version française à gauche, l'emblème
    au centre, la version anglaise à droite — les deux langues officielles de
    la République.
    """

    republique_fr: str = "RÉPUBLIQUE DU CAMEROUN"
    devise_fr: str = "Paix – Travail – Patrie"
    ministere_fr: str = "MINISTÈRE DES POSTES ET TÉLÉCOMMUNICATIONS"
    agence_fr: str = (
        "AGENCE NATIONALE DES TECHNOLOGIES DE L'INFORMATION ET DE LA COMMUNICATION"
    )
    service_fr: str = "CENTRE DE RÉPONSE AUX INCIDENTS INFORMATIQUES"

    republique_en: str = "REPUBLIC OF CAMEROON"
    devise_en: str = "Peace – Work – Fatherland"
    ministere_en: str = "MINISTRY OF POSTS AND TELECOMMUNICATIONS"
    agence_en: str = (
        "NATIONAL AGENCY FOR INFORMATION AND COMMUNICATION TECHNOLOGIES"
    )
    service_en: str = "COMPUTER INCIDENT RESPONSE TEAM"

    logo: str = ""
    """Chemin du fichier d'emblème. Vide : un cartouche de réserve est tracé."""

    def colonnes(self) -> tuple[list[str], list[str]]:
        gauche = [
            self.republique_fr,
            self.devise_fr,
            "**********",
            self.ministere_fr,
            "**********",
            self.agence_fr,
            "**********",
            self.service_fr,
        ]
        droite = [
            self.republique_en,
            self.devise_en,
            "**********",
            self.ministere_en,
            "**********",
            self.agence_en,
            "**********",
            self.service_en,
        ]
        return gauche, droite

    def to_dict(self) -> dict[str, Any]:
        return {
            "republique": {"fr": self.republique_fr, "en": self.republique_en},
            "devise": {"fr": self.devise_fr, "en": self.devise_en},
            "ministere": {"fr": self.ministere_fr, "en": self.ministere_en},
            "agence": {"fr": self.agence_fr, "en": self.agence_en},
            "service": {"fr": self.service_fr, "en": self.service_en},
        }


@dataclass(slots=True)
class Document:
    """Un rapport composé, prêt à être rendu dans n'importe quel format."""

    titre: str
    objet: str
    """Ce que le rapport couvre, en une phrase. Figure sous « Objet : »."""
    reference: str
    """Numéro d'ordre administratif, à la manière d'un courrier officiel."""
    lieu: str = "Yaoundé"
    etabli_le: datetime | None = None
    etabli_par: str = ""
    entete: EnTeteAdministratif = field(default_factory=EnTeteAdministratif)
    blocs: list[Bloc] = field(default_factory=list)
    signataire: str = "Le Chef du Centre de Réponse aux Incidents Informatiques"
    mention_finale: str = ""

    def ajouter(self, *blocs: Bloc) -> Document:
        self.blocs.extend(blocs)
        return self

    @property
    def tableaux(self) -> list[Tableau]:
        return [b for b in self.blocs if isinstance(b, Tableau)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "titre": self.titre,
            "objet": self.objet,
            "reference": self.reference,
            "lieu": self.lieu,
            "etabli_le": self.etabli_le.isoformat() if self.etabli_le else None,
            "etabli_par": self.etabli_par,
            "entete": self.entete.to_dict(),
            "signataire": self.signataire,
            "mention_finale": self.mention_finale,
            "contenu": [b.to_dict() for b in self.blocs],
        }
