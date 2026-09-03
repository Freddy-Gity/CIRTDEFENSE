"""Ce que l'exploitant demande de couvrir dans son rapport.

Auparavant, l'onglet Rapports produisait d'office un bilan des vingt-quatre
dernières heures. C'est rarement ce qu'on cherche : on veut le compte rendu
*d'une intervention précise* pour l'annexer à un courrier, ou *de toutes les
attaques réseau du mois* pour un comité, ou *des seuls incidents critiques*
pour la hiérarchie.

Cinq façons de délimiter un rapport, et une seule mécanique derrière : un
filtre appliqué au portefeuille d'incidents, qui rend en plus le libellé
administratif du périmètre — celui qui figurera sous « Objet : ».
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from ..domain.taxonomy import BY_CODE, AttackFamily
from . import langage


class Perimetre(StrEnum):
    PERIODE = "periode"
    """Toute l'activité sur une durée."""
    INCIDENT = "incident"
    """Une intervention précise, désignée par son numéro."""
    FAMILLE = "famille"
    """Une famille d'attaque : réseau, applicative, interne, infrastructure."""
    CRITICITE = "criticite"
    """Un niveau de gravité et au-dessus."""
    TYPE = "type"
    """Un type précis du catalogue métier : A1, B4, C2…"""


FENETRES: dict[str, int] = {
    "24h": 24,
    "7j": 24 * 7,
    "30j": 24 * 30,
    "90j": 24 * 90,
    "1an": 24 * 365,
}

LIBELLES_FENETRE: dict[str, str] = {
    "24h": "les dernières vingt-quatre heures",
    "7j": "les sept derniers jours",
    "30j": "les trente derniers jours",
    "90j": "les quatre-vingt-dix derniers jours",
    "1an": "les douze derniers mois",
}

# Ordre de gravité, du plus faible au plus fort. Sélectionner « élevée »
# retient aussi le critique : on ne demande pas un rapport sur les incidents
# graves en espérant que les plus graves en soient absents.
ECHELLE_CRITICITE = ("info", "low", "medium", "high", "critical")


@dataclass(slots=True)
class Selection:
    """Le périmètre demandé, et de quoi le décrire en français."""

    perimetre: Perimetre = Perimetre.PERIODE
    fenetre: str = "24h"
    valeur: str = ""
    """Numéro d'incident, code de famille, niveau de gravité ou code de type."""

    @property
    def heures(self) -> int:
        return FENETRES.get(self.fenetre, 24)

    @property
    def depuis(self) -> datetime:
        return datetime.now(UTC) - timedelta(hours=self.heures)

    def valider(self) -> str:
        """Rend un message d'erreur en clair, ou une chaîne vide si tout va bien."""
        if self.perimetre is not Perimetre.INCIDENT and self.fenetre not in FENETRES:
            return (
                f"durée « {self.fenetre} » inconnue ; "
                f"choisir parmi : {', '.join(FENETRES)}"
            )
        if self.perimetre is Perimetre.INCIDENT and not self.valeur:
            return "indiquer le numéro de l'intervention à rapporter"
        if self.perimetre is Perimetre.FAMILLE and self.valeur not in {
            f.value for f in AttackFamily
        }:
            return (
                f"famille « {self.valeur} » inconnue ; choisir parmi : "
                f"{', '.join(f.value for f in AttackFamily)}"
            )
        if self.perimetre is Perimetre.CRITICITE and self.valeur not in ECHELLE_CRITICITE:
            return (
                f"niveau de gravité « {self.valeur} » inconnu ; choisir parmi : "
                f"{', '.join(ECHELLE_CRITICITE)}"
            )
        if self.perimetre is Perimetre.TYPE and self.valeur not in BY_CODE:
            return f"type d'attaque « {self.valeur} » absent du catalogue"
        return ""

    # -- description administrative ------------------------------------------

    def objet(self) -> str:
        """La phrase qui figurera sous « Objet : » dans l'en-tête du document."""
        duree = LIBELLES_FENETRE.get(self.fenetre, self.fenetre)
        match self.perimetre:
            case Perimetre.INCIDENT:
                return (
                    "Compte rendu de l'intervention n° "
                    f"{langage.numero_intervention(self.valeur)}"
                )
            case Perimetre.FAMILLE:
                famille = _famille(self.valeur)
                intitule = famille.label.lower() if famille else self.valeur
                return f"Compte rendu des interventions sur {intitule} — {duree}"
            case Perimetre.CRITICITE:
                niveau = langage.criticite(self.valeur)
                return (
                    f"Compte rendu des interventions de gravité {niveau} "
                    f"et supérieure — {duree}"
                )
            case Perimetre.TYPE:
                type_attaque = BY_CODE.get(self.valeur)
                intitule = type_attaque.label if type_attaque else self.valeur
                return f"Compte rendu des interventions de type « {intitule} » — {duree}"
            case _:
                return f"Compte rendu général des opérations — {duree}"

    def titre(self) -> str:
        match self.perimetre:
            case Perimetre.INCIDENT:
                return "RAPPORT D'INTERVENTION"
            case Perimetre.PERIODE:
                return "RAPPORT PÉRIODIQUE D'OPÉRATIONS"
            case _:
                return "RAPPORT THÉMATIQUE D'OPÉRATIONS"

    def suffixe_de_fichier(self) -> str:
        """Nom de fichier sans accent : un en-tête HTTP ne transporte que de l'ASCII."""
        match self.perimetre:
            case Perimetre.INCIDENT:
                return f"intervention-{self.valeur}"
            case Perimetre.PERIODE:
                return f"operations-{self.fenetre}"
            case _:
                valeur = "".join(c for c in self.valeur if c.isalnum() or c == "-")
                return f"{self.perimetre.value}-{valeur}-{self.fenetre}"

    # -- application du filtre ------------------------------------------------

    def retient(self, incident: dict[str, Any]) -> bool:
        """L'incident entre-t-il dans le périmètre demandé ?

        Le filtre porte sur le portefeuille, jamais sur le journal : un
        rapport décrit des interventions, pas des lignes de journal.
        """
        match self.perimetre:
            case Perimetre.INCIDENT:
                return incident.get("incident_id") == self.valeur
            case Perimetre.FAMILLE:
                return incident.get("family") == self.valeur
            case Perimetre.CRITICITE:
                return _au_moins(incident.get("severity", ""), self.valeur)
            case Perimetre.TYPE:
                return incident.get("attack_code") == self.valeur
            case _:
                return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "perimetre": self.perimetre.value,
            "fenetre": self.fenetre,
            "valeur": self.valeur,
            "objet": self.objet(),
            "titre": self.titre(),
        }


def _au_moins(gravite: str, plancher: str) -> bool:
    try:
        return ECHELLE_CRITICITE.index(gravite) >= ECHELLE_CRITICITE.index(plancher)
    except ValueError:
        return False


def _famille(valeur: str) -> AttackFamily | None:
    try:
        return AttackFamily(valeur)
    except ValueError:
        return None


def choix_possibles() -> dict[str, Any]:
    """Ce que l'interface propose dans ses menus, servi par le serveur.

    Les libellés sont écrits ici et nulle part ailleurs : une famille renommée
    dans le catalogue ne doit pas obliger à retoucher le code de l'interface.
    """
    return {
        "perimetres": [
            {"cle": Perimetre.PERIODE.value, "libelle": "Toute l'activité d'une période"},
            {"cle": Perimetre.INCIDENT.value, "libelle": "Une intervention précise"},
            {"cle": Perimetre.FAMILLE.value, "libelle": "Une famille d'attaque"},
            {"cle": Perimetre.CRITICITE.value, "libelle": "Un niveau de gravité"},
            {"cle": Perimetre.TYPE.value, "libelle": "Un type d'attaque du catalogue"},
        ],
        "fenetres": [
            {"cle": cle, "libelle": LIBELLES_FENETRE[cle].capitalize()} for cle in FENETRES
        ],
        "familles": [
            {"cle": f.value, "libelle": f"{f.code} — {f.label}"} for f in AttackFamily
        ],
        "criticites": [
            {"cle": c, "libelle": langage.criticite(c).capitalize()}
            for c in reversed(ECHELLE_CRITICITE)
        ],
        "types": [
            {"cle": code, "libelle": f"{code} — {t.label}"} for code, t in BY_CODE.items()
        ],
        "formats": [
            {"cle": "pdf", "libelle": "PDF — document officiel prêt à signer"},
            {"cle": "docx", "libelle": "Word — pour reprise et annotation"},
            {"cle": "md", "libelle": "Markdown — texte brut"},
            {"cle": "json", "libelle": "JSON — pour un autre système"},
        ],
    }
