"""Qualification d'une menace hors catalogue (EF-29).

Le confinement de repli protège sans nommer : il agit sur des indicateurs
observés, jamais sur un type d'attaque supposé. L'incident reste donc, une
fois contenu, une « menace inconnue » — et le restera à chaque occurrence si
rien ne vient l'inscrire quelque part.

Ce module produit une **proposition** de qualification, et rien de plus. Elle
n'a aucun effet sur le comportement du moteur tant qu'un humain ne l'a pas
validée. Le choix est délibéré : un catalogue qui s'enrichirait seul dériverait
sans contrôle, et l'on ne saurait plus, au bout de quelques mois, sur quoi la
plateforme fonde ses réponses.

**Ce que la proposition affirme, et ce qu'elle n'affirme pas.** Elle décrit ce
qui a été observé — une communication sortante, un compte sollicité, un port
inattendu — et en déduit une famille et un nom descriptif. Elle ne prétend pas
identifier l'attaque : nommer « exfiltration » ce qui pourrait être une
sauvegarde mal configurée serait exactement l'invention que la garde EF-04
interdit ailleurs. Le nom proposé décrit le symptôme ; c'est l'analyste qui
décide s'il porte un diagnostic.

**La clé de reconnaissance.** Une entrée validée est retrouvée non par la
catégorie de l'événement — elle vaut `unknown` pour toutes les menaces hors
catalogue, et servirait donc de clé à toutes indifféremment — mais par la
*signature des indicateurs observés*. Deux incidents qui présentent la même
forme d'observation sont reconnus comme du même type ; deux incidents de
formes différentes restent distincts.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..domain.enums import Severity, SourceKind
from ..domain.events import DetectionEvent
from ..domain.taxonomy import AttackFamily

# Indicateurs qui rattachent une observation à une famille du catalogue CIRT.
# Un indicateur absent de cette table ne compte pas : il n'oriente rien.
_FAMILLE_PAR_INDICATEUR: dict[str, AttackFamily] = {
    # A — réseau
    "src_ip": AttackFamily.NETWORK,
    "srcip": AttackFamily.NETWORK,
    "source_ip": AttackFamily.NETWORK,
    "dest_ip": AttackFamily.NETWORK,
    "dstip": AttackFamily.NETWORK,
    "destination_ip": AttackFamily.NETWORK,
    "dest_port": AttackFamily.NETWORK,
    "dstport": AttackFamily.NETWORK,
    "port": AttackFamily.NETWORK,
    "proto": AttackFamily.NETWORK,
    "domain": AttackFamily.NETWORK,
    # B — applicatif
    "url": AttackFamily.APPLICATION,
    "uri": AttackFamily.APPLICATION,
    "http_method": AttackFamily.APPLICATION,
    "user_agent": AttackFamily.APPLICATION,
    "app_proto": AttackFamily.APPLICATION,
    "payload": AttackFamily.APPLICATION,
    # C — comportemental / interne
    "user": AttackFamily.INSIDER,
    "srcuser": AttackFamily.INSIDER,
    "dstuser": AttackFamily.INSIDER,
    "account": AttackFamily.INSIDER,
    "ueba_score": AttackFamily.INSIDER,
}

# À défaut d'indicateur orientant, la source de détection tranche.
_FAMILLE_PAR_SOURCE: dict[SourceKind, AttackFamily] = {
    SourceKind.INFRASTRUCTURE: AttackFamily.INFRASTRUCTURE,
    SourceKind.UEBA: AttackFamily.INSIDER,
    SourceKind.NIDS: AttackFamily.NETWORK,
    SourceKind.EDR: AttackFamily.INSIDER,
}

# Indicateurs retenus dans la signature. Sont volontairement exclues les
# valeurs volatiles — une adresse, un identifiant de session — car deux
# occurrences du même type d'attaque n'auront pas les mêmes. Ce qui se répète,
# c'est la *forme* de l'observation, pas son contenu.
_SIGNIFIANTS = frozenset(_FAMILLE_PAR_INDICATEUR)


@dataclass(slots=True)
class FicheDeQualification:
    """Proposition soumise à l'analyste. Chaque champ est corrigeable."""

    incident_id: str
    label: str
    family: str
    category: str
    """Clé de reconnaissance : signature des indicateurs, pas la catégorie."""
    severity: str
    dangerousness: float
    signal: str
    """Ce qui a été observé, en clair. C'est la justification de la fiche."""
    observed_indicators: list[str] = field(default_factory=list)
    source_product: str = ""
    rationale: str = ""
    """Pourquoi cette famille et ce nom ont été proposés."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "label": self.label,
            "family": self.family,
            "category": self.category,
            "severity": self.severity,
            "dangerousness": round(self.dangerousness, 1),
            "signal": self.signal,
            "observed_indicators": self.observed_indicators,
            "source_product": self.source_product,
            "rationale": self.rationale,
        }


def signature(event: DetectionEvent) -> str:
    """Clé stable identifiant la *forme* d'une observation.

    Deux occurrences d'une même menace inédite — mêmes natures d'indicateurs,
    même famille — produisent la même clé, même si les adresses et les comptes
    diffèrent. C'est ce qui permet à la seconde d'être reconnue.
    """
    retenus = sorted(k for k in event.indicators if k in _SIGNIFIANTS)
    famille = _famille(event, retenus)
    empreinte = hashlib.sha256("|".join(retenus).encode()).hexdigest()[:8]
    return f"appris_{famille.value}_{empreinte}"


def _famille(event: DetectionEvent, retenus: list[str]) -> AttackFamily:
    """Famille majoritaire parmi les indicateurs, la source tranchant à défaut."""
    comptes: dict[AttackFamily, int] = {}
    for cle in retenus:
        famille = _FAMILLE_PAR_INDICATEUR[cle]
        comptes[famille] = comptes.get(famille, 0) + 1
    if comptes:
        # À égalité, l'ordre de déclaration de l'énumération tranche, pour que
        # la fonction reste déterministe d'une exécution à l'autre.
        maximum = max(comptes.values())
        for famille in AttackFamily:
            if comptes.get(famille) == maximum:
                return famille
    return _FAMILLE_PAR_SOURCE.get(event.source, AttackFamily.NETWORK)


class Qualifier:
    """Compose une fiche de qualification à partir des seuls faits observés."""

    def propose(
        self,
        event: DetectionEvent,
        incident_id: str,
        dangerousness: float = 5.0,
        severity: Severity | None = None,
    ) -> FicheDeQualification:
        retenus = sorted(k for k in event.indicators if k in _SIGNIFIANTS)
        famille = _famille(event, retenus)
        observations = self._observations(event, retenus)

        return FicheDeQualification(
            incident_id=incident_id,
            label=self._nom(event, famille, retenus),
            family=famille.value,
            category=signature(event),
            severity=(severity or event.severity).value,
            dangerousness=dangerousness,
            signal=" ; ".join(observations) or "aucun indicateur exploitable",
            observed_indicators=retenus,
            source_product=event.source_product,
            rationale=self._motif(famille, retenus, event),
        )

    # -- composition du nom --------------------------------------------------

    @staticmethod
    def _nom(event: DetectionEvent, famille: AttackFamily, retenus: list[str]) -> str:
        """Nom descriptif du symptôme, jamais un diagnostic.

        « Communication sortante vers une adresse externe » est vérifiable ;
        « exfiltration de données » ne l'est pas — ce serait interpréter.
        """
        cible = event.asset.hostname or event.asset.asset_id
        sortant = any(k in retenus for k in ("dest_ip", "dstip", "destination_ip", "domain"))
        entrant = any(k in retenus for k in ("src_ip", "srcip", "source_ip"))
        compte = any(k in retenus for k in ("user", "srcuser", "dstuser", "account"))
        port = any(k in retenus for k in ("dest_port", "dstport", "port"))

        match famille:
            case AttackFamily.NETWORK if sortant:
                base = "Communication sortante vers une destination externe non référencée"
            case AttackFamily.NETWORK if entrant:
                base = "Sollicitation entrante depuis une adresse externe non référencée"
            case AttackFamily.NETWORK:
                base = "Trafic réseau sans correspondance au catalogue"
            case AttackFamily.APPLICATION:
                base = f"Requête applicative anormale sur {cible}"
            case AttackFamily.INSIDER:
                base = "Usage inhabituel d'un compte"
            case _:
                base = f"Dégradation de service constatée sur {cible}"

        precisions = []
        if compte and famille is not AttackFamily.INSIDER:
            precisions.append("compte impliqué")
        if port and famille is not AttackFamily.NETWORK:
            precisions.append("port inattendu")
        return base + (f" ({', '.join(precisions)})" if precisions else "")

    # -- justification -------------------------------------------------------

    @staticmethod
    def _observations(event: DetectionEvent, retenus: list[str]) -> list[str]:
        return [f"{cle} = {event.indicators[cle]}" for cle in retenus]

    @staticmethod
    def _motif(famille: AttackFamily, retenus: list[str], event: DetectionEvent) -> str:
        if retenus:
            return (
                f"famille {famille.code} ({famille.label}) déduite de "
                f"{len(retenus)} indicateur(s) observé(s) : {', '.join(retenus)}. "
                "Le nom proposé décrit ce qui a été constaté, il ne pose pas de diagnostic."
            )
        return (
            f"aucun indicateur orientant ; famille {famille.code} déduite de la source "
            f"de détection ({event.source.value}). Proposition à corriger."
        )
