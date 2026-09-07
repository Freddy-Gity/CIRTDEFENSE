"""Ce que la plateforme fait d'elle-même quand un agent écarte un geste.

Un refus ne rend pas la menace inoffensive. La plateforme ne peut ni passer
outre — l'agent a tranché — ni faire comme si de rien n'était. Elle doit donc
faire **autre chose**, et le dire.

La règle est arbitrée par la dangerosité de l'incident, seuil porté par la
configuration d'autonomie :

* **sous le seuil** — l'actif passe en surveillance rapprochée. Aucun effet
  sur les équipements : les contrôles se resserrent, l'incident reste ouvert,
  et la machine cesse d'être perdue de vue. C'est une mesure d'attention, pas
  de confinement.

* **au-dessus du seuil** — la plateforme applique une quarantaine, mais
  **jamais avec le geste que l'agent vient d'écarter**. Elle passe par une
  substitution entièrement réversible. Rejouer le geste refusé sous un autre
  nom viderait le refus de son sens ; appliquer un geste plus léger, annulable
  d'un clic, est une réponse proportionnée que l'agent peut défaire.

Cette distinction est le cœur du module. Sans elle, « écarter » deviendrait un
bouton décoratif, ou pire, un bouton que la plateforme contourne.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..domain.enums import AuditEventType
from ..logging_setup import log_with
from .conseil import Conseil, Conseiller
from .substitution import Alternative

logger = logging.getLogger(__name__)

SEUIL_QUARANTAINE = 7.0
"""Dangerosité à partir de laquelle un refus déclenche tout de même un
confinement de substitution. Sur l'échelle de dix du catalogue métier, 7
correspond au seuil « élevée » — celui à partir duquel le Centre considère
qu'une menace ne peut pas rester sans mesure."""


@dataclass(slots=True)
class Escalade:
    """Ce que la plateforme a décidé de faire après le refus."""

    mesure: str
    """« surveillance » | « quarantaine » | « aucune »"""
    intitule: str
    """Formulé pour l'agent, en français courant."""
    motif: str
    dangerosite: float
    seuil: float
    alternative: Alternative | None = None
    action: Any = None
    """Résultat d'exécution, quand une quarantaine a effectivement été posée."""
    propositions: list[Alternative] = field(default_factory=list)
    """Les autres substitutions possibles, soumises à l'agent."""
    conseil: Any = None
    """Le conseil complet : par quel niveau de la cascade il a été obtenu."""

    @property
    def a_agi(self) -> bool:
        return self.action is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mesure": self.mesure,
            "intitule": self.intitule,
            "motif": self.motif,
            "dangerosite": self.dangerosite,
            "seuil": self.seuil,
            "alternative": self.alternative.to_dict() if self.alternative else None,
            "action": self.action.to_dict() if self.action else None,
            "propositions": [p.to_dict() for p in self.propositions],
            "conseil": self.conseil.to_dict() if self.conseil else None,
        }


class ServiceEscalade:
    """Applique la suite d'un refus. Ne décide jamais d'exécuter le geste refusé."""

    def __init__(
        self,
        conseiller: Conseiller,
        executor: Any,
        incidents: Any,
        ledger: Any,
        seuil: float = SEUIL_QUARANTAINE,
    ) -> None:
        self._conseiller = conseiller
        self._executor = executor
        self._incidents = incidents
        self._ledger = ledger
        self._seuil = seuil

    def apres_refus(self, attente: dict[str, Any], acteur: str, motif_humain: str) -> Escalade:
        incident = self._incidents.get(attente["incident_id"])
        dangerosite = float(getattr(incident, "dangerousness", 0.0) or 0.0)

        conseil = self._conseiller.conseiller(attente, incident)

        if dangerosite >= self._seuil and not conseil.vide:
            return self._quarantaine(attente, incident, conseil, dangerosite, acteur)
        return self._surveillance(attente, incident, conseil, dangerosite, acteur, motif_humain)

    # ------------------------------------------------------------ mesures

    def _quarantaine(
        self,
        attente: dict[str, Any],
        incident: Any,
        conseil: Conseil,
        dangerosite: float,
        acteur: str,
    ) -> Escalade:
        """Confinement de substitution, entièrement réversible.

        On applique le geste que le conseil a retenu : il sert le même but en
        engageant le moins, et il a passé les trois conditions de la
        substitution. L'agent peut l'annuler comme n'importe quelle autre
        action.
        """
        retenue = conseil.retenue
        assert retenue is not None  # garanti par `not conseil.vide` chez l'appelant
        resultat = self._executor.execute(
            retenue.spec,
            incident_id=attente["incident_id"],
            decision_id=attente["decision_id"],
            watch_target=attente["target"],
        )
        if incident is not None:
            incident.register_action(resultat)
            self._marquer(incident, "quarantaine", dangerosite)
            self._incidents.save(incident)

        escalade = Escalade(
            mesure="quarantaine",
            intitule=(
                "Mise en quarantaine par un geste de substitution : "
                f"{retenue.entree.description}"
            ),
            motif=(
                f"La dangerosité de l'intervention atteint {dangerosite}/10, au-delà du "
                f"seuil de {self._seuil} au-dessus duquel le Centre n'accepte pas qu'une "
                "menace reste sans mesure. Le geste que vous avez écarté n'a pas été "
                "appliqué : la plateforme lui a substitué un geste entièrement "
                f"réversible, que vous pouvez annuler à tout moment. {conseil.justification}"
            ),
            dangerosite=dangerosite,
            seuil=self._seuil,
            alternative=retenue,
            action=resultat,
            propositions=list(conseil.autres),
            conseil=conseil,
        )
        self._inscrire(attente, escalade, acteur)
        log_with(
            logger,
            logging.WARNING,
            "refus humain : quarantaine de substitution appliquee",
            incident_id=attente["incident_id"],
            ecarte=f"{attente['actuator']}:{attente['verb']}",
            substitut=retenue.entree.key,
            dangerosite=dangerosite,
        )
        return escalade

    def _surveillance(
        self,
        attente: dict[str, Any],
        incident: Any,
        conseil: Conseil,
        dangerosite: float,
        acteur: str,
        motif_humain: str,
    ) -> Escalade:
        """Aucun geste sur les équipements : l'actif passe sous l'œil.

        C'est la mesure la plus faible que la plateforme puisse prendre sans
        rester inerte, et elle respecte entièrement le refus de l'agent.
        """
        if incident is not None:
            self._marquer(incident, "renforcee", dangerosite)
            self._incidents.save(incident)

        if not conseil.vide:
            intitule = (
                "Surveillance rapprochée de l'actif, et proposition d'un geste "
                "plus léger soumise à votre décision"
            )
        else:
            intitule = "Surveillance rapprochée de l'actif"

        escalade = Escalade(
            mesure="surveillance",
            intitule=intitule,
            motif=(
                f"La dangerosité de l'intervention est de {dangerosite}/10, en deçà du "
                f"seuil de {self._seuil}. Votre refus est appliqué tel quel : aucun "
                "geste n'a été posé sur les équipements. L'actif reste sous "
                "surveillance rapprochée et l'intervention demeure ouverte."
                + (
                    " Un geste moins engageant est proposé ci-dessous ; il n'est "
                    f"appliqué que si vous le demandez. {conseil.justification}"
                    if not conseil.vide
                    else f" {conseil.justification}"
                )
            ),
            dangerosite=dangerosite,
            seuil=self._seuil,
            alternative=conseil.retenue,
            propositions=list(conseil.autres),
            conseil=conseil,
        )
        del motif_humain
        self._inscrire(attente, escalade, acteur)
        return escalade

    # ------------------------------------------------------------- outils

    @staticmethod
    def _marquer(incident: Any, niveau: str, dangerosite: float) -> None:
        """Le niveau de surveillance vit sur l'incident, pas sur un registre à part.

        L'actif touché n'est pas toujours une plateforme déclarée dans l'onglet
        Surveillance ; le rattacher à l'incident garantit que la mention suit
        l'affaire, quel que soit l'équipement.
        """
        incident.labels["surveillance"] = {
            "niveau": niveau,
            "depuis": datetime.now(UTC).isoformat(),
            "dangerosite": dangerosite,
        }

    def _inscrire(self, attente: dict[str, Any], escalade: Escalade, acteur: str) -> None:
        self._ledger.record(
            AuditEventType.CONFIRMATION_RESOLVED,
            {
                "pending_id": attente["pending_id"],
                "resolution": "declined",
                "suite": escalade.mesure,
                "ecarte": f"{attente['actuator']}:{attente['verb']}",
                "substitut": escalade.alternative.entree.key if escalade.alternative else None,
                "applique": escalade.a_agi,
                "dangerosite": escalade.dangerosite,
                "seuil": escalade.seuil,
            },
            actor=acteur,
            incident_id=attente["incident_id"],
            decision_id=attente["decision_id"],
            action_id=escalade.action.action_id if escalade.action else None,
        )
