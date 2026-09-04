"""La cascade : recherche déterministe, puis rédaction, puis choix assisté.

Trois niveaux, et le premier porte les deux autres :

1. **Recherche de substitution** (:mod:`substitution`) — déterministe, hors
   ligne, reproductible. Elle produit les candidats et elle seule.
2. **Rédaction** — un modèle de langage reformule le « pourquoi celui-ci » en
   français lisible. Le choix ne change pas ; seul le texte s'améliore.
3. **Choix assisté** — le modèle désigne, *parmi les candidats déjà calculés*,
   celui qui convient le mieux à la situation.

L'invariant qui rend le niveau 3 acceptable tient en une phrase : **le modèle
choisit dans une liste, il ne la fabrique pas**. Tout candidat a donc déjà
passé les trois conditions de la substitution — exécutable seul, entièrement
réversible, strictement moins engageant que le geste écarté. Un modèle qui
répondrait n'importe quoi ne peut pas faire sortir un geste dangereux : sa
réponse est confrontée à la liste, et rejetée si elle n'y figure pas.

C'est aussi ce qui préserve l'ADR-003. Celui-ci interdit au modèle de choisir
l'action *exécutée sans validation*. Ici, rien n'est exécuté : on prépare une
proposition qu'un agent lira et acceptera ou non. La distinction est celle
entre concevoir la réponse et la décider.

À tous les niveaux, l'indisponibilité du modèle est un cas nominal, pas une
panne : la plateforme retombe sur le niveau 1 et n'en dit rien à l'agent, sinon
la mention du fournisseur employé.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from ..logging_setup import log_with
from .substitution import Alternative, Substitution

logger = logging.getLogger(__name__)

CONSIGNE = """\
Tu assistes un analyste d'un centre national de réponse aux incidents.

Il vient d'écarter un geste de confinement que la plateforme lui proposait.
La plateforme a calculé une liste de gestes de remplacement — tous vérifiés
comme entièrement réversibles et moins engageants que celui qu'il a écarté.

TA TÂCHE : désigner celui qui convient le mieux, et dire pourquoi.

RÈGLES ABSOLUES :
- Tu choisis EXCLUSIVEMENT dans la liste fournie. Proposer un geste qui n'y
  figure pas est une faute grave : la plateforme le rejetterait, et l'analyste
  perdrait du temps.
- Tu n'inventes aucun chiffre, aucun nom de machine, aucun identifiant.
- Tu ne minimises pas ce que le geste retenu ne fait pas.

FORMAT DE RÉPONSE, strictement :
Première ligne : la clé du geste retenu, seule, telle qu'elle apparaît dans la
liste (exemple : network:move_to_vlan).
Lignes suivantes : deux ou trois phrases en français courant expliquant
pourquoi celui-ci, et ce qu'il ne couvre pas. Pas de puces, pas de titre.
Pas de terme technique : l'analyste lit du français, pas des identifiants.\
"""


@dataclass(slots=True)
class Conseil:
    """Ce que la plateforme recommande, et par quel moyen elle y est arrivée."""

    retenue: Alternative | None
    autres: list[Alternative]
    justification: str
    niveau: str
    """« deterministe » | « redige » | « choisi »"""
    fournisseur: str

    @property
    def vide(self) -> bool:
        return self.retenue is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "retenue": self.retenue.to_dict() if self.retenue else None,
            "autres": [a.to_dict() for a in self.autres],
            "justification": self.justification,
            "niveau": self.niveau,
            "fournisseur": self.fournisseur,
            "explication_niveau": NIVEAUX.get(self.niveau, ""),
        }


NIVEAUX: dict[str, str] = {
    "deterministe": (
        "Proposition calculée par la plateforme à partir de son catalogue, sans "
        "modèle de langage. Reproductible à l'identique."
    ),
    "redige": (
        "Proposition calculée par la plateforme ; la justification a été mise en "
        "forme par un modèle de langage à partir des mêmes faits."
    ),
    "choisi": (
        "Proposition désignée par un modèle de langage parmi les gestes que la "
        "plateforme avait retenus comme sûrs. Aucun geste hors de cette liste ne "
        "peut être proposé."
    ),
}


class Conseiller:
    """Enchaîne les trois niveaux, du plus sûr au plus riche."""

    def __init__(
        self,
        substitution: Substitution,
        provider: Any = None,
        choix_assiste: bool = True,
    ) -> None:
        self._substitution = substitution
        self._provider = provider
        self._choix_assiste = choix_assiste

    def conseiller(
        self,
        attente: dict[str, Any],
        incident: Any = None,
    ) -> Conseil:
        candidats = self._substitution.alternatives(
            attente["actuator"],
            attente["verb"],
            attente["target"],
            dict(attente.get("parameters") or {}),
        )
        if not candidats:
            return Conseil(
                retenue=None,
                autres=[],
                justification=(
                    "La plateforme ne connaît aucun geste plus léger servant le même "
                    "objectif. Le geste écarté était déjà le moins engageant de son "
                    "catalogue pour cette situation."
                ),
                niveau="deterministe",
                fournisseur="aucun",
            )

        # Niveau 1 : le socle. Il tient seul, et c'est lui qu'on rend si tout
        # le reste échoue.
        socle = Conseil(
            retenue=candidats[0],
            autres=candidats[1:4],
            justification=f"{candidats[0].motif} {candidats[0].reserve}",
            niveau="deterministe",
            fournisseur="aucun",
        )
        if self._provider is None or not getattr(self._provider, "available", lambda: False)():
            return socle

        # Niveaux 2 et 3 : un seul appel les sert tous les deux. Le modèle
        # désigne et justifie ; si sa désignation ne tient pas, on garde celle
        # du socle et on ne conserve que le texte.
        rendu = self._interroger(attente, incident, candidats, socle)
        if rendu is None:
            return socle
        return rendu

    # -------------------------------------------------------------- modèle

    def _interroger(
        self,
        attente: dict[str, Any],
        incident: Any,
        candidats: list[Alternative],
        socle: Conseil,
    ) -> Conseil | None:
        faits = _faits(attente, incident, candidats)
        question = (
            "Quel geste de remplacement proposer à l'analyste, et pourquoi ?\n\n"
            + CONSIGNE
        )
        try:
            texte = self._provider.render(question, faits, socle.justification)
        except Exception as exc:  # noqa: BLE001 - le repli couvre tout échec
            log_with(
                logger,
                logging.WARNING,
                "conseil : modele indisponible, repli sur la recherche deterministe",
                error=str(exc),
            )
            return None

        if not texte or texte.strip() == socle.justification.strip():
            return None

        cle, justification = _decouper(texte)
        par_cle = {a.entree.key: a for a in candidats}
        retenue = par_cle.get(cle) if self._choix_assiste else None

        if retenue is None:
            # Le modèle n'a pas désigné un candidat valide : on ne suit pas son
            # choix, mais son texte reste utile pour expliquer celui du socle.
            if cle:
                log_with(
                    logger,
                    logging.WARNING,
                    "conseil : geste propose hors de la liste, choix deterministe conserve",
                    propose=cle,
                    retenu=socle.retenue.entree.key if socle.retenue else None,
                )
            return Conseil(
                retenue=socle.retenue,
                autres=socle.autres,
                justification=justification or socle.justification,
                niveau="redige",
                fournisseur=getattr(self._provider, "name", "inconnu"),
            )

        autres = [a for a in candidats if a.entree.key != retenue.entree.key][:3]
        return Conseil(
            retenue=retenue,
            autres=autres,
            justification=justification or f"{retenue.motif} {retenue.reserve}",
            niveau="choisi",
            fournisseur=getattr(self._provider, "name", "inconnu"),
        )


# ------------------------------------------------------------------ outils


def _faits(
    attente: dict[str, Any], incident: Any, candidats: list[Alternative]
) -> dict[str, Any]:
    """Les seules données transmises au modèle. Rien d'autre n'existe pour lui."""
    return {
        "geste_ecarte": {
            "intitule": attente.get("expected_effect") or f"{attente['verb']}",
            "cible": attente["target"],
            "effet_residuel": attente.get("residual_effect", ""),
            "reversibilite": attente.get("reversibility", ""),
        },
        "incident": {
            "type": getattr(incident, "attack_label", "") or "menace non qualifiée",
            "gravite": getattr(getattr(incident, "severity", None), "value", ""),
            "dangerosite": getattr(incident, "dangerousness", 0.0),
        }
        if incident is not None
        else {},
        "gestes_possibles": [
            {
                "cle": a.entree.key,
                "ce_qu_il_fait": a.entree.description,
                "objectif_servi": a.but.intitule,
                "equipements_touches": a.entree.typical_blast_radius,
                "annulable_entierement": True,
            }
            for a in candidats
        ],
    }


def _decouper(texte: str) -> tuple[str, str]:
    """Sépare la clé désignée de la justification.

    Le modèle est prié de mettre la clé seule en première ligne. On tolère
    qu'il l'entoure de ponctuation ou de gras, mais pas qu'il la noie dans une
    phrase : dans ce cas la clé est jugée absente et le choix du socle tient.
    """
    lignes = [ligne.strip() for ligne in texte.strip().splitlines() if ligne.strip()]
    if not lignes:
        return "", ""
    tete = lignes[0].strip("`*_ .:—-")
    cle = tete if ":" in tete and " " not in tete else ""
    corps = "\n".join(lignes[1:] if cle else lignes).strip()
    return cle, corps


def dumps(conseil: Conseil) -> str:
    return json.dumps(conseil.to_dict(), ensure_ascii=False, indent=2, default=str)
