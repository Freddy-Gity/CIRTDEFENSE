"""Que proposer quand un agent écarte un geste ?

Un refus laisse la menace entière. Répondre « très bien » et clore le dossier
serait la pire des issues : l'agent a écarté *ce geste-là*, pas le besoin de
contenir. La plateforme doit donc chercher **ce qu'elle sait encore faire**,
et le proposer.

La recherche s'appuie sur deux notions déclarées, et sur rien d'autre :

* **le but visé** — plusieurs gestes servent le même objectif de confinement.
  Couper une machine du réseau se fait en l'isolant depuis l'agent de poste,
  ou en la basculant dans un réseau de quarantaine. Le second est moins
  engageant que le premier, et sert le même but.

* **l'engagement** — ce que le geste coûte s'il se révèle inutile. Il se
  calcule à partir du catalogue de réversibilité, jamais à la main : degré de
  réversibilité, rayon d'action, effet résiduel après annulation.

Une alternative n'est retenue que si elle est **strictement moins engageante**
que le geste écarté. Proposer plus engageant après un refus reviendrait à
passer outre, ce que la plateforme s'interdit.

Ce module ne fait aucun appel réseau et ne dépend d'aucun modèle. Il constitue
le socle de la cascade décrite dans l'ADR-004 : la justification rédigée et le
choix assisté viennent par-dessus, jamais à la place.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..domain.action import ActionSpec
from ..domain.enums import Reversibility
from .reversibility import CatalogEntry, ReversibilityCatalog


class Cible(StrEnum):
    """Ce sur quoi un geste s'applique.

    Deux gestes ne sont substituables que s'ils portent sur la même chose :
    remplacer le verrouillage d'un compte par le blocage d'une adresse ne
    protège pas le même objet, même si les deux « contiennent » quelque chose.
    """

    MACHINE = "machine"
    COMPTE = "compte"
    ADRESSE = "adresse"
    DOMAINE = "domaine"
    PORT = "port"
    SERVICE = "service"
    FICHIER = "fichier"
    APPLICATION = "application"


@dataclass(frozen=True, slots=True)
class But:
    """Un objectif de confinement, et les gestes qui le servent."""

    code: str
    intitule: str
    """Formulé en français courant : il figure tel quel dans l'interface."""
    cible: Cible
    gestes: tuple[str, ...]


# Table des buts. C'est de la connaissance métier explicite, au même titre
# qu'un playbook : elle se lit, se critique et se corrige par un analyste du
# CIRT sans toucher au moteur.
BUTS: tuple[But, ...] = (
    But(
        code="isolement",
        intitule="couper une machine du reste du réseau",
        cible=Cible.MACHINE,
        gestes=(
            "edr:isolate_host",
            "network:move_to_vlan",
            "network:block_lateral",
            "network:throttle_egress",
        ),
    ),
    But(
        code="flux_sortant",
        intitule="interrompre un transfert de données vers l'extérieur",
        cible=Cible.ADRESSE,
        gestes=(
            "network:cut_egress_connection",
            "edge:blackhole_ip",
            "firewall:block_ip",
            "firewall:rate_limit_ip",
            "edge:edge_rate_limit",
        ),
    ),
    But(
        code="compte",
        intitule="empêcher l'usage d'un compte compromis",
        cible=Cible.COMPTE,
        gestes=(
            "iam:delete_account",
            "iam:disable_account",
            "iam:lock_account",
            "iam:revoke_sessions",
            "iam:force_password_reset",
            "iam:revoke_privilege",
            "iam:restrict_export",
            "iam:revoke_token",
            "iam:block_resource_access",
            "iam:force_mfa",
        ),
    ),
    But(
        code="origine",
        intitule="écarter le trafic d'une adresse hostile",
        cible=Cible.ADRESSE,
        gestes=(
            "edge:blackhole_ip",
            "firewall:block_ip",
            "edge:edge_rate_limit",
            "firewall:rate_limit_ip",
            "edge:enable_scrubbing",
        ),
    ),
    But(
        code="domaine",
        intitule="rendre un nom de domaine injoignable",
        cible=Cible.DOMAINE,
        gestes=(
            "firewall:block_domain",
            "dns:block_resolution",
            "dns:sinkhole_domain",
        ),
    ),
    But(
        code="programme",
        intitule="neutraliser un programme malveillant",
        cible=Cible.FICHIER,
        gestes=(
            "edr:wipe_disk",
            "edr:shutdown_host",
            "edr:kill_process",
            "edr:quarantine_file",
        ),
    ),
    But(
        code="service",
        intitule="rétablir un service dégradé",
        cible=Cible.SERVICE,
        gestes=(
            "service:restart_service",
            "service:failover",
            "service:close_idle_connections",
        ),
    ),
    But(
        code="surface",
        intitule="refermer un point d'entrée inutile",
        cible=Cible.PORT,
        gestes=("config:restore_baseline", "config:close_port"),
    ),
    But(
        code="application",
        intitule="protéger une application exposée",
        cible=Cible.APPLICATION,
        gestes=(
            "waf:block_pattern",
            "waf:rate_limit_rule",
            "waf:block_request",
            "waf:sanitize_field",
        ),
    ),
)

_BUT_PAR_GESTE: dict[str, tuple[But, ...]] = {}
for _but in BUTS:
    for _geste in _but.gestes:
        _BUT_PAR_GESTE.setdefault(_geste, ())
        _BUT_PAR_GESTE[_geste] += (_but,)


# Poids de l'irréversibilité dans le calcul d'engagement. Volontairement très
# supérieur au rayon d'action : un geste irréversible à rayon 1 engage plus
# qu'un geste réversible à rayon 4, parce que le second se défait.
_POIDS_REVERSIBILITE: dict[Reversibility, int] = {
    Reversibility.REVERSIBLE: 0,
    Reversibility.PARTIALLY_REVERSIBLE: 10,
    Reversibility.IRREVERSIBLE: 100,
}


def engagement(entree: CatalogEntry) -> int:
    """Ce que le geste coûte s'il se révèle inutile.

    Calculé depuis le catalogue, jamais fixé à la main : ajouter un geste au
    catalogue suffit à le placer correctement dans l'ordre, sans toucher ici.
    """
    return (
        _POIDS_REVERSIBILITE[entree.reversibility]
        + entree.typical_blast_radius
        + (1 if entree.residual_effect else 0)
    )


@dataclass(slots=True)
class Alternative:
    """Un geste que la plateforme sait encore proposer après un refus."""

    spec: ActionSpec
    entree: CatalogEntry
    but: But
    engagement: int
    ecart: int
    """De combien elle engage moins que le geste écarté."""
    rang: int
    """Position dans la table des buts : sert à départager à engagement égal."""
    motif: str
    """Pourquoi celle-ci — rédigé en français, prêt pour l'interface."""
    reserve: str
    """Ce qu'elle ne fait pas, que le geste écarté aurait fait."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.entree.key,
            "actuator": self.entree.actuator,
            "verb": self.entree.verb,
            "target": self.spec.target,
            "reversibility": self.entree.reversibility.value,
            "rollback_verb": self.entree.rollback_verb,
            "blast_radius": self.entree.typical_blast_radius,
            "but": self.but.intitule,
            "engagement": self.engagement,
            "ecart": self.ecart,
            "motif": self.motif,
            "reserve": self.reserve,
            "description": self.entree.description,
        }


class Substitution:
    """Cherche ce que la plateforme sait encore faire après un refus."""

    def __init__(self, catalog: ReversibilityCatalog) -> None:
        self._catalog = catalog

    def alternatives(
        self, actuator: str, verb: str, target: str, parameters: dict[str, Any] | None = None
    ) -> list[Alternative]:
        """Les gestes substituables au geste écarté, du moins engageant au plus.

        Rend une liste vide plutôt qu'un repli approximatif quand rien ne
        convient : « je ne sais pas faire moins » est une réponse, et elle
        vaut mieux qu'une proposition qui ne tiendrait pas.
        """
        ecarte = self._catalog.get(actuator, verb)
        if ecarte is None:
            return []
        plafond = engagement(ecarte)
        vus: set[str] = set()
        trouvees: list[Alternative] = []

        for but in _BUT_PAR_GESTE.get(ecarte.key, ()):
            for rang, cle in enumerate(but.gestes):
                if cle == ecarte.key or cle in vus:
                    continue
                # Une clé de catalogue s'écrit « actuateur:verbe ».
                actionneur, _, verbe_candidat = cle.partition(":")
                candidat = self._catalog.get(actionneur, verbe_candidat)
                if candidat is None:
                    continue
                if not self._recevable(candidat, plafond):
                    continue
                vus.add(cle)
                trouvees.append(
                    self._composer(candidat, ecarte, but, target, parameters or {}, rang)
                )

        # À engagement égal, la table des buts tranche : elle range les gestes
        # du plus fort au plus léger, ce qui est exactement l'ordre dans lequel
        # un analyste les proposerait. Un tri alphabétique aurait mis « bloquer
        # l'accès à une ressource » devant « désactiver le compte », alors que
        # le second remplace bien mieux un verrouillage.
        trouvees.sort(key=lambda a: (a.engagement, a.rang))
        return trouvees

    @staticmethod
    def _recevable(candidat: CatalogEntry, plafond: int) -> bool:
        """Trois conditions, et aucune n'est négociable.

        Le candidat doit être exécutable seul, entièrement réversible, et
        strictement moins engageant que le geste refusé. La troisième est la
        plus importante : proposer plus engageant après un refus reviendrait
        à passer outre la décision de l'agent.
        """
        return (
            candidat.autonomously_executable
            and candidat.reversibility is Reversibility.REVERSIBLE
            and engagement(candidat) < plafond
        )

    def _composer(
        self,
        candidat: CatalogEntry,
        ecarte: CatalogEntry,
        but: But,
        target: str,
        parameters: dict[str, Any],
        rang: int,
    ) -> Alternative:
        cout = engagement(candidat)
        spec = ActionSpec(
            verb=candidat.verb,
            actuator=candidat.actuator,
            target=target,
            parameters=dict(parameters),
            reversibility=candidat.reversibility,
            rollback_verb=candidat.rollback_verb,
            blast_radius=candidat.typical_blast_radius,
            expected_effect=candidat.description,
        )
        return Alternative(
            spec=spec,
            entree=candidat,
            but=but,
            engagement=cout,
            ecart=engagement(ecarte) - cout,
            rang=rang,
            motif=_motif(candidat, ecarte, but),
            reserve=_reserve(candidat, ecarte),
        )


# ------------------------------------------------------------- rédaction


def _motif(candidat: CatalogEntry, ecarte: CatalogEntry, but: But) -> str:
    """Le « pourquoi celle-ci », en français, sans identifiant technique.

    Ce texte est le repli déterministe de la cascade : quand un modèle est
    disponible il en rédige un meilleur, mais celui-ci doit tenir seul.
    """
    raisons = [f"sert le même objectif — {but.intitule}"]
    del but
    if ecarte.reversibility is not Reversibility.REVERSIBLE:
        raisons.append("s'annule entièrement, contrairement au geste écarté")
    if candidat.typical_blast_radius < ecarte.typical_blast_radius:
        raisons.append(
            f"touche moins d'équipements ({candidat.typical_blast_radius} "
            f"contre {ecarte.typical_blast_radius})"
        )
    if ecarte.residual_effect and not candidat.residual_effect:
        raisons.append("ne laisse aucune trace après annulation")
    intro = candidat.description.rstrip(".")
    return f"{intro}. Proposée parce qu'elle " + ", ".join(raisons) + "."


def _reserve(candidat: CatalogEntry, ecarte: CatalogEntry) -> str:
    """Ce que l'alternative ne fera pas.

    L'omettre serait vendre la proposition : l'agent doit savoir ce qu'il perd
    en acceptant un geste moins engageant.
    """
    if candidat.typical_blast_radius < ecarte.typical_blast_radius:
        return (
            "Confinement plus étroit que celui qui a été écarté : la menace "
            "peut subsister en dehors du périmètre traité."
        )
    return (
        "Confinement plus léger que celui qui a été écarté : à surveiller de "
        "près dans les heures qui suivent."
    )
