"""Confinement de repli pour une menace non cataloguée.

Le catalogue CIRT couvre 22 types. Une plateforme nationale en rencontrera
d'autres, et se taire devant l'inconnu serait la pire des postures : une
menace inédite est précisément celle contre laquelle personne n'est préparé.

**Le raisonnement qui rend ce module défendable.** Le moteur refuse d'agir
quand le contexte n'est pas documenté (EF-04), et il a raison : choisir un
playbook pour un type d'attaque qu'on ne connaît pas revient à deviner, et un
geste autonome fondé sur une hypothèse fausse peut coûter plus cher que
l'attaque. Ce module ne lève pas cette garde — il change de fondement.

Il ne déduit rien du *type* d'attaque, qu'il ignore et n'essaie pas de
nommer. Il part des **indicateurs effectivement observés** : une adresse
publique présente dans l'événement, un compte impliqué, un hôte touché, un
domaine interrogé, un port en écoute. Ce sont des faits, pas des hypothèses,
et chacun appelle un geste défensif dont la pertinence ne dépend pas de la
nature exacte de la menace : bloquer une adresse hostile protège quelle que
soit l'attaque qu'elle porte.

**La règle de partage.** Un geste réversible part seul — l'analyste constate
après coup, et peut annuler. Un geste partiellement réversible ou
irréversible ne part jamais : il devient une demande de confirmation qui
reste ouverte jusqu'à ce qu'un humain tranche. C'est l'extension au cas
inconnu du principe déjà tenu partout ailleurs (Axe 2) : la réversibilité est
la condition d'agir seul.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ..domain.action import ActionSpec
from ..domain.enums import Reversibility
from ..domain.events import DetectionEvent
from .reversibility import ReversibilityCatalog

RAYON_MAXIMAL_AUTONOME = 2
"""Au-delà, l'action touche trop d'entités pour partir sans qualification."""


@dataclass(slots=True)
class Suggestion:
    """Un geste défensif, avec le fait observé qui le motive."""

    spec: ActionSpec
    basis: str
    """L'indicateur observé qui justifie ce geste, en clair."""
    autonomous: bool
    """Vrai si le geste part seul : réversible, annulable, rayon contenu."""
    residual_effect: str = ""
    """Ce qui subsisterait après annulation. Vide si l'annulation est totale."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verb": self.spec.verb,
            "actuator": self.spec.actuator,
            "target": self.spec.target,
            "reversibility": self.spec.reversibility.value,
            "blast_radius": self.spec.blast_radius,
            "basis": self.basis,
            "autonomous": self.autonomous,
            "residual_effect": self.residual_effect,
            "expected_effect": self.spec.expected_effect,
        }


@dataclass(slots=True)
class FallbackPlan:
    autonomous: list[Suggestion] = field(default_factory=list)
    """Gestes réversibles : ils partent, l'humain constate."""
    requires_confirmation: list[Suggestion] = field(default_factory=list)
    """Gestes durables : ils attendent qu'un humain tranche."""
    observations: list[str] = field(default_factory=list)
    """Les indicateurs retenus, pour que le plan se relise."""

    @property
    def empty(self) -> bool:
        return not self.autonomous and not self.requires_confirmation

    def to_dict(self) -> dict[str, Any]:
        return {
            "autonomous": [s.to_dict() for s in self.autonomous],
            "requires_confirmation": [s.to_dict() for s in self.requires_confirmation],
            "observations": self.observations,
        }


# Ce qui appartient au parc, et qu'on ne bloque donc pas en aveugle : les
# plages privees RFC 1918, la boucle locale, le lien-local et le multicast.
# La liste est ecrite explicitement plutot que deleguee a `is_private`, qui
# range aussi les plages de documentation RFC 5737 (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) parmi les adresses privees. Or ce sont
# precisement celles qui tiennent le role de l'attaquant externe dans les
# scenarios de demonstration : les traiter comme internes rendrait le
# confinement muet au moment ou l'on cherche a l'eprouver.
INTERNES = tuple(
    ipaddress.ip_network(reseau)
    for reseau in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
    )
)
INTERNES_V6 = tuple(
    ipaddress.ip_network(reseau) for reseau in ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
)


def _est_externe(adresse: str) -> bool:
    """Vrai si l'adresse n'appartient pas au parc de l'organisation."""
    try:
        ip = ipaddress.ip_address(adresse)
    except ValueError:
        return False
    reseaux = INTERNES_V6 if ip.version == 6 else INTERNES
    return not any(ip in reseau for reseau in reseaux)


class FallbackPlanner:
    """Construit un plan de confinement à partir des seuls indicateurs."""

    def __init__(self, catalog: ReversibilityCatalog) -> None:
        self._catalog = catalog

    def plan(self, event: DetectionEvent) -> FallbackPlan:
        plan = FallbackPlan()
        for actuator, verb, cible, motif, parametres in self._candidats(event):
            entree = self._catalog.get(actuator, verb)
            if entree is None:
                # Un verbe absent du catalogue de réversibilité n'a pas de
                # contrat d'annulation connu : il ne peut être ni exécuté seul,
                # ni proposé, puisqu'on ne saurait pas le défaire.
                continue

            spec = ActionSpec(
                verb=verb,
                actuator=actuator,
                target=cible,
                parameters=parametres,
                reversibility=entree.reversibility,
                rollback_verb=entree.rollback_verb,
                blast_radius=entree.typical_blast_radius,
                expected_effect=entree.description,
            )
            autonome = (
                entree.reversibility is Reversibility.REVERSIBLE
                and bool(entree.rollback_verb)
                and entree.typical_blast_radius <= RAYON_MAXIMAL_AUTONOME
            )
            suggestion = Suggestion(
                spec=spec,
                basis=motif,
                autonomous=autonome,
                residual_effect=entree.residual_effect,
            )
            (plan.autonomous if autonome else plan.requires_confirmation).append(suggestion)
            # Un meme indicateur motive plusieurs gestes : ne le citer qu'une
            # fois, sinon le motif de la decision se repete inutilement.
            if motif not in plan.observations:
                plan.observations.append(motif)
        return plan

    def _candidats(self, event: DetectionEvent) -> list[tuple[str, str, str, str, dict[str, Any]]]:
        """Les gestes que chaque indicateur observé rend pertinents.

        L'ordre n'a pas d'importance : le partage entre autonome et à
        confirmer se fait ensuite, sur la réversibilité et non sur une
        priorité qu'il faudrait inventer.
        """
        indicateurs = event.indicators
        candidats: list[tuple[str, str, str, str, dict[str, Any]]] = []
        motif = f"menace non cataloguée sur {event.asset.correlation_key()}"

        source = str(indicateurs.get("src_ip") or indicateurs.get("srcip") or "")
        if source and _est_externe(source):
            candidats.append(
                (
                    "firewall",
                    "block_ip",
                    source,
                    f"adresse source externe observée : {source}",
                    {"reason": motif, "direction": "inbound"},
                )
            )

        destination = str(indicateurs.get("dest_ip") or indicateurs.get("dstip") or "")
        if destination and _est_externe(destination):
            candidats.append(
                (
                    "network",
                    "cut_egress_connection",
                    destination,
                    f"destination sortante externe observée : {destination}",
                    {"reason": motif},
                )
            )

        domaine = str(indicateurs.get("domain") or "")
        if domaine:
            candidats.append(
                (
                    "dns",
                    "block_resolution",
                    domaine,
                    f"domaine interrogé : {domaine}",
                    {"reason": motif},
                )
            )

        compte = str(
            event.asset.user or indicateurs.get("user") or indicateurs.get("dstuser") or ""
        )
        if compte:
            candidats.append(
                (
                    "iam",
                    "revoke_sessions",
                    compte,
                    f"compte impliqué : {compte}",
                    {"reason": motif},
                )
            )
            candidats.append(
                (
                    "iam",
                    "force_mfa",
                    compte,
                    f"compte impliqué : {compte}",
                    {"reason": motif},
                )
            )
            # Verrouiller prive l'utilisateur de son poste : durable, donc
            # soumis a confirmation par le catalogue de reversibilite.
            candidats.append(
                (
                    "iam",
                    "lock_account",
                    compte,
                    f"compte impliqué : {compte}",
                    {"reason": motif},
                )
            )

        # Les normaliseurs ne nomment pas le port de la meme facon : Suricata
        # rend `dest_port`, Wazuh `dstport`. Lire les deux evite que la reponse
        # depende de la source qui a remonte l'evenement.
        port = (
            indicateurs.get("dest_port") or indicateurs.get("dstport") or indicateurs.get("port")
        )
        if port:
            candidats.append(
                (
                    "config",
                    "close_port",
                    str(port),
                    f"port concerné : {port}",
                    {"reason": motif, "host": event.asset.correlation_key()},
                )
            )

        # Un instantane est protecteur, pas restrictif : il preserve l'etat
        # avant que la menace ne le detruise, et n'a aucun effet de bord.
        hote = event.asset.correlation_key()
        if hote and hote != "unknown" and event.asset.criticality >= 3:
            candidats.append(
                (
                    "backup",
                    "trigger_snapshot",
                    hote,
                    f"actif de criticité {event.asset.criticality}/5 exposé : {hote}",
                    {"reason": motif},
                )
            )
            # Isoler coupe les sessions en cours : effet durable, a confirmer.
            candidats.append(
                (
                    "edr",
                    "isolate_host",
                    hote,
                    f"actif de criticité {event.asset.criticality}/5 exposé : {hote}",
                    {"reason": motif},
                )
            )

        return candidats
