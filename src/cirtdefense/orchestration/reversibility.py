"""Catalogue de reversibilite (EF-14).

En v2.1 ce catalogue documentait la difficulte d'annulation pour aider
l'analyste a prioriser. En v3.0 il devient un mecanisme de securite
operationnelle : une action absente du catalogue, ou declaree irreversible,
n'est jamais executee de facon autonome. C'est la mesure compensatoire
principale annoncee au CDCF §1.4.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..domain.enums import Reversibility


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    verb: str
    actuator: str
    reversibility: Reversibility
    rollback_verb: str | None
    description: str
    rollback_description: str = ""
    residual_effect: str = ""
    """Ce qui subsiste apres annulation. Vide si l'annulation est totale."""
    typical_blast_radius: int = 1
    max_rollback_seconds: int = 60
    """Delai au-dela duquel l'annulation est consideree comme echouee."""

    @property
    def key(self) -> str:
        return f"{self.actuator}:{self.verb}"

    @property
    def autonomously_executable(self) -> bool:
        return self.reversibility is not Reversibility.IRREVERSIBLE and bool(self.rollback_verb)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "verb": self.verb,
            "actuator": self.actuator,
            "reversibility": self.reversibility.value,
            "rollback_verb": self.rollback_verb,
            "description": self.description,
            "rollback_description": self.rollback_description,
            "residual_effect": self.residual_effect,
            "typical_blast_radius": self.typical_blast_radius,
            "max_rollback_seconds": self.max_rollback_seconds,
            "autonomously_executable": self.autonomously_executable,
        }


DEFAULT_ENTRIES: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        verb="block_ip",
        actuator="firewall",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unblock_ip",
        description="Ajoute une regle de rejet pour une adresse source.",
        rollback_description="Retire la regle ; aucun etat n'est perdu.",
        typical_blast_radius=1,
        max_rollback_seconds=15,
    ),
    CatalogEntry(
        verb="rate_limit_ip",
        actuator="firewall",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="clear_rate_limit",
        description="Limite le debit accepte depuis une adresse source.",
        rollback_description="Retire la limitation.",
        typical_blast_radius=1,
        max_rollback_seconds=15,
    ),
    CatalogEntry(
        verb="block_domain",
        actuator="firewall",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unblock_domain",
        description="Bloque la resolution et le trafic vers un domaine.",
        rollback_description="Retire l'entree de la liste de blocage.",
        typical_blast_radius=2,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="isolate_host",
        actuator="edr",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="release_host",
        description="Place la machine en quarantaine reseau, agent maintenu.",
        rollback_description="Leve la quarantaine et retablit la connectivite.",
        residual_effect="Les connexions et sessions en cours sont perdues et "
        "ne sont pas retablies par la levee de quarantaine.",
        typical_blast_radius=1,
        max_rollback_seconds=60,
    ),
    CatalogEntry(
        verb="kill_process",
        actuator="edr",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="restart_process",
        description="Termine un processus identifie comme malveillant.",
        rollback_description="Relance le processus depuis son chemin d'origine.",
        residual_effect="L'etat en memoire du processus est definitivement perdu.",
        typical_blast_radius=1,
        max_rollback_seconds=45,
    ),
    CatalogEntry(
        verb="quarantine_file",
        actuator="edr",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="restore_file",
        description="Deplace un fichier vers la zone de quarantaine chiffree.",
        rollback_description="Restaure le fichier a son emplacement d'origine.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="disable_account",
        actuator="iam",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="enable_account",
        description="Desactive un compte dans l'annuaire.",
        rollback_description="Reactive le compte avec ses attributs d'origine.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="revoke_sessions",
        actuator="iam",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="noop_restore_sessions",
        description="Invalide les jetons de session actifs d'un compte.",
        rollback_description="Leve l'invalidation ; l'utilisateur doit se "
        "reauthentifier, ce qui est le comportement nominal attendu.",
        residual_effect="Les sessions invalidees ne sont pas restaurees : "
        "l'utilisateur doit ouvrir une nouvelle session.",
        typical_blast_radius=1,
        max_rollback_seconds=20,
    ),
    CatalogEntry(
        verb="force_password_reset",
        actuator="iam",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="cancel_password_reset",
        description="Marque le mot de passe comme a renouveler a la prochaine ouverture.",
        rollback_description="Retire l'obligation de renouvellement.",
        residual_effect="Si l'utilisateur a deja renouvele, l'ancien mot de "
        "passe n'est pas retabli.",
        typical_blast_radius=1,
        max_rollback_seconds=20,
    ),
    CatalogEntry(
        verb="throttle_egress",
        actuator="network",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="clear_egress_throttle",
        description="Limite le debit sortant d'une machine.",
        rollback_description="Retire la limitation de debit.",
        typical_blast_radius=1,
        max_rollback_seconds=15,
    ),
    CatalogEntry(
        verb="move_to_vlan",
        actuator="network",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="restore_vlan",
        description="Bascule un port d'acces vers un VLAN de quarantaine.",
        rollback_description="Retablit le VLAN d'origine, memorise avant bascule.",
        typical_blast_radius=1,
        max_rollback_seconds=45,
    ),
    CatalogEntry(
        verb="notify",
        actuator="notify",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="retract_notification",
        description="Emet une notification vers l'analyste ou l'exploitation.",
        rollback_description="Marque la notification comme retiree.",
        typical_blast_radius=1,
        max_rollback_seconds=5,
    ),
    # --- Reponses volumetriques et de bordure (A1, A2) --------------------
    CatalogEntry(
        verb="enable_scrubbing",
        actuator="edge",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="disable_scrubbing",
        description="Active le nettoyage de trafic chez l'operateur de transit.",
        rollback_description="Desactive le nettoyage et retablit le routage nominal.",
        typical_blast_radius=3,
        max_rollback_seconds=120,
    ),
    CatalogEntry(
        verb="blackhole_ip",
        actuator="edge",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="release_blackhole",
        description="Annonce un trou noir pour une source en tete de volumetrie.",
        rollback_description="Retire l'annonce ; la regle expire de toute facon (TTL court).",
        typical_blast_radius=2,
        max_rollback_seconds=120,
    ),
    CatalogEntry(
        verb="edge_rate_limit",
        actuator="edge",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="clear_edge_rate_limit",
        description="Limite le debit accepte en bordure pour une source.",
        rollback_description="Retire la limitation.",
        typical_blast_radius=2,
        max_rollback_seconds=60,
    ),
    # --- Reponses applicatives (A2, B1, B2, B4, B6) ------------------------
    CatalogEntry(
        verb="block_pattern",
        actuator="waf",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unblock_pattern",
        description="Bloque un motif de requete au pare-feu applicatif.",
        rollback_description="Retire la regle de motif.",
        typical_blast_radius=4,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="block_request",
        actuator="waf",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unblock_request",
        description="Bloque une requete ou un point d'entree precis.",
        rollback_description="Retire le blocage.",
        typical_blast_radius=2,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="rate_limit_rule",
        actuator="waf",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="clear_rate_limit_rule",
        description="Pose une limitation de debit par IP ou par session.",
        rollback_description="Retire la limitation.",
        typical_blast_radius=3,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="sanitize_field",
        actuator="waf",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="clear_sanitize_field",
        description="Active la sanitisation a la volee d'un champ soumis.",
        rollback_description="Desactive la sanitisation.",
        typical_blast_radius=2,
        max_rollback_seconds=30,
    ),
    # --- Reponses DNS (A7) --------------------------------------------------
    CatalogEntry(
        verb="sinkhole_domain",
        actuator="dns",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="release_domain",
        description="Detourne la resolution d'un domaine vers une adresse controlee.",
        rollback_description="Retablit la resolution nominale.",
        typical_blast_radius=2,
        max_rollback_seconds=60,
    ),
    CatalogEntry(
        verb="block_resolution",
        actuator="dns",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unblock_resolution",
        description="Empeche la resolution d'un domaine.",
        rollback_description="Retire l'entree de blocage.",
        typical_blast_radius=2,
        max_rollback_seconds=60,
    ),
    # --- Reponses reseau complementaires (A5, A6) ---------------------------
    CatalogEntry(
        verb="cut_egress_connection",
        actuator="network",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="restore_egress_connection",
        description="Coupe une connexion sortante identifiee.",
        rollback_description="Leve le blocage ; la connexion doit etre rouverte par l'hote.",
        residual_effect="La connexion coupee n'est pas retablie : "
        "l'application doit la reouvrir d'elle-meme.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="block_lateral",
        actuator="network",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unblock_lateral",
        description="Bloque les protocoles de propagation laterale (SMB, RDP, WinRM).",
        rollback_description="Retablit les protocoles bloques.",
        typical_blast_radius=2,
        max_rollback_seconds=60,
    ),
    # --- Reponses sur les comptes et les droits (A4, B6, B7, C1 a C4) -------
    CatalogEntry(
        verb="lock_account",
        actuator="iam",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="unlock_account",
        description="Verrouille temporairement un compte cible.",
        rollback_description="Deverrouille le compte.",
        residual_effect="L'utilisateur legitime a ete gene pendant la duree du verrouillage.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="force_mfa",
        actuator="iam",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="clear_mfa_requirement",
        description="Exige une authentification renforcee a la prochaine connexion.",
        rollback_description="Retire l'exigence.",
        typical_blast_radius=1,
        max_rollback_seconds=20,
    ),
    CatalogEntry(
        verb="revoke_token",
        actuator="iam",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="reissue_token",
        description="Revoque temporairement un jeton d'API.",
        rollback_description="Reemet un jeton pour la meme application.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="revoke_privilege",
        actuator="iam",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="restore_privilege",
        description="Revoque un privilege accorde hors processus et retablit le role anterieur.",
        rollback_description="Retablit le privilege tel qu'il etait avant revocation.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    CatalogEntry(
        verb="block_resource_access",
        actuator="iam",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="restore_resource_access",
        description="Bloque l'acces en cours a une ressource hors profil.",
        rollback_description="Retablit l'acces.",
        typical_blast_radius=1,
        max_rollback_seconds=20,
    ),
    CatalogEntry(
        verb="restrict_export",
        actuator="iam",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="restore_export",
        description="Restreint temporairement les droits d'ecriture et d'export d'un compte.",
        rollback_description="Retablit les droits d'origine.",
        residual_effect="Les exports tentes pendant la restriction ont echoue "
        "et doivent etre relances par l'utilisateur.",
        typical_blast_radius=1,
        max_rollback_seconds=30,
    ),
    # --- Reponses infrastructure (A6, D2, D3, D4) ---------------------------
    CatalogEntry(
        verb="trigger_snapshot",
        actuator="backup",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="unlink_snapshot",
        description="Declenche un instantane de sauvegarde de l'hote.",
        rollback_description="Detache l'instantane de l'incident SANS le supprimer : "
        "un snapshot pris pendant une attaque garde sa valeur de preuve.",
        typical_blast_radius=1,
        max_rollback_seconds=60,
    ),
    CatalogEntry(
        verb="restart_service",
        actuator="service",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="cancel_restart",
        description="Redemarre un service sous controle de la plateforme.",
        rollback_description="Marque l'operation comme annulee ; le service reste demarre, "
        "ce qui est l'etat recherche.",
        residual_effect="L'interruption survenue pendant le redemarrage ne se rattrape pas.",
        typical_blast_radius=2,
        max_rollback_seconds=120,
    ),
    CatalogEntry(
        verb="failover",
        actuator="service",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="failback",
        description="Bascule le service vers un noeud de secours.",
        rollback_description="Rebascule vers le noeud nominal.",
        typical_blast_radius=3,
        max_rollback_seconds=180,
    ),
    CatalogEntry(
        verb="close_idle_connections",
        actuator="service",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        rollback_verb="restore_connections",
        description="Ferme les connexions inactives saturant le service.",
        rollback_description="Leve la fermeture systematique ; les clients se reconnectent.",
        residual_effect="Les connexions fermees ne sont pas retablies.",
        typical_blast_radius=3,
        max_rollback_seconds=60,
    ),
    CatalogEntry(
        verb="close_port",
        actuator="config",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="reopen_port",
        description="Ferme un port ouvert non prevu par la configuration de reference.",
        rollback_description="Rouvre le port.",
        typical_blast_radius=2,
        max_rollback_seconds=60,
    ),
    CatalogEntry(
        verb="restore_baseline",
        actuator="config",
        reversibility=Reversibility.REVERSIBLE,
        rollback_verb="revert_restore",
        description="Restaure la configuration de reference sur une derive mineure.",
        rollback_description="Retablit la configuration relevee avant restauration.",
        typical_blast_radius=3,
        max_rollback_seconds=180,
    ),
    # --- Entrees irreversibles : documentees pour etre explicitement exclues.
    # Leur presence dans le catalogue n'est pas contradictoire ; elle rend
    # visible ce que l'autonomie ne couvre pas (CDCF §1.4.3, limites assumees).
    CatalogEntry(
        verb="wipe_disk",
        actuator="edr",
        reversibility=Reversibility.IRREVERSIBLE,
        rollback_verb=None,
        description="Efface le contenu du disque de la machine.",
        residual_effect="Perte definitive des donnees non sauvegardees.",
        typical_blast_radius=1,
    ),
    CatalogEntry(
        verb="delete_account",
        actuator="iam",
        reversibility=Reversibility.IRREVERSIBLE,
        rollback_verb=None,
        description="Supprime definitivement un compte de l'annuaire.",
        residual_effect="Perte des attributs, des appartenances et des droits.",
        typical_blast_radius=1,
    ),
    CatalogEntry(
        verb="shutdown_host",
        actuator="edr",
        reversibility=Reversibility.IRREVERSIBLE,
        rollback_verb=None,
        description="Arrete physiquement la machine.",
        residual_effect="Le redemarrage exige une intervention locale ; il "
        "n'est pas garanti a distance.",
        typical_blast_radius=1,
    ),
)


class ReversibilityCatalog:
    def __init__(self, entries: tuple[CatalogEntry, ...] = DEFAULT_ENTRIES) -> None:
        self._entries: dict[str, CatalogEntry] = {e.key: e for e in entries}

    def get(self, actuator: str, verb: str) -> CatalogEntry | None:
        return self._entries.get(f"{actuator}:{verb}")

    def require(self, actuator: str, verb: str) -> CatalogEntry:
        entry = self.get(actuator, verb)
        if entry is None:
            raise UnknownActionError(
                f"action '{actuator}:{verb}' absente du catalogue de reversibilite ; "
                "elle ne peut pas etre executee en autonomie"
            )
        return entry

    def is_autonomously_executable(self, actuator: str, verb: str) -> bool:
        entry = self.get(actuator, verb)
        return entry is not None and entry.autonomously_executable

    def add(self, entry: CatalogEntry) -> None:
        """Gestion du catalogue par l'administrateur (role renforce en v3.0)."""
        self._entries[entry.key] = entry

    def remove(self, actuator: str, verb: str) -> bool:
        return self._entries.pop(f"{actuator}:{verb}", None) is not None

    def all(self) -> list[CatalogEntry]:
        return sorted(self._entries.values(), key=lambda e: e.key)

    def autonomous_subset(self) -> list[CatalogEntry]:
        return [e for e in self.all() if e.autonomously_executable]

    def to_dict(self) -> dict[str, Any]:
        entries = self.all()
        return {
            "total": len(entries),
            "autonomously_executable": sum(1 for e in entries if e.autonomously_executable),
            "entries": [e.to_dict() for e in entries],
        }


class UnknownActionError(ValueError):
    """Action hors catalogue : refus d'execution autonome."""


_catalog: ReversibilityCatalog | None = None


def get_catalog() -> ReversibilityCatalog:
    global _catalog
    if _catalog is None:
        _catalog = ReversibilityCatalog()
    return _catalog
