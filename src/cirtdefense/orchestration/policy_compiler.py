"""Compilation d'une politique en langage naturel (EF-15, version v3.0).

En v2.1, l'intention en langage naturel filtrait des recommandations deja
produites, en temps reel. En v3.0 elle est compilee **a priori** en contraintes
deterministes que le moteur applique ensuite seul.

Le deplacement n'est pas cosmetique. Il garantit que le langage naturel ne se
trouve jamais sur le chemin d'execution : au moment ou une action est evaluee,
il n'y a plus que des predicats. Une meme phrase compilee une fois produit le
meme comportement a chaque incident, et cette compilation est relisible,
versionnee et signee par une empreinte.

**Ce que le compilateur refuse de faire.** Une phrase qu'il ne reconnait pas
n'est pas approximee : elle est rapportee comme non compilee et l'administrateur
en est informe. Deviner l'intention d'une consigne de securite mal comprise
serait le pire des comportements possibles — la politique paraitrait appliquee
alors qu'elle ne le serait pas.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from ..domain.enums import Reversibility, Severity
from ..domain.policy import IRREVERSIBLE_GUARD, Constraint, PolicyRule, ResponsePolicy
from ..logging_setup import log_with

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CompilationReport:
    policy: ResponsePolicy
    compiled_sentences: list[str] = field(default_factory=list)
    unparsed_sentences: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def fully_compiled(self) -> bool:
        return not self.unparsed_sentences

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "compiled_sentences": self.compiled_sentences,
            "unparsed_sentences": self.unparsed_sentences,
            "warnings": self.warnings,
            "fully_compiled": self.fully_compiled,
        }


def _fold(text: str) -> str:
    """Supprime les accents et normalise la casse pour la reconnaissance.

    L'administrateur ecrit « criticité » ou « criticite » indifferemment ;
    la politique ne doit pas dependre de la saisie des accents.
    """
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


# Vocabulaire reconnu : verbes metier vers verbes techniques.
VERB_SYNONYMS: dict[str, tuple[str, ...]] = {
    # Reseau et pare-feu
    "block_ip": (
        "bloquer une adresse",
        "bloquer l'adresse",
        "bloquer",
        "blocage",
        "blocages",
        "bloque",
    ),
    "rate_limit_ip": ("limiter le rythme", "limitation de rythme", "brider le rythme"),
    "block_domain": ("bloquer un domaine", "blocage de domaine"),
    "throttle_egress": ("limiter le debit", "limitation de debit", "brider"),
    "cut_egress_connection": (
        "couper la connexion",
        "coupure de connexion",
        "couper une connexion",
    ),
    "block_lateral": ("bloquer les mouvements lateraux", "blocage lateral"),
    "move_to_vlan": (
        "basculer le vlan",
        "changer de vlan",
        "quarantaine reseau",
        "mettre en quarantaine reseau",
    ),
    # Bordure / operateur
    "enable_scrubbing": ("activer le nettoyage", "nettoyage de trafic", "scrubbing"),
    "blackhole_ip": ("trou noir", "blackhole", "blackholing"),
    "edge_rate_limit": ("limiter en bordure", "limitation en bordure"),
    # Poste et serveur
    "isolate_host": ("isoler", "isolement", "isole", "isoler un hote", "isoler une machine"),
    "kill_process": ("tuer un processus", "arreter un processus", "terminer un processus"),
    "quarantine_file": (
        "mettre en quarantaine un fichier",
        "quarantaine de fichier",
        "quarantaine du fichier",
    ),
    # Comptes et acces
    "disable_account": (
        "desactiver un compte",
        "desactivation de compte",
        "desactiver",
        "desactivation",
    ),
    "lock_account": (
        "verrouiller",
        "verrouillage",
        "verrouiller un compte",
        "suspendre un compte",
        "suspension de compte",
    ),
    "revoke_sessions": (
        "revoquer les sessions",
        "revoquer de sessions",
        "revocation de session",
        "deconnecter",
        "invalider les sessions",
    ),
    "force_password_reset": ("forcer le renouvellement", "reinitialiser le mot de passe"),
    "force_mfa": (
        "forcer mfa",
        "forcer le second facteur",
        "authentification renforcee",
        "forcage mfa",
    ),
    "revoke_token": ("revoquer un jeton", "revoquer le jeton", "revocation de jeton"),
    "revoke_privilege": (
        "revoquer un privilege",
        "revoquer le privilege",
        "revocation de privilege",
        "retirer un privilege",
    ),
    "block_resource_access": ("bloquer l'acces", "blocage d'acces", "bloquer un acces"),
    "restrict_export": ("restreindre l'export", "restriction d'export", "restreindre les droits"),
    # Applicatif
    "block_pattern": ("bloquer un motif", "blocage de motif", "regle waf"),
    "block_request": ("bloquer la requete", "bloquer une requete", "blocage de requete"),
    "rate_limit_rule": ("limiter le debit applicatif", "limitation applicative"),
    "sanitize_field": ("sanitiser", "sanitisation", "filtrer un champ"),
    # DNS
    "sinkhole_domain": ("sinkhole", "detourner un domaine", "detournement de domaine"),
    "block_resolution": ("bloquer la resolution", "blocage de resolution"),
    # Infrastructure
    "trigger_snapshot": ("declencher un instantane", "snapshot", "instantane de sauvegarde"),
    "restart_service": ("redemarrer", "redemarrage", "redemarrer un service"),
    "failover": ("basculer", "bascule", "basculer vers le secours"),
    "close_idle_connections": ("fermer les connexions inactives", "fermeture des connexions"),
    "close_port": ("fermer un port", "fermeture de port", "fermer le port"),
    "restore_baseline": (
        "restaurer la configuration",
        "restauration de configuration",
        "restaurer la reference",
    ),
    # Information
    "notify": ("notifier", "notification", "avertir", "prevenir"),
}

DENY_MARKERS = (
    "ne jamais",
    "jamais",
    "ne pas",
    "interdire",
    "interdit",
    "refuser",
    "refus",
    "aucun",
    "aucune",
    "proscrire",
    "exclure",
    "empecher",
)
ALLOW_MARKERS = ("autoriser", "permettre", "toujours autoriser", "accepter")

_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_CRITICALITY = re.compile(
    r"criticit[e]?\s*(?:de\s*)?(?:superieure?\s*ou\s*egale\s*a\s*|>=\s*|=\s*)?(\d)"
)
_BLAST = re.compile(r"(?:rayon|impact|portee)[^\d]{0,30}(\d+)")
_HOURS = re.compile(r"entre\s*(\d{1,2})\s*h(?:eures?)?\s*(?:et|a)\s*(\d{1,2})\s*h(?:eures?)?")
_ZONE = re.compile(r"zone\s+([a-z0-9_\-]+)")


class PolicyCompiler:
    """Reconnait une grammaire documentee de consignes de securite.

    La grammaire est volontairement etroite. Elle couvre les formes qu'un
    administrateur emploie effectivement pour borner une reponse automatique,
    et rejette explicitement le reste.
    """

    def compile(
        self,
        text: str,
        policy_id: str = "default",
        version: str = "1",
        author: str = "administrateur",
        default_effect: str = "allow",
    ) -> CompilationReport:
        sentences = self._split(text)
        rules: list[PolicyRule] = [IRREVERSIBLE_GUARD]
        compiled: list[str] = []
        unparsed: list[str] = []
        warnings: list[str] = []

        for index, sentence in enumerate(sentences, start=1):
            rule = self._compile_sentence(sentence, index)
            if rule is None:
                unparsed.append(sentence)
                log_with(
                    logger,
                    logging.WARNING,
                    "phrase de politique non compilee : elle ne sera pas appliquee",
                    sentence=sentence,
                )
                continue
            rules.append(rule)
            compiled.append(sentence)

        if unparsed:
            warnings.append(
                f"{len(unparsed)} phrase(s) non reconnue(s) : elles n'ont AUCUN effet sur "
                "le moteur. Les reformuler ou les traduire en regles explicites."
            )
        if default_effect == "allow" and not any(r.effect == "deny" for r in rules[1:]):
            warnings.append(
                "aucune restriction compilee au-dela du garde-fou d'irreversibilite : "
                "toute action reversible du catalogue sera executee."
            )

        policy = ResponsePolicy(
            policy_id=policy_id,
            version=version,
            rules=rules,
            source_text=text,
            default_effect=default_effect,
            author=author,
        )
        return CompilationReport(
            policy=policy,
            compiled_sentences=compiled,
            unparsed_sentences=unparsed,
            warnings=warnings,
        )

    # -- reconnaissance -----------------------------------------------------

    @staticmethod
    def _split(text: str) -> list[str]:
        """Decoupe en phrases sans casser les adresses.

        Un decoupage naif sur le point pulverise « 10.0.0.0/8 » en fragments
        inexploitables : la plage disparaissait silencieusement de la regle
        compilee. Le separateur est donc un point qui n'est pas suivi d'un
        chiffre.
        """
        raw = re.split(r"[;\n]+|\.(?!\d)", text)
        return [s.strip(" -•\t") for s in raw if len(s.strip(" -•\t")) > 3]

    def _compile_sentence(self, sentence: str, index: int) -> PolicyRule | None:
        folded = _fold(sentence)
        effect = self._effect_of(folded)
        if effect is None:
            return None

        constraints = self._constraints_of(folded)
        if not constraints:
            # Une consigne sans aucune condition identifiable serait une regle
            # s'appliquant a tout : trop dangereuse pour etre devinee.
            return None

        return PolicyRule(
            rule_id=f"R-{index:03d}",
            effect=effect,
            constraints=tuple(constraints),
            source_sentence=sentence.strip(),
            priority=10 if effect == "deny" else 50,
        )

    @staticmethod
    def _effect_of(folded: str) -> str | None:
        """Une interdiction prime sur une autorisation dans la meme phrase :
        « autoriser le blocage mais jamais en interne » est une restriction."""
        if any(marker in folded for marker in DENY_MARKERS):
            return "deny"
        if any(marker in folded for marker in ALLOW_MARKERS):
            return "allow"
        return None

    def _constraints_of(self, folded: str) -> list[Constraint]:
        constraints: list[Constraint] = []

        verbs = [
            verb for verb, synonyms in VERB_SYNONYMS.items() if any(s in folded for s in synonyms)
        ]
        if len(verbs) == 1:
            constraints.append(Constraint("action.verb", "eq", verbs[0]))
        elif len(verbs) > 1:
            constraints.append(Constraint("action.verb", "in", sorted(verbs)))

        cidr = _CIDR.search(folded)
        if cidr:
            constraints.append(Constraint("action.target", "matches", _cidr_to_regex(cidr.group())))
        elif "interne" in folded or "prive" in folded:
            constraints.append(
                Constraint(
                    "action.target",
                    "matches",
                    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)",
                )
            )
        else:
            ip = _IP.search(folded)
            if ip:
                constraints.append(Constraint("action.target", "eq", ip.group()))

        criticality = _CRITICALITY.search(folded)
        if criticality:
            constraints.append(Constraint("asset.criticality", "gte", int(criticality.group(1))))

        blast = _BLAST.search(folded)
        if blast:
            constraints.append(Constraint("action.blast_radius", "gte", int(blast.group(1))))

        zone = _ZONE.search(folded)
        if zone:
            constraints.append(Constraint("asset.zone", "eq", zone.group(1)))

        for severity in Severity:
            if f"gravite {severity.value}" in folded or f"severite {severity.value}" in folded:
                constraints.append(Constraint("incident.severity", "lte", severity.value))
                break

        if "irreversible" in folded:
            constraints.append(
                Constraint("action.reversibility", "eq", Reversibility.IRREVERSIBLE.value)
            )
        elif "partiellement reversible" in folded:
            constraints.append(
                Constraint("action.reversibility", "eq", Reversibility.PARTIALLY_REVERSIBLE.value)
            )

        hours = _HOURS.search(folded)
        if hours:
            start, end = int(hours.group(1)), int(hours.group(2))
            # Une plage qui franchit minuit ne peut pas s'exprimer par un seul
            # encadrement : on retient la borne basse, plus restrictive, et on
            # le signale plutot que de produire une regle silencieusement fausse.
            if start <= end:
                constraints.append(Constraint("time.hour", "gte", start))
                constraints.append(Constraint("time.hour", "lte", end))
            else:
                constraints.append(Constraint("time.hour", "gte", start))

        return constraints


def _cidr_to_regex(cidr: str) -> str:
    """Traduit un prefixe en expression reguliere sur les octets pleins.

    Seuls les prefixes /8, /16 et /24 sont traduits exactement ; les autres
    sont ramenes au prefixe plein inferieur, ce qui elargit la regle. Un
    elargissement d'une regle d'interdiction reste du cote sur.
    """
    network, _, bits = cidr.partition("/")
    octets = network.split(".")
    kept = min(int(bits) // 8, 4)
    prefix = ".".join(octets[:kept])
    return "^" + re.escape(prefix) + (r"\." if kept < 4 else "$")
