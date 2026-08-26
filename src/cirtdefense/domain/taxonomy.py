"""Catalogue des reactions autonomes par type d'attaque (CIRT / ANTIC).

Transcription fidele du document « Classification des reactions autonomes par
type d'attaque/intrusion ». Chaque ligne du document devient une entrée ici :
c'est la référence unique à laquelle le classificateur, les playbooks et les
tests se rapportent.

Deux principes du document sont portes par le code lui-même :

- **Aucune ligne ne déclenche d'action irréversible en automatique.** Un test
  de recette le vérifie sur l'ensemble du catalogue, de sorte qu'une entrée
  ajoutee plus tard ne puisse pas franchir cette limite en silence.
- **La réversibilité conditionne ce que le moteur autonome peut déclencher**
  (Axe 2), et la priorité arbitre l'ordre de traitement (Axe 4).

Pour le rançongiciel (A6), la réponse reste l'isolation réseau — jamais une
remédiation complète. C'est le point de vigilance signale pour la soutenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .enums import Reversibility, Severity


class AttackFamily(StrEnum):
    """Les quatre familles du catalogue."""

    NETWORK = "network"
    """A — Attaques réseau."""
    APPLICATION = "application"
    """B — Attaques applicatives."""
    INSIDER = "insider"
    """C — Comportemental / insider (source UEBA)."""
    INFRASTRUCTURE = "infrastructure"
    """D — Infrastructure (source Surveillance)."""

    @property
    def label(self) -> str:
        return _FAMILY_LABELS[self]

    @property
    def code(self) -> str:
        return _FAMILY_CODES[self]


_FAMILY_LABELS = {
    AttackFamily.NETWORK: "Attaques réseau",
    AttackFamily.APPLICATION: "Attaques applicatives",
    AttackFamily.INSIDER: "Comportemental / insider",
    AttackFamily.INFRASTRUCTURE: "Infrastructure",
}

_FAMILY_CODES = {
    AttackFamily.NETWORK: "A",
    AttackFamily.APPLICATION: "B",
    AttackFamily.INSIDER: "C",
    AttackFamily.INFRASTRUCTURE: "D",
}


class Priority(StrEnum):
    """Priorité de traitement au sens de l'Axe 4 (portefeuille d'incidents)."""

    CRITICAL = "critique"
    HIGH = "haute"
    MEDIUM = "moyenne"
    LOW = "basse"

    @property
    def rank(self) -> int:
        return _PRIORITY_RANK[self]


_PRIORITY_RANK = {
    Priority.CRITICAL: 4,
    Priority.HIGH: 3,
    Priority.MEDIUM: 2,
    Priority.LOW: 1,
}


@dataclass(frozen=True, slots=True)
class AttackType:
    """Une ligne du catalogue.

    `category` fait le lien avec la catégorie normalisée du `DetectionEvent` :
    c'est par elle que le playbook correspondant est retrouve.
    """

    code: str
    """Identifiant du document : A1 a A7, B1 a B7, C1 a C4, D1 a D4."""
    family: AttackFamily
    label: str
    category: str
    """Catégorie normalisée, clé de correspondance avec les playbooks."""
    detection_sources: tuple[str, ...]
    signal: str
    """Signal caractéristique, tel que decrit au document."""
    prescribed_actions: str
    """Actions correctives prescrites, en clair."""
    reversibility: Reversibility
    priority: Priority
    priority_rationale: str = ""
    base_severity: Severity = Severity.MEDIUM
    """Gravité plancher : un événement de ce type ne descend jamais en dessous."""
    dangerousness: int = 5
    """Degré de dangerosité intrinseque, 1 a 10.

    Distinct de la priorité : la priorité arbitre l'ordre de traitement, la
    dangerosité mesure le dommage potentiel si l'attaque aboutit. Un scan (A3)
    est peu prioritaire mais precurseur ; un rançongiciel (A6) est les deux.
    """
    residual_effect: str = ""
    """Ce que l'action corrective laisse comme gêne, s'il y en à une."""
    no_direct_action: bool = False
    """Vrai pour les lignes « sans action corrective directe » (D1)."""

    @property
    def full_label(self) -> str:
        return f"{self.code} — {self.label}"

    @property
    def autonomously_actionable(self) -> bool:
        return not self.no_direct_action and self.reversibility is not Reversibility.IRREVERSIBLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "family": self.family.value,
            "family_code": self.family.code,
            "family_label": self.family.label,
            "label": self.label,
            "category": self.category,
            "detection_sources": list(self.detection_sources),
            "signal": self.signal,
            "prescribed_actions": self.prescribed_actions,
            "reversibility": self.reversibility.value,
            "priority": self.priority.value,
            "priority_rank": self.priority.rank,
            "priority_rationale": self.priority_rationale,
            "base_severity": self.base_severity.value,
            "dangerousness": self.dangerousness,
            "residual_effect": self.residual_effect,
            "no_direct_action": self.no_direct_action,
            "autonomously_actionable": self.autonomously_actionable,
        }


# ---------------------------------------------------------------------------
# A — Attaques réseau
# ---------------------------------------------------------------------------

NETWORK_ATTACKS: tuple[AttackType, ...] = (
    AttackType(
        code="A1",
        family=AttackFamily.NETWORK,
        label="DDoS volumétrique (SYN/UDP flood, amplification DNS/NTP)",
        category="ddos_volumetric",
        detection_sources=("Surveillance infrastructure", "Détection réseau existante"),
        signal="Pic de trafic entrant, saturation de bande passante",
        prescribed_actions=(
            "Activation scrubbing / rate-limiting en amont (edge), "
            "blackholing des IP sources en tête de volumétrie"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.HIGH,
        priority_rationale="service impacte immédiatement",
        base_severity=Severity.HIGH,
        dangerousness=7,
    ),
    AttackType(
        code="A2",
        family=AttackFamily.NETWORK,
        label="DDoS applicatif (HTTP flood, Slowloris)",
        category="ddos_application",
        detection_sources=("Surveillance infrastructure",),
        signal="Nombre de connexions/sessions anormal, temps de réponse dégrade",
        prescribed_actions=(
            "Règle WAF de limitation de débit par IP/session, fermeture des connexions inactives"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=6,
    ),
    AttackType(
        code="A3",
        family=AttackFamily.NETWORK,
        label="Scan de reconnaissance (port scan, scan de vulnerabilites)",
        category="scan",
        detection_sources=("Surveillance infrastructure", "Détection réseau"),
        signal="Séquence de connexions a ports multiples depuis une même source",
        prescribed_actions="Blocage temporaire de l'IP source au pare-feu",
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.LOW,
        priority_rationale="pas d'impact direct, mais precurseur",
        base_severity=Severity.LOW,
        dangerousness=3,
    ),
    AttackType(
        code="A4",
        family=AttackFamily.NETWORK,
        label="Brute force / credential stuffing",
        category="bruteforce",
        detection_sources=("UEBA (comportemental)",),
        signal="Nombre d'échecs d'authentification anormal, ciblage de comptes multiples",
        prescribed_actions=(
            "Verrouillage temporaire du/des compte(s) cible(s), blocage IP, "
            "forçage MFA à la prochaine connexion"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.HIGH,
        priority_rationale="moyenne a haute selon le compte cible",
        base_severity=Severity.MEDIUM,
        dangerousness=6,
        residual_effect="déverrouillage manuel possible mais gêne l'utilisateur légitime",
    ),
    AttackType(
        code="A5",
        family=AttackFamily.NETWORK,
        label="Exfiltration de données (tunneling DNS, transferts anormaux)",
        category="exfiltration",
        detection_sources=("UEBA", "Surveillance"),
        signal="Volume sortant anormal, requêtes DNS atypiques (longueur, fréquence)",
        prescribed_actions=(
            "Coupure de la connexion sortante concernée, "
            "mise en quarantaine réseau de l'hôte source"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.HIGH,
        priority_rationale="donnée potentiellement déjà partie",
        base_severity=Severity.HIGH,
        dangerousness=9,
        residual_effect="interruption de service pour l'hôte",
    ),
    AttackType(
        code="A6",
        family=AttackFamily.NETWORK,
        label="Ransomware (chiffrement de masse, propagation latérale)",
        category="ransomware",
        detection_sources=("UEBA (activité fichiers massive)", "Surveillance"),
        signal="Taux de modification/chiffrement de fichiers anormal, propagation SMB/RDP suspecte",
        prescribed_actions=(
            "Isolation réseau immédiate de l'hôte (quarantaine VLAN), blocage des "
            "mouvements latéraux, déclenchement snapshot/sauvegarde si disponible "
            "— jamais d'action irréversible automatique"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.CRITICAL,
        priority_rationale="priorité maximale",
        base_severity=Severity.CRITICAL,
        dangerousness=10,
        residual_effect="isolation levée après investigation",
    ),
    AttackType(
        code="A7",
        family=AttackFamily.NETWORK,
        label="Command & Control (beaconing, connexions sortantes suspectes)",
        category="c2",
        detection_sources=("UEBA", "Enrichissement (IOC via CVE/OSINT)"),
        signal="Connexions périodiques vers IP/domaine a reputation dégradée",
        prescribed_actions=(
            "Sinkhole DNS, blocage de l'IP/domaine C2, isolation de l'hôte si beaconing confirme"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=8,
        residual_effect="isolation levée après investigation, si elle a été appliquée",
    ),
)


# ---------------------------------------------------------------------------
# B — Attaques applicatives
# ---------------------------------------------------------------------------

APPLICATION_ATTACKS: tuple[AttackType, ...] = (
    AttackType(
        code="B1",
        family=AttackFamily.APPLICATION,
        label="Injection SQL",
        category="sql_injection",
        detection_sources=("Surveillance applicative", "WAF"),
        signal="Motifs de requêtes anormaux dans les paramètres",
        prescribed_actions="Règle WAF de blocage du motif, blocage temporaire de la source",
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=8,
    ),
    AttackType(
        code="B2",
        family=AttackFamily.APPLICATION,
        label="XSS (stocké / reflété)",
        category="xss",
        detection_sources=("Surveillance applicative",),
        signal="Contenu suspect dans les champs soumis (balises script, encodages)",
        prescribed_actions=(
            "Filtrage/sanitisation à la volee si possible, blocage de la requête, "
            "alerte si contenu déjà stocké"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.MEDIUM,
        base_severity=Severity.MEDIUM,
        dangerousness=5,
        residual_effect="un contenu déjà stocké reste à traiter manuellement",
    ),
    AttackType(
        code="B3",
        family=AttackFamily.APPLICATION,
        label="RCE (exécution de code distante)",
        category="rce",
        detection_sources=("UEBA (process anormal)", "Surveillance"),
        signal="Processus enfant inattendu lance par un service applicatif",
        prescribed_actions="Isolation réseau immédiate de l'hôte, kill du processus suspect",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.CRITICAL,
        base_severity=Severity.CRITICAL,
        dangerousness=10,
        residual_effect="perte de session/état applicatif",
    ),
    AttackType(
        code="B4",
        family=AttackFamily.APPLICATION,
        label="Path traversal / LFI / RFI",
        category="path_traversal",
        detection_sources=("Surveillance applicative",),
        signal="Motifs '../', chemins hors racine applicative dans les requêtes",
        prescribed_actions="Blocage de la requête, règle WAF",
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.MEDIUM,
        base_severity=Severity.MEDIUM,
        dangerousness=6,
    ),
    AttackType(
        code="B5",
        family=AttackFamily.APPLICATION,
        label="Upload de fichier malveillant (webshell)",
        category="webshell_upload",
        detection_sources=("Surveillance", "Enrichissement (signature connue)"),
        signal="Fichier exécutable/script depose dans un répertoire non prévu",
        prescribed_actions=(
            "Mise en quarantaine du fichier (déplacement, pas suppression), "
            "blocage de l'IP uploadeuse"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=9,
    ),
    AttackType(
        code="B6",
        family=AttackFamily.APPLICATION,
        label="Abus d'API / contournement de rate limit",
        category="api_abuse",
        detection_sources=("Surveillance applicative",),
        signal="Volume de requêtes anormal par clé API/token",
        prescribed_actions="Révocation temporaire du token, rate-limiting renforce",
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.MEDIUM,
        priority_rationale="basse a moyenne",
        base_severity=Severity.MEDIUM,
        dangerousness=4,
    ),
    AttackType(
        code="B7",
        family=AttackFamily.APPLICATION,
        label="Broken authentication / session hijacking",
        category="session_hijacking",
        detection_sources=("UEBA (impossible travel, anomalie de session)",),
        signal="Session utilisée depuis deux localisations incompatibles, réutilisation de token",
        prescribed_actions=(
            "Révocation de la session/du token concerné, forçage de re-authentification"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=8,
    ),
)


# ---------------------------------------------------------------------------
# C — Comportemental / insider (source UEBA)
# ---------------------------------------------------------------------------

INSIDER_ANOMALIES: tuple[AttackType, ...] = (
    AttackType(
        code="C1",
        family=AttackFamily.INSIDER,
        label="Élévation de privilège anormale",
        category="privilege_escalation",
        detection_sources=("UEBA",),
        signal="Changement de rôle/permission hors processus habituel, sans ticket associe",
        prescribed_actions=(
            "Révocation immédiate du privilège accordé, restauration du rôle antérieur"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=8,
    ),
    AttackType(
        code="C2",
        family=AttackFamily.INSIDER,
        label="Accès a des ressources hors profil habituel",
        category="abnormal_access",
        detection_sources=("UEBA",),
        signal="Consultation de ressources jamais accédées par l'entité, hors périmètre métier",
        prescribed_actions=(
            "Blocage de l'accès en cours, alerte — pas de révocation de compte "
            "(risque de faux positif plus élève)"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.MEDIUM,
        priority_rationale="basse a moyenne selon la sensibilite de la ressource",
        base_severity=Severity.MEDIUM,
        dangerousness=4,
    ),
    AttackType(
        code="C3",
        family=AttackFamily.INSIDER,
        label="Exfiltration lente (staging, volumes anormaux sur durée)",
        category="slow_exfiltration",
        detection_sources=("UEBA",),
        signal="Accumulation progressive de données dans un espace non habituel",
        prescribed_actions="Restriction temporaire des droits d'écriture/export du compte, alerte",
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.HIGH,
        priority_rationale="moyenne a haute",
        base_severity=Severity.MEDIUM,
        dangerousness=7,
        residual_effect="l'utilisateur perd temporairement ses droits d'export",
    ),
    AttackType(
        code="C4",
        family=AttackFamily.INSIDER,
        label="Compte compromis (impossible travel, horaires atypiques)",
        category="compromised_account",
        detection_sources=("UEBA",),
        signal="Connexions incompatibles geographiquement/temporellement",
        prescribed_actions=(
            "Suspension temporaire du compte, révocation de toutes les sessions activés, "
            "forçage MFA"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.HIGH,
        base_severity=Severity.HIGH,
        dangerousness=8,
        residual_effect="gêne l'utilisateur légitime le temps de la vérification",
    ),
)


# ---------------------------------------------------------------------------
# D — Infrastructure (source Surveillance)
# ---------------------------------------------------------------------------

INFRASTRUCTURE_FINDINGS: tuple[AttackType, ...] = (
    AttackType(
        code="D1",
        family=AttackFamily.INFRASTRUCTURE,
        label="Certificat TLS expire ou faible",
        category="tls_certificate",
        detection_sources=("Scan sslyze périodique",),
        signal="Certificat expire, algorithme ou taille de clé insuffisants",
        prescribed_actions=(
            "Notification + génération automatique d'un rapport — pas d'action "
            "corrective directe possible (dépend d'une autorité de certification externe)"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.LOW,
        priority_rationale="preventif, pas une intrusion active",
        base_severity=Severity.LOW,
        dangerousness=3,
        no_direct_action=True,
    ),
    AttackType(
        code="D2",
        family=AttackFamily.INFRASTRUCTURE,
        label="Port inattendu ouvert",
        category="unexpected_port",
        detection_sources=("Scan Nmap périodique",),
        signal="Delta entre les ports observés et la configuration attendue",
        prescribed_actions=(
            "Fermeture du port si sous contrôle de la plateforme, "
            "sinon alerte de dérive de configuration"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.MEDIUM,
        base_severity=Severity.MEDIUM,
        dangerousness=5,
    ),
    AttackType(
        code="D3",
        family=AttackFamily.INFRASTRUCTURE,
        label="Service indisponible (panne ou déni de service)",
        category="service_unavailable",
        detection_sources=("Sonde httpx en échec répète",),
        signal="Échecs répétés de la sonde de disponibilité",
        prescribed_actions=(
            "Redémarrage du service si sous contrôle, bascule vers un nœud de secours si disponible"
        ),
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        priority=Priority.HIGH,
        priority_rationale="haute si service critique",
        base_severity=Severity.HIGH,
        dangerousness=6,
        residual_effect="interruption pendant le redémarrage",
    ),
    AttackType(
        code="D4",
        family=AttackFamily.INFRASTRUCTURE,
        label="Dérive de configuration (drift)",
        category="config_drift",
        detection_sources=("Comparaison à la configuration de référence",),
        signal="Écart entre configuration observée et configuration de référence",
        prescribed_actions=(
            "Alerte + restauration automatique de la configuration de référence "
            "si le delta est mineur"
        ),
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.MEDIUM,
        priority_rationale="basse a moyenne",
        base_severity=Severity.LOW,
        dangerousness=4,
    ),
)


CATALOG: tuple[AttackType, ...] = (
    *NETWORK_ATTACKS,
    *APPLICATION_ATTACKS,
    *INSIDER_ANOMALIES,
    *INFRASTRUCTURE_FINDINGS,
)

BY_CODE: dict[str, AttackType] = {a.code: a for a in CATALOG}
BY_CATEGORY: dict[str, AttackType] = {a.category: a for a in CATALOG}


def get(code: str) -> AttackType | None:
    return BY_CODE.get(code.upper())


def for_category(category: str) -> AttackType | None:
    return BY_CATEGORY.get(category)


def by_family(family: AttackFamily) -> list[AttackType]:
    return [a for a in CATALOG if a.family is family]


def families() -> dict[str, list[AttackType]]:
    return {f.value: by_family(f) for f in AttackFamily}


def summary() -> dict[str, Any]:
    return {
        "total": len(CATALOG),
        "by_family": {f.code: len(by_family(f)) for f in AttackFamily},
        "autonomously_actionable": sum(1 for a in CATALOG if a.autonomously_actionable),
        "irreversible": sum(1 for a in CATALOG if a.reversibility is Reversibility.IRREVERSIBLE),
        "types": [a.to_dict() for a in CATALOG],
    }
