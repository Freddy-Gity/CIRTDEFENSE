"""Scénarios de démonstration, un par ligne du catalogue CIRT.

Chaque scénario porte la charge utile qu'un collecteur émettrait réellement
pour l'attaque decrite, avec les indicateurs dont le playbook a besoin. Un
scénario dont les indicateurs seraient incomplets produirait une décision sans
action — et donnerait à croire, a tort, que la plateforme ne réagit pas.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..domain.taxonomy import BY_CODE, AttackType

# Parc fictif du site, reutilise par tous les scénarios pour que la
# corrélation d'incidents et le portefeuille aient du sens.
ASSETS: dict[str, dict[str, Any]] = {
    "srv-web-01": {
        "hostname": "srv-web-01",
        "ip": "10.0.1.10",
        "criticality": 4,
        "zone": "dmz",
        "kind": "serveur web",
        "owner": "Direction des systèmes d'information",
        "latitude": 3.8712,
        "longitude": 11.5174,
    },
    "srv-web-02": {
        "hostname": "srv-web-02",
        "ip": "10.0.1.11",
        "criticality": 4,
        "zone": "dmz",
        "kind": "serveur web",
        "owner": "Direction des systèmes d'information",
        "latitude": 3.8709,
        "longitude": 11.5181,
    },
    "srv-db-01": {
        "hostname": "srv-db-01",
        "ip": "10.0.2.20",
        "criticality": 5,
        "zone": "interne",
        "kind": "base de données",
        "owner": "Direction des systèmes d'information",
        "latitude": 3.8664,
        "longitude": 11.5212,
    },
    "srv-app-01": {
        "hostname": "srv-app-01",
        "ip": "10.0.2.30",
        "criticality": 4,
        "zone": "interne",
        "kind": "serveur applicatif",
        "owner": "Direction des services en ligne",
        "latitude": 3.8671,
        "longitude": 11.5203,
    },
    "srv-file-01": {
        "hostname": "srv-file-01",
        "ip": "10.0.2.40",
        "criticality": 3,
        "zone": "interne",
        "kind": "serveur de fichiers",
        "owner": "Direction administrative",
        "latitude": 3.8658,
        "longitude": 11.5228,
    },
    "srv-mail-01": {
        "hostname": "srv-mail-01",
        "ip": "10.0.2.50",
        "criticality": 5,
        "zone": "interne",
        "kind": "serveur de messagerie",
        "owner": "Direction des systèmes d'information",
        "latitude": 3.8683,
        "longitude": 11.5196,
    },
    "poste-114": {
        "hostname": "poste-114",
        "ip": "10.0.5.114",
        "criticality": 2,
        "zone": "bureautique",
        "kind": "poste de travail",
        "owner": "Service comptabilité",
        "latitude": 3.8641,
        "longitude": 11.5265,
    },
    "fw-dmz-01": {
        "hostname": "fw-dmz-01",
        "ip": "10.0.0.1",
        "criticality": 5,
        "zone": "dmz",
        "kind": "pare-feu",
        "owner": "Équipe sécurité réseau",
        "latitude": 3.8725,
        "longitude": 11.5158,
    },
}

# Adresses externes hostiles utilisées par les scénarios. Plages documentaires
# (RFC 5737) et adresses manifestement fictives : aucune adresse réelle n'est
# designee comme malveillante dans un jeu de démonstration.
HOSTILE_IPS = ("203.0.113.42", "203.0.113.77", "198.51.100.23", "192.0.2.155")
HOSTILE_DOMAINS = ("update-c2.example", "cdn-sync.example", "telemetry-node.example")


@dataclass(slots=True)
class Scenario:
    """Un scénario rejouable, rattache à une ligne du catalogue."""

    code: str
    source: str
    """Normaliseur cible : wazuh, suricata, syslog, generic_json."""
    title: str
    narrative: str
    """Ce que le scénario raconte, en une phrase, pour l'interface."""
    payload_builder: Any = field(repr=False, default=None)
    expected_actions: tuple[str, ...] = ()
    """Actions attendues. Sert à l'interface et aux tests de non-régression."""

    @property
    def attack_type(self) -> AttackType:
        return BY_CODE[self.code]

    def to_dict(self) -> dict[str, Any]:
        attack = self.attack_type
        return {
            "code": self.code,
            "source": self.source,
            "title": self.title,
            "narrative": self.narrative,
            "expected_actions": list(self.expected_actions),
            "family": attack.family.value,
            "family_code": attack.family.code,
            "family_label": attack.family.label,
            "label": attack.label,
            "category": attack.category,
            "signal": attack.signal,
            "prescribed_actions": attack.prescribed_actions,
            "reversibility": attack.reversibility.value,
            "priority": attack.priority.value,
            "dangerousness": attack.dangerousness,
            "detection_sources": list(attack.detection_sources),
            "no_direct_action": attack.no_direct_action,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _asset(name: str) -> dict[str, Any]:
    data = ASSETS[name]
    return {"asset_id": name, **data}


def _generic(
    category: str,
    *,
    asset: str,
    severity: str,
    confidence: float,
    title: str,
    description: str = "",
    indicators: dict[str, Any] | None = None,
    user: str | None = None,
    mitre: tuple[str, ...] = (),
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "occurred_at": _now(),
        "source": "siem",
        "source_product": "cirtdefense-demo",
        "asset": _asset(asset),
        "title": title,
        "description": description or title,
        "indicators": indicators or {},
        "mitre_techniques": list(mitre),
    }
    if user:
        payload["asset"]["user"] = user
    return payload


# ---------------------------------------------------------------------------
# Constructeurs de charges utiles, un par ligne du catalogue
# ---------------------------------------------------------------------------


def _a1_ddos_volumetrique() -> dict[str, Any]:
    return _generic(
        "ddos_volumetric",
        asset="fw-dmz-01",
        severity="high",
        confidence=0.95,
        title="Pic de trafic entrant — saturation du lien de transit",
        description=(
            "Inondation SYN depuis de multiples sources ; bande passante saturée "
            "à 98 % du lien, latence en hausse sur tous les services exposés."
        ),
        indicators={
            "srcip": HOSTILE_IPS[0],
            "pps": 2_400_000,
            "bandwidth_utilization": 0.98,
            "flood_type": "syn",
        },
        mitre=("T1498", "T1498.001"),
    )


def _a2_ddos_applicatif() -> dict[str, Any]:
    return _generic(
        "ddos_application",
        asset="srv-web-01",
        severity="high",
        confidence=0.85,
        title="Épuisement du pool de connexions — Slowloris suspecte",
        description=(
            "1 840 connexions simultanees maintenues ouvertes sans émission de "
            "données ; temps de réponse median passe de 95 ms a 4 200 ms."
        ),
        indicators={
            "srcip": HOSTILE_IPS[1],
            "open_connections": 1840,
            "median_response_ms": 4200,
            "bytes_per_connection": 12,
        },
        mitre=("T1499", "T1499.002"),
    )


def _a3_scan() -> dict[str, Any]:
    return _generic(
        "scan",
        asset="fw-dmz-01",
        severity="low",
        confidence=0.7,
        title="Balayage de ports depuis une source externe",
        description="1 024 ports sondes en 38 secondes depuis une adresse unique.",
        indicators={"srcip": HOSTILE_IPS[2], "ports_scanned": 1024, "duration_seconds": 38},
        mitre=("T1046", "T1595"),
    )


def _a4_bruteforce() -> dict[str, Any]:
    """Émis au format Wazuh : c'est l'UEBA/EDR qui détecte ce type."""
    return {
        "timestamp": _now(),
        "rule": {
            "level": 10,
            "description": "Multiple failed password attempts followed by success",
            "groups": ["authentication_failed", "authentication_success"],
            "mitre": {"id": ["T1110", "T1110.003"]},
        },
        "agent": {"id": "srv-mail-01", "name": "srv-mail-01", "ip": "10.0.2.50"},
        "data": {"srcip": HOSTILE_IPS[3], "dstuser": "a.mbarga", "failed_attempts": 247},
        "cirt": {"criticality": 5, "zone": "interne"},
    }


def _a5_exfiltration() -> dict[str, Any]:
    return _generic(
        "exfiltration",
        asset="srv-db-01",
        severity="high",
        confidence=0.8,
        title="Volume sortant anormal vers une destination externe",
        description=(
            "8,4 Go transferes en 22 minutes vers une adresse jamais contactee "
            "auparavant ; requêtes DNS de longueur atypique en parallele."
        ),
        indicators={
            "dest_ip": HOSTILE_IPS[0],
            "bytes": 8_400_000_000,
            "duration_minutes": 22,
            "dns_query_length_avg": 187,
        },
        mitre=("T1041", "T1048"),
    )


def _a6_ransomware() -> dict[str, Any]:
    return _generic(
        "ransomware",
        asset="srv-file-01",
        severity="critical",
        confidence=0.92,
        title="Chiffrement de masse en cours — propagation SMB détectée",
        description=(
            "14 200 fichiers modifies en 4 minutes avec extension inconnue ; "
            "tentatives de connexion SMB vers 37 hôtes du même segment ; "
            "service de cliches instantanés arrête."
        ),
        indicators={
            "process": "svchost32.exe",
            "files_modified": 14200,
            "window_minutes": 4,
            "smb_targets": 37,
            "shadow_copies_deleted": True,
        },
        mitre=("T1486", "T1490", "T1021.002"),
    )


def _a7_c2() -> dict[str, Any]:
    """Émis au format Suricata : détection réseau."""
    return {
        "timestamp": _now(),
        "alert": {
            "signature": "ET TROJAN Observed DNS Query to C2 Domain",
            "category": "command and control",
            "severity": 1,
            "signature_id": 2028371,
        },
        "src_ip": "10.0.2.30",
        "dest_ip": HOSTILE_IPS[1],
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "host": "srv-app-01",
        "dns": {"rrname": HOSTILE_DOMAINS[0]},
    }


def _b1_sql_injection() -> dict[str, Any]:
    return _generic(
        "sql_injection",
        asset="srv-web-02",
        severity="high",
        confidence=0.88,
        title="Motif d'injection SQL dans les paramètres de requête",
        description=(
            "Séquence UNION SELECT détectée dans le paramètre 'id' du point "
            "d'entrée /api/clients ; 43 tentatives en 2 minutes."
        ),
        indicators={
            "srcip": HOSTILE_IPS[2],
            "pattern": "UNION SELECT",
            "endpoint": "/api/clients",
            "attempts": 43,
        },
        mitre=("T1190",),
    )


def _b2_xss() -> dict[str, Any]:
    return _generic(
        "xss",
        asset="srv-web-01",
        severity="medium",
        confidence=0.75,
        title="Contenu suspect soumis dans un champ de formulaire",
        description="Balise script encodee détectée dans le champ 'commentaire'.",
        indicators={
            "srcip": HOSTILE_IPS[3],
            "pattern": "<script>",
            "field": "commentaire",
            "encoding": "url",
        },
        mitre=("T1059.007",),
    )


def _b3_rce() -> dict[str, Any]:
    return _generic(
        "rce",
        asset="srv-app-01",
        severity="critical",
        confidence=0.9,
        title="Processus enfant inattendu lance par un service applicatif",
        description=(
            "Le service tomcat a lance un interpreteur de commandes, "
            "suivi d'une connexion sortante vers une adresse externe."
        ),
        indicators={
            "process": "/bin/sh",
            "parent_process": "tomcat",
            "dest_ip": HOSTILE_IPS[0],
        },
        mitre=("T1190", "T1059"),
    )


def _b4_path_traversal() -> dict[str, Any]:
    return _generic(
        "path_traversal",
        asset="srv-web-02",
        severity="high",
        confidence=0.82,
        title="Tentative de traversee de chemin",
        description="Motif de remontée de répertoire vers /etc/passwd.",
        indicators={
            "srcip": HOSTILE_IPS[1],
            "pattern": "../../../etc/passwd",
            "endpoint": "/download",
        },
        mitre=("T1083",),
    )


def _b5_webshell() -> dict[str, Any]:
    return _generic(
        "webshell_upload",
        asset="srv-web-01",
        severity="high",
        confidence=0.9,
        title="Fichier exécutable depose dans un répertoire de televersement",
        description=(
            "Fichier PHP depose dans /var/www/uploads, répertoire servi par "
            "le serveur web et non prévu pour du code exécutable."
        ),
        indicators={
            "srcip": HOSTILE_IPS[2],
            "file_path": "/var/www/uploads/img_2941.php",
            "file_type": "php",
        },
        mitre=("T1505.003",),
    )


def _b6_api_abuse() -> dict[str, Any]:
    return _generic(
        "api_abuse",
        asset="srv-app-01",
        severity="medium",
        confidence=0.78,
        title="Volume de requêtes anormal pour un jeton d'API",
        description=(
            "84 000 requêtes en une heure pour un jeton dont l'usage nominal "
            "est de 200 requêtes par jour ; enumeration sequentielle d'identifiants."
        ),
        indicators={
            "srcip": HOSTILE_IPS[3],
            "token_id": "tok_partenaire_0417",
            "requests_per_hour": 84000,
        },
        mitre=("T1190",),
    )


def _b7_session_hijacking() -> dict[str, Any]:
    return _generic(
        "session_hijacking",
        asset="srv-app-01",
        severity="high",
        confidence=0.85,
        user="n.fotso",
        title="Session utilisée depuis deux localisations incompatibles",
        description=(
            "Même jeton de session présente depuis Douala puis depuis une "
            "adresse externe, a 6 minutes d'intervalle."
        ),
        indicators={
            "token_id": "sess_8f21ba",
            "srcip": HOSTILE_IPS[0],
            "interval_minutes": 6,
        },
        mitre=("T1550", "T1539"),
    )


def _c1_privilege_escalation() -> dict[str, Any]:
    return _generic(
        "privilege_escalation",
        asset="srv-db-01",
        severity="high",
        confidence=0.8,
        user="s.eyenga",
        title="Ajout au groupe d'administration hors processus",
        description=(
            "Le compte a été ajoute au groupe Administrateurs sans demande "
            "associée, en dehors des heures ouvrables."
        ),
        indicators={"privilege": "db_admin", "previous_role": "db_reader"},
        mitre=("T1098", "T1068"),
    )


def _c2_abnormal_access() -> dict[str, Any]:
    return _generic(
        "abnormal_access",
        asset="srv-file-01",
        severity="medium",
        confidence=0.65,
        user="j.ngono",
        title="Consultation de ressources hors périmètre métier",
        description=(
            "Accès a 340 documents du service financier par un compte rattache "
            "à la direction technique, sans precedent sur 180 jours."
        ),
        indicators={"resource": "/partage/finance/2026", "documents_accessed": 340},
        mitre=("T1530",),
    )


def _c3_slow_exfiltration() -> dict[str, Any]:
    return _generic(
        "slow_exfiltration",
        asset="srv-file-01",
        severity="medium",
        confidence=0.72,
        user="p.atangana",
        title="Accumulation progressive dans un espace non habituel",
        description=(
            "1,2 Go rassembles par increments de 40 Mo sur 11 jours dans un "
            "répertoire temporaire, sous les seuils de détection volumétrique."
        ),
        indicators={"staging_path": "/tmp/.cache_u", "bytes": 1_200_000_000, "days": 11},
        mitre=("T1074", "T1030"),
    )


def _c4_compromised_account() -> dict[str, Any]:
    return _generic(
        "compromised_account",
        asset="srv-mail-01",
        severity="high",
        confidence=0.87,
        user="m.tchoumi",
        title="Connexions geographiquement incompatibles",
        description=(
            "Authentification depuis Yaounde puis, 12 minutes plus tard, depuis "
            "une adresse localisee hors du continent."
        ),
        indicators={"srcip": HOSTILE_IPS[1], "interval_minutes": 12, "distance_km": 5800},
        mitre=("T1078",),
    )


def _d1_tls_certificate() -> dict[str, Any]:
    return _generic(
        "tls_certificate",
        asset="srv-web-02",
        severity="low",
        confidence=0.99,
        title="Certificat TLS expire",
        description=(
            "Le certificat du service à expiré il y a 3 jours ; signature "
            "SHA-1, clé RSA de 1024 bits."
        ),
        indicators={
            "expired_days": 3,
            "signature_algorithm": "sha1WithRSA",
            "key_bits": 1024,
        },
    )


def _d2_unexpected_port() -> dict[str, Any]:
    return _generic(
        "unexpected_port",
        asset="srv-app-01",
        severity="medium",
        confidence=0.95,
        title="Port ouvert absent de la configuration attendue",
        description=(
            "Le port 4444/tcp répond sur l'hôte alors qu'il ne figure pas dans "
            "la configuration de référence."
        ),
        indicators={"port": "4444", "protocol": "tcp", "service": "inconnu"},
        mitre=("T1571",),
    )


def _d3_service_unavailable() -> dict[str, Any]:
    return _generic(
        "service_unavailable",
        asset="srv-mail-01",
        severity="high",
        confidence=0.98,
        title="Service injoignable — échecs répétés de la sonde",
        description="7 échecs consecutifs de la sonde de disponibilité sur 3 minutes.",
        indicators={"consecutive_failures": 7, "standby_node": "srv-mail-02"},
    )


def _d4_config_drift() -> dict[str, Any]:
    return _generic(
        "config_drift",
        asset="srv-web-01",
        severity="low",
        confidence=0.9,
        title="Écart à la configuration de référence",
        description=(
            "3 paramètres divergent de la référence, dont la désactivation "
            "de la journalisation des accès."
        ),
        indicators={"delta_count": 3, "changed": "access_log,tls_min_version,keepalive"},
        mitre=("T1562",),
    )


# ---------------------------------------------------------------------------
# Registre des scénarios
# ---------------------------------------------------------------------------

SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        code="A1",
        source="generic_json",
        payload_builder=_a1_ddos_volumetrique,
        title="Inondation SYN saturant le lien de transit",
        narrative="Le lien est saturé avant nos équipements : la réponse se joue en bordure.",
        expected_actions=("edge:enable_scrubbing", "edge:blackhole_ip", "notify:notify"),
    ),
    Scenario(
        code="A2",
        source="generic_json",
        payload_builder=_a2_ddos_applicatif,
        title="Slowloris épuisant le pool de connexions",
        narrative="Peu d'octets, beaucoup de connexions : la réponse est applicative.",
        expected_actions=("waf:rate_limit_rule", "service:close_idle_connections"),
    ),
    Scenario(
        code="A3",
        source="generic_json",
        payload_builder=_a3_scan,
        title="Balayage de 1 024 ports depuis une source externe",
        narrative="Signal précoce de faible gravité : réponse graduée, pas de blocage brutal.",
        expected_actions=("firewall:rate_limit_ip",),
    ),
    Scenario(
        code="A4",
        source="wazuh",
        payload_builder=_a4_bruteforce,
        title="247 échecs d'authentification suivis d'un succès",
        narrative="Le succès après la rafale change tout : le compte est présumé compromis.",
        expected_actions=("firewall:block_ip", "iam:revoke_sessions"),
    ),
    Scenario(
        code="A5",
        source="generic_json",
        payload_builder=_a5_exfiltration,
        title="8,4 Go sortants vers une destination inconnue",
        narrative="La donnée est peut-être déjà partie : coupure immédiate de la destination.",
        expected_actions=("firewall:block_ip", "network:throttle_egress"),
    ),
    Scenario(
        code="A6",
        source="generic_json",
        payload_builder=_a6_ransomware,
        title="Chiffrement de 14 200 fichiers en 4 minutes",
        narrative=(
            "Priorité maximale. La réponse s'arrête à l'isolation : jamais de "
            "remédiation automatique, qui serait irréversible."
        ),
        expected_actions=(
            "network:move_to_vlan",
            "network:block_lateral",
            "backup:trigger_snapshot",
            "edr:kill_process",
            "notify:notify",
        ),
    ),
    Scenario(
        code="A7",
        source="suricata",
        payload_builder=_a7_c2,
        title="Beaconing TLS vers un domaine de commande et contrôle",
        narrative="Sinkhole DNS et blocage : on coupe le canal sans aveugler l'investigation.",
        expected_actions=("firewall:block_ip", "edr:isolate_host"),
    ),
    Scenario(
        code="B1",
        source="generic_json",
        payload_builder=_b1_sql_injection,
        title="UNION SELECT dans les paramètres de /api/clients",
        narrative="Blocage du motif au WAF, puis de la source.",
        expected_actions=("waf:block_pattern", "firewall:block_ip"),
    ),
    Scenario(
        code="B2",
        source="generic_json",
        payload_builder=_b2_xss,
        title="Balise script encodee dans un champ de formulaire",
        narrative="Un contenu déjà stocké n'est pas retiré automatiquement : il est signalé.",
        expected_actions=("waf:block_pattern", "waf:sanitize_field"),
    ),
    Scenario(
        code="B3",
        source="generic_json",
        payload_builder=_b3_rce,
        title="Interpreteur de commandes lance par le service tomcat",
        narrative="Compromission directe : isolation immédiate et arrêt du processus.",
        expected_actions=("edr:isolate_host", "edr:kill_process"),
    ),
    Scenario(
        code="B4",
        source="generic_json",
        payload_builder=_b4_path_traversal,
        title="Remontée de répertoire vers /etc/passwd",
        narrative="Blocage du motif et du point d'entrée vise.",
        expected_actions=("waf:block_pattern", "waf:block_request"),
    ),
    Scenario(
        code="B5",
        source="generic_json",
        payload_builder=_b5_webshell,
        title="Fichier PHP depose dans un répertoire de televersement",
        narrative="Quarantaine — déplacement, pas suppression : le fichier reste une preuve.",
        expected_actions=("edr:quarantine_file", "firewall:block_ip"),
    ),
    Scenario(
        code="B6",
        source="generic_json",
        payload_builder=_b6_api_abuse,
        title="84 000 requêtes en une heure sur un jeton partenaire",
        narrative="Révocation du jeton, reemissible : la gêne est temporaire.",
        expected_actions=("iam:revoke_token", "waf:rate_limit_rule"),
    ),
    Scenario(
        code="B7",
        source="generic_json",
        payload_builder=_b7_session_hijacking,
        title="Même session depuis deux localisations incompatibles",
        narrative="Le second facteur distingue l'utilisateur légitime de l'attaquant.",
        expected_actions=("iam:revoke_sessions", "iam:force_mfa", "iam:revoke_token"),
    ),
    Scenario(
        code="C1",
        source="generic_json",
        payload_builder=_c1_privilege_escalation,
        title="Ajout au groupe d'administration sans demande associée",
        narrative="Révocation du privilège et restauration du rôle antérieur.",
        expected_actions=("iam:revoke_sessions",),
    ),
    Scenario(
        code="C2",
        source="generic_json",
        payload_builder=_c2_abnormal_access,
        title="340 documents financiers consultes par un compte technique",
        narrative=(
            "Le catalogue exclut ici la révocation de compte : le risque de "
            "faux positif est trop élève."
        ),
        expected_actions=("iam:block_resource_access", "notify:notify"),
    ),
    Scenario(
        code="C3",
        source="generic_json",
        payload_builder=_c3_slow_exfiltration,
        title="1,2 Go accumules par increments sur 11 jours",
        narrative="Sous les seuils volumétriques : c'est l'accumulation qui trahit.",
        expected_actions=("iam:restrict_export", "notify:notify"),
    ),
    Scenario(
        code="C4",
        source="generic_json",
        payload_builder=_c4_compromised_account,
        title="Connexions a 5 800 km d'intervalle en 12 minutes",
        narrative="Les trois actions du catalogue s'appliquent ensemble.",
        expected_actions=("iam:lock_account", "iam:revoke_sessions", "iam:force_mfa"),
    ),
    Scenario(
        code="D1",
        source="generic_json",
        payload_builder=_d1_tls_certificate,
        title="Certificat expire, SHA-1, clé de 1024 bits",
        narrative=(
            "Aucune action corrective possible : le renouvellement dépend d'une "
            "autorité externe. Le système constate et s'abstient."
        ),
        expected_actions=("notify:notify",),
    ),
    Scenario(
        code="D2",
        source="generic_json",
        payload_builder=_d2_unexpected_port,
        title="Port 4444/tcp ouvert hors configuration de référence",
        narrative="Fermeture si le port est sous contrôle, alerte de dérive sinon.",
        expected_actions=("config:close_port", "notify:notify"),
    ),
    Scenario(
        code="D3",
        source="generic_json",
        payload_builder=_d3_service_unavailable,
        title="7 échecs consecutifs de la sonde de disponibilité",
        narrative="Bascule vers le nœud de secours déclare, sinon redémarrage.",
        expected_actions=("service:failover", "service:restart_service"),
    ),
    Scenario(
        code="D4",
        source="generic_json",
        payload_builder=_d4_config_drift,
        title="3 paramètres divergents, dont la journalisation désactivée",
        narrative="Dérive mineure : restauration admise. Au-delà du seuil, elle serait refusée.",
        expected_actions=("config:restore_baseline", "notify:notify"),
    ),
)

BY_CODE_SCENARIO: dict[str, Scenario] = {s.code: s for s in SCENARIOS}


def get_scenario(code: str) -> Scenario | None:
    return BY_CODE_SCENARIO.get(code.upper())


def list_scenarios() -> list[dict[str, Any]]:
    return [s.to_dict() for s in SCENARIOS]


def build_payload(code: str) -> dict[str, Any]:
    """Fabrique la charge utile du scénario, prete pour l'adaptateur."""
    scenario = get_scenario(code)
    if scenario is None:
        raise KeyError(f"scénario '{code}' inconnu ; codes valides : {sorted(BY_CODE_SCENARIO)}")
    return scenario.payload_builder()


def random_scenario(rng: random.Random | None = None) -> Scenario:
    return (rng or random).choice(SCENARIOS)


def by_family() -> dict[str, list[dict[str, Any]]]:
    """Scénarios groupes par famille, pour l'affichage de l'interface."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for scenario in SCENARIOS:
        grouped.setdefault(scenario.attack_type.family.code, []).append(scenario.to_dict())
    return grouped
