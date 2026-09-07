"""Traduction du vocabulaire technique en français courant.

Un rapport d'opérations est lu par un directeur, un magistrat ou un auditeur.
Aucun d'eux n'a à savoir ce que signifie `edr:isolate_host`, ni pourquoi une
décision porte l'issue `no_grounded_context`. Écrire ces termes dans un
document officiel, c'est demander au lecteur de faire le travail de traduction
que la plateforme aurait dû faire.

Ce module tient donc **une seule table de correspondance**, employée par les
quatre formats d'export. Le rapport dit la même chose en PDF, en Word, en
Markdown et en JSON — seule la mise en forme change.

Règle de rédaction suivie ici : on décrit **le geste et son effet**, pas la
commande. « Blocage d'une adresse au pare-feu » plutôt que `block_ip` ;
« mise en quarantaine réseau d'une machine » plutôt que `isolate_host`.
"""

from __future__ import annotations

# --------------------------------------------------------------- les gestes
# Chaque entrée : (nom du geste, effet obtenu, effet de son annulation).
GESTES: dict[str, tuple[str, str]] = {
    # Pare-feu et bordure de réseau
    "firewall:block_ip": (
        "Blocage d'une adresse au pare-feu",
        "l'adresse ne peut plus joindre le réseau de l'organisation",
    ),
    "firewall:block_domain": (
        "Blocage d'un nom de domaine au pare-feu",
        "le domaine devient injoignable depuis le réseau",
    ),
    "firewall:rate_limit_ip": (
        "Limitation du débit accordé à une adresse",
        "l'adresse reste jointe mais son trafic est bridé",
    ),
    "edge:blackhole_ip": (
        "Mise en trou noir d'une adresse chez l'opérateur",
        "le trafic de cette adresse est écarté avant d'atteindre nos liens",
    ),
    "edge:enable_scrubbing": (
        "Activation du nettoyage de trafic chez l'opérateur",
        "le trafic d'attaque est filtré en amont de nos équipements",
    ),
    "edge:edge_rate_limit": (
        "Limitation du débit en bordure de réseau",
        "le volume entrant est ramené à un niveau soutenable",
    ),
    # Postes et serveurs
    "edr:isolate_host": (
        "Mise en quarantaine réseau d'une machine",
        "la machine est coupée du réseau mais reste administrable",
    ),
    "edr:kill_process": (
        "Arrêt d'un programme en cours d'exécution",
        "le programme malveillant cesse de fonctionner",
    ),
    "edr:quarantine_file": (
        "Mise à l'écart d'un fichier suspect",
        "le fichier est déplacé dans une zone sécurisée et ne peut plus s'exécuter",
    ),
    "edr:shutdown_host": (
        "Extinction d'une machine",
        "la machine est éteinte",
    ),
    "edr:wipe_disk": (
        "Effacement du disque d'une machine",
        "les données du disque sont détruites",
    ),
    # Comptes et accès
    "iam:disable_account": (
        "Désactivation d'un compte utilisateur",
        "le compte ne permet plus de se connecter",
    ),
    "iam:lock_account": (
        "Verrouillage temporaire d'un compte",
        "le compte est suspendu le temps de la vérification",
    ),
    "iam:revoke_sessions": (
        "Fermeture des sessions ouvertes d'un compte",
        "l'utilisateur est déconnecté de partout et doit se reconnecter",
    ),
    "iam:force_mfa": (
        "Exigence d'une authentification renforcée",
        "une seconde preuve d'identité est demandée à la prochaine connexion",
    ),
    "iam:force_password_reset": (
        "Renouvellement imposé du mot de passe",
        "l'utilisateur devra choisir un nouveau mot de passe",
    ),
    "iam:revoke_token": (
        "Révocation d'un jeton d'accès applicatif",
        "le jeton ne donne plus accès au service",
    ),
    "iam:revoke_privilege": (
        "Retrait d'un privilège d'administration",
        "le compte perd les droits étendus qui lui avaient été accordés",
    ),
    "iam:block_resource_access": (
        "Blocage de l'accès à une ressource",
        "la ressource n'est plus accessible depuis ce compte",
    ),
    "iam:restrict_export": (
        "Restriction des droits d'exportation de données",
        "les téléchargements en masse sont empêchés",
    ),
    "iam:delete_account": (
        "Suppression d'un compte",
        "le compte et ses droits sont supprimés",
    ),
    # Réseau interne
    "network:cut_egress_connection": (
        "Coupure d'une connexion sortante",
        "le transfert en cours vers l'extérieur est interrompu",
    ),
    "network:move_to_vlan": (
        "Placement d'une machine en réseau de quarantaine",
        "la machine est isolée du reste du parc",
    ),
    "network:throttle_egress": (
        "Bridage du débit sortant d'une machine",
        "un transfert de données devient trop lent pour aboutir",
    ),
    "network:block_lateral": (
        "Blocage des déplacements entre machines internes",
        "la progression de l'attaquant dans le réseau est arrêtée",
    ),
    # Applicatif
    "waf:block_pattern": (
        "Blocage d'un motif de requête malveillante",
        "les requêtes de cette forme sont rejetées avant d'atteindre l'application",
    ),
    "waf:block_request": (
        "Blocage d'une requête précise",
        "la requête identifiée est rejetée",
    ),
    "waf:rate_limit_rule": (
        "Limitation du nombre de requêtes acceptées",
        "l'application cesse d'être saturée",
    ),
    "waf:sanitize_field": (
        "Nettoyage d'un champ de saisie",
        "le contenu dangereux est neutralisé avant traitement",
    ),
    # Résolution de noms
    "dns:sinkhole_domain": (
        "Détournement d'un nom de domaine",
        "les machines qui interrogent ce domaine sont dirigées vers un puits",
    ),
    "dns:block_resolution": (
        "Blocage de la résolution d'un nom de domaine",
        "le domaine ne peut plus être traduit en adresse",
    ),
    # Infrastructure
    "backup:trigger_snapshot": (
        "Déclenchement d'une sauvegarde immédiate",
        "un instantané est pris avant que la situation n'empire",
    ),
    "service:restart_service": (
        "Redémarrage d'un service",
        "le service repart depuis un état sain",
    ),
    "service:failover": (
        "Bascule vers le service de secours",
        "l'activité continue sur l'installation de repli",
    ),
    "service:close_idle_connections": (
        "Fermeture des connexions inactives",
        "les ressources retenues sans usage sont libérées",
    ),
    "config:close_port": (
        "Fermeture d'un port ouvert sans raison",
        "le point d'entrée inutile est refermé",
    ),
    "config:restore_baseline": (
        "Rétablissement de la configuration de référence",
        "l'équipement retrouve sa configuration validée",
    ),
    # Information
    "notify:notify": (
        "Information de l'équipe d'astreinte",
        "l'analyste est prévenu de ce qui a été fait",
    ),
}


# ------------------------------------------------------- issues de décision
ISSUES: dict[str, str] = {
    "autonomous_execution": "Réponse engagée automatiquement",
    "no_action_needed": "Aucune réponse nécessaire",
    "no_grounded_context": "Aucune réponse engagée — la menace n'est pas documentée",
    "policy_denied": "Aucune réponse engagée — les consignes de l'agence s'y opposent",
    "breaker_open": "Aucune réponse engagée — la réponse automatique était suspendue",
    "out_of_catalog": "Aucune réponse engagée — aucun geste sûr n'était applicable",
}

MOTIFS_DE_REFUS: dict[str, str] = {
    "contexte non fonde": "menace absente de la documentation de référence",
    "politique": "consignes de l'agence",
    "coupe-circuit": "réponse automatique suspendue",
    "hors catalogue": "aucun geste sûr applicable",
}


# ----------------------------------------------------------- états d'action
ETATS_ACTION: dict[str, str] = {
    "planned": "prévue",
    "executing": "en cours",
    "executed": "menée à bien",
    "failed": "en échec",
    "blocked_by_policy": "écartée par les consignes",
    "blocked_by_breaker": "écartée, réponse automatique suspendue",
    "rolled_back": "annulée par la plateforme",
    "rollback_failed": "annulation impossible — intervention requise",
}

ETATS_INCIDENT: dict[str, str] = {
    "open": "en cours de traitement",
    "contained": "contenue",
    "rolled_back": "revenue à son état initial",
    "closed": "close",
}

CRITICITES: dict[str, str] = {
    "info": "pour information",
    "low": "faible",
    "medium": "moyenne",
    "high": "élevée",
    "critical": "critique",
}

PRIORITES: dict[str, str] = {
    "critique": "à traiter en priorité absolue",
    "haute": "à traiter en priorité",
    "moyenne": "à traiter dans l'ordre courant",
    "basse": "à traiter quand la charge le permet",
}

POSTURES: dict[str, str] = {
    "simulation": "répétition — les gestes sont calculés et tracés, sans effet sur les équipements",
    "live": "production — les gestes sont appliqués sur les équipements",
}

COUPE_CIRCUIT: dict[str, str] = {
    "closed": "en service",
    "open": "suspendu",
}


# ------------------------------------------------------------- traducteurs


def geste(cle: str) -> str:
    """« firewall:block_ip » devient « Blocage d'une adresse au pare-feu »."""
    entree = GESTES.get(cle)
    if entree:
        return entree[0]
    # Repli lisible plutôt qu'un identifiant brut : un geste ajouté au
    # catalogue sans être traduit ici doit rester compréhensible.
    _, _, verbe = cle.partition(":")
    return verbe.replace("_", " ").capitalize() or cle


def effet(cle: str) -> str:
    entree = GESTES.get(cle)
    return entree[1] if entree else ""


def issue(valeur: str) -> str:
    return ISSUES.get(valeur, valeur.replace("_", " "))


def etat_action(valeur: str) -> str:
    return ETATS_ACTION.get(valeur, valeur.replace("_", " "))


def etat_incident(valeur: str) -> str:
    return ETATS_INCIDENT.get(valeur, valeur.replace("_", " "))


def criticite(valeur: str) -> str:
    return CRITICITES.get(valeur, valeur)


def priorite(valeur: str) -> str:
    return PRIORITES.get(valeur, valeur)


def posture(mode: str) -> str:
    return POSTURES.get(mode, mode)


def coupe_circuit(etat: str) -> str:
    return COUPE_CIRCUIT.get(etat, etat)


def motif_de_refus(cle: str) -> str:
    for fragment, libelle in MOTIFS_DE_REFUS.items():
        if fragment in cle.lower():
            return libelle
    return cle


def dangerosite(valeur: float) -> str:
    """La note sur dix se double d'une appréciation en clair."""
    if valeur >= 9:
        return "extrême"
    if valeur >= 7:
        return "élevée"
    if valeur >= 4:
        return "modérée"
    return "faible"


def duree(millisecondes: int | float | None) -> str:
    if millisecondes is None:
        return "durée non mesurée"
    if millisecondes < 1000:
        return "moins d'une seconde"
    secondes = millisecondes / 1000
    if secondes < 60:
        return f"{secondes:.0f} secondes"
    return f"{secondes / 60:.0f} minutes"


def nombre(valeur: int, singulier: str, pluriel: str | None = None) -> str:
    """« 1 incident » / « 3 incidents », sans le « (s) » disgracieux."""
    if valeur == 1:
        return f"1 {singulier}"
    return f"{valeur} {pluriel or singulier + 's'}"


# ------------------------------------------------- déroulement d'une affaire
# Les libellés du registre, tels qu'ils doivent apparaître dans la colonne
# « Ce qui s'est passé » d'une chronologie. Rédigés au passé composé : on
# raconte des faits établis, pas un état courant.
EVENEMENTS: dict[str, str] = {
    "event.ingested": "Réception d'une observation en provenance d'un capteur",
    "context.enriched": "Recherche des cas comparables dans la documentation de référence",
    "decision.made": "Décision de la plateforme sur la conduite à tenir",
    "action.executed": "Application d'un geste sur les équipements",
    "action.failed": "Échec de l'application d'un geste",
    "analyst.notified": "Information de l'équipe d'astreinte",
    "rollback.triggered": "Demande d'annulation d'un geste",
    "rollback.completed": "Annulation effective d'un geste",
    "rollback.failed": "Échec d'une annulation — intervention humaine requise",
    "manual.rollback": "Annulation demandée par un analyste",
    "breaker.tripped": "Suspension automatique de la réponse autonome",
    "breaker.reset": "Rétablissement de la réponse autonome",
    "policy.compiled": "Prise en compte de nouvelles consignes de réponse",
    "catalog.updated": "Mise à jour du catalogue des menaces connues",
    "confirmation.requested": "Demande de confirmation adressée à un responsable",
    "confirmation.resolved": "Réponse apportée à une demande de confirmation",
    "qualification.proposed": "Ouverture d'une fiche de qualification d'une menace inédite",
    "qualification.resolved": "Décision sur une fiche de qualification",
    "degraded.enter": "Passage en fonctionnement dégradé",
    "degraded.replay": "Reprise des observations mises en attente",
    "demo.reset": "Remise à zéro de l'environnement de démonstration",
}


def evenement(cle: str) -> str:
    return EVENEMENTS.get(cle, cle.replace(".", " — ").replace("_", " "))


def acteur(valeur: str) -> str:
    """« system:orchestrator » devient « la plateforme », « human:a.mbarga »
    devient « l'agent a.mbarga ». Le lecteur d'un rapport doit pouvoir
    distinguer d'un coup d'œil ce que la machine a fait de ce qu'un agent a
    décidé — c'est la question qu'on lui posera en premier."""
    qui, _, nom = valeur.partition(":")
    if qui == "human":
        return f"l'agent {nom}" if nom else "un agent"
    if qui == "adapter":
        return f"la plateforme, sur signalement du {source(nom)}"
    if qui in ("system", "engine", "watcher", "scheduler"):
        return "la plateforme"
    return valeur or "—"


# ------------------------------------------------------- sources de collecte
SOURCES: dict[str, str] = {
    "siem": "corrélateur d'événements de sécurité",
    "wazuh": "agent de surveillance des serveurs",
    "suricata": "sonde de surveillance du réseau",
    "generic_json": "capteur générique",
    "cloud_audit": "journal d'activité de l'hébergeur",
    "edr": "agent de protection des postes",
    "firewall": "pare-feu",
    "waf": "protection applicative",
    "dns": "service de résolution de noms",
    "manuel": "signalement humain",
}


def source(cle: str) -> str:
    return SOURCES.get(cle, (cle or "").replace("_", " ") or "origine non précisée")


def numero_intervention(incident_id: str) -> str:
    """« inc_f4c2f037a9fc46cd » devient « INT-F4C2F037 ».

    Un rapport officiel porte des numéros d'affaire, pas des identifiants de
    base de données. La partie conservée reste unique et permet de retrouver
    l'intervention dans la plateforme.
    """
    _, _, empreinte = incident_id.partition("_")
    return f"INT-{empreinte[:8].upper()}" if empreinte else incident_id
