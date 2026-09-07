"""Composition du rapport : des faits vers un document lisible.

Ce module est le seul endroit où l'on décide *ce que dit* un rapport. Les
quatre rendus (PDF, Word, Markdown, JSON) n'en connaissent que la sortie —
une suite de blocs — et se contentent de la mettre en page.

Deux compositions coexistent, parce que deux lectures existent :

* le **compte rendu d'intervention**, qui raconte une affaire du début à la
  fin — ce qui a été observé, ce que la plateforme a décidé, ce qu'elle a
  fait, dans quel ordre ;
* le **rapport d'activité**, qui agrège un ensemble d'interventions et
  répond à la question du décideur : que s'est-il passé, en quelle quantité,
  et la plateforme s'est-elle bien tenue ?

Règle de rédaction tenue partout : aucun identifiant technique n'atteint la
page. Un verbe d'actuateur devient un geste nommé en français, un `outcome`
devient une phrase, un horodatage ISO devient une date. La traduction est
centralisée dans :mod:`langage`, jamais improvisée ici.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..domain.taxonomy import BY_CODE
from . import langage
from .document import (
    Document,
    Encadre,
    EnTeteAdministratif,
    Graphique,
    Liste,
    Paragraphe,
    Tableau,
    Titre,
)
from .selection import Perimetre, Selection

ROMAINS = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII")

# Au-delà, un tableau d'intervention cesse d'être lu : on le tronque en le
# disant, plutôt que de livrer trente pages que personne n'ouvrira.
PLAFOND_LIGNES = 30


class Compositeur:
    """Assemble un document à partir des dépôts de la plateforme.

    Ne lit que ce que le périmètre demandé impose : un compte rendu
    d'intervention n'a aucune raison de parcourir le portefeuille entier.
    """

    def __init__(
        self,
        collector: Any,
        portfolio: Any,
        incidents: Any,
        actions: Any,
        ledger: Any,
        decisions: Any = None,
        settings: Any = None,
        site_id: str = "cirt-cm-01",
        logo: str | Path = "",
    ) -> None:
        self._collector = collector
        self._portfolio = portfolio
        self._incidents = incidents
        self._actions = actions
        self._ledger = ledger
        self._decisions = decisions
        self._settings = settings
        self._site_id = site_id
        self._logo = str(logo)

    # ------------------------------------------------------------------ API

    def composer(self, selection: Selection, etabli_par: str = "") -> Document:
        erreur = selection.valider()
        if erreur:
            raise ValueError(erreur)
        document = self._coquille(selection, etabli_par)
        if selection.perimetre is Perimetre.INCIDENT:
            self._compte_rendu(document, selection)
        else:
            self._activite(document, selection)
        return document

    # -------------------------------------------------------------- coquille

    def _coquille(self, selection: Selection, etabli_par: str) -> Document:
        maintenant = datetime.now(UTC)
        return Document(
            titre=selection.titre(),
            objet=selection.objet(),
            reference=self._reference(selection, maintenant),
            etabli_le=maintenant,
            etabli_par=etabli_par or "Plateforme CIRTDEFENSE",
            entete=EnTeteAdministratif(logo=self._logo),
            mention_finale=(
                "Le présent document est établi à partir du registre "
                "d'événements de la plateforme, dont l'intégrité est vérifiée "
                "à chaque édition. Il peut être produit à l'appui d'un rapport "
                "de sécurité ou d'une procédure."
            ),
        )

    def _reference(self, selection: Selection, quand: datetime) -> str:
        """Numéro d'ordre du document.

        Il est calculé à partir du périmètre et du jour d'édition : deux
        éditions du même rapport le même jour portent le même numéro, ce
        qu'attend un service d'archives. Un périmètre différent, ou un autre
        jour, donne un autre numéro.
        """
        graine = f"{selection.perimetre}|{selection.fenetre}|{selection.valeur}|{quand:%Y%m%d}"
        ordre = int(hashlib.sha256(graine.encode()).hexdigest()[:6], 16) % 10000
        return f"N° {ordre:04d}/RAP/MINPOSTEL/ANTIC/CIRT/{quand:%Y}"

    # ------------------------------------------------- rapport d'activité

    def _activite(self, document: Document, selection: Selection) -> None:
        faits = self._collector.collect(
            hours=selection.heures, label=selection.objet()
        )
        retenus = self._incidents_du_perimetre(selection)
        gestes, annulations = self._gestes(retenus)
        numero = _Numerotation()

        self._section_objet(document, selection, numero, len(retenus))
        self._section_conditions(document, faits, numero)
        self._section_ensemble(document, faits, retenus, gestes, annulations, numero)
        self._section_nature(document, retenus, numero)
        self._section_interventions(document, retenus, numero)
        self._section_gestes(document, gestes, numero)
        self._section_abstentions(document, faits, numero)
        self._section_tracabilite(document, faits, numero)
        self._section_conclusion(document, faits, retenus, gestes, annulations, numero)

    def _section_objet(
        self,
        document: Document,
        selection: Selection,
        numero: _Numerotation,
        combien: int,
    ) -> None:
        debut = selection.depuis
        fin = datetime.now(UTC)
        document.ajouter(
            Titre("Objet du rapport", numero=numero()),
            Paragraphe(
                f"Le présent rapport rend compte de l'activité du Centre de "
                f"réponse aux incidents informatiques entre le "
                f"{_date_longue(debut)} et le {_date_longue(fin)}."
            ),
            Paragraphe(_phrase_de_perimetre(selection, combien)),
            Paragraphe(
                "Les interventions décrites ci-après ont été conduites par la "
                "plateforme automatisée de réponse aux incidents. Celle-ci "
                "décide et agit sans attendre l'accord préalable d'un agent ; "
                "l'équipe d'astreinte en est informée immédiatement après et "
                "conserve le pouvoir de revenir sur chaque geste appliqué."
            ),
        )

    def _section_conditions(
        self, document: Document, faits: Any, numero: _Numerotation
    ) -> None:
        document.ajouter(
            Titre("Conditions de fonctionnement sur la période", numero=numero()),
            Liste(
                [
                    "Réponse automatique : "
                    + ("en service" if faits.autonomy_effective else "hors service"),
                    "Effet sur les équipements : " + langage.posture(faits.actuation_mode),
                    "Dispositif de suspension automatique : "
                    + langage.coupe_circuit(faits.breaker_state)
                    + (
                        f" — {langage.nombre(faits.breaker_trips, 'déclenchement')} "
                        "sur la période"
                        if faits.breaker_trips
                        else ""
                    ),
                ]
            ),
        )
        if faits.actuation_mode != "live":
            document.ajouter(
                Encadre(
                    "Portée des résultats présentés",
                    "La plateforme fonctionnait en répétition. Les gestes "
                    "recensés dans ce rapport ont été décidés, tracés et "
                    "chronométrés, mais n'ont produit aucun effet sur les "
                    "équipements réels. Les chiffres mesurent le comportement "
                    "du système, non une action opérée sur le réseau.",
                    ton="attention",
                )
            )
        if not faits.autonomy_effective:
            document.ajouter(
                Encadre(
                    "Réponse automatique interrompue",
                    "La réponse automatique était hors service sur tout ou "
                    "partie de la période. Les menaces survenues pendant cet "
                    "intervalle n'ont pas reçu de traitement automatique.",
                    ton="alerte",
                )
            )

    def _section_ensemble(
        self,
        document: Document,
        faits: Any,
        retenus: list[dict[str, Any]],
        gestes: Counter[str],
        annulations: int,
        numero: _Numerotation,
    ) -> None:
        total_gestes = sum(gestes.values())
        document.ajouter(
            Titre("Vue d'ensemble", numero=numero()),
            Paragraphe(
                f"Sur la période considérée, la plateforme a pris en charge "
                f"{langage.nombre(len(retenus), 'intervention')} et appliqué "
                f"{langage.nombre(total_gestes, 'geste')} sur les équipements. "
                + (
                    f"Elle est revenue d'elle-même sur "
                    f"{langage.nombre(annulations, 'geste')}, soit "
                    f"{_pourcent(annulations, total_gestes)} de ce qu'elle avait "
                    "engagé."
                    if annulations
                    else "Aucun geste n'a eu à être défait."
                )
            ),
            Tableau(
                entetes=["Indicateur", "Valeur"],
                alignements=["gauche", "droite"],
                lignes=[
                    ["Interventions prises en charge", str(len(retenus))],
                    ["Gestes appliqués sur les équipements", str(faits.actions_executed)],
                    ["Gestes annulés", str(faits.actions_rolled_back)],
                    ["— dont annulés par la plateforme elle-même",
                     str(faits.autonomous_rollbacks)],
                    ["— dont annulés à la demande d'un agent", str(faits.manual_rollbacks)],
                    ["Gestes n'ayant pas abouti", str(faits.actions_failed)],
                    ["Gestes écartés par les consignes de l'agence",
                     str(faits.actions_blocked)],
                    ["Part des gestes revenus en arrière",
                     f"{faits.rollback_ratio:.0%}"],
                    ["Situations où la plateforme s'est abstenue",
                     str(faits.refusals_total)],
                ],
                legende="Chiffres clés de la période",
            ),
            Paragraphe(
                "La part des gestes revenus en arrière est l'indicateur à "
                "surveiller en priorité : elle mesure la fréquence à laquelle "
                "la plateforme doit défaire ce qu'elle vient de faire. Une "
                "valeur qui s'élève durablement justifie de revoir les "
                "consignes de réponse.",
                accent=True,
            ),
        )

    def _section_nature(
        self, document: Document, retenus: list[dict[str, Any]], numero: _Numerotation
    ) -> None:
        if not retenus:
            return
        familles = Counter(i.get("family_label") or "Non qualifiée" for i in retenus)
        types = Counter(i.get("attack_code") or "" for i in retenus)
        gravites = Counter(i.get("severity") or "" for i in retenus)

        document.ajouter(
            Titre("Nature des menaces traitées", numero=numero()),
            Paragraphe(
                "Chaque intervention est rattachée à un type d'attaque du "
                "catalogue métier du Centre. Ce rattachement détermine la "
                "conduite à tenir : c'est le document métier qui commande, "
                "non l'appréciation du moment."
            ),
            Tableau(
                entetes=["Famille d'attaque", "Interventions", "Part"],
                alignements=["gauche", "droite", "droite"],
                lignes=[
                    [nom, str(n), _pourcent(n, len(retenus))]
                    for nom, n in familles.most_common()
                ],
                legende="Répartition par famille d'attaque",
            ),
            Graphique(
                "Interventions par famille d'attaque",
                [(nom, float(n)) for nom, n in familles.most_common()],
                unite="intervention",
            ),
        )

        lignes_types = [
            [code, _libelle_type(code), str(n)]
            for code, n in types.most_common()
            if code
        ]
        if lignes_types:
            document.ajouter(
                Tableau(
                    entetes=["Code", "Type d'attaque", "Interventions"],
                    alignements=["gauche", "gauche", "droite"],
                    lignes=lignes_types,
                    legende="Répartition par type du catalogue",
                )
            )

        lignes_gravite = [
            [langage.criticite(niveau).capitalize(), str(n), _pourcent(n, len(retenus))]
            for niveau, n in sorted(
                gravites.items(),
                key=lambda kv: -_rang_gravite(kv[0]),
            )
            if niveau
        ]
        if lignes_gravite:
            document.ajouter(
                Tableau(
                    entetes=["Gravité", "Interventions", "Part"],
                    alignements=["gauche", "droite", "droite"],
                    lignes=lignes_gravite,
                    legende="Répartition par gravité",
                )
            )

    def _section_interventions(
        self, document: Document, retenus: list[dict[str, Any]], numero: _Numerotation
    ) -> None:
        if not retenus:
            document.ajouter(
                Titre("Interventions", numero=numero()),
                Paragraphe(
                    "Aucune intervention n'entre dans le périmètre demandé. "
                    "Cette absence est un résultat : elle signifie que la "
                    "plateforme n'a rien eu à traiter qui corresponde aux "
                    "critères retenus, non qu'elle n'a pas fonctionné."
                ),
            )
            return

        ordonnes = sorted(retenus, key=lambda i: -float(i.get("risk_score") or 0))
        montres = ordonnes[:PLAFOND_LIGNES]
        document.ajouter(
            Titre("Interventions conduites", numero=numero()),
            Paragraphe(
                "Les interventions sont présentées par ordre d'enjeu "
                "décroissant. L'enjeu combine la gravité constatée, "
                "l'importance de la machine touchée, le nombre d'observations "
                "concordantes et la priorité fixée par le catalogue métier."
            ),
            Tableau(
                entetes=[
                    "Intervention",
                    "Nature",
                    "Gravité",
                    "État",
                    "Gestes",
                    "Annulés",
                ],
                alignements=["gauche", "gauche", "gauche", "gauche", "droite", "droite"],
                lignes=[
                    [
                        _numero_court(i.get("incident_id", "")),
                        i.get("attack_label") or "Menace non qualifiée",
                        langage.criticite(i.get("severity", "")).capitalize(),
                        langage.etat_incident(i.get("status", "")).capitalize(),
                        str(i.get("actions_executed", 0)),
                        str(i.get("actions_rolled_back", 0)),
                    ]
                    for i in montres
                ],
                legende="Interventions du périmètre, par ordre d'enjeu",
            ),
        )
        if len(ordonnes) > PLAFOND_LIGNES:
            document.ajouter(
                Paragraphe(
                    f"Le tableau ci-dessus présente les {PLAFOND_LIGNES} "
                    f"interventions les plus engageantes sur "
                    f"{len(ordonnes)} au total. Le détail complet est "
                    "consultable dans le portefeuille d'incidents de la "
                    "plateforme."
                )
            )

    def _section_gestes(
        self, document: Document, gestes: Counter[str], numero: _Numerotation
    ) -> None:
        if not gestes:
            return
        document.ajouter(
            Titre("Gestes appliqués sur les équipements", numero=numero()),
            Paragraphe(
                "Le tableau suivant recense les gestes que la plateforme a "
                "réellement appliqués, avec l'effet obtenu par chacun. Tous "
                "ont été appliqués sans accord préalable d'un agent, "
                "conformément à la posture retenue par le Centre."
            ),
            Tableau(
                entetes=["Geste", "Effet obtenu", "Nombre"],
                alignements=["gauche", "gauche", "droite"],
                lignes=[
                    [langage.geste(cle), langage.effet(cle) or "—", str(n)]
                    for cle, n in gestes.most_common()
                ],
                legende="Gestes appliqués et effet obtenu",
            ),
            Graphique(
                "Gestes les plus fréquemment appliqués",
                [(langage.geste(cle), float(n)) for cle, n in gestes.most_common(8)],
                unite="application",
            ),
        )

    def _section_abstentions(
        self, document: Document, faits: Any, numero: _Numerotation
    ) -> None:
        if not faits.refusals:
            return
        document.ajouter(
            Titre("Situations où la plateforme s'est abstenue", numero=numero()),
            Paragraphe(
                "Une abstention n'est pas une panne : c'est un garde-fou qui "
                "s'exerce. La plateforme s'interdit d'agir lorsqu'elle ne "
                "dispose pas d'un cas comparable documenté, lorsque les "
                "consignes de l'agence s'y opposent, ou lorsqu'aucun geste "
                "réversible ne convient à la situation."
            ),
            Tableau(
                entetes=["Motif de l'abstention", "Occurrences"],
                alignements=["gauche", "droite"],
                lignes=[
                    [motif.capitalize(), str(n)]
                    for motif, n in sorted(
                        faits.refusals.items(), key=lambda kv: -kv[1]
                    )
                ],
                legende="Abstentions par motif",
            ),
            Paragraphe(
                "Un nombre élevé d'abstentions faute de cas comparable "
                "documenté signale une documentation en retard sur les "
                "menaces observées. La réponse consiste à enrichir cette "
                "documentation, non à abaisser le niveau d'exigence de la "
                "plateforme."
            ),
        )

    def _section_tracabilite(
        self, document: Document, faits: Any, numero: _Numerotation
    ) -> None:
        document.ajouter(
            Titre("Traçabilité et intégrité du registre", numero=numero()),
            Paragraphe(
                "Chaque observation reçue, chaque décision prise et chaque "
                "geste appliqué est inscrit dans un registre dont les entrées "
                "sont chaînées entre elles. Modifier une entrée passée rompt "
                "la chaîne et devient visible immédiatement."
            ),
            Liste(
                [
                    f"Entrées inscrites sur la période : {faits.audit_entries}",
                    "État de la chaîne : "
                    + ("intacte" if faits.audit_chain_valid else "ROMPUE"),
                    f"Informations non encore acquittées par un agent : "
                    f"{faits.notifications_pending}",
                ]
            ),
        )
        if not faits.audit_chain_valid:
            document.ajouter(
                Encadre(
                    "Le registre a été altéré",
                    "La chaîne des entrées du registre est rompue : une "
                    "entrée a été modifiée en dehors de la plateforme. Il "
                    "s'agit d'un incident de sécurité portant sur la "
                    "plateforme elle-même, et non d'une anomalie de "
                    "fonctionnement. Le fichier de données doit être préservé "
                    "en l'état et une enquête ouverte.",
                    ton="alerte",
                )
            )

    def _section_conclusion(
        self,
        document: Document,
        faits: Any,
        retenus: list[dict[str, Any]],
        gestes: Counter[str],
        annulations: int,
        numero: _Numerotation,
    ) -> None:
        total = sum(gestes.values())
        if not retenus:
            appreciation = (
                "Aucune intervention n'a été nécessaire sur le périmètre "
                "demandé au cours de la période."
            )
        elif total and annulations / total > 0.3:
            appreciation = (
                "La proportion de gestes revenus en arrière est élevée. Elle "
                "invite à réexaminer les consignes de réponse applicables aux "
                "types d'attaque les plus fréquents de la période."
            )
        else:
            appreciation = (
                "La plateforme a traité les menaces qui lui ont été soumises "
                "en restant dans les limites fixées par les consignes de "
                "l'agence, et sans qu'une intervention humaine ait été "
                "nécessaire pour engager la réponse."
            )
        document.ajouter(
            Titre("Appréciation d'ensemble", numero=numero()),
            Paragraphe(appreciation),
            Paragraphe(
                "Le Centre reste destinataire de toute observation "
                "complémentaire susceptible d'enrichir la documentation de "
                "référence, dont dépend directement la capacité de la "
                "plateforme à répondre seule."
            ),
        )

    # ------------------------------------------- compte rendu d'intervention

    def _compte_rendu(self, document: Document, selection: Selection) -> None:
        incident = self._incidents.get(selection.valeur)
        if incident is None:
            raise LookupError(f"aucune intervention ne porte le numéro {selection.valeur}")

        donnees = incident.to_dict()
        actions = self._actions.for_incident(incident.incident_id)
        chronologie = self._ledger.incident_timeline(incident.incident_id)
        decisions = (
            self._decisions.for_incident(incident.incident_id) if self._decisions else []
        )
        numero = _Numerotation()

        self._cr_identification(document, donnees, numero)
        self._cr_observations(document, incident, numero)
        self._cr_decision(document, decisions, numero)
        self._cr_gestes(document, actions, numero)
        self._cr_chronologie(document, chronologie, numero)
        self._cr_conclusion(document, donnees, actions, numero)

    def _cr_identification(
        self, document: Document, donnees: dict[str, Any], numero: _Numerotation
    ) -> None:
        document.ajouter(
            Titre("Identification de l'intervention", numero=numero()),
            Paragraphe(
                "Le présent compte rendu retrace une intervention conduite "
                "par la plateforme automatisée de réponse aux incidents du "
                "Centre. Il est établi à partir du registre d'événements et "
                "peut être produit à l'appui d'une procédure."
            ),
            Tableau(
                entetes=["Élément", "Valeur"],
                lignes=[
                    [
                        "Numéro d'intervention",
                        _numero_court(donnees.get("incident_id", "")),
                    ],
                    ["Référence dans la plateforme", donnees.get("incident_id", "")],
                    ["Ouverte le", _date_longue(_lire_date(donnees.get("opened_at")))],
                    [
                        "Dernière évolution",
                        _date_longue(_lire_date(donnees.get("updated_at"))),
                    ],
                    [
                        "Nature de la menace",
                        donnees.get("attack_label") or "Menace non qualifiée",
                    ],
                    ["Famille d'attaque", donnees.get("family_label") or "—"],
                    [
                        "Gravité retenue",
                        langage.criticite(donnees.get("severity", "")).capitalize(),
                    ],
                    [
                        "Dangerosité",
                        f"{donnees.get('dangerousness', 0)}/10 "
                        f"({langage.dangerosite(float(donnees.get('dangerousness') or 0))})",
                    ],
                    [
                        "Traitement",
                        langage.priorite(donnees.get("priority", "")).capitalize()
                        if donnees.get("priority")
                        else "—",
                    ],
                    [
                        "État actuel",
                        langage.etat_incident(donnees.get("status", "")).capitalize(),
                    ],
                    [
                        "Importance de la machine touchée",
                        f"{donnees.get('asset_criticality', 3)} sur 5",
                    ],
                    ["Site", donnees.get("site_id", "")],
                ],
                legende="Fiche d'identification",
            ),
        )

    def _cr_observations(
        self, document: Document, incident: Any, numero: _Numerotation
    ) -> None:
        evenements = list(incident.events)
        document.ajouter(
            Titre("Ce qui a été observé", numero=numero()),
            Paragraphe(
                f"La plateforme a reçu "
                f"{langage.nombre(len(evenements), 'observation')} "
                "concordante(s) de la part des capteurs déployés. Ce sont ces "
                "observations, et elles seules, qui ont fondé la suite."
                if len(evenements) > 1
                else "La plateforme a reçu une observation d'un capteur "
                "déployé sur le réseau. C'est elle qui a fondé la suite."
            ),
        )
        if not evenements:
            return
        document.ajouter(
            Tableau(
                entetes=["Reçue le", "Source", "Nature signalée", "Machine", "Fiabilité"],
                lignes=[
                    [
                        _date_courte(_lire_date(_attribut(e, "received_at"))),
                        langage.source(str(_attribut(e, "source") or "")),
                        str(_attribut(e, "category") or "—"),
                        _machine(e),
                        f"{float(_attribut(e, 'confidence') or 0):.0%}",
                    ]
                    for e in evenements[:PLAFOND_LIGNES]
                ],
                legende="Observations reçues des capteurs",
            )
        )

    def _cr_decision(
        self, document: Document, decisions: list[dict[str, Any]], numero: _Numerotation
    ) -> None:
        document.ajouter(Titre("Ce que la plateforme a décidé", numero=numero()))
        if not decisions:
            document.ajouter(
                Paragraphe(
                    "Aucune décision formelle n'est enregistrée pour cette "
                    "intervention."
                )
            )
            return
        for decision in decisions:
            trace = decision.get("trace") or {}
            sources = trace.get("context_sources") or []
            document.ajouter(Paragraphe(_motif(decision)))
            if sources:
                document.ajouter(
                    Paragraphe(
                        "Cette décision s'appuie sur "
                        f"{langage.nombre(len(sources), 'cas comparable', 'cas comparables')} "
                        "issus de la documentation de référence du Centre. La "
                        "plateforme ne s'autorise à agir que lorsqu'elle "
                        "retrouve un précédent documenté ; à défaut, elle "
                        "s'abstient et alerte."
                    ),
                    Liste([_nom_de_source(s) for s in sources[:6]]),
                )
            ecartees = trace.get("rejected_actions") or []
            if ecartees:
                document.ajouter(
                    Paragraphe("Gestes envisagés puis écartés :"),
                    Liste(
                        [
                            f"{langage.geste(_cle_geste(r))} — "
                            f"{langage.motif_de_refus(str(r.get('reason', '')))}"
                            for r in ecartees[:8]
                        ]
                    ),
                )

    def _cr_gestes(
        self, document: Document, actions: list[Any], numero: _Numerotation
    ) -> None:
        document.ajouter(Titre("Gestes appliqués", numero=numero()))
        if not actions:
            document.ajouter(
                Paragraphe(
                    "Aucun geste n'a été appliqué sur les équipements dans le "
                    "cadre de cette intervention."
                )
            )
            return
        document.ajouter(
            Tableau(
                entetes=["Geste", "Cible", "Effet obtenu", "Issue", "Durée"],
                lignes=[
                    [
                        langage.geste(_cle_action(a)),
                        _cible(a),
                        langage.effet(_cle_action(a)) or "—",
                        langage.etat_action(_valeur(a.status)).capitalize(),
                        langage.duree(a.duration_ms),
                    ]
                    for a in actions
                ],
                legende="Gestes appliqués au cours de l'intervention",
            )
        )
        annulees = [a for a in actions if _valeur(a.status) == "rolled_back"]
        if annulees:
            document.ajouter(
                Paragraphe(
                    f"{langage.nombre(len(annulees), 'geste')} "
                    "a fait l'objet d'une annulation. L'annulation rétablit "
                    "l'équipement dans l'état où il se trouvait avant "
                    "l'intervention."
                ),
                Liste(
                    [
                        f"{langage.geste(_cle_action(a))} — annulé "
                        f"{_a_l_initiative(a)}"
                        + (f" ({a.rollback_reason})" if a.rollback_reason else "")
                        for a in annulees
                    ]
                ),
            )
        echecs = [a for a in actions if _valeur(a.status) in ("failed", "rollback_failed")]
        if echecs:
            document.ajouter(
                Encadre(
                    "Gestes n'ayant pas abouti",
                    f"{langage.nombre(len(echecs), 'geste')} n'a pas pu être "
                    "mené à son terme. Une vérification manuelle de l'état de "
                    "l'équipement concerné est nécessaire.",
                    ton="attention",
                )
            )

    def _cr_chronologie(
        self, document: Document, entrees: list[Any], numero: _Numerotation
    ) -> None:
        document.ajouter(
            Titre("Déroulement", numero=numero()),
            Paragraphe(
                "Le déroulement ci-dessous est extrait du registre de la "
                "plateforme. Il est présenté dans l'ordre où les faits se "
                "sont produits, sans reconstitution."
            ),
        )
        if not entrees:
            document.ajouter(Paragraphe("Le registre ne comporte aucune entrée."))
            return
        document.ajouter(
            Tableau(
                entetes=["Horodatage", "Ce qui s'est passé", "À l'initiative de"],
                lignes=[
                    [
                        _date_courte(_lire_date(e.recorded_at)),
                        langage.evenement(e.event_type),
                        langage.acteur(e.actor),
                    ]
                    for e in entrees
                ],
                legende="Déroulement des faits",
            )
        )

    def _cr_conclusion(
        self,
        document: Document,
        donnees: dict[str, Any],
        actions: list[Any],
        numero: _Numerotation,
    ) -> None:
        appliques = sum(1 for a in actions if _valeur(a.status) == "executed")
        etat = langage.etat_incident(donnees.get("status", ""))
        document.ajouter(
            Titre("Conclusion", numero=numero()),
            Paragraphe(
                f"À la date d'établissement du présent compte rendu, "
                f"l'intervention est {etat}. "
                + (
                    f"{langage.nombre(appliques, 'geste')} "
                    f"{'demeure' if appliques == 1 else 'demeurent'} en "
                    "vigueur sur les équipements."
                    if appliques
                    else "Aucun geste n'est actuellement maintenu sur les "
                    "équipements."
                )
            ),
            Paragraphe(
                "L'ensemble des éléments présentés est conservé dans le "
                "registre de la plateforme et peut être vérifié à tout moment."
            ),
        )

    # ------------------------------------------------------------- collecte

    def _incidents_du_perimetre(self, selection: Selection) -> list[dict[str, Any]]:
        """Le portefeuille, filtré par le périmètre *et* par la période.

        Le filtre de période s'applique sur la dernière évolution de
        l'intervention, pas sur son ouverture : une affaire ouverte il y a
        deux mois et sur laquelle la plateforme est intervenue hier appartient
        au rapport d'hier.
        """
        depuis = selection.depuis
        retenus: list[dict[str, Any]] = []
        for entree in self._portfolio.list(limit=1000):
            donnees = entree.to_dict()
            if not selection.retient(donnees):
                continue
            evolution = _lire_date(donnees.get("updated_at"))
            if evolution and evolution < depuis:
                continue
            retenus.append(donnees)
        return retenus

    def _gestes(self, retenus: list[dict[str, Any]]) -> tuple[Counter[str], int]:
        """Compte les gestes appliqués et ceux revenus en arrière.

        On lit les actions incident par incident plutôt que d'utiliser les
        compteurs globaux : un rapport thématique ne doit compter que les
        gestes de son périmètre.
        """
        gestes: Counter[str] = Counter()
        annulations = 0
        for incident in retenus:
            for action in self._actions.for_incident(incident.get("incident_id", "")):
                statut = _valeur(action.status)
                if statut in ("executed", "rolled_back"):
                    gestes[_cle_action(action)] += 1
                if statut == "rolled_back":
                    annulations += 1
        return gestes, annulations


class _Numerotation:
    """Numérotation romaine des parties, à la manière d'un acte administratif."""

    def __init__(self) -> None:
        self._n = 0

    def __call__(self) -> str:
        self._n += 1
        return ROMAINS[self._n - 1] if self._n <= len(ROMAINS) else str(self._n)


# ------------------------------------------------------------------ outils

_MOIS = (
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
)


def _date_longue(valeur: datetime | None) -> str:
    if valeur is None:
        return "date inconnue"
    return f"{valeur.day} {_MOIS[valeur.month - 1]} {valeur.year} à {valeur:%H h %M}"


def _date_courte(valeur: datetime | None) -> str:
    return valeur.strftime("%d/%m/%Y %H:%M") if valeur else "—"


def _lire_date(valeur: Any) -> datetime | None:
    if isinstance(valeur, datetime):
        return valeur if valeur.tzinfo else valeur.replace(tzinfo=UTC)
    if not valeur:
        return None
    try:
        lue = datetime.fromisoformat(str(valeur))
    except ValueError:
        return None
    return lue if lue.tzinfo else lue.replace(tzinfo=UTC)


def _valeur(brut: Any) -> str:
    """Un statut peut arriver en énumération ou en chaîne selon la source."""
    return getattr(brut, "value", brut) or ""


def _attribut(objet: Any, nom: str) -> Any:
    if isinstance(objet, dict):
        return objet.get(nom)
    return getattr(objet, nom, None)


def _machine(evenement: Any) -> str:
    asset = _attribut(evenement, "asset")
    if asset is None:
        return "—"
    for champ in ("hostname", "ip", "asset_id", "user"):
        valeur = _attribut(asset, champ)
        if valeur:
            return str(valeur)
    return "—"


def _cle_action(action: Any) -> str:
    spec = _attribut(action, "spec")
    if spec is None:
        return str(_attribut(action, "verb") or "")
    return f"{_attribut(spec, 'actuator')}:{_attribut(spec, 'verb')}"


def _cle_geste(rejet: dict[str, Any]) -> str:
    """Un geste écarté est tracé sous la forme « actuateur:verbe » ou juste
    « verbe » selon l'ancienneté de l'entrée."""
    for champ in ("action", "key", "verb"):
        valeur = rejet.get(champ)
        if valeur:
            return str(valeur)
    return ""


def _cible(action: Any) -> str:
    spec = _attribut(action, "spec")
    return str(_attribut(spec, "target") or "—") if spec else "—"


def _a_l_initiative(action: Any) -> str:
    acteur = str(_attribut(action, "rollback_actor") or "")
    return f"par {langage.acteur(acteur)}" if acteur else "automatiquement"


def _motif(decision: dict[str, Any]) -> str:
    """Rédige le motif d'une décision à partir de ses données structurées.

    Le moteur produit par ailleurs un motif technique — identifiant de
    playbook, codes de règles, empreinte de politique — destiné au journal
    d'audit et à la contestation. Il a sa place dans le registre, pas dans un
    document que lit un directeur : on reformule ici les mêmes faits.
    """
    classification = decision.get("classification") or {}
    trace = decision.get("trace") or {}
    phrases = [langage.issue(decision.get("outcome", "")) + "."]

    if classification.get("label"):
        phrases.append(
            f"La menace a été reconnue comme relevant de « "
            f"{classification['label']} », de gravité "
            f"{langage.criticite(str(classification.get('severity', '')))}"
            + (
                f" et de dangerosité {classification['dangerousness']}/10 "
                f"({langage.dangerosite(float(classification['dangerousness']))})"
                if classification.get("dangerousness") is not None
                else ""
            )
            + "."
        )

    retenues = len(decision.get("actions") or [])
    if retenues:
        phrases.append(
            f"La conduite à tenir prévue pour ce type de menace comportait "
            f"{langage.nombre(retenues, 'geste')}, que les consignes de "
            "l'agence ont autorisé."
        )
    ecartees = trace.get("rejected_actions") or []
    if ecartees:
        phrases.append(
            f"{langage.nombre(len(ecartees), 'autre geste', 'autres gestes')} "
            "a été écarté avant toute application."
        )
    return " ".join(phrases)


def _nom_de_source(chemin: str) -> str:
    """« knowledge/exfiltration.md » devient « Fiche de référence Exfiltration ».

    Le lecteur doit comprendre qu'on lui cite un document, pas un fichier.
    """
    nom = str(chemin).replace("\\", "/").rsplit("/", 1)[-1]
    nom = nom.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").strip()
    return f"Fiche de référence « {nom.capitalize()} »" if nom else str(chemin)


def _numero_court(incident_id: str) -> str:
    return langage.numero_intervention(incident_id)


def _libelle_type(code: str) -> str:
    attaque = BY_CODE.get(code)
    return attaque.label if attaque else "Type appris en exploitation"


def _rang_gravite(niveau: str) -> int:
    echelle = ("info", "low", "medium", "high", "critical")
    return echelle.index(niveau) if niveau in echelle else -1


def _pourcent(part: int, total: int) -> str:
    return f"{part / total:.0%}" if total else "—"


def _phrase_de_perimetre(selection: Selection, combien: int) -> str:
    """Dit en une phrase ce que le rapport couvre — et ce qu'il ne couvre pas.

    Un rapport thématique donne des chiffres partiels ; le lecteur doit le
    savoir dès la première page, sans quoi il les prendra pour le tout.
    """
    quantite = langage.nombre(combien, "intervention")
    match selection.perimetre:
        case Perimetre.FAMILLE:
            return (
                f"Il porte exclusivement sur les attaques de la famille "
                f"retenue et recense {quantite}. Les menaces d'autres "
                "familles survenues sur la même période n'y figurent pas."
            )
        case Perimetre.CRITICITE:
            return (
                f"Il porte exclusivement sur les interventions atteignant le "
                f"niveau de gravité retenu et recense {quantite}. Les "
                "interventions de moindre gravité n'y figurent pas."
            )
        case Perimetre.TYPE:
            return (
                f"Il porte exclusivement sur un type d'attaque du catalogue "
                f"métier et recense {quantite}. Les autres types survenus sur "
                "la même période n'y figurent pas."
            )
        case _:
            return (
                f"Il couvre l'ensemble de l'activité de la période, soit "
                f"{quantite}."
            )
