"""Assistant conversationnel adosse aux faits.

La reconnaissance d'intention est **déterministe** : un ensemble ferme de
questions reconnues, chacune servie par une collecte de faits précise. C'est
un choix, pas une limitation technique — il garantit qu'une même question
donne la même réponse, et qu'aucune question ne reçoit une réponse fabriquée.

Une question non reconnue est déclarée telle quelle, avec la liste de ce que
l'assistant sait faire. Le modèle de langage, quand il est configuré,
intervient uniquement pour la mise en forme, jamais pour produire un fait.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..domain.taxonomy import BY_CODE, CATALOG, AttackFamily
from ..llm import LlmProvider, OfflineProvider
from .conversation import Conversation, MemoireDesConversations, Raisonnement, Tour
from .facts import FactCollector, OperationsFacts


class Intent(StrEnum):
    # -- registre social : converser, ce n'est pas seulement repondre --------
    GREETING = "salutation"
    THANKS = "remerciement"
    FAREWELL = "conge"
    IDENTITY = "identite"
    CAPABILITIES = "capacites"
    FOLLOW_UP = "suivi"
    # -- registre metier -----------------------------------------------------
    SIMULATE = "simulation"
    DAILY_BRIEF = "bilan_du_jour"
    PERIOD_BRIEF = "bilan_periode"
    INCIDENT_DETAIL = "detail_incident"
    STATISTICS = "statistiques"
    CATALOG = "catalogue"
    POSTURE = "posture"
    REFUSALS = "refus"
    ROLLBACKS = "annulations"
    REPORT = "rapport"
    UNKNOWN = "inconnu"


@dataclass(slots=True)
class Answer:
    intent: Intent
    text: str
    facts: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    """Origine des chiffrés cités : journal, portefeuille, catalogue."""
    provider: str = "offline"
    reasoning: list[dict[str, str]] = field(default_factory=list)
    """Comment cette réponse a été construite, étape par étape."""
    follow_ups: list[str] = field(default_factory=list)
    """Suites proposées, tirées de l'état réel et non d'une liste figée."""
    hours: int = 0
    period_label: str = ""
    incident_id: str = ""
    action: dict[str, Any] | None = None
    """Effet demandé par la question, à exécuter par l'appelant.

    L'assistant reconnaît l'intention, il n'agit pas lui-même : c'est la route
    qui déclenche, journalise et rend le résultat. Cette séparation garantit
    qu'aucun texte produit par un modèle ne se retrouve sur le chemin d'une
    action — le verbe et sa cible viennent d'un motif, jamais d'une phrase
    générée.
    """

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent.value,
            "text": self.text,
            "facts": self.facts,
            "sources": self.sources,
            "provider": self.provider,
            "reasoning": self.reasoning,
            "follow_ups": self.follow_ups,
            "hours": self.hours,
            "period_label": self.period_label,
            "action": self.action,
        }


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


# Motifs reconnus. L'ordre compte : le premier qui correspond l'emporte, donc
# les intentions les plus spécifiques sont placees en tête.
PATTERNS: tuple[tuple[Intent, tuple[str, ...]], ...] = (
    (Intent.INCIDENT_DETAIL, (r"\binc_[0-9a-f]{6,}\b",)),
    (
        Intent.GREETING,
        (
            r"^\s*(bonjour|bonsoir|salut|coucou|hello|hey|yo|bjr)\b",
            r"^\s*(bien le bonjour|comment (ca|allez).?vous|ca va)\b",
        ),
    ),
    (Intent.THANKS, (r"^\s*(merci|thanks|nickel|parfait|super|tres bien)\b", r"\bmerci\b")),
    (
        Intent.FAREWELL,
        (r"^\s*(au revoir|a bientot|bonne (journee|soiree|nuit)|bye|ciao|a plus)\b",),
    ),
    (
        Intent.IDENTITY,
        (
            r"\bqui\s+(es|est).?tu\b",
            r"\btu\s+es\s+qui\b",
            r"\bpresente.?toi\b",
            r"\bton\s+role\b",
            r"\bc'?est\s+quoi\s+cette\s+plateforme\b",
        ),
    ),
    (
        Intent.CAPABILITIES,
        (
            r"\bque\s+(sais|peux).?tu\s+faire\b",
            r"\bqu'?est.ce\s+que\s+tu\s+sais\s+faire\b",
            r"\bcomment\s+(tu\s+marches|ca\s+marche|t'?utiliser)\b",
            r"^\s*aide\b",
            r"^\s*help\b",
            r"\btes\s+capacites\b",
        ),
    ),
    (
        Intent.SIMULATE,
        (
            r"\b(declenche|declencher|lance|lancer|simule|simuler|joue|jouer)\b[^.]*"
            r"\b(simulation|scenario|attaque|incident|demonstration)\b",
            r"\bsimulation\b[^.]*\b(de|d\')\s*(attaque|incident)\b",
            r"\bsimule\b",
        ),
    ),
    (Intent.REPORT, (r"\brapport\b", r"\bgenere[rz]?\s+un\s+rapport\b", r"\bexport")),
    (Intent.REFUSALS, (r"\brefus", r"n'?a\s+(pas|rien)\s+(agi|fait)", r"pourquoi.*rien")),
    (Intent.ROLLBACKS, (r"\bannul", r"\brollback\b", r"\bretour\s+arriere\b")),
    (
        Intent.CATALOG,
        (
            r"\bcatalogue\b",
            r"\bquels?\s+types?\b",
            r"\bque\s+sais.tu\s+traiter\b",
            r"\btypes?\s+d'?attaques?\b",
        ),
    ),
    (
        Intent.POSTURE,
        (
            r"\bposture\b",
            r"\bcoupe.circuit\b",
            r"\betat\s+du\s+systeme\b",
            r"\bautonomie\b",
            r"\bmode\b",
        ),
    ),
    (
        Intent.DAILY_BRIEF,
        (
            r"\bbilan\b",
            r"\bresume\b",
            r"\bjournee\b",
            r"\baujourd'?hui\b",
            r"\bquoi\s+de\s+neuf\b",
            r"\bope?rations?\s+du\s+jour\b",
        ),
    ),
    (
        Intent.STATISTICS,
        (r"\bstatistiques?\b", r"\bchiffres?\b", r"\bcombien\b", r"\bindicateurs?\b"),
    ),
)

# Une question de suivi ne se reconnait pas a un mot-cle metier mais a sa
# forme : elle est courte, souvent introduite par « et », et renvoie a ce qui
# vient d'etre dit. Hors conversation elle n'a aucun sens ; c'est pourquoi
# elle n'entre pas dans PATTERNS et n'est testee qu'avec un fil ouvert.
_LIBELLE_INTENT: dict[Intent, str] = {
    Intent.DAILY_BRIEF: "bilan des opérations",
    Intent.PERIOD_BRIEF: "bilan sur une période",
    Intent.STATISTICS: "statistiques",
    Intent.POSTURE: "posture d'autonomie",
    Intent.REFUSALS: "refus d'agir",
    Intent.ROLLBACKS: "annulations",
    Intent.REPORT: "rapport d'opérations",
    Intent.CATALOG: "catalogue des attaques",
    Intent.INCIDENT_DETAIL: "détail d'un incident",
    Intent.SIMULATE: "déclenchement d'une simulation",
    Intent.GREETING: "salutation",
    Intent.THANKS: "remerciement",
    Intent.FAREWELL: "prise de congé",
    Intent.IDENTITY: "présentation",
    Intent.CAPABILITIES: "capacités",
    Intent.UNKNOWN: "hors périmètre",
}

# Seules les intentions metier portent un contenu qu'une question de suivi
# peut prolonger. « et sur sept jours ? » apres un bonjour ne veut rien dire :
# heriter d'une salutation ferait repondre a cote avec aplomb.
_HERITABLES = frozenset(
    {
        Intent.DAILY_BRIEF,
        Intent.PERIOD_BRIEF,
        Intent.STATISTICS,
        Intent.POSTURE,
        Intent.REFUSALS,
        Intent.ROLLBACKS,
        Intent.REPORT,
        Intent.CATALOG,
        Intent.INCIDENT_DETAIL,
    }
)

_AVEC_PERIODE = frozenset(
    {
        Intent.DAILY_BRIEF,
        Intent.PERIOD_BRIEF,
        Intent.STATISTICS,
        Intent.REFUSALS,
        Intent.ROLLBACKS,
        Intent.REPORT,
    }
)

SUIVI = (
    r"^\s*et\b",
    r"^\s*(detaille|precise|explique|developpe|continue|encore|pourquoi|comment)\b",
    r"\b(plus\s+de\s+detail|en\s+detail|davantage)\b",
    r"^\s*(oui|ok|d'?accord|vas.?y|je\s+veux\s+bien|volontiers)\b",
)


def _est_un_suivi(folded: str) -> bool:
    return any(re.search(motif, folded) for motif in SUIVI)


def _pourquoi(intent: Intent, folded: str) -> str:
    """L'indice qui a fait basculer la reconnaissance.

    Montrer le mot declencheur vaut mieux qu'annoncer une intention : on peut
    contester « j'ai lu *bilan* » ; on ne peut pas contester « j'ai compris ».
    """
    for candidate, motifs in PATTERNS:
        if candidate is not intent:
            continue
        for motif in motifs:
            trouve = re.search(motif, folded)
            if trouve:
                extrait = trouve.group(0).strip()
                return (
                    f"« {extrait} » reconnu → {_LIBELLE_INTENT.get(intent, intent.value)}"
                    if extrait
                    else _LIBELLE_INTENT.get(intent, intent.value)
                )
    if intent is Intent.UNKNOWN:
        return "aucun motif connu dans la question"
    return _LIBELLE_INTENT.get(intent, intent.value)


_PERIODE = re.compile(r"(\d{1,3})\s*(heure|jour|semaine)")
_CODE = re.compile(r"\b([abcd])\s?-?\s?([1-9])\b")

# Le catalogue est rédigé avec les termes du métier, souvent anglais. Un
# analyste demande « un rançongiciel », pas « un ransomware » : sans ces
# synonymes l'assistant refuserait une demande parfaitement claire.
SYNONYMES: dict[str, str] = {
    "rancongiciel": "A6",
    "ranconlogiciel": "A6",
    "cryptolocker": "A6",
    "deni de service": "A1",
    "saturation": "A1",
    "inondation": "A1",
    "slowloris": "A2",
    "balayage": "A3",
    "reconnaissance": "A3",
    "force brute": "A4",
    "bourrage": "A4",
    "fuite de donnees": "A5",
    "vol de donnees": "A5",
    "commande et controle": "A7",
    "beaconing": "A7",
    "injection": "B1",
    "script intersites": "B2",
    "execution de code": "B3",
    "traversee de repertoire": "B4",
    "remontee de repertoire": "B4",
    "webshell": "B5",
    "fichier malveillant": "B5",
    "abus d api": "B6",
    "detournement de session": "B7",
    "vol de session": "B7",
    "elevation de privilege": "C1",
    "escalade de privilege": "C1",
    "hors profil": "C2",
    "exfiltration lente": "C3",
    "compte compromis": "C4",
    "certificat": "D1",
    "port ouvert": "D2",
    "port inattendu": "D2",
    "service indisponible": "D3",
    "panne": "D3",
    "derive de configuration": "D4",
    "derive": "D4",
    # Sigles du métier : courts mais sans ambiguïté, à condition de les
    # chercher comme des mots entiers — « api » ne doit pas se reconnaître
    # dans « rapide ».
    "ddos": "A1",
    "scan": "A3",
    "c2": "A7",
    "sql": "B1",
    "xss": "B2",
    "rce": "B3",
    "lfi": "B4",
    "rfi": "B4",
    "api": "B6",
    "tls": "D1",
    "drift": "D4",
}


def _code_de_scenario(folded: str) -> str | None:
    """Le code explicite prime ; sinon le libellé le plus long qui correspond.

    Trier par longueur évite qu'« exfiltration » l'emporte sur « exfiltration
    lente » quand les deux figurent dans la phrase.
    """
    match = _CODE.search(folded)
    if match:
        code = f"{match.group(1).upper()}{match.group(2)}"
        if code in BY_CODE:
            return code

    candidats = [
        (len(terme), code)
        for terme, code in SYNONYMES.items()
        if re.search(rf"\b{re.escape(terme)}\b", folded)
    ]
    for attaque in CATALOG:
        for terme in _termes(attaque.label) + _termes(attaque.category):
            if len(terme) > 4 and terme in folded:
                candidats.append((len(terme), attaque.code))
    if not candidats:
        return None
    # Le terme le plus long l'emporte ; à longueur égale, le code le plus bas,
    # c'est-à-dire l'entrée la plus générale du catalogue. « exfiltration »
    # seul désigne A5, pas C3 qui en est le cas particulier lent.
    candidats.sort(key=lambda c: (-c[0], c[1]))
    return candidats[0][1]


def _termes(libelle: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", _fold(libelle)) if t]


def _famille_demandee(folded: str) -> str | None:
    for famille in AttackFamily:
        if _fold(famille.label) in folded:
            return famille.code
    match = re.search(r"\bfamille\s+([abcd])\b", folded)
    return match.group(1).upper() if match else None


class AssistantService:
    def __init__(
        self,
        collector: FactCollector,
        provider: LlmProvider | None = None,
    ) -> None:
        self._collector = collector
        self._provider = provider or OfflineProvider()
        self._memoire = MemoireDesConversations()

    def oublier(self, conversation_id: str) -> bool:
        """Efface un fil. Le journal d'audit, lui, ne s'efface pas."""
        return self._memoire.oublier(conversation_id)

    # -- point d'entrée ------------------------------------------------------

    def ask(self, question: str, conversation_id: str | None = None) -> Answer:
        """Répond en tenant le fil, et en montrant comment la réponse se construit."""
        fil = self._memoire.obtenir(conversation_id)
        folded = _fold(question)
        trace = Raisonnement()

        intent = self._detect(folded)
        # La forme de la question et son intention sont deux choses distinctes :
        # « et les annulations ? » est reconnue d'emblee, et reste malgre tout
        # un suivi — c'est ce qui lui fait heriter la periode du tour precedent.
        suivi = not fil.vide and _est_un_suivi(folded)
        if intent is Intent.UNKNOWN and suivi:
            # « et sur sept jours ? » n'a de sens que rapporte au tour
            # precedent. Sans le fil, l'assistant declarerait ne pas comprendre
            # une question parfaitement claire pour son interlocuteur.
            precedente = fil.derniere_intention()
            heritee = Intent(precedente) if precedente else Intent.UNKNOWN
            if heritee in _HERITABLES:
                intent = heritee
                trace.ajouter(
                    "Question de suivi",
                    f"« {question.strip()} » se rattache au tour précédent "
                    f"({_LIBELLE_INTENT.get(intent, intent.value)})",
                )
            elif _PERIODE.search(folded):
                # Le tour precedent ne se prolonge pas, mais la question porte
                # une periode : c'est un bilan qu'on demande.
                intent = Intent.PERIOD_BRIEF
                trace.ajouter(
                    "Question de suivi",
                    "le tour précédent ne se prolonge pas, mais une période est "
                    "indiquée → bilan sur cette période",
                )

        if not trace:
            trace.ajouter("Intention reconnue", _pourquoi(intent, folded))

        hours, label, herite = self._periode_avec_fil(folded, fil, suivi=suivi)
        if intent in _AVEC_PERIODE:
            trace.ajouter(
                "Période retenue",
                f"{label}"
                + (
                    " — reprise du tour précédent"
                    if herite
                    else (" — lue dans la question" if _PERIODE.search(folded) else " par défaut")
                ),
            )

        reponse = self._repondre(intent, question, folded, hours, label, fil, trace)
        reponse.reasoning = trace.to_list()
        reponse.hours, reponse.period_label = hours, label

        fil.ajouter(Tour(role="humain", texte=question))
        fil.ajouter(
            Tour(
                role="assistant",
                texte=reponse.text,
                intent=reponse.intent.value,
                hours=reponse.hours if reponse.intent in _AVEC_PERIODE else 0,
                label=reponse.period_label,
                incident_id=reponse.incident_id,
            )
        )
        return reponse

    def _repondre(
        self,
        intent: Intent,
        question: str,
        folded: str,
        hours: int,
        label: str,
        fil: Conversation,
        trace: Raisonnement,
    ) -> Answer:
        match intent:
            case Intent.GREETING:
                return self._salutation(fil, trace)
            case Intent.THANKS:
                return self._remerciement(trace)
            case Intent.FAREWELL:
                return self._conge(fil, trace)
            case Intent.IDENTITY:
                return self._identite(trace)
            case Intent.CAPABILITIES:
                return self._capacites(trace)
            case Intent.SIMULATE:
                return self._simulation(question, folded)
            case Intent.INCIDENT_DETAIL:
                return self._incident(question, folded, fil)
            case Intent.CATALOG:
                return self._catalog(question)
            case Intent.UNKNOWN:
                return self._unknown(question, fil)
            case _:
                trace.ajouter(
                    "Collecte des faits",
                    "journal d'audit, portefeuille d'incidents, état du coupe-circuit",
                )
                facts = self._collector.collect(hours=hours, label=label)
                trace.ajouter(
                    "Faits obtenus",
                    f"{facts.incidents_total} incident(s), "
                    f"{facts.actions_executed} action(s), "
                    f"{facts.audit_entries} entrée(s) de journal",
                )
                trace.ajouter(
                    "Vérification",
                    "chaîne d'audit intacte"
                    if facts.audit_chain_valid
                    else "chaîne d'audit ROMPUE — signalé dans la réponse",
                )
                return self._compose(intent, question, facts, trace)

    def _periode_avec_fil(
        self, folded: str, fil: Conversation, *, suivi: bool
    ) -> tuple[int, str, bool]:
        """La période lue dans la question prime ; le fil ne sert qu'au suivi.

        Une question posée en entier tient seule : « fais le bilan du jour »
        veut dire aujourd'hui, même si le tour précédent parlait de sept jours.
        Seule une question de suivi — « et les annulations ? » — hérite de la
        période, puisque c'est précisément ce à quoi elle se rattache.
        """
        if _PERIODE.search(folded):
            heures, libelle = self._period(folded)
            return heures, libelle, False
        if suivi:
            heritee = fil.derniere_periode()
            if heritee:
                return heritee[0], heritee[1], True
        return 24, "dernières 24 heures", False

    def daily_brief(self) -> Answer:
        """Bilan des opérations du jour — l'usage principal de l'assistant."""
        facts = self._collector.collect(hours=24, label="dernières 24 heures")
        return self._compose(Intent.DAILY_BRIEF, "Bilan des opérations du jour", facts)

    def suggestions(self) -> list[str]:
        return [
            "Fais le bilan des opérations du jour",
            "Déclenche une simulation de rançongiciel",
            "Génère un rapport des opérations sur 7 jours",
            "Montre les statistiques des dernières opérations",
            "Combien d'actions ont été annulées ?",
            "Quels types d'attaques sais-tu traiter ?",
        ]

    # -- registre social -----------------------------------------------------
    #
    # Repondre « bonjour » a un bonjour ne coute rien et change tout : un outil
    # qui ignore la politesse se fait obeir, il ne se fait pas consulter. Ces
    # reponses restent pourtant ancrees — elles ne racontent que ce que la
    # plateforme sait, jamais une amabilite creuse.

    def _salutation(self, fil: Conversation, trace: Raisonnement) -> Answer:
        trace.ajouter("Registre", "salutation — réponse conviviale, puis état courant")
        trace.ajouter("Collecte des faits", "relevé rapide des dernières 24 heures")
        faits = self._collector.collect(hours=24, label="dernières 24 heures")

        if fil.nombre_echanges() > 0:
            ouverture = "Re-bonjour."
        else:
            ouverture = "Bonjour. Je suis l'assistant d'exploitation de la plateforme."

        if faits.incidents_total == 0:
            etat = "Rien à signaler sur les dernières 24 heures : aucun incident traité."
        else:
            etat = (
                f"Sur les dernières 24 heures : **{faits.incidents_total} incident(s)** "
                f"traité(s) et **{faits.actions_executed} action(s)** exécutée(s) "
                "sans validation préalable."
            )
            if faits.actions_rolled_back:
                etat += f" {faits.actions_rolled_back} action(s) ont été annulées."

        if not faits.autonomy_effective:
            etat += (
                "\n\n⚠️ L'autonomie est actuellement suspendue : aucune action "
                "n'est exécutée jusqu'au réarmement."
            )

        return Answer(
            intent=Intent.GREETING,
            text=f"{ouverture}\n\n{etat}\n\nQue puis-je faire pour vous ?",
            facts=faits.to_dict(),
            sources=["portefeuille d'incidents", "journal d'audit"],
            provider=self._provider.name,
            follow_ups=self._suites(faits),
        )

    def _remerciement(self, trace: Raisonnement) -> Answer:
        trace.ajouter("Registre", "remerciement — accusé bref, sans relance inutile")
        return Answer(
            intent=Intent.THANKS,
            text="Avec plaisir. Je reste disponible si vous voulez creuser un point.",
            provider=self._provider.name,
        )

    def _conge(self, fil: Conversation, trace: Raisonnement) -> Answer:
        trace.ajouter("Registre", "prise de congé — récapitulatif de la séance")
        echanges = fil.nombre_echanges()
        recap = (
            f"Nous avons échangé sur {echanges} point(s) durant cette séance. "
            if echanges > 1
            else ""
        )
        return Answer(
            intent=Intent.FAREWELL,
            text=(
                f"Bonne continuation. {recap}La plateforme continue de traiter les "
                "incidents en autonomie ; vous retrouverez chaque action au journal "
                "d'audit à votre retour."
            ),
            provider=self._provider.name,
        )

    def _identite(self, trace: Raisonnement) -> Answer:
        trace.ajouter("Registre", "présentation — rôle et limites")
        return Answer(
            intent=Intent.IDENTITY,
            text=(
                "Je suis l'assistant d'exploitation de CIRTDEFENSE, une plateforme "
                "d'orchestration autonome de la réponse aux incidents de sécurité.\n\n"
                "Concrètement : la plateforme détecte, décide et agit seule ; moi, "
                "je vous explique ce qu'elle a fait et pourquoi, et je déclenche "
                "certaines opérations quand vous me le demandez.\n\n"
                "Une limite que je tiens à poser d'emblée : **je ne réponds qu'à "
                "partir des données de la plateforme** — journal d'audit, "
                "portefeuille d'incidents, catalogue CIRT. Si un chiffre n'y figure "
                "pas, je vous le dis plutôt que de le combler. Un nombre inventé "
                "dans un bilan de sécurité vous ferait croire informé alors que "
                "vous ne le seriez pas."
            ),
            sources=["configuration de la plateforme"],
            provider=self._provider.name,
            follow_ups=["Que sais-tu faire ?", "Fais le bilan des opérations du jour"],
        )

    def _capacites(self, trace: Raisonnement) -> Answer:
        trace.ajouter("Registre", "capacités — ce que je sais faire, par famille")
        return Answer(
            intent=Intent.CAPABILITIES,
            text=(
                "Voici ce que je sais faire.\n\n"
                "**Rendre compte**\n"
                "- le bilan des opérations du jour, ou sur la période que vous fixez\n"
                "- les statistiques : incidents, actions, taux d'annulation\n"
                "- la posture d'autonomie et l'état du coupe-circuit\n"
                "- le détail d'un incident, si vous me donnez son identifiant\n\n"
                "**Expliquer**\n"
                "- pourquoi le système a refusé d'agir\n"
                "- quelles actions ont été annulées, et par qui\n"
                "- quels types d'attaques figurent au catalogue CIRT\n\n"
                "**Agir**\n"
                "- déclencher une simulation, par code (« lance A6 »), par nom "
                "(« simule un rançongiciel ») ou par famille\n"
                "- générer un rapport d'opérations exportable\n\n"
                "Posez la question comme elle vous vient : je comprends les "
                "reformulations et les questions de suivi."
            ),
            provider=self._provider.name,
            follow_ups=[
                "Fais le bilan des opérations du jour",
                "Déclenche une simulation de rançongiciel",
                "Quelle est la posture d'autonomie actuelle ?",
            ],
        )

    # -- suites proposées ----------------------------------------------------

    def _suites(self, f: OperationsFacts) -> list[str]:
        """Suggestions tirées de l'état réel, pas d'une liste figée.

        Proposer « voulez-vous le détail des annulations ? » quand il n'y en a
        eu aucune serait du bavardage. Chaque suite ci-dessous n'apparaît que
        si l'état l'a rendue pertinente.
        """
        suites: list[str] = []
        if f.actions_rolled_back:
            suites.append("Pourquoi ces actions ont-elles été annulées ?")
        if f.refusals:
            suites.append("Pourquoi le système a-t-il refusé d'agir ?")
        if not f.audit_chain_valid:
            suites.append("Détaille la rupture de la chaîne d'audit")
        if not f.autonomy_effective:
            suites.append("Quelle est la posture d'autonomie actuelle ?")
        if f.incidents_total == 0:
            suites.append("Déclenche une simulation de rançongiciel")
        else:
            suites.append("Montre les statistiques des dernières opérations")
        suites.append("Génère un rapport des opérations sur 7 jours")
        return suites[:3]

    # -- effets demandés -----------------------------------------------------

    def _simulation(self, question: str, folded: str) -> Answer:
        """Reconnaît quelle simulation est demandée, sans la déclencher.

        Trois formulations sont acceptées : un code de catalogue (« lance A6 »),
        un nom d'attaque (« simule un rançongiciel »), ou une famille
        (« simule les attaques réseau »). À défaut, l'assistant demande de
        préciser plutôt que de choisir un scénario au hasard.
        """
        code = _code_de_scenario(folded)
        if code:
            attaque = BY_CODE[code]
            return Answer(
                intent=Intent.SIMULATE,
                text=(
                    f"Je déclenche le scénario **{code} — {attaque.label}**.\n\n"
                    "La charge utile envoyée est celle qu'un collecteur produirait pour "
                    "cette attaque ; la plateforme la traite comme une alerte réelle."
                ),
                sources=["catalogue CIRT"],
                action={"kind": "run_scenario", "code": code},
            )

        famille = _famille_demandee(folded)
        if famille:
            return Answer(
                intent=Intent.SIMULATE,
                text=f"Je déclenche l'ensemble des scénarios de la famille **{famille}**.",
                sources=["catalogue CIRT"],
                action={"kind": "run_family", "family": famille},
            )

        if re.search(r"\b(tout|tous|toutes|catalogue|22)\b", folded):
            return Answer(
                intent=Intent.SIMULATE,
                text="Je déclenche les 22 scénarios du catalogue, famille par famille.",
                sources=["catalogue CIRT"],
                action={"kind": "run_all"},
            )

        exemples = ", ".join(f"{a.code} ({a.label.split(' (')[0]})" for a in CATALOG[:4])
        return Answer(
            intent=Intent.SIMULATE,
            text=(
                "Je peux déclencher une simulation, mais il me faut savoir laquelle.\n\n"
                f"Indiquez un code du catalogue — {exemples}… — un nom d'attaque "
                "(« rançongiciel », « injection SQL »), une famille (A, B, C ou D), "
                "ou « tout le catalogue »."
            ),
            sources=["catalogue CIRT"],
        )

    # -- reconnaissance ------------------------------------------------------

    @staticmethod
    def _detect(folded: str) -> Intent:
        for intent, motifs in PATTERNS:
            if any(re.search(m, folded) for m in motifs):
                return intent
        return Intent.UNKNOWN

    @staticmethod
    def _period(folded: str) -> tuple[int, str]:
        match = _PERIODE.search(folded)
        if not match:
            return 24, "dernières 24 heures"
        quantite, unite = int(match.group(1)), match.group(2)
        heures = {"heure": 1, "jour": 24, "semaine": 168}[unite] * quantite
        pluriel = "s" if quantite > 1 else ""
        return heures, f"{quantite} {unite}{pluriel}"

    # -- rédaction -----------------------------------------------------------

    def _compose(
        self,
        intent: Intent,
        question: str,
        facts: OperationsFacts,
        trace: Raisonnement | None = None,
    ) -> Answer:
        rendu = {
            Intent.DAILY_BRIEF: self._texte_bilan,
            Intent.PERIOD_BRIEF: self._texte_bilan,
            Intent.STATISTICS: self._texte_statistiques,
            Intent.POSTURE: self._texte_posture,
            Intent.REFUSALS: self._texte_refus,
            Intent.ROLLBACKS: self._texte_annulations,
            Intent.REPORT: self._texte_bilan,
        }[intent](facts)

        payload = facts.to_dict()
        texte = self._provider.render(question, payload, rendu)
        if trace is not None:
            trace.ajouter(
                "Rédaction",
                "hors ligne, déterministe"
                if self._provider.name == "offline"
                else (
                    f"mise en forme par {self._provider.name} — les chiffres restent ceux collectés"
                ),
            )
        return Answer(
            intent=intent,
            text=texte,
            facts=payload,
            sources=["journal d'audit", "portefeuille d'incidents"],
            provider=self._provider.name,
            follow_ups=self._suites(facts),
        )

    @staticmethod
    def _texte_bilan(f: OperationsFacts) -> str:
        lignes = [f"**Bilan des opérations — {f.period_label}**", ""]

        if not f.incidents_total:
            lignes += [
                "Aucun incident traité sur la période.",
                "",
                f"Posture : autonomie {'active' if f.autonomy_effective else 'SUSPENDUE'}, "
                f"actionnement « {f.actuation_mode} ».",
            ]
            return "\n".join(lignes)

        lignes += [
            f"{f.incidents_total} incident(s) traité(s), "
            f"{f.actions_executed} action(s) exécutée(s) sans validation préalable.",
        ]

        if f.incidents_by_family:
            repartition = ", ".join(f"{k} : {v}" for k, v in sorted(f.incidents_by_family.items()))
            lignes.append(f"Répartition par famille — {repartition}.")

        if f.incidents_by_priority:
            prio = ", ".join(f"{k} : {v}" for k, v in sorted(f.incidents_by_priority.items()))
            lignes.append(f"Répartition par priorité (Axe 4) — {prio}.")

        if f.most_dangerous:
            m = f.most_dangerous
            lignes.append(
                f"Incident le plus dangereux : {m['type']} — {m['libelle']} "
                f"({m['dangerosite']}/10)."
            )

        lignes.append("")
        if f.actions_rolled_back:
            lignes.append(
                f"**{f.actions_rolled_back} action(s) annulée(s)** "
                f"({f.autonomous_rollbacks} par la boucle de contrôle, "
                f"{f.manual_rollbacks} par un analyste) — "
                f"taux d'annulation {f.rollback_ratio:.0%}."
            )
            if f.rollback_ratio > 0.2:
                lignes.append(
                    "Ce taux est anormalement élevé : le système défait une part "
                    "importante de ce qu'il fait. à analyser avant de poursuivre."
                )
        else:
            lignes.append("Aucune action annulée : tous les confinements ont tenu.")

        if f.actions_failed:
            lignes.append(f"{f.actions_failed} action(s) en échec d'exécution.")

        if f.refusals_total:
            motifs = ", ".join(f"{k} ({v})" for k, v in sorted(f.refusals.items()))
            lignes.append(f"{f.refusals_total} refus d'agir — {motifs}.")

        if f.breaker_trips:
            lignes.append(
                f"**Coupe-circuit déclenche {f.breaker_trips} fois** ; "
                f"état actuel : {f.breaker_state}."
            )

        lignes += [
            "",
            f"Journal d'audit : {f.audit_entries} entrée(s) sur la période, "
            f"chaîne {'intacte' if f.audit_chain_valid else 'ROMPUE'}.",
        ]
        if not f.audit_chain_valid:
            lignes.append(
                "La rupture de chaîne est un incident de sécurité sur la "
                "plateforme elle-même et demande une enquête."
            )
        if f.notifications_pending:
            lignes.append(f"{f.notifications_pending} notification(s) non acquittée(s).")
        return "\n".join(lignes)

    @staticmethod
    def _texte_statistiques(f: OperationsFacts) -> str:
        return "\n".join(
            [
                f"**Indicateurs — {f.period_label}**",
                "",
                f"- Incidents traités : {f.incidents_total}",
                f"- Actions exécutées : {f.actions_executed}",
                f"- Actions annulées : {f.actions_rolled_back} "
                f"(dont {f.autonomous_rollbacks} autonomes)",
                f"- Actions en échec : {f.actions_failed}",
                f"- Actions refusées par la politique : {f.actions_blocked}",
                f"- Taux d'annulation : {f.rollback_ratio:.0%}",
                f"- Refus d'agir : {f.refusals_total}",
                f"- Entrées de journal : {f.audit_entries}",
            ]
        )

    @staticmethod
    def _texte_posture(f: OperationsFacts) -> str:
        lignes = [
            "**Posture d'autonomie**",
            "",
            f"- Autonomie effective : {'OUI' if f.autonomy_effective else 'NON'}",
            f"- Mode d'actionnement : {f.actuation_mode}"
            + (
                "  (aucun effet réel sur les équipements)"
                if f.actuation_mode != "live"
                else "  (actions réelles)"
            ),
            f"- Coupe-circuit : {f.breaker_state}",
            f"- Chaîne d'audit : {'intacte' if f.audit_chain_valid else 'ROMPUE'}",
        ]
        if not f.autonomy_effective:
            lignes += [
                "",
                "Aucune action n'est exécutée tant que l'administrateur n'a pas "
                "rearme le coupe-circuit. Le système ne se rearme jamais seul : "
                "il ne peut pas juger que la cause de son emballement a disparu.",
            ]
        return "\n".join(lignes)

    @staticmethod
    def _texte_refus(f: OperationsFacts) -> str:
        if not f.refusals:
            return (
                f"Aucun refus d'agir sur la période ({f.period_label}) : "
                "chaque événement traité a donne lieu à une réponse."
            )
        lignes = [f"**Refus d'agir — {f.period_label}**", ""]
        for motif, nombre in sorted(f.refusals.items(), key=lambda kv: -kv[1]):
            lignes.append(f"- {nombre} × {motif}")
        lignes += [
            "",
            "Un refus n'est pas un dysfonctionnement. Le système s'abstient "
            "lorsqu'il ne dispose pas d'un fondement documentaire, lorsque la "
            "politique l'interdit, ou lorsque le coupe-circuit est ouvert.",
        ]
        if any("non fondé" in m for m in f.refusals):
            lignes.append(
                "Les refus pour contexte non fondé signalent une base de "
                "connaissance en retard sur les menaces observées : la réponse "
                "est d'enrichir le corpus, pas d'abaisser le seuil."
            )
        return "\n".join(lignes)

    @staticmethod
    def _texte_annulations(f: OperationsFacts) -> str:
        if not f.actions_rolled_back:
            return (
                f"Aucune action annulée sur la période ({f.period_label}). "
                "Tous les confinements engagés ont tenu."
            )
        return "\n".join(
            [
                f"**Annulations — {f.period_label}**",
                "",
                f"- {f.actions_rolled_back} action(s) annulée(s) au total",
                f"- dont {f.autonomous_rollbacks} par la boucle de contrôle (EF-25)",
                f"- dont {f.manual_rollbacks} par un analyste, a posteriori",
                f"- taux d'annulation : {f.rollback_ratio:.0%}",
                "",
                "Le taux d'annulation mesure la fréquence à laquelle le système "
                "doit défaire ce qu'il vient de faire. Au-delà de 20 %, il nuit "
                "plus qu'il ne protege sur une partie du périmètre.",
            ]
        )

    # -- intentions particulieres -------------------------------------------

    def _incident(self, question: str, folded: str, fil: Conversation | None = None) -> Answer:
        match = re.search(r"\binc_[0-9a-f]{6,}\b", folded)
        incident_id = match.group() if match else ""
        detail = self._collector.incident_detail(incident_id)

        if detail is None:
            return Answer(
                intent=Intent.INCIDENT_DETAIL,
                text=f"Aucun incident ne porte l'identifiant `{incident_id}`.",
                sources=["portefeuille d'incidents"],
                provider=self._provider.name,
            )

        i = detail["incident"]
        lignes = [
            f"**Incident {i['incident_id']}**",
            "",
            f"- Type : {i.get('attack_code') or '?'} — {i.get('attack_label') or i['category']}",
            f"- Famille : {i.get('family_label') or 'non classifiee'}",
            f"- Criticité : {i['severity']} · Dangerosité : {i.get('dangerousness', 0)}/10",
            f"- Priorité (Axe 4) : {i.get('priority') or '—'}"
            f" · Score de risque : {i['risk_score']}",
            f"- État : {i['status']} · {i['event_count']} événement(s)",
            "",
            f"**Actions ({len(detail['actions'])})**",
        ]
        for a in detail["actions"]:
            lignes.append(
                f"- `{a['actuator']}:{a['verb']}` sur {a['target']} — {a['status']}"
                + (f" (annulée : {a['rollback_reason']})" if a.get("rollback_reason") else "")
            )
        lignes += ["", f"**Chronologie ({len(detail['chronologie'])} entrées)**"]
        for e in detail["chronologie"]:
            lignes.append(f"- {e['seq']}. {e['type']} — {e['acteur']}")

        texte = self._provider.render(question, detail, "\n".join(lignes))
        return Answer(
            intent=Intent.INCIDENT_DETAIL,
            text=texte,
            facts=detail,
            sources=["portefeuille d'incidents", "journal d'audit"],
            provider=self._provider.name,
        )

    def _catalog(self, question: str) -> Answer:
        facts = self._collector.catalog_facts()
        familles = ", ".join(f"{k} : {v}" for k, v in sorted(facts["par_famille"].items()))
        texte = "\n".join(
            [
                f"La plateforme traite **{facts['types_catalogues']} types d'attaques** "
                "codifies au catalogue CIRT.",
                "",
                f"Répartition par famille — {familles} "
                "(A : réseau, B : applicatif, C : comportemental/insider, D : infrastructure).",
                "",
                "Une menace absente de ce catalogue ne déclenche aucune action : le "
                "contexte est déclaré non fondé et le système s'abstient. C'est une "
                "limite assumee du périmètre autonome.",
            ]
        )
        if facts["hors_perimetre_autonome"]:
            texte += (
                "\n\nSans action corrective directe : "
                + ", ".join(facts["hors_perimetre_autonome"])
                + " — la réponse s'y limite au constat et à la notification."
            )
        return Answer(
            intent=Intent.CATALOG,
            text=self._provider.render(question, facts, texte),
            facts=facts,
            sources=["catalogue CIRT"],
            provider=self._provider.name,
        )

    def _unknown(self, question: str, fil: Conversation | None = None) -> Answer:
        # Un refus n'est pas une fin de non-recevoir : il dit ce qui manque et
        # ouvre une porte. Sans cela l'utilisateur reformule a l'aveugle.
        entree = (
            "Je ne suis pas sûr de comprendre cette demande."
            if fil and not fil.vide
            else "Je ne sais pas répondre à cette question."
        )
        texte = "\n".join(
            [
                entree,
                "",
                "Je m'appuie exclusivement sur les données de la plateforme — "
                "journal d'audit, portefeuille d'incidents, catalogue CIRT — et je "
                "ne complète jamais un fait manquant. Si votre question sort de ce "
                "périmètre, je préfère vous le dire.",
                "",
                "Reformulez, ou essayez l'une de ces pistes :",
                *[f"- {s}" for s in self.suggestions()[:4]],
            ]
        )
        return Answer(
            intent=Intent.UNKNOWN,
            text=texte,
            provider=self._provider.name,
            follow_ups=self.suggestions()[:3],
        )
