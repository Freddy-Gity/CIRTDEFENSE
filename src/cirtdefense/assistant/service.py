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

from ..llm import LlmProvider, OfflineProvider
from .facts import FactCollector, OperationsFacts


class Intent(StrEnum):
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent.value,
            "text": self.text,
            "facts": self.facts,
            "sources": self.sources,
            "provider": self.provider,
        }


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


# Motifs reconnus. L'ordre compte : le premier qui correspond l'emporte, donc
# les intentions les plus spécifiques sont placees en tête.
PATTERNS: tuple[tuple[Intent, tuple[str, ...]], ...] = (
    (Intent.INCIDENT_DETAIL, (r"\binc_[0-9a-f]{6,}\b",)),
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

_PERIODE = re.compile(r"(\d{1,3})\s*(heure|jour|semaine)")


class AssistantService:
    def __init__(
        self,
        collector: FactCollector,
        provider: LlmProvider | None = None,
    ) -> None:
        self._collector = collector
        self._provider = provider or OfflineProvider()

    # -- point d'entrée ------------------------------------------------------

    def ask(self, question: str) -> Answer:
        folded = _fold(question)
        intent = self._detect(folded)
        hours, label = self._period(folded)

        match intent:
            case Intent.INCIDENT_DETAIL:
                return self._incident(question, folded)
            case Intent.CATALOG:
                return self._catalog(question)
            case Intent.UNKNOWN:
                return self._unknown(question)
            case _:
                facts = self._collector.collect(hours=hours, label=label)
                return self._compose(intent, question, facts)

    def daily_brief(self) -> Answer:
        """Bilan des opérations du jour — l'usage principal de l'assistant."""
        facts = self._collector.collect(hours=24, label="dernières 24 heures")
        return self._compose(Intent.DAILY_BRIEF, "Bilan des opérations du jour", facts)

    def suggestions(self) -> list[str]:
        return [
            "Fais le bilan des opérations du jour",
            "Combien d'actions ont été annulées ?",
            "Pourquoi le système a-t-il refusé d'agir ?",
            "Quelle est la posture d'autonomie actuelle ?",
            "Quels types d'attaques sais-tu traiter ?",
            "Génère un rapport des opérations sur 7 jours",
        ]

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

    def _compose(self, intent: Intent, question: str, facts: OperationsFacts) -> Answer:
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
        return Answer(
            intent=intent,
            text=texte,
            facts=payload,
            sources=["journal d'audit", "portefeuille d'incidents"],
            provider=self._provider.name,
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
                "Tous les confinements engages ont tenu."
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

    def _incident(self, question: str, folded: str) -> Answer:
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

    def _unknown(self, question: str) -> Answer:
        texte = "\n".join(
            [
                "Je ne sais pas répondre à cette question.",
                "",
                "Je m'appuie exclusivement sur les données de la plateforme — "
                "journal d'audit, portefeuille d'incidents, catalogue — et je ne "
                "complète jamais un fait manquant.",
                "",
                "Voici ce que je sais faire :",
                *[f"- {s}" for s in self.suggestions()],
            ]
        )
        return Answer(intent=Intent.UNKNOWN, text=texte, provider=self._provider.name)
