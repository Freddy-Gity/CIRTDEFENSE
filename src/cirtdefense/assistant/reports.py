"""Generation de rapports d'operations.

Un rapport n'est pas un bilan plus long : c'est une piece destinee a etre
transmise, archivee et opposee. Il porte donc son perimetre, sa periode, son
empreinte de politique et l'etat de la chaine d'audit — de quoi etre rejuge
plus tard par quelqu'un qui n'etait pas la.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..domain.taxonomy import BY_CODE
from .facts import FactCollector, OperationsFacts


class ReportBuilder:
    def __init__(self, collector: FactCollector, site_id: str = "cirt-cm-01") -> None:
        self._collector = collector
        self._site_id = site_id

    def build(self, hours: int = 24, label: str | None = None) -> dict[str, Any]:
        libelle = label or _libelle(hours)
        facts = self._collector.collect(hours=hours, label=libelle)
        return {
            "site_id": self._site_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "period": libelle,
            "facts": facts.to_dict(),
            "markdown": self.to_markdown(facts),
        }

    def to_markdown(self, facts: OperationsFacts) -> str:
        f = facts
        # Certaines sections sont omises quand elles n'ont rien a dire ; la
        # numerotation se calcule donc au fil de l'ecriture plutot que d'etre
        # figee, sans quoi le rapport sauterait des numeros.
        section = _Numerotation()
        lignes: list[str] = [
            f"# Rapport d'operations — {self._site_id}",
            "",
            f"**Periode couverte** : {f.period_label}  ",
            f"**Du** {_date(f.since)} **au** {_date(f.until)}  ",
            f"**Genere le** {_date(datetime.now(UTC))}",
            "",
            "---",
            "",
            section("Posture d'exploitation"),
            "",
            f"- Autonomie effective : **{'oui' if f.autonomy_effective else 'non'}**",
            f"- Mode d'actionnement : **{f.actuation_mode}**"
            + ("" if f.actuation_mode == "live" else " — aucun effet reel sur les equipements"),
            f"- Coupe-circuit : **{f.breaker_state}**"
            + (f" — {f.breaker_trips} declenchement(s) sur la periode" if f.breaker_trips else ""),
            "",
            section("Volumetrie"),
            "",
            "| Indicateur | Valeur |",
            "|---|---|",
            f"| Incidents traites | {f.incidents_total} |",
            f"| Actions executees | {f.actions_executed} |",
            f"| Actions annulees | {f.actions_rolled_back} |",
            f"| — dont autonomes (EF-25) | {f.autonomous_rollbacks} |",
            f"| — dont manuelles (analyste) | {f.manual_rollbacks} |",
            f"| Actions en echec | {f.actions_failed} |",
            f"| Actions refusees par la politique | {f.actions_blocked} |",
            f"| **Taux d'annulation** | **{f.rollback_ratio:.0%}** |",
            f"| Refus d'agir | {f.refusals_total} |",
            "",
        ]

        if f.incidents_by_family:
            lignes += [
                section("Repartition des incidents"),
                "",
                "### Par famille d'attaque",
                "",
                "| Famille | Incidents |",
                "|---|---|",
                *[f"| {k} | {v} |" for k, v in sorted(f.incidents_by_family.items())],
                "",
            ]

        if f.incidents_by_priority:
            lignes += [
                "### Par priorite de traitement (Axe 4)",
                "",
                "| Priorite | Incidents |",
                "|---|---|",
                *[f"| {k} | {v} |" for k, v in sorted(f.incidents_by_priority.items())],
                "",
            ]

        if f.incidents_by_attack_type:
            lignes += [
                "### Par type du catalogue",
                "",
                "| Code | Libelle | Incidents |",
                "|---|---|---|",
                *[
                    f"| {code} | {_libelle_type(code)} | {n} |"
                    for code, n in sorted(f.incidents_by_attack_type.items())
                ],
                "",
            ]

        if f.top_incidents:
            lignes += [
                section("Incidents les plus engageants"),
                "",
                "| Incident | Type | Criticite | Dangerosite | Priorite | Risque "
                "| Exec. | Annul. |",
                "|---|---|---|---|---|---|---|---|",
                *[
                    f"| `{i['incident_id'][:18]}` | {i['type']} | {i['criticite']} "
                    f"| {i['dangerosite']}/10 | {i['priorite']} | {i['risque']} "
                    f"| {i['actions_executees']} | {i['actions_annulees']} |"
                    for i in f.top_incidents
                ],
                "",
            ]

        if f.refusals:
            lignes += [
                section("Refus d'agir"),
                "",
                "| Motif | Occurrences |",
                "|---|---|",
                *[f"| {k} | {v} |" for k, v in sorted(f.refusals.items(), key=lambda kv: -kv[1])],
                "",
                "Un refus n'est pas un dysfonctionnement : il traduit l'application",
                "d'un garde-fou. Un volume eleve de refus pour contexte non fonde",
                "signale une base de connaissance en retard sur les menaces",
                "observees ; la reponse est d'enrichir le corpus documentaire, non",
                "d'abaisser le seuil d'exigence.",
                "",
            ]

        lignes += [
            section("Tracabilite"),
            "",
            f"- Entrees de journal sur la periode : **{f.audit_entries}**",
            f"- Chaine d'empreintes : **{'intacte' if f.audit_chain_valid else 'ROMPUE'}**",
            f"- Notifications non acquittees : {f.notifications_pending}",
            "",
        ]
        if not f.audit_chain_valid:
            lignes += [
                "> **Alerte : la chaine du journal d'audit est rompue.**",
                ">",
                "> Une entree a ete alteree en dehors de l'application.",
                "> C'est un incident de securite portant sur la plateforme",
                "> elle-meme, et non une anomalie de fonctionnement.",
                "> Preserver le fichier de base et enqueter.",
                "",
            ]

        lignes += [
            "---",
            "",
            "## Note de lecture",
            "",
            "La plateforme execute les actions correctives **sans validation",
            "humaine prealable**. Chaque action figurant dans ce rapport a ete",
            "decidee et appliquee par le systeme seul ; l'analyste en a ete",
            "informe apres coup et disposait d'un pouvoir d'annulation.",
            "",
            "Le taux d'annulation est l'indicateur a surveiller en priorite : il",
            "mesure la frequence a laquelle le systeme doit defaire ce qu'il vient",
            "de faire.",
        ]
        return "\n".join(lignes)


class _Numerotation:
    """Compteur de sections, incremente a chaque titre reellement ecrit."""

    def __init__(self) -> None:
        self._n = 0

    def __call__(self, titre: str) -> str:
        self._n += 1
        return f"## {self._n}. {titre}"


def _libelle_type(code: str) -> str:
    attack = BY_CODE.get(code)
    return attack.label if attack else "—"


def _libelle(hours: int) -> str:
    if hours <= 24:
        return f"dernieres {hours} heures"
    jours = hours // 24
    return f"{jours} jour{'s' if jours > 1 else ''}"


def _date(value: datetime) -> str:
    return value.strftime("%d/%m/%Y %H:%M UTC")
