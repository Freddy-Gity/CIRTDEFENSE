"""Classification d'une attaque selon le catalogue CIRT.

Produit, pour tout `DetectionEvent`, les quatre qualifications demandees :

- **type** : la ligne du catalogue (A1 a D4) ;
- **catégorie** : la famille (réseau, applicative, insider, infrastructure) ;
- **criticité** : la gravité effective, croisee avec la criticité de l'actif ;
- **dangerosité** : le dommage potentiel si l'attaque aboutit, sur 10.

Criticité et dangerosité mesurent deux choses differentes, et les confondre
conduirait a mal prioriser. Un scan de reconnaissance (A3) est de criticité
basse — il ne casse rien — mais annonce une intrusion : sa dangerosité reste
moderee et non nulle. Un service indisponible (D3) est de criticité haute sur
un actif vital alors que sa dangerosité intrinseque est moyenne : la panne
gêne, elle ne donne pas la main à un attaquant.

La classification est **déterministe et explicable** : chaque score
s'accompagne des facteurs qui l'ont produit. Sans validation humaine en amont,
une qualification qu'on ne sait pas justifier a posteriori ne vaut rien.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..domain.enums import Reversibility, Severity
from ..domain.events import DetectionEvent
from ..domain.taxonomy import BY_CATEGORY, AttackFamily, AttackType, Priority

# Correspondance des catégories generiques heritees vers le catalogue codifie.
# Ce sont des rapprochements au mieux, pour les sources qui ne discriminent pas
# plus finement. Une source capable de distinguer une injection SQL d'un XSS
# doit émettre la catégorie précise plutôt que de s'en remettre à ce tableau.
LEGACY_ALIASES: dict[str, str] = {
    "dos": "ddos_volumetric",
    "malware": "ransomware",
    "lateral_movement": "ransomware",
    "web_attack": "sql_injection",
    "behaviour_anomaly": "abnormal_access",
    "infrastructure_degradation": "service_unavailable",
}


@dataclass(slots=True)
class Classification:
    """Qualification complète d'un événement."""

    attack_type: AttackType | None
    category: str
    severity: Severity
    """Criticité effective : plancher du catalogue releve par la source et l'actif."""
    asset_criticality: int
    dangerousness: float
    """0 a 10. Dommage potentiel si l'attaque aboutit."""
    priority: Priority
    confidence: float
    factors: list[str] = field(default_factory=list)
    """Facteurs ayant produit les scores, en clair."""
    aliased_from: str | None = None
    """Catégorie d'origine si un rapprochement a été nécessaire."""

    @property
    def is_catalogued(self) -> bool:
        return self.attack_type is not None

    @property
    def code(self) -> str:
        return self.attack_type.code if self.attack_type else "?"

    @property
    def family(self) -> AttackFamily | None:
        return self.attack_type.family if self.attack_type else None

    @property
    def label(self) -> str:
        return (
            self.attack_type.label if self.attack_type else f"Type non catalogue ({self.category})"
        )

    def family_label_or_blank(self) -> str:
        return self.family.label if self.family else "hors catalogue"

    @property
    def danger_band(self) -> str:
        """Bande lisible, pour l'affichage et les rapports."""
        if self.dangerousness >= 9:
            return "extreme"
        if self.dangerousness >= 7:
            return "elevee"
        if self.dangerousness >= 4:
            return "moderee"
        return "faible"

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalogued": self.is_catalogued,
            "code": self.code,
            "label": self.label,
            "category": self.category,
            "family": self.family.value if self.family else None,
            "family_code": self.family.code if self.family else None,
            "family_label": self.family.label if self.family else None,
            "severity": self.severity.value,
            "asset_criticality": self.asset_criticality,
            "dangerousness": round(self.dangerousness, 1),
            "danger_band": self.danger_band,
            "priority": self.priority.value,
            "priority_rank": self.priority.rank,
            "confidence": self.confidence,
            "factors": self.factors,
            "aliased_from": self.aliased_from,
            "detection_sources": (
                list(self.attack_type.detection_sources) if self.attack_type else []
            ),
            "signal": self.attack_type.signal if self.attack_type else "",
            "prescribed_actions": (self.attack_type.prescribed_actions if self.attack_type else ""),
            "reversibility": (self.attack_type.reversibility.value if self.attack_type else None),
            "residual_effect": self.attack_type.residual_effect if self.attack_type else "",
        }


class Classifier:
    """Rattache un événement au catalogue et calcule ses scores.

    Deux catalogues sont consultés, dans cet ordre : le document métier du
    CIRT — 22 lignes, figées — puis le catalogue appris, alimenté par les
    qualifications qu'un humain a validées (EF-29). Le second ne prend jamais
    le pas sur le premier.

    Une entrée apprise donne un **nom** et une **famille** à l'incident ; elle
    ne donne pas de playbook. Savoir comment s'appelle une menace n'apprend pas
    comment y répondre : la réponse restera le confinement de repli, déduit des
    indicateurs, tant qu'une fiche documentaire n'aura pas été rédigée.
    """

    def __init__(self, learned: Any = None) -> None:
        self._learned = learned

    def classify(self, event: DetectionEvent) -> Classification:
        attack_type, aliased_from = self._resolve(event.category)
        if attack_type is None:
            attack_type = self._from_learned(event)
        factors: list[str] = []

        severity = self._effective_severity(event, attack_type, factors)
        dangerousness = self._dangerousness(event, attack_type, factors)
        priority = self._priority(event, attack_type, dangerousness, factors)

        if aliased_from:
            factors.append(
                f"catégorie '{aliased_from}' rapprochee du type {attack_type.code} "
                "faute de qualification plus fine par la source"
            )

        return Classification(
            attack_type=attack_type,
            category=event.category,
            severity=severity,
            asset_criticality=event.asset.criticality,
            dangerousness=dangerousness,
            priority=priority,
            confidence=event.confidence,
            factors=factors,
            aliased_from=aliased_from,
        )

    def _from_learned(self, event: DetectionEvent) -> AttackType | None:
        """Cherche l'événement dans le catalogue appris, par signature.

        La recherche ne se fait pas sur `event.category` : celle-ci vaut
        `unknown` pour toutes les menaces hors catalogue, et servirait donc de
        clé à toutes indifféremment. C'est la *forme* des indicateurs observés
        qui identifie le type.
        """
        if self._learned is None:
            return None
        from .qualifier import signature

        cle = signature(event)
        for entree in self._learned.validated():
            if entree.get("category") == cle:
                return _type_appris(entree)
        return None

    # -- résolution du type --------------------------------------------------

    @staticmethod
    def _resolve(category: str) -> tuple[AttackType | None, str | None]:
        direct = BY_CATEGORY.get(category)
        if direct is not None:
            return direct, None
        alias = LEGACY_ALIASES.get(category)
        if alias is not None:
            return BY_CATEGORY.get(alias), category
        return None, None

    # -- criticité -----------------------------------------------------------

    @staticmethod
    def _effective_severity(
        event: DetectionEvent, attack_type: AttackType | None, factors: list[str]
    ) -> Severity:
        """La gravité du catalogue est un plancher, pas un plafond.

        Une source peut remonter plus grave que le plancher — elle observe le
        cas concret. Elle ne peut pas remonter moins grave : le catalogue
        exprime ce que le type d'attaque vaut au minimum.
        """
        severity = event.severity
        if attack_type is not None and attack_type.base_severity > severity:
            factors.append(
                f"gravité relevée de {severity.value} a {attack_type.base_severity.value} "
                f"(plancher du type {attack_type.code})"
            )
            severity = attack_type.base_severity
        if event.asset.criticality >= 5 and severity < Severity.CRITICAL:
            promoted = Severity.CRITICAL if severity is Severity.HIGH else Severity.HIGH
            factors.append(f"gravité relevée a {promoted.value} : actif de criticité maximale")
            severity = promoted
        return severity

    # -- dangerosité ---------------------------------------------------------

    @staticmethod
    def _dangerousness(
        event: DetectionEvent, attack_type: AttackType | None, factors: list[str]
    ) -> float:
        """Dommage potentiel si l'attaque aboutit, sur 10.

        Trois facteurs, tous explicites :
        base du catalogue, criticité de l'actif, confiance de la source.
        Un type hors catalogue part d'une base moyenne : on ne sait pas, on ne
        prejuge donc ni dans un sens ni dans l'autre.
        """
        if attack_type is None:
            base = 5.0
            factors.append("dangerosité de base 5/10 : type hors catalogue, aucune référence")
        else:
            base = float(attack_type.dangerousness)
            factors.append(f"dangerosité de base {base:.0f}/10 pour le type {attack_type.code}")

        criticality_bonus = (event.asset.criticality - 3) * 0.5
        if criticality_bonus:
            factors.append(
                f"{criticality_bonus:+.1f} : actif de criticité {event.asset.criticality}/5"
            )

        # La confiance module sans jamais annuler : une détection incertaine
        # sur un rançongiciel reste plus dangereuse qu'un scan certain.
        confidence_factor = 0.7 + 0.3 * event.confidence
        factors.append(f"x{confidence_factor:.2f} : confiance de la source {event.confidence:.0%}")

        return round(max(0.0, min(10.0, (base + criticality_bonus) * confidence_factor)), 1)

    # -- priorité Axe 4 ------------------------------------------------------

    @staticmethod
    def _priority(
        event: DetectionEvent,
        attack_type: AttackType | None,
        dangerousness: float,
        factors: list[str],
    ) -> Priority:
        if attack_type is None:
            return Priority.MEDIUM

        priority = attack_type.priority
        if attack_type.priority_rationale:
            factors.append(f"priorité {priority.value} — {attack_type.priority_rationale}")
        else:
            factors.append(f"priorité {priority.value} au catalogue")

        # Le document prevoit explicitement des priorités conditionnelles
        # (« moyenne a haute selon le compte cible », « haute si service
        # critique »). L'actif tranche ce que le catalogue laisse ouvert.
        if event.asset.criticality >= 5 and priority is Priority.HIGH:
            factors.append("priorité portee a critique : actif de criticité maximale")
            return Priority.CRITICAL
        if event.asset.criticality <= 1 and priority is Priority.MEDIUM:
            factors.append("priorité abaissee a basse : actif accessoire")
            return Priority.LOW
        return priority


def _type_appris(entree: dict[str, Any]) -> AttackType:
    """Traduit une entrée validée du catalogue appris en ligne de catalogue.

    Le reste de la plateforme ne fait aucune différence entre une ligne du
    document CIRT et une ligne apprise, *sauf* sur un point : les actions
    prescrites restent vides. Le confinement continue de venir des indicateurs
    observés, jamais d'un nom.
    """
    try:
        famille = AttackFamily(entree.get("family", "network"))
    except ValueError:
        famille = AttackFamily.NETWORK
    try:
        gravite = Severity(entree.get("severity", "medium"))
    except ValueError:
        gravite = Severity.MEDIUM

    return AttackType(
        code=entree.get("code") or "L??",
        family=famille,
        label=entree.get("label", "Type appris"),
        category=entree.get("category", ""),
        detection_sources=(entree.get("source_product", "") or "observation",),
        signal=entree.get("signal", ""),
        prescribed_actions="",
        reversibility=Reversibility.REVERSIBLE,
        priority=Priority.MEDIUM,
        priority_rationale="type appris : priorité moyenne par défaut, à réviser",
        base_severity=gravite,
        dangerousness=int(round(float(entree.get("dangerousness", 5.0)))),
    )
