"""Planificateur : de l'evenement enrichi aux actions candidates (EF-05, EF-06).

Le choix de l'action vient de playbooks ecrits par des humains, jamais d'un
texte genere. C'est un choix d'architecture assume : en autonomie totale, la
question « pourquoi le systeme a-t-il fait cela ? » doit trouver sa reponse
dans un fichier versionne et relisible, pas dans les poids d'un modele.

Le planificateur ne decide pas d'executer. Il propose des actions candidates ;
le filtrage par politique, catalogue et coupe-circuit se fait ensuite dans le
moteur. Cette separation permet de tracer ce qui a ete envisage *puis* ecarte,
ce qui est precisement ce qu'un auditeur cherche a reconstituer.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..domain.action import ActionSpec
from ..domain.enums import Severity
from ..domain.events import DetectionEvent
from ..logging_setup import log_with
from .reversibility import ReversibilityCatalog, get_catalog

logger = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\.([a-z_0-9]+)\}")


@dataclass(slots=True)
class PlannedAction:
    spec: ActionSpec
    rule_id: str
    optional: bool = False


@dataclass(slots=True)
class PlanningResult:
    playbook_id: str = ""
    playbook_version: str = ""
    matched_rules: list[str] = field(default_factory=list)
    actions: list[PlannedAction] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    """Actions envisagees puis ecartees, avec le motif. Trace d'audit."""

    @property
    def specs(self) -> list[ActionSpec]:
        return [a.spec for a in self.actions]


@dataclass(slots=True)
class Playbook:
    playbook_id: str
    version: str
    category: str
    description: str
    rules: list[dict[str, Any]]
    source_path: str = ""


class PlaybookLoadError(ValueError):
    """Playbook mal forme : refus de chargement plutot que comportement devine."""


class Planner:
    def __init__(
        self,
        playbooks: dict[str, Playbook],
        catalog: ReversibilityCatalog | None = None,
    ) -> None:
        self._playbooks = playbooks
        self._catalog = catalog or get_catalog()

    @classmethod
    def from_directory(
        cls, directory: Path | str, catalog: ReversibilityCatalog | None = None
    ) -> Planner:
        playbooks: dict[str, Playbook] = {}
        base = Path(directory)
        for path in sorted(base.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            missing = [k for k in ("id", "category", "rules") if k not in data]
            if missing:
                raise PlaybookLoadError(
                    f"playbook '{path.name}' incomplet : champs manquants {missing}"
                )
            playbooks[data["category"]] = Playbook(
                playbook_id=data["id"],
                version=str(data.get("version", "1.0")),
                category=data["category"],
                description=str(data.get("description", "")).strip(),
                rules=data["rules"],
                source_path=str(path),
            )
        return cls(playbooks, catalog)

    def categories(self) -> list[str]:
        return sorted(self._playbooks)

    def get(self, category: str) -> Playbook | None:
        return self._playbooks.get(category)

    def plan(self, event: DetectionEvent) -> PlanningResult:
        playbook = self._playbooks.get(event.category)
        if playbook is None:
            log_with(
                logger, logging.WARNING,
                "aucun playbook pour cette categorie : aucune action planifiee",
                category=event.category, event_id=event.event_id,
            )
            return PlanningResult(
                skipped=[{
                    "action": "-",
                    "reason": f"aucun playbook ne couvre la categorie '{event.category}'",
                }]
            )

        result = PlanningResult(
            playbook_id=playbook.playbook_id, playbook_version=playbook.version
        )
        for rule in playbook.rules:
            rule_id = str(rule.get("id", "?"))
            if not self._rule_matches(rule.get("when") or {}, event):
                continue
            result.matched_rules.append(rule_id)
            for action in rule.get("actions") or []:
                self._build_action(action, rule_id, event, result)
        return result

    # -- evaluation des conditions -----------------------------------------

    def _rule_matches(self, conditions: dict[str, Any], event: DetectionEvent) -> bool:
        for key, expected in conditions.items():
            if not self._condition_holds(key, expected, event):
                return False
        return True

    def _condition_holds(self, key: str, expected: Any, event: DetectionEvent) -> bool:
        match key:
            case "severity_min":
                return event.severity >= Severity(expected)
            case "severity_max":
                return event.severity <= Severity(expected)
            case "confidence_min":
                return event.confidence >= float(expected)
            case "asset_criticality_min":
                return event.asset.criticality >= int(expected)
            case "asset_criticality_max":
                return event.asset.criticality <= int(expected)
            case "user_present":
                return bool(event.asset.user) is bool(expected)
            case "indicators_present":
                return all(self._indicator(event, name) for name in expected)
            case "indicators_absent":
                return not any(self._indicator(event, name) for name in expected)
            case "category":
                return event.category == expected
            case "zone_in":
                return event.asset.zone in expected
            case "zone_not_in":
                return event.asset.zone not in expected
            case "target_private":
                return _is_private(str(self._indicator(event, str(expected)) or ""))
            case "target_not_private":
                value = self._indicator(event, str(expected))
                return bool(value) and not _is_private(str(value))
            case _:
                raise PlaybookLoadError(f"condition de playbook inconnue : '{key}'")

    @staticmethod
    def _indicator(event: DetectionEvent, name: str) -> Any:
        """Les sources ne nomment pas les indicateurs de la meme facon ;
        `srcip` et `src_ip` designent la meme chose."""
        aliases = {
            "srcip": ("srcip", "src_ip", "source_ip"),
            "src_ip": ("src_ip", "srcip", "source_ip"),
            "dest_ip": ("dest_ip", "dstip", "destination_ip", "dst_ip"),
            "dstip": ("dstip", "dest_ip", "destination_ip", "dst_ip"),
        }
        for candidate in aliases.get(name, (name,)):
            if event.indicators.get(candidate):
                return event.indicators[candidate]
        return None

    # -- construction des actions ------------------------------------------

    def _build_action(
        self,
        action: dict[str, Any],
        rule_id: str,
        event: DetectionEvent,
        result: PlanningResult,
    ) -> None:
        verb = str(action.get("verb", ""))
        actuator = str(action.get("actuator", ""))
        label = f"{actuator}:{verb}"
        optional = bool(action.get("optional", False))

        # Condition supplementaire portee par l'action elle-meme.
        threshold = action.get("when_severity_min")
        if threshold and not (event.severity >= Severity(threshold)):
            result.skipped.append({
                "action": label,
                "reason": f"gravite {event.severity.value} inferieure au seuil {threshold}",
            })
            return

        target = self._resolve(str(action.get("target", "")), event)
        if not target:
            result.skipped.append({
                "action": label,
                "reason": f"cible non resolue depuis '{action.get('target')}' "
                          "(indicateur absent de l'evenement)",
            })
            return

        entry = self._catalog.get(actuator, verb)
        if entry is None:
            result.skipped.append({
                "action": label,
                "reason": "action absente du catalogue de reversibilite",
            })
            return
        if not entry.autonomously_executable:
            result.skipped.append({
                "action": label,
                "reason": f"action {entry.reversibility.value} : hors du perimetre autonome",
            })
            return

        parameters = {
            k: self._resolve(v, event) if isinstance(v, str) else v
            for k, v in (action.get("parameters") or {}).items()
        }
        parameters.setdefault("incident_source_event", event.event_id)

        result.actions.append(
            PlannedAction(
                spec=ActionSpec(
                    verb=verb,
                    actuator=actuator,
                    target=target,
                    parameters=parameters,
                    reversibility=entry.reversibility,
                    rollback_verb=entry.rollback_verb,
                    blast_radius=int(action.get("blast_radius", entry.typical_blast_radius)),
                    expected_effect=str(action.get("expected_effect", entry.description)).strip(),
                    timeout_seconds=int(action.get("timeout_seconds", 30)),
                ),
                rule_id=rule_id,
                optional=optional,
            )
        )

    def _resolve(self, template: str, event: DetectionEvent) -> str:
        """Remplace `{asset.user}` ou `{indicators.srcip}` par la valeur reelle.

        Un motif non resolu rend une chaine vide : l'action sera ecartee plus
        haut. On ne substitue jamais une valeur de repli — agir sur une cible
        devinee est precisement ce que l'autonomie ne doit pas se permettre.
        """
        if not template:
            return ""

        def substitute(match: re.Match[str]) -> str:
            namespace, name = match.group(1), match.group(2)
            if namespace == "asset":
                return str(getattr(event.asset, name, "") or "")
            if namespace == "indicators":
                return str(self._indicator(event, name) or "")
            if namespace == "event":
                return str(getattr(event, name, "") or "")
            return ""

        resolved = _PLACEHOLDER.sub(substitute, template)
        return "" if "{" in resolved or not resolved.strip() else resolved


def _is_private(address: str) -> bool:
    from ..actuators.firewall import is_private

    return is_private(address)
