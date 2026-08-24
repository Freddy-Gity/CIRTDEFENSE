"""Politique de reponse compilee (EF-15, version v3.0).

L'administrateur ecrit sa politique en langage naturel. Elle est compilee
*une fois*, a priori, en contraintes deterministes ; le moteur autonome
n'evalue ensuite que ces contraintes. Le langage naturel ne se trouve donc
jamais sur le chemin d'execution : une reformulation du modele ne peut pas
changer le comportement d'une action deja compilee.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from .action import ActionSpec
from .decision import PolicyVerdict
from .enums import Reversibility, Severity


@dataclass(frozen=True, slots=True)
class Constraint:
    """Predicat elementaire evalue sur (action, contexte)."""

    field: str
    """action.verb, action.actuator, action.target, action.reversibility,
    action.blast_radius, incident.severity, incident.category, asset.zone,
    asset.criticality, time.hour"""
    operator: str
    """eq, ne, in, not_in, gte, lte, matches"""
    value: Any

    def evaluate(self, ctx: dict[str, Any]) -> bool:
        actual = ctx.get(self.field)
        if actual is None:
            return False
        match self.operator:
            case "eq":
                return actual == self.value
            case "ne":
                return actual != self.value
            case "in":
                return actual in self.value
            case "not_in":
                return actual not in self.value
            case "gte":
                return _as_number(actual) >= _as_number(self.value)
            case "lte":
                return _as_number(actual) <= _as_number(self.value)
            case "matches":
                return bool(re.search(str(self.value), str(actual)))
            case _:
                raise ValueError(f"operateur de contrainte inconnu : {self.operator}")

    def describe(self) -> str:
        return f"{self.field} {self.operator} {self.value}"


def _as_number(value: Any) -> float:
    if isinstance(value, Severity):
        return float(value.rank)
    if isinstance(value, str):
        try:
            return float(Severity(value).rank)
        except ValueError:
            return float(value)
    return float(value)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """Regle compilee. `effect` = allow | deny | require_approval_none.

    Il n'existe volontairement pas d'effet « demander validation » : ce serait
    reintroduire EF-13 dans sa version anterieure. Une action que la politique
    n'autorise pas est refusee, pas mise en attente d'un humain.
    """

    rule_id: str
    effect: str
    constraints: tuple[Constraint, ...] = ()
    source_sentence: str = ""
    priority: int = 100
    """Plus la valeur est basse, plus la regle est evaluee tot."""

    def __post_init__(self) -> None:
        if self.effect not in ("allow", "deny"):
            raise ValueError(f"effet de regle invalide : {self.effect}")

    def matches(self, ctx: dict[str, Any]) -> bool:
        return all(c.evaluate(ctx) for c in self.constraints)

    def describe(self) -> str:
        body = " ET ".join(c.describe() for c in self.constraints) or "toujours"
        return f"[{self.rule_id}] {self.effect.upper()} si {body}"


@dataclass(slots=True)
class ResponsePolicy:
    """Politique complete, versionnee et empreinte pour l'audit."""

    policy_id: str = "default"
    version: str = "1"
    rules: list[PolicyRule] = field(default_factory=list)
    source_text: str = ""
    default_effect: str = "allow"
    """`allow` : tout ce qui n'est pas refuse est execute (posture v3.0).
    Passer a `deny` transforme la politique en liste blanche stricte."""
    compiled_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    author: str = "administrateur"

    def checksum(self) -> str:
        """Empreinte du **comportement** de la politique, pas de sa redaction.

        Seuls l'effet et les contraintes de chaque regle entrent dans le
        calcul ; la phrase d'origine en est exclue. C'est ce qui rend
        l'empreinte utile en audit : elle repond a « le comportement du moteur
        a-t-il change ? », et deux redactions equivalentes — avec ou sans
        accents, reformulees — donnent bien la meme empreinte. L'identite
        documentaire de la politique, elle, est portee par `version` et
        `author`.
        """
        payload = json.dumps(
            [
                {
                    "rule_id": r.rule_id,
                    "effect": r.effect,
                    "priority": r.priority,
                    "constraints": [asdict(c) for c in r.constraints],
                }
                for r in sorted(self.rules, key=lambda r: r.rule_id)
            ],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def evaluate(self, action: ActionSpec, context: dict[str, Any]) -> PolicyVerdict:
        """Premiere regle satisfaite qui tranche ; sinon `default_effect`."""
        ctx = self._build_context(action, context)
        for rule in sorted(self.rules, key=lambda r: (r.priority, r.rule_id)):
            if rule.matches(ctx):
                return PolicyVerdict(
                    allowed=rule.effect == "allow",
                    rule_id=rule.rule_id,
                    rule_text=rule.source_sentence or rule.describe(),
                    reason=f"regle {rule.rule_id} appliquee ({rule.effect})",
                )
        return PolicyVerdict(
            allowed=self.default_effect == "allow",
            rule_id=None,
            rule_text=None,
            reason=f"aucune regle applicable, effet par defaut = {self.default_effect}",
        )

    @staticmethod
    def _build_context(action: ActionSpec, context: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {
            "action.verb": action.verb,
            "action.actuator": action.actuator,
            "action.target": action.target,
            "action.reversibility": action.reversibility.value,
            "action.blast_radius": action.blast_radius,
            "time.hour": datetime.now(UTC).hour,
        }
        merged.update(context)
        return merged

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "checksum": self.checksum(),
            "default_effect": self.default_effect,
            "compiled_at": self.compiled_at.isoformat(),
            "author": self.author,
            "source_text": self.source_text,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "effect": r.effect,
                    "priority": r.priority,
                    "source_sentence": r.source_sentence,
                    "constraints": [c.describe() for c in r.constraints],
                }
                for r in sorted(self.rules, key=lambda r: (r.priority, r.rule_id))
            ],
        }


IRREVERSIBLE_GUARD = PolicyRule(
    rule_id="R-GUARD-IRREVERSIBLE",
    effect="deny",
    constraints=(Constraint("action.reversibility", "eq", Reversibility.IRREVERSIBLE.value),),
    source_sentence=(
        "Garde-fou structurel : aucune action irreversible n'est executee de facon "
        "autonome, faute de pouvoir garantir le rollback exige par EF-25."
    ),
    priority=0,
)
"""Regle socle injectee dans toute politique compilee.

C'est la limite assumee du CDCF 1.4.3 : l'autonomie totale s'exerce sur le
catalogue reversible. Une action irreversible sort du perimetre autonome et
reste un geste humain.
"""
