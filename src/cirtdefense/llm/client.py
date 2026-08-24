"""Fournisseurs de redaction."""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from ..logging_setup import log_with

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
Tu es l'assistant d'exploitation d'une plateforme d'orchestration autonome de
la reponse aux incidents de securite, operee par un CIRT national.

REGLE ABSOLUE : tu ne disposes d'aucune information en dehors des donnees
factuelles qui te sont fournies dans le message. Tu ne dois JAMAIS inventer
un chiffre, un identifiant d'incident, un horodatage ou un nom d'actif. Si une
donnee ne figure pas dans les faits fournis, dis explicitement qu'elle n'est
pas disponible.

Ton role est de mettre en forme et d'expliquer ces faits, pas de les completer.
Un chiffre invente dans un bilan de securite est une faute grave : il conduirait
un decideur a se croire informe alors qu'il ne l'est pas.

Reponds en francais, de facon concise et factuelle. Emploie les termes du
metier (incident, confinement, annulation, coupe-circuit). N'ajoute ni formule
de politesse ni proposition d'aide supplementaire.\
"""


class LlmProvider(Protocol):
    """Contrat minimal : rendre un texte a partir de faits verifies."""

    name: str

    def available(self) -> bool: ...

    def render(self, question: str, facts: dict[str, Any], fallback: str) -> str:
        """Redige une reponse. `fallback` est le texte deterministe deja
        construit : il est rendu tel quel si le modele est indisponible."""


class OfflineProvider:
    """Rendu deterministe. Rend le texte deja compose par l'assistant."""

    name = "offline"

    def available(self) -> bool:
        return True

    def render(self, question: str, facts: dict[str, Any], fallback: str) -> str:
        return fallback


class AnthropicProvider:
    """Redaction par modele Claude.

    Le client est construit paresseusement : le paquet `anthropic` est une
    dependance optionnelle, et la plateforme doit demarrer sans lui.
    """

    name = "anthropic"

    def __init__(self, api_key: str = "", model: str = "claude-opus-5") -> None:
        self._api_key = api_key
        self._model = model
        self._client: Any = None

    def available(self) -> bool:
        return bool(self._api_key)

    def _ensure_client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def render(self, question: str, facts: dict[str, Any], fallback: str) -> str:
        if not self.available():
            return fallback
        try:
            import anthropic
        except ImportError:
            log_with(
                logger,
                logging.WARNING,
                "paquet 'anthropic' absent : repli sur le rendu deterministe",
            )
            return fallback

        message = (
            f"Question de l'exploitant :\n{question}\n\n"
            "Faits verifies, extraits du journal d'audit et du portefeuille "
            "d'incidents. Ce sont les SEULES donnees dont tu disposes :\n"
            f"```json\n{json.dumps(facts, ensure_ascii=False, indent=2, default=str)}\n```\n\n"
            "Redige la reponse a partir de ces seuls faits."
        )

        try:
            response = self._ensure_client().messages.create(
                model=self._model,
                max_tokens=16000,
                system=SYSTEM_PROMPT,
                thinking={"type": "adaptive"},
                messages=[{"role": "user", "content": message}],
            )
        except anthropic.APIStatusError as exc:
            # Une indisponibilite du modele ne doit jamais priver l'exploitant
            # de son bilan : le texte deterministe reste disponible.
            log_with(
                logger,
                logging.WARNING,
                "modele indisponible : repli sur le rendu deterministe",
                status=exc.status_code,
                error=str(exc),
            )
            return fallback
        except anthropic.APIConnectionError as exc:
            log_with(
                logger,
                logging.WARNING,
                "modele injoignable : repli sur le rendu deterministe",
                error=str(exc),
            )
            return fallback

        if response.stop_reason == "refusal":
            log_with(logger, logging.WARNING, "redaction refusee par le modele")
            return fallback

        text = "\n".join(b.text for b in response.content if b.type == "text").strip()
        return text or fallback


def build_provider(provider: str, api_key: str = "", model: str = "claude-opus-5") -> LlmProvider:
    """Fabrique le fournisseur configure.

    Un fournisseur `anthropic` sans cle retombe sur le rendu deterministe
    plutot que d'echouer au demarrage : la plateforme doit rester operante.
    """
    if provider == "anthropic" and api_key:
        return AnthropicProvider(api_key=api_key, model=model)
    if provider == "anthropic":
        log_with(
            logger,
            logging.WARNING,
            "fournisseur 'anthropic' demande sans cle : rendu deterministe applique",
        )
    return OfflineProvider()
