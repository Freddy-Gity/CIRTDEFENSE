"""Accès optionnel à un modèle de langage.

Deux implantations derriere un même contrat :

- `OfflineProvider` : rendu déterministe à partir de gabarits. C'est le
  **défaut**, et il n'est pas un pis-aller — il garantit que la plateforme
  reste opérante sans connexion, contrainte du mode dégrade (Axe 5), et que
  les rapports sont reproductibles d'une exécution à l'autre.
- `AnthropicProvider` : rédaction par modèle, activée explicitement.

Dans les deux cas, **les chiffrés ne viennent jamais du modèle**. Ils sont
calcules par `assistant.facts` à partir du journal et du portefeuille, puis
passes au redacteur. Un assistant de sécurité qui inventerait un nombre
d'incidents serait pire qu'inutile.
"""

from .client import AnthropicProvider, LlmProvider, OfflineProvider, build_provider

__all__ = ["AnthropicProvider", "LlmProvider", "OfflineProvider", "build_provider"]
