"""Acces optionnel a un modele de langage.

Deux implantations derriere un meme contrat :

- `OfflineProvider` : rendu deterministe a partir de gabarits. C'est le
  **defaut**, et il n'est pas un pis-aller — il garantit que la plateforme
  reste operante sans connexion, contrainte du mode degrade (Axe 5), et que
  les rapports sont reproductibles d'une execution a l'autre.
- `AnthropicProvider` : redaction par modele, activee explicitement.

Dans les deux cas, **les chiffres ne viennent jamais du modele**. Ils sont
calcules par `assistant.facts` a partir du journal et du portefeuille, puis
passes au redacteur. Un assistant de securite qui inventerait un nombre
d'incidents serait pire qu'inutile.
"""

from .client import AnthropicProvider, LlmProvider, OfflineProvider, build_provider

__all__ = ["AnthropicProvider", "LlmProvider", "OfflineProvider", "build_provider"]
