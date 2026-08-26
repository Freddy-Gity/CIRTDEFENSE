"""Connecteurs d'action : la frontiere entre la décision et le monde réel.

Chaque actuateur expose un ensemble de verbes et leur annulation. Deux
propriétés sont exigees de toute implantation :

- **idempotence** : rejouer une action déjà appliquée ne doit pas echouer ;
- **jeton d'annulation** : l'exécution rend de quoi annuler *précisément* ce
  qui a été fait, et non de quoi appliquer un geste inverse approximatif.

Sans ces deux propriétés, la boucle EF-25 ne peut rien garantir.
"""

from .base import ActuationOutcome, Actuator, ActuatorError, ActuatorRegistry

__all__ = ["Actuator", "ActuatorError", "ActuatorRegistry", "ActuationOutcome"]
