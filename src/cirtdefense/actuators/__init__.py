"""Connecteurs d'action : la frontiere entre la decision et le monde reel.

Chaque actuateur expose un ensemble de verbes et leur annulation. Deux
proprietes sont exigees de toute implantation :

- **idempotence** : rejouer une action deja appliquee ne doit pas echouer ;
- **jeton d'annulation** : l'execution rend de quoi annuler *precisement* ce
  qui a ete fait, et non de quoi appliquer un geste inverse approximatif.

Sans ces deux proprietes, la boucle EF-25 ne peut rien garantir.
"""

from .base import Actuator, ActuatorError, ActuatorRegistry, ActuationOutcome

__all__ = ["Actuator", "ActuatorError", "ActuatorRegistry", "ActuationOutcome"]
