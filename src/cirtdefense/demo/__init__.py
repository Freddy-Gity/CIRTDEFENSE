"""Mode démonstration : simulation des 22 types d'attaques du catalogue.

Ce paquet ne fabrique pas d'attaque : il fabrique la **charge utile qu'une
attaque réelle ferait produire au collecteur**. La plateforme, elle, ne voit
aucune difference — c'est le même adaptateur d'ingestion qui reçoit le même
JSON qu'un Wazuh ou un Suricata de production emettrait.

C'est la seule maniere honnete de demontrer la chaîne autonome sans mener
d'attaque réelle contre une infrastructure.
"""

from .scenarios import SCENARIOS, Scenario, build_payload, get_scenario, list_scenarios

__all__ = ["SCENARIOS", "Scenario", "build_payload", "get_scenario", "list_scenarios"]
