"""Mode demonstration : simulation des 22 types d'attaques du catalogue.

Ce paquet ne fabrique pas d'attaque : il fabrique la **charge utile qu'une
attaque reelle ferait produire au collecteur**. La plateforme, elle, ne voit
aucune difference — c'est le meme adaptateur d'ingestion qui recoit le meme
JSON qu'un Wazuh ou un Suricata de production emettrait.

C'est la seule maniere honnete de demontrer la chaine autonome sans mener
d'attaque reelle contre une infrastructure.
"""

from .scenarios import SCENARIOS, Scenario, build_payload, get_scenario, list_scenarios

__all__ = ["SCENARIOS", "Scenario", "build_payload", "get_scenario", "list_scenarios"]
