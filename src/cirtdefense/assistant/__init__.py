"""Assistant d'exploitation : bilan des opérations et génération de rapports.

L'assistant répond **exclusivement** à partir des données de la plateforme —
journal d'audit, portefeuille d'incidents, catalogue. Il ne dispose d'aucune
connaissance propre et ne complète jamais un fait manquant.

Cette contrainte prolonge EF-04 : la plateforme refuse d'agir sur un contexte
non fondé ; elle refuse symétriquement de rapporter un fait qu'elle n'a pas
observe. Un bilan de sécurité comportant un chiffre invente conduirait un
décideur a se croire informe alors qu'il ne l'est pas.
"""

from .facts import FactCollector, OperationsFacts
from .reports import ReportBuilder
from .service import Answer, AssistantService

__all__ = [
    "Answer",
    "AssistantService",
    "FactCollector",
    "OperationsFacts",
    "ReportBuilder",
]
