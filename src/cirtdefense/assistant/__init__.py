"""Assistant d'exploitation : bilan des operations et generation de rapports.

L'assistant repond **exclusivement** a partir des donnees de la plateforme —
journal d'audit, portefeuille d'incidents, catalogue. Il ne dispose d'aucune
connaissance propre et ne complete jamais un fait manquant.

Cette contrainte prolonge EF-04 : la plateforme refuse d'agir sur un contexte
non fonde ; elle refuse symetriquement de rapporter un fait qu'elle n'a pas
observe. Un bilan de securite comportant un chiffre invente conduirait un
decideur a se croire informe alors qu'il ne l'est pas.
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
