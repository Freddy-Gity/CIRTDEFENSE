"""Adaptateur d'ingestion (EF-18 a EF-20).

Point d'entrée unique de la plateforme. Son rôle est de ramener n'importe
quelle source à un `DetectionEvent` : c'est ce qui permet d'ajouter un
collecteur sans toucher à l'orchestration.
"""
