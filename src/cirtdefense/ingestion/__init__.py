"""Adaptateur d'ingestion (EF-18 a EF-20).

Point d'entree unique de la plateforme. Son role est de ramener n'importe
quelle source a un `DetectionEvent` : c'est ce qui permet d'ajouter un
collecteur sans toucher a l'orchestration.
"""
