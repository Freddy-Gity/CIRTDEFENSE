"""Modèle métier pur : aucune dependance à une base, un réseau ou un framework.

Cette couche porte les invariants du CDCF. Toute règle qui doit rester vraie
quel que soit le canal d'entrée (API, adaptateur, rejeu du mode dégrade) est
exprimee ici et nulle part ailleurs.
"""
