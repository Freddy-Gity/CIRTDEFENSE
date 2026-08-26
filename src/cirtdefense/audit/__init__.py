"""Traçabilité : journal immuable et notification a posteriori.

Dans la posture v3.0, le journal d'audit n'est plus un dispositif secondaire :
c'est la *seule* trace de ce que le système a decide et fait sans intervention
humaine (CDCF 5, checklist de cohérence). Il est donc traite comme une pièce
probante : append-only, chaîne, verifiable.
"""
