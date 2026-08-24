"""Tracabilite : journal immuable et notification a posteriori.

Dans la posture v3.0, le journal d'audit n'est plus un dispositif secondaire :
c'est la *seule* trace de ce que le systeme a decide et fait sans intervention
humaine (CDCF 5, checklist de coherence). Il est donc traite comme une piece
probante : append-only, chaine, verifiable.
"""
