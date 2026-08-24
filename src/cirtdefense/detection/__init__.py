"""Sources de detection internes : UEBA et surveillance d'infrastructure.

Elles ne sont pas des consommateurs de la plateforme mais des producteurs :
leur sortie est un `DetectionEvent`, exactement comme celle d'un collecteur
externe. La surveillance joue en plus un second role, decisif en v3.0 :
fermer la boucle de controle apres une action (EF-25).
"""
