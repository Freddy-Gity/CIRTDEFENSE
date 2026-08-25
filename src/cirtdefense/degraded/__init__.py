"""Mode dégrade (Axe 5) : fonctionnement en perte de connectivite.

L'Axe 5 gagne en importance avec le pivot v3.0. Un système qui agit seul doit
savoir ce qu'il fait quand il ne voit plus ses équipements : continuer a agir
à l'aveugle serait le pire comportement, puisque la boucle de contrôle EF-25
ne pourrait plus constater ses propres degats.

La règle retenue est donc : en mode dégrade, le système **observe et met en
file**, il n'agit pas. Il rejoue à la reprise, après avoir vérifié que les
événements en file sont toujours d'actualite.
"""
