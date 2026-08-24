"""Mode degrade (Axe 5) : fonctionnement en perte de connectivite.

L'Axe 5 gagne en importance avec le pivot v3.0. Un systeme qui agit seul doit
savoir ce qu'il fait quand il ne voit plus ses equipements : continuer a agir
a l'aveugle serait le pire comportement, puisque la boucle de controle EF-25
ne pourrait plus constater ses propres degats.

La regle retenue est donc : en mode degrade, le systeme **observe et met en
file**, il n'agit pas. Il rejoue a la reprise, apres avoir verifie que les
evenements en file sont toujours d'actualite.
"""
