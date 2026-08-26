---
categories: xss
attack_code: B2
mitre: T1059.007 T1189
---

# Script intersite — XSS (B2)

## Description
Injection de code executable dans le navigateur d'un autre utilisateur, par
un champ soumis mal filtre. La variante reflechie s'execute dans la reponse
immediate ; la variante stockee persiste dans les donnees applicatives et
touche tous les visiteurs ulterieurs.

## Indicateurs caracteristiques
- Balises de script ou gestionnaires d'evenements dans les champs soumis.
- Encodages destines a contourner un filtre (hexadecimal, URL, unicode).
- Contenu suspect retrouve dans des donnees deja enregistrees.

## Reponse documentee
Le blocage du motif au pare-feu applicatif est la reponse documentee de
premier niveau, reversible.

La sanitisation a la volee du champ concerne est documentee et reversible.

Lorsque le contenu est deja stocke, la reponse documentee est le
**signalement** : le retrait du contenu touche des donnees applicatives et
sort du perimetre des actions reversibles maitrisees.

## Limites
Un contenu deja stocke continue d'etre servi jusqu'a son retrait manuel. La
reponse automatique empeche l'aggravation, elle ne repare pas l'existant.
