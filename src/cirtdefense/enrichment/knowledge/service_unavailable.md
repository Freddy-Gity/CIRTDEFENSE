---
categories: service_unavailable
attack_code: D3
mitre: T1499 T1498
---

# Service indisponible (D3)

## Description
Echec repete de la sonde de disponibilite sur un service. La cause peut etre
une panne ou un deni de service ; la distinction n'est pas toujours etablie
au moment du constat, mais l'indisponibilite, elle, est un fait mesure.

## Indicateurs caracteristiques
- Echecs consecutifs de la sonde de disponibilite.
- Absence totale de reponse ou codes d'erreur systematiques.
- Effondrement du debit utile jusqu'a l'arret.

## Reponse documentee
La bascule vers un noeud de secours est la reponse documentee de premier
niveau lorsqu'un noeud de secours est declare. Elle est reversible par
rebascule.

Le redemarrage du service est documente lorsque le service est sous controle
de la plateforme. Il est partiellement reversible : l'interruption survenue
pendant le redemarrage ne se rattrape pas.

## Limites
Un redemarrage sans diagnostic peut masquer la cause reelle et se repeter.
Si l'indisponibilite resulte d'une attaque en cours, le redemarrage ne fait
que retarder l'echeance.
