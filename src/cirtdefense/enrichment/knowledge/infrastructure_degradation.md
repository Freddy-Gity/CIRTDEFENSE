---
categories: infrastructure_degradation
---

# Degradation de service d'infrastructure

## Description
Sortie d'un service de ses seuils nominaux : indisponibilite, latence
excessive, taux d'erreur eleve, effondrement du debit. La cause peut etre
malveillante ou accidentelle, et cette distinction ne peut pas toujours etre
etablie au moment de la detection.

## Indicateurs caracteristiques
- Cible injoignable par la sonde de sante.
- Latence superieure au seuil de service defini pour la cible.
- Taux d'erreur superieur au seuil de service.
- Debit utile inferieur au minimum attendu.

## Reponse documentee
La notification de l'equipe d'exploitation est la reponse documentee de
premier niveau. Une degradation dont la cause n'est pas etablie comme
malveillante ne justifie pas d'action corrective automatique : le risque
d'aggraver la panne par une action inadaptee depasse le benefice attendu.

Lorsque la degradation coincide avec une action corrective que la plateforme
vient d'executer sur la meme cible, la reponse documentee est l'annulation
automatique de cette action, conformement a la boucle de controle fermee.

## Limites
La correction d'une panne d'infrastructure d'origine non malveillante sort du
perimetre de la plateforme. Le systeme constate, notifie et se retient d'agir.
