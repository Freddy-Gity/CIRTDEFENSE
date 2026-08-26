---
categories: webshell_upload
attack_code: B5
mitre: T1505.003 T1105
---

# Televersement de webshell (B5)

## Description
Depot d'un fichier executable ou interpretable dans un repertoire servi par
l'application, offrant a l'attaquant une console persistante accessible par
simple requete web.

## Indicateurs caracteristiques
- Fichier de type script depose dans un repertoire de televersement.
- Extension incoherente avec le type de contenu declare.
- Requetes ulterieures vers ce fichier depuis une source unique.

## Reponse documentee
La mise en quarantaine du fichier est la reponse documentee de premier
niveau. Le catalogue precise **deplacement, pas suppression** : le fichier
reste une piece d'investigation et l'action demeure reversible par
restauration.

Le blocage de l'adresse ayant procede au televersement est documente et
reversible.

## Limites
La quarantaine du fichier ne corrige pas la faille de televersement qui a
permis son depot. Un second fichier peut etre depose par le meme chemin.
