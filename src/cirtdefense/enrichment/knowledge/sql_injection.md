---
categories: sql_injection
attack_code: B1
mitre: T1190 T1059
---

# Injection SQL (B1)

## Description
Insertion de fragments SQL dans les parametres d'une application web afin de
detourner la requete construite par celle-ci : lecture de donnees hors
perimetre, contournement d'authentification, voire execution de commandes
selon la configuration du serveur de base de donnees.

## Indicateurs caracteristiques
- Motifs SQL dans les parametres de requete : apostrophes, UNION SELECT,
  commentaires, conditions toujours vraies.
- Erreurs de base de donnees renvoyees au client.
- Temps de reponse anormaux revelant une injection aveugle temporisee.

## Reponse documentee
La regle de blocage du motif au pare-feu applicatif est la reponse
documentee de premier niveau, reversible par retrait de la regle. Son rayon
d'impact est superieur a celui d'une regle reseau : un motif trop general
rejette du trafic legitime.

Le blocage temporaire de l'adresse source est documente et reversible.

## Limites
Le blocage de motif ne corrige pas la vulnerabilite applicative sous-jacente,
qui reste exploitable par une variante non couverte par la regle. Le
correctif applicatif releve de l'equipe de developpement.
