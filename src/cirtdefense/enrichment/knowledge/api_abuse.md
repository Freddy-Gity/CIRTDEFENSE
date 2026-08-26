---
categories: api_abuse
attack_code: B6
mitre: T1078 T1190
---

# Abus d'interface applicative (B6)

## Description
Utilisation d'une cle ou d'un jeton d'API au-dela de l'usage prevu :
extraction massive de donnees, contournement des limitations de debit par
rotation de jetons ou d'adresses.

## Indicateurs caracteristiques
- Volume de requetes anormal rapporte a une cle ou un jeton donne.
- Enumeration sequentielle d'identifiants de ressources.
- Requetes provenant d'origines incompatibles avec l'usage declare du jeton.

## Reponse documentee
La revocation temporaire du jeton est la reponse documentee de premier
niveau. Elle est reversible : un nouveau jeton peut etre emis pour la meme
application.

Le renforcement de la limitation de debit est documente et reversible.

## Limites
La revocation d'un jeton interrompt une integration legitime si le jeton
avait ete detourne plutot que cree par l'attaquant. Le rayon d'impact doit
etre evalue avant revocation d'un jeton de service.
