---
categories: session_hijacking
attack_code: B7
mitre: T1550 T1539 T1078
---

# Detournement de session (B7)

## Description
Reutilisation par un tiers d'un jeton de session valide, obtenu par vol,
interception ou prediction. L'attaquant herite des droits de l'utilisateur
sans jamais s'authentifier.

## Indicateurs caracteristiques
- Meme session utilisee depuis deux localisations geographiquement
  incompatibles dans un intervalle trop court.
- Reutilisation d'un jeton apres deconnexion declaree.
- Changement brutal d'empreinte de navigateur sur une session etablie.

## Reponse documentee
La revocation de la session ou du jeton concerne est la reponse documentee
de premier niveau, reversible : l'utilisateur legitime se reauthentifie.

Le forcage d'une authentification renforcee est documente et reversible ; il
distingue l'utilisateur legitime, qui detient le second facteur, de
l'attaquant qui ne le detient pas.

## Limites
La revocation impose une reconnexion a l'utilisateur legitime. C'est une
gene mineure au regard de l'acces non autorise qu'elle interrompt.
