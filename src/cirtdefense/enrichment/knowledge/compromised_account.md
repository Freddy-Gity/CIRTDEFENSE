---
categories: compromised_account
attack_code: C4
mitre: T1078 T1110 T1621
---

# Compte compromis (C4)

## Description
Utilisation d'identifiants valides par un tiers. Se manifeste par des
incoherences geographiques ou temporelles : connexions depuis deux points
inatteignables dans l'intervalle, activite aux heures ou l'entite n'opere
jamais.

## Indicateurs caracteristiques
- Connexions depuis des localisations geographiquement incompatibles.
- Activite en dehors des plages horaires habituelles de l'entite.
- Sequence d'echecs d'authentification suivie d'un succes.

## Reponse documentee
Les trois actions du catalogue s'appliquent conjointement.

Le verrouillage temporaire du compte est documente et partiellement
reversible : il expire de lui-meme, contrairement a une desactivation.

La revocation de toutes les sessions actives est documentee et reversible.

Le forcage d'une authentification renforcee est documente et reversible ;
il permet a l'utilisateur legitime de reprendre la main.

## Limites
Les trois actions genent l'utilisateur legitime le temps de la verification.
C'est le cout assume face a un compte potentiellement aux mains d'un tiers.
