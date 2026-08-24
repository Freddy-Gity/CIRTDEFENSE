---
categories: lateral_movement
mitre: T1021 T1021.002 T1550 T1078
---

# Deplacement lateral

## Description
Progression de l'attaquant d'une machine compromise vers d'autres machines du
meme reseau, en reutilisant des identifiants valides ou en exploitant des
services d'administration a distance.

## Indicateurs caracteristiques
- Authentifications d'un meme compte sur un nombre inhabituel de machines.
- Creation de service distant, execution via SMB ou WMI.
- Utilisation d'outils d'administration a distance hors du perimetre habituel.
- Reutilisation d'empreinte d'authentification (pass the hash).

## Techniques MITRE ATT&CK associees
T1021 (Remote Services), T1021.002 (SMB/Windows Admin Shares), T1550 (Use
Alternate Authentication Material), T1078 (Valid Accounts).

## Reponse documentee
La desactivation du compte utilise pour la progression est la reponse
documentee de premier niveau : elle coupe le moyen de deplacement sans
immobiliser les machines. L'action est reversible par reactivation.

L'isolement reseau de la machine d'origine est documente et reversible ; il
est retenu lorsque plusieurs comptes distincts sont impliques, ce qui indique
que la machine elle-meme est le point de depart.

La revocation des sessions actives du compte concerne est une reponse
documentee et reversible : les sessions peuvent etre reouvertes apres
verification.

## Limites
La desactivation d'un compte de service utilise par des traitements
automatises interrompt ces traitements. La criticite du compte doit etre
consultee avant l'action.
