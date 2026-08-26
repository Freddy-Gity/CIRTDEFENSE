---
categories: privilege_escalation
mitre: T1068 T1548 T1134 T1098
---

# Elevation de privileges

## Description
Obtention par l'attaquant de droits superieurs a ceux du compte initialement
compromis, par exploitation d'une vulnerabilite locale, d'une mauvaise
configuration ou d'un jeton d'authentification.

## Indicateurs caracteristiques
- Ajout d'un compte a un groupe d'administration.
- Execution d'un processus en contexte systeme depuis un compte non privilegie.
- Manipulation de jeton, contournement du controle de compte utilisateur.
- Modification de tache planifiee s'executant avec des droits eleves.

## Techniques MITRE ATT&CK associees
T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control
Mechanism), T1134 (Access Token Manipulation), T1098 (Account Manipulation).

## Reponse documentee
La revocation des sessions actives du compte concerne est la reponse
documentee de premier niveau : elle invalide les jetons obtenus. L'action est
reversible, les sessions pouvant etre reouvertes apres verification.

La desactivation du compte est documentee et reversible par reactivation ;
elle est retenue lorsque l'elevation a abouti a la creation d'un acces
persistant.

L'isolement reseau de la machine est documente et reversible lorsque
l'elevation resulte de l'exploitation d'une vulnerabilite locale non corrigee.

## Limites
La desactivation d'un compte d'administration en cours d'usage legitime
interrompt les operations d'exploitation. La criticite doit etre consultee.
