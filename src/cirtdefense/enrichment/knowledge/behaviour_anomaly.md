---
categories: behaviour_anomaly
mitre: T1078 T1530
---

# Anomalie comportementale (UEBA)

## Description
Ecart significatif entre le comportement observe d'une entite (utilisateur ou
machine) et son profil de reference : volume d'activite, horaires, diversite
des sources, categories d'evenements. Une anomalie comportementale n'est pas
en soi une attaque : c'est une presomption qui demande corroboration.

## Indicateurs caracteristiques
- Activite hors des plages horaires habituelles de l'entite.
- Multiplication des adresses sources pour un meme compte.
- Apparition de categories d'evenements absentes du profil.
- Volume de donnees sortant sans commune mesure avec l'habitude.

## Techniques MITRE ATT&CK associees
T1078 (Valid Accounts) lorsque l'anomalie traduit un compte detourne,
T1530 (Data from Cloud Storage Object) pour les acces massifs a des donnees.

## Reponse documentee
La revocation des sessions actives de l'entite est la reponse documentee de
premier niveau : reversible, d'impact limite, elle force une nouvelle
authentification et interrompt un detournement de session en cours.

La desactivation du compte est documentee et reversible ; elle n'est retenue
que lorsque l'anomalie se conjugue a un autre signal de compromission, la
seule anomalie statistique ne justifiant pas d'immobiliser un utilisateur.

## Limites
Un profil de reference etabli sur trop peu d'observations produit des faux
positifs. Aucune action n'est engagee sur une entite dont le profil n'est pas
etabli.
