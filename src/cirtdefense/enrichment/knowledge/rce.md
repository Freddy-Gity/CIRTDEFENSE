---
categories: rce
attack_code: B3
mitre: T1190 T1059 T1203
---

# Execution de code distante (B3)

## Description
L'attaquant obtient l'execution de code arbitraire sur l'hote, via une
vulnerabilite applicative ou une deserialisation non maitrisee. C'est la
compromission la plus directe : elle donne un acces equivalent a celui du
service exploite.

## Indicateurs caracteristiques
- Processus enfant inattendu lance par un service applicatif (interpreteur
  de commandes issu d'un serveur web, par exemple).
- Connexion sortante initiee par un processus applicatif.
- Ecriture de fichiers dans des repertoires servis par l'application.

## Reponse documentee
L'isolation reseau immediate de l'hote est la reponse documentee de premier
niveau. Elle est partiellement reversible : la quarantaine se leve, mais
l'etat applicatif et les sessions en cours sont perdus.

L'arret du processus suspect est documente et partiellement reversible.

## Limites
L'isolation stoppe l'exploitation en cours mais ne retire pas une persistance
deja installee. Une investigation est necessaire avant remise en service.
