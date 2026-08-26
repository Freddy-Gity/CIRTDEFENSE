---
categories: tls_certificate
attack_code: D1
mitre: 
---

# Certificat TLS expire ou faible (D1)

## Description
Certificat de service arrive a expiration, signe avec un algorithme obsolete,
ou dote d'une cle de taille insuffisante. Constat preventif : il signale une
faiblesse, pas une intrusion en cours.

## Indicateurs caracteristiques
- Date d'expiration depassee ou proche.
- Algorithme de signature obsolete.
- Taille de cle inferieure aux recommandations en vigueur.
- Chaine de certification incomplete.

## Reponse documentee
La notification accompagnee d'un rapport est la **seule** reponse documentee.

Le catalogue classe cette ligne « sans action corrective directe possible » :
le renouvellement d'un certificat depend d'une autorite de certification
externe, hors du controle de la plateforme. Aucune action automatique n'est
engagee, et cette abstention est un choix explicite plutot qu'une lacune.

## Limites
La plateforme ne peut ni emettre ni renouveler un certificat. Le traitement
releve integralement de l'equipe d'exploitation.
