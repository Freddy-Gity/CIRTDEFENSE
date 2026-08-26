---
categories: scan
mitre: T1046 T1595 T1018
---

# Balayage et reconnaissance reseau

## Description
Enumeration des machines, des ports ouverts et des services exposes. Le
balayage precede l'exploitation et constitue un signal precoce, mais de
gravite intrinseque faible.

## Indicateurs caracteristiques
- Connexions vers un grand nombre de ports depuis une meme source.
- Balayage horizontal : meme port sur de nombreuses adresses.
- Signature d'outil de balayage dans les en-tetes ou le sequencement.

## Techniques MITRE ATT&CK associees
T1046 (Network Service Discovery), T1595 (Active Scanning),
T1018 (Remote System Discovery).

## Reponse documentee
La limitation de debit sur l'adresse source est la reponse documentee de
premier niveau : elle neutralise l'efficacite du balayage sans couper une
source potentiellement legitime. L'action est reversible par retrait de la
limitation.

Le blocage de l'adresse source est documente et reversible ; il est retenu
lorsque le balayage persiste apres limitation, ou lorsque la source est deja
connue de la veille comme malveillante.

## Limites
Un balayage depuis une source interne correspond frequemment a un outil
d'inventaire legitime. La zone de l'actif source doit etre consultee avant
toute action de blocage.
