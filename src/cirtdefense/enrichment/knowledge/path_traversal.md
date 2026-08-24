---
categories: path_traversal
attack_code: B4
mitre: T1083 T1190
---

# Traversee de chemin, LFI et RFI (B4)

## Description
Manipulation d'un parametre de chemin afin d'acceder a des fichiers hors de
la racine applicative, voire d'inclure et d'executer un fichier local ou
distant.

## Indicateurs caracteristiques
- Motifs de remontee de repertoire dans les parametres.
- Chemins absolus vers des fichiers systeme sensibles.
- Inclusion d'une URL distante dans un parametre de chemin.

## Reponse documentee
Le blocage du motif au pare-feu applicatif est la reponse documentee de
premier niveau, reversible.

Le blocage du point d'entree vise est documente et reversible lorsque
l'exploitation se concentre sur une route identifiee.

## Limites
Le blocage de motif ne corrige pas la validation d'entree defaillante. Les
variantes d'encodage peuvent contourner une regle trop litterale.
