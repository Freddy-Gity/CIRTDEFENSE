---
categories: config_drift
attack_code: D4
mitre: T1562 T1078
---

# Derive de configuration (D4)

## Description
Ecart entre la configuration observee d'un systeme et sa configuration de
reference. Peut resulter d'une intervention non tracee comme d'une
modification malveillante destinee a affaiblir une protection.

## Indicateurs caracteristiques
- Divergence entre l'etat observe et la reference.
- Modification non associee a un changement declare.
- Affaiblissement d'un parametre de securite.

## Reponse documentee
La restauration automatique de la configuration de reference est la reponse
documentee, **conditionnee a un delta mineur**. Elle est reversible : la
configuration relevee avant restauration est retablie sur annulation.

Le signalement est documente et systematique, quel que soit le delta.

## Limites
Au-dela d'un delta mineur, la restauration est refusee : une reference
obsolete ecraserait un changement legitime recent. La condition n'est pas
decorative, elle protege contre une correction pire que le mal.
