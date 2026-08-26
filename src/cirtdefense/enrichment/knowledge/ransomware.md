---
categories: ransomware
attack_code: A6
mitre: T1486 T1490 T1021 T1489
---

# Rancongiciel (A6)

## Description
Chiffrement de masse des donnees d'un hote, souvent accompagne d'une
propagation laterale vers les partages accessibles et d'une destruction des
sauvegardes locales. C'est le type d'attaque dont la fenetre d'action est la
plus courte : le chiffrement se compte en minutes.

## Indicateurs caracteristiques
- Taux de modification ou de chiffrement de fichiers anormalement eleve.
- Propagation SMB ou RDP vers d'autres hotes du meme segment.
- Extinction des services de sauvegarde, effacement des cliches instantanes.
- Depot d'une note de rancon dans les repertoires traites.

## Reponse documentee
L'isolation reseau immediate de l'hote par bascule en VLAN de quarantaine est
la reponse documentee de premier niveau. Elle est partiellement reversible :
la quarantaine se leve apres investigation, les connexions en cours sont
perdues.

Le blocage des protocoles de propagation laterale (SMB, RDP, WinRM) est
documente et reversible ; il coupe la progression sans isoler completement
l'hote de son agent de securite.

Le declenchement d'un instantane de sauvegarde est documente lorsqu'il est
disponible. L'instantane n'est jamais supprime automatiquement.

L'arret du processus de chiffrement identifie est documente et partiellement
reversible.

**Aucune action irreversible n'est engagee automatiquement.** La remediation
— restauration, reinstallation, effacement — releve d'une decision humaine
apres investigation.

## Limites
L'isolation limite la propagation mais ne recouvre pas les donnees deja
chiffrees. Sur un hote assurant un service vital, l'isolation interrompt ce
service : c'est un cout assume, la propagation etant le risque superieur.
