---
categories: exfiltration
mitre: T1041 T1048 T1567 T1560
---

# Exfiltration de donnees

## Description
Transfert non autorise de donnees depuis le systeme d'information vers une
destination controlee par l'attaquant. L'exfiltration suit generalement une
phase de collecte et intervient tardivement dans la chaine d'attaque, ce qui
en fait un signal d'urgence.

## Indicateurs caracteristiques
- Volume sortant anormalement eleve depuis un poste ou un serveur.
- Transfert vers un service de stockage externe non approuve.
- Tunnel DNS ou HTTPS vers un domaine inconnu.
- Activite d'archivage massive precedant le transfert.

## Techniques MITRE ATT&CK associees
T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative
Protocol), T1567 (Exfiltration Over Web Service), T1560 (Archive Collected Data).

## Reponse documentee
Le blocage de la destination externe au pare-feu interrompt le transfert en
cours ; l'action est reversible par retrait de la regle.

La limitation de debit sortant sur la machine concernee est une reponse
documentee et reversible, preferable au blocage complet lorsque la machine
assure par ailleurs un service legitime.

L'isolement reseau de la machine source est documente lorsque le volume
exfiltre continue de croitre malgre le blocage de la destination.

## Limites
Le blocage d'une destination unique est contourne des lors que l'attaquant
dispose d'une destination de repli. La surveillance du volume sortant doit
etre maintenue apres l'action.
