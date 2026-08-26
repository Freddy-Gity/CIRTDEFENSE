---
categories: unexpected_port
attack_code: D2
mitre: T1046 T1571
---

# Port inattendu ouvert (D2)

## Description
Ecart entre les ports effectivement ouverts sur un hote et ceux prevus par
la configuration de reference. Peut traduire une porte derobee comme une
simple erreur de deploiement.

## Indicateurs caracteristiques
- Port ouvert absent de la configuration attendue.
- Service non identifie repondant sur ce port.
- Apparition datant du dernier deploiement.

## Reponse documentee
La fermeture du port est la reponse documentee lorsque le port est sous
controle de la plateforme. Elle est reversible par reouverture.

Lorsque le port n'est pas sous controle de la plateforme, la reponse
documentee est l'alerte de derive de configuration.

## Limites
La fermeture d'un port peut interrompre un service legitime deploye hors
processus. La configuration de reference doit etre tenue a jour, faute de
quoi chaque deploiement legitime produit une alerte.
