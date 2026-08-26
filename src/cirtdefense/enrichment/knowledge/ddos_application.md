---
categories: ddos_application
attack_code: A2
mitre: T1499 T1499.002 T1499.003
---

# DDoS applicatif (A2)

## Description
Epuisement des ressources applicatives — connexions, sessions, fils
d'execution — par un volume de requetes modeste en octets mais couteux a
traiter. L'inondation HTTP et Slowloris en sont les formes courantes. Le
volume reseau restant faible, la detection volumetrique ne voit rien.

## Indicateurs caracteristiques
- Nombre de connexions ou de sessions simultanees anormalement eleve.
- Temps de reponse degrade sans hausse correspondante du trafic en octets.
- Connexions maintenues ouvertes sans emission de donnees (Slowloris).
- Requetes ciblant systematiquement les points d'entree les plus couteux.

## Reponse documentee
La regle de limitation de debit par adresse ou par session au pare-feu
applicatif est la reponse documentee de premier niveau. Elle est reversible
par retrait de la regle.

La fermeture des connexions inactives est documentee ; elle libere les
emplacements accapares. Elle est partiellement reversible : les connexions
fermees ne sont pas retablies, les clients legitimes se reconnectent.

## Limites
Une limitation trop stricte degrade l'experience des utilisateurs legitimes.
Le seuil doit etre calibre sur le trafic nominal du service concerne.
