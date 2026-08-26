---
categories: dos
mitre: T1498 T1499
---

# Deni de service

## Description
Saturation deliberee d'un service ou d'un lien reseau visant a le rendre
indisponible. La forme distribuee (DDoS) mobilise de nombreuses sources, ce
qui rend le blocage unitaire inoperant.

## Indicateurs caracteristiques
- Effondrement du debit utile et hausse brutale de la latence.
- Volume de connexions incompletes (inondation SYN).
- Taux d'erreur en forte hausse sur le service cible.

## Techniques MITRE ATT&CK associees
T1498 (Network Denial of Service), T1499 (Endpoint Denial of Service).

## Reponse documentee
La limitation de debit sur les sources identifiees est la reponse documentee
de premier niveau, reversible par retrait de la limitation.

Le blocage des sources majoritaires au pare-feu est documente et reversible.
Il n'est efficace que si les sources sont peu nombreuses.

## Limites
Contre une attaque volumetrique distribuee, aucune action locale ne suffit :
l'attenuation releve de l'operateur de transit. Le systeme documente alors
l'incident et notifie sans pretendre le resoudre seul.
