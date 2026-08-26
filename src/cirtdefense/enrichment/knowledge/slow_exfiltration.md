---
categories: slow_exfiltration
attack_code: C3
mitre: T1074 T1030 T1567
---

# Exfiltration lente (C3)

## Description
Extraction progressive de donnees, chaque transfert restant sous les seuils
de detection volumetrique. Les donnees sont d'abord rassemblees dans un
espace intermediaire avant transfert, ce qui rend l'accumulation observable
avant la sortie.

## Indicateurs caracteristiques
- Accumulation progressive de donnees dans un espace non habituel.
- Transferts fractionnes reguliers, de volume constant et modere.
- Activite d'archivage ou de compression precedant les transferts.

## Reponse documentee
La restriction temporaire des droits d'ecriture et d'export du compte est la
reponse documentee de premier niveau. Elle est partiellement reversible : les
droits se retablissent, mais les exports tentes pendant la restriction ont
echoue et doivent etre relances.

Le signalement pour investigation est documente et systematique.

## Limites
La restriction n'a pas d'effet retroactif : le volume deja accumule ou deja
sorti n'est pas recupere. L'investigation doit en etablir l'ampleur.
