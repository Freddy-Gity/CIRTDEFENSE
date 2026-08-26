---
categories: ddos_volumetric
attack_code: A1
mitre: T1498 T1498.001 T1498.002
---

# DDoS volumetrique (A1)

## Description
Saturation deliberee du lien reseau par un volume de trafic depassant la
capacite de transit : inondation SYN ou UDP, amplification via DNS ou NTP.
Le lien est sature avant que le trafic n'atteigne les equipements du site, ce
qui rend toute regle locale inoperante.

## Indicateurs caracteristiques
- Pic de trafic entrant sans rapport avec l'activite habituelle.
- Saturation de la bande passante du lien de transit.
- Sources multiples emettant un trafic homogene et sans etat.
- Reponses d'amplification (DNS, NTP) sans requete correspondante.

## Reponse documentee
L'activation du nettoyage de trafic (scrubbing) en bordure est la reponse
documentee de premier niveau : elle s'exerce en amont du lien sature, seul
endroit ou elle peut avoir un effet. L'action est reversible, la regle
portant une duree de vie courte.

Le trou noir (blackholing) des adresses sources en tete de volumetrie est
documente et reversible. Il n'est efficace que si la volumetrie se concentre
sur un petit nombre de sources.

La limitation de debit en bordure est documentee et reversible.

## Limites
Contre une attaque veritablement distribuee, aucune action locale ni de
bordure ne suffit : l'attenuation releve de l'operateur de transit. Le
systeme constate alors, notifie, et se retient d'engager des actions qui
aggraveraient l'indisponibilite.
