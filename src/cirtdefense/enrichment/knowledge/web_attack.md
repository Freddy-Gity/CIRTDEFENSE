---
categories: web_attack
mitre: T1190 T1505.003 T1059
---

# Attaque applicative web

## Description
Exploitation d'une vulnerabilite d'une application web exposee : injection SQL,
script intersite (XSS), traversee de chemin, televersement de web shell.

## Indicateurs caracteristiques
- Motifs d'injection dans les parametres de requete.
- Codes de reponse anormaux en rafale sur un meme point d'entree.
- Creation d'un fichier executable dans un repertoire servi par le serveur web.
- Requetes provenant d'outils automatises identifiables par leur en-tete.

## Techniques MITRE ATT&CK associees
T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell),
T1059 (Command and Scripting Interpreter).

## Reponse documentee
Le blocage de l'adresse source au pare-feu ou sur le pare-feu applicatif est
la reponse documentee de premier niveau, reversible par retrait de la regle.

La mise en quarantaine du fichier televerse identifie comme web shell est une
reponse documentee et reversible par restauration.

La limitation de debit sur la source est une reponse documentee et reversible,
adaptee lorsque la source emet un volume eleve sans qu'une compromission soit
etablie.

## Limites
Le blocage par adresse source est inefficace contre une attaque distribuee.
Le correctif applicatif reste la seule reponse durable et releve de l'equipe
applicative, hors du perimetre de la reponse automatique.
