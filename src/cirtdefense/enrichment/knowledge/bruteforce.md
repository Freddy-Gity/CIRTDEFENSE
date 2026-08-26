---
categories: bruteforce
mitre: T1110 T1110.001 T1110.003 T1078
---

# Attaque par force brute sur authentification

## Description
Une attaque par force brute (bruteforce) consiste a tenter un grand nombre de
combinaisons identifiant / mot de passe contre un service d'authentification
expose : SSH, RDP, VPN, portail web, messagerie. La variante par pulverisation
de mots de passe (password spray) essaie un mot de passe courant contre de
nombreux comptes, ce qui contourne les verrouillages par compte.

## Indicateurs caracteristiques
- Volume anormal d'echecs d'authentification depuis une meme adresse source.
- Echecs repartis sur de nombreux comptes depuis une source unique.
- Tentatives hors heures ouvrables sur des comptes a privileges.
- Succes d'authentification survenant immediatement apres une serie d'echecs :
  signal fort de compromission effective du compte.

## Techniques MITRE ATT&CK associees
T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying),
T1078 (Valid Accounts) lorsque l'attaque a abouti.

## Reponse documentee
La reponse de premier niveau est le blocage de l'adresse source au pare-feu,
action reversible dont l'annulation consiste a retirer la regle. Elle est
appropriee lorsque la source est externe au systeme d'information.

Lorsque des echecs concernent un compte unique et que l'authentification a
fini par reussir, la desactivation temporaire du compte concerne est la
reponse documentee : elle interrompt l'usage du compte compromis. Cette action
est reversible par reactivation du compte.

Le blocage d'une adresse source appartenant a une plage interne de confiance
est deconseille : il coupe un usage legitime pour un cout superieur au gain.

## Limites
Une adresse source derriere un relais partage (NAT operateur, passerelle
d'entreprise) fait porter le blocage sur des utilisateurs innocents. Le
rayon d'impact de l'action doit etre evalue avant blocage.
