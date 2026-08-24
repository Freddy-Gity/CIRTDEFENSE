---
categories: abnormal_access
attack_code: C2
mitre: T1078 T1530
---

# Acces hors profil habituel (C2)

## Description
Consultation par une entite de ressources qu'elle n'a jamais accedees et qui
sortent de son perimetre metier. Signal comportemental faible : un changement
de poste ou de mission produit exactement la meme observation.

## Indicateurs caracteristiques
- Ressource jamais accedee auparavant par cette entite.
- Acces hors du perimetre metier declare.
- Absence de demande ou de ticket associe au changement de perimetre.

## Reponse documentee
Le blocage de l'acces en cours est la reponse documentee de premier niveau,
reversible et d'impact limite au seul acces concerne.

Le catalogue exclut explicitement la revocation du compte sur ce type
d'anomalie : le risque de faux positif y est plus eleve qu'ailleurs, et
l'immobilisation d'un utilisateur legitime couterait davantage que l'acces
constate.

## Limites
Un profil de reference etabli sur une periode trop courte produit des faux
positifs a chaque evolution legitime du perimetre d'un utilisateur.
