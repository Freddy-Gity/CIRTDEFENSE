# ADR-004 — Ce que la plateforme fait quand un agent ecarte un geste

**Statut** : acte

---

## Contexte

L'alerte persistante (EF-28) inscrit les gestes a effet durable que la
plateforme refuse de s'autoriser seule. Trois issues s'offrent a l'agent :
confirmer, se charger du geste lui-meme, ou l'ecarter.

L'issue « ecarter » posait une question restee sans reponse. Un refus ne rend
pas la menace inoffensive : il dit seulement que *ce geste-la* ne convient
pas. Refermer le dossier sur ce refus laissait la menace entiere et la
plateforme inerte, alors qu'elle sait souvent faire autre chose.

Deux ecueils symetriques se presentaient :

- **ne rien faire** — « ecarter » devient un bouton d'abandon, et la
  responsabilite bascule silencieusement sur un agent qui vient justement de
  dire qu'il ne voulait pas de ce geste ;
- **passer outre** — appliquer quand meme un confinement equivalent vide le
  refus de son sens, et l'agent apprend que son avis ne compte pas.

## Decision

Un refus declenche une **suite**, en trois temps.

### 1. Chercher un geste moins engageant servant le meme but

Le module `orchestration/substitution.py` s'appuie sur deux notions declarees :

- **le but vise** — une table explicite rattache chaque geste du catalogue a
  un objectif de confinement. Isoler une machine depuis l'agent de poste et la
  basculer dans un VLAN de quarantaine servent le meme but ;
- **l'engagement** — ce que le geste coute s'il se revele inutile, calcule
  depuis le catalogue de reversibilite : degre de reversibilite, rayon
  d'action, effet residuel apres annulation.

Une alternative n'est retenue que si elle est executable seul, **entierement
reversible**, et **strictement moins engageante** que le geste ecarte.

### 2. Prendre une mesure proportionnee a la dangerosite

Sous le seuil `decline_quarantine_threshold` (7/10 par defaut), l'actif passe
en **surveillance rapprochee** : aucun geste sur les equipements, le refus
s'applique tel quel, l'incident reste ouvert. Au-dessus, la plateforme
applique le geste de substitution retenu.

**Le geste ecarte n'est jamais rejoue** — ni sous son nom, ni sous un autre.
C'est ce qui distingue une substitution d'un contournement.

### 3. Soumettre la proposition, et la rendre acceptable

Une proposition qu'on ne peut pas accepter est un commentaire. La route
`POST /pending/{id}/substitute` execute le geste retenu, avec les memes
garanties que tout autre : controle de pre-vol, journal, jeton d'annulation,
boucle de controle. Le geste applique vient du conseil enregistre, jamais de
la requete.

## La cascade d'intelligence

`orchestration/conseil.py` enchaine trois niveaux :

1. **recherche deterministe** — hors ligne, reproductible, sans modele ;
2. **redaction** — un modele de langage reformule le « pourquoi celui-ci » ;
3. **choix assiste** — le modele designe, *parmi les candidats deja calcules*,
   celui qui convient le mieux.

L'invariant qui rend le niveau 3 acceptable : **le modele choisit dans une
liste, il ne la fabrique pas**. Tout candidat a deja passe les trois
conditions de la substitution. Un modele qui repondrait n'importe quoi ne peut
pas faire sortir un geste dangereux — sa reponse est confrontee a la liste et
rejetee si elle n'y figure pas. Un test le verifie avec un fournisseur qui
propose deliberement d'effacer un disque.

Le niveau employe est declare a l'agent : il doit savoir si un modele est
intervenu dans ce qu'il lit.

## Rapport a l'ADR-003

L'ADR-003 interdit au modele de choisir l'action **executee sans validation**.
Ici, rien n'est execute sur la foi du modele : on prepare une proposition
qu'un agent lira et acceptera ou non, et le confinement automatique du cas 2
retient le premier candidat de la liste deterministe. La distinction est celle
entre concevoir la reponse et la decider ; l'ADR-003 tient.

## Consequences

- « Je m'en charge » n'est plus une cloture mais un **engagement** : le dossier
  passe en prise en charge et reste visible jusqu'a ce que l'agent rende
  compte. Un engagement que plus personne ne voit est le defaut meme que
  l'alerte persistante corrige.
- La table des buts est de la connaissance metier : elle se lit, se critique et
  se corrige par un analyste du CIRT sans toucher au moteur. Elle demande donc
  une relecture metier, au meme titre qu'un playbook.
- Le classement des alternatives depend de la justesse du catalogue de
  reversibilite. Une entree mal declaree y produit une proposition mal classee
  — c'est le bon endroit pour la corriger, mais il faut la corriger.
