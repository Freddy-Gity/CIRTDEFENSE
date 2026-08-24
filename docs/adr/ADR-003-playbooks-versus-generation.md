# ADR-003 — Le choix de l'action vient d'un playbook, jamais d'un texte genere

**Statut** : acte

---

## Contexte

La plateforme s'appuie sur un modele de langage pour l'enrichissement (RAG) et
pour la compilation de la politique. Une conception plus directe consisterait
a demander au modele quelle action entreprendre, en lui fournissant le
contexte enrichi.

## Decision

Le choix de l'action est fait par un **playbook YAML versionne**
(`orchestration/playbooks/`). Le modele de langage n'intervient :

- ni dans le choix de l'action ;
- ni dans son parametrage ;
- ni dans l'evaluation de la politique au moment de l'execution.

Il sert a la recherche documentaire et, hors du chemin d'execution, a la
compilation d'une politique — compilation dont le resultat est un ensemble de
predicats relisibles, pas un texte.

## Justification

**La question « pourquoi ? » doit avoir une reponse consultable.** Sans
validation humaine en amont, la seule defense d'une action est sa
justification a posteriori. Un playbook rend une reponse exacte : telle regle
de tel fichier, dans telle version. Un modele generatif rend au mieux une
reconstruction plausible de son propre raisonnement — ce qui n'est pas la
meme chose, et ne se verifie pas.

**Le determinisme est une exigence, pas un confort.** La meme menace doit
produire la meme reponse. Un modele generatif, meme a temperature nulle, n'en
offre aucune garantie entre deux versions du modele. Un playbook si.

**Le perimetre d'action doit etre enumerable.** On doit pouvoir dire
exactement ce que le systeme est capable de faire. Avec des playbooks, c'est
la reunion de leurs actions, intersectee avec le catalogue de reversibilite :
un ensemble fini, inspectable, publiable. Avec une generation libre, le
perimetre est l'espace des sorties du modele.

**Les playbooks sont revisables par des humains du metier.** Un analyste du
CIRT peut lire, critiquer et corriger un fichier YAML de vingt lignes. C'est
la condition pour que la connaissance des analystes entre reellement dans le
systeme — et le seul moyen de la corriger apres un incident.

**La contrainte de non-invention (EF-04) porte alors sur le bon objet.** Elle
verifie que le *contexte* est documente. Si l'action etait generee, il
faudrait en outre verifier que l'action elle-meme n'est pas inventee —
c'est-a-dire resoudre un probleme nettement plus difficile, avec pour seul
outil le modele qui vient de produire la sortie a verifier.

## Consequences

- Ajouter une famille de menace demande deux fichiers : un document de
  connaissance et un playbook. C'est un cout reel, assume.
- Une menace sans playbook ne declenche aucune action. C'est visible dans la
  trace de decision, pas silencieux.
- La qualite du systeme depend de la qualite des playbooks. Ils sont donc
  versionnes, dates et cites dans chaque decision.

## Ce que cela n'exclut pas

Une evolution ulterieure pourrait faire **proposer** par un modele un
playbook, revu et valide par un analyste avant integration. Le modele
contribuerait alors a la conception du systeme, pas a ses decisions
d'execution. La distinction est ce qui compte ici.
