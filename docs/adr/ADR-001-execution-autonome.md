# ADR-001 — Execution autonome sans validation humaine prealable

**Statut** : acte (CDCF/CDCT v3.0)
**Inverse** : EF-07 et EF-13 des versions v2.0 et v2.1, ou l'absence
d'execution automatique etait qualifiee de principe *non negociable*.

---

## Contexte

Les versions anterieures du cahier des charges posaient que la plateforme
produirait des recommandations soumises a la validation d'un analyste. Ce
principe reposait sur une hypothese implicite : qu'un analyste est disponible
au moment ou la recommandation est produite.

Cette hypothese ne tient pas dans le contexte d'exploitation vise. Un CIRT
national traite des incidents en dehors des heures ouvrables, avec un effectif
d'analystes limite, sur un perimetre etendu. Le delai entre la detection et la
validation devient le facteur dominant du delai de confinement — et ce delai
est precisement ce que l'attaquant exploite : une progression laterale ou un
chiffrement par rancongiciel se comptent en minutes.

## Decision

La plateforme execute toute action corrective retenue par le moteur, sans
validation humaine prealable, quel que soit le score de confiance.

## Justification du changement de posture de risque

Le renversement d'un principe qualifie de non negociable appelle une
justification explicite. Elle tient en trois points.

**1. Le risque n'est pas cree, il est deplace.** En v2.1, le risque residuel
etait celui d'un confinement tardif : l'attaque progresse pendant que la
recommandation attend. En v3.0, il devient celui d'un confinement errone : une
action inutile ou nuisible est appliquee. Les deux risques sont reels ; le
second a la propriete d'etre **detectable et reversible**, ce que le premier
n'est pas. On ne rattrape pas un chiffrement acheve ; on retire une regle de
pare-feu.

**2. L'autonomie est bornee au reversible.** Elle ne s'exerce que sur les
actions du catalogue dont l'annulation est garantie (EF-14). Trois actions
irreversibles figurent au catalogue precisement pour etre exclues :
`wipe_disk`, `delete_account`, `shutdown_host`. Une action irreversible reste
un geste humain. Le perimetre autonome est donc, par construction, celui ou
une erreur se repare.

**3. Le controle humain n'est pas supprime, il est deplace.** L'analyste
conserve un pouvoir d'annulation integral, exerce apres coup. Ce que la v3.0
supprime, c'est le **blocage** en amont, pas le recours.

## Mesures compensatoires retenues

| Mesure | Ce qu'elle couvre | Implantation |
|---|---|---|
| Garde de non-invention (EF-04) | Le systeme agit sur une menace qu'il ne comprend pas | `enrichment/grounding.py` |
| Catalogue de reversibilite (EF-14) | Le systeme fait quelque chose d'irrattrapable | `orchestration/reversibility.py` |
| Politique compilee (EF-15) | Le systeme fait quelque chose que le CIRT ne veut pas | `orchestration/policy_compiler.py` |
| Boucle de controle fermee (EF-25) | Le systeme a raison sur la menace mais nuit a la cible | `orchestration/rollback.py` |
| Coupe-circuit (EF-26) | Le systeme se trompe en boucle | `orchestration/circuit_breaker.py` |
| Journal immuable | On ne peut pas reconstituer ce qui s'est passe | `audit/ledger.py` |
| Notification a posteriori (EF-13) | L'analyste decouvre trop tard | `audit/notifier.py` |

Ces mesures couvrent des modes de defaillance **distincts** : aucune ne rend
les autres superflues.

## Mesures compensatoires ecartees

**Validation prealable pour les actions a fort rayon d'impact.** Ecartee : ce
serait retablir EF-13 sous un seuil, donc conserver le probleme initial pour
les cas les plus urgents — ceux qui ont justement le plus fort rayon d'impact.
La contrainte de rayon d'impact est traitee par la politique, qui **refuse**
au lieu de mettre en attente.

**Delai de grace avant application, permettant a un analyste d'interrompre.**
Ecartee : un delai qu'aucun analyste ne surveille est un delai perdu ; un
delai qu'un analyste surveille est une validation prealable deguisee.

**Seuil de confiance en deca duquel on n'agit pas.** Ecartee comme mecanisme
principal : le score de confiance d'un modele n'est pas une probabilite
calibree et n'est pas comparable d'une source a l'autre. Le fondement
documentaire (EF-04), verifiable, lui est prefere. La confiance reste utilisee
comme condition dans les playbooks, ou elle a un sens local.

## Limites assumees

Ce que l'autonomie totale **ne couvre pas**, et qui doit etre dit :

1. **Les actions hors catalogue.** Une menace appelant une reponse non
   repertoriee ne declenche rien. Le systeme journalise et notifie.

2. **Les menaces non documentees.** Une categorie absente de la base de
   connaissance rend le contexte non fonde : le systeme refuse d'agir. C'est
   une limite reelle — un vecteur inedit ne sera pas traite automatiquement —
   et c'est un choix delibere : agir sur une hypothese serait pire.

3. **Les attaques distribuees a grande echelle.** Une attaque volumetrique
   depasse les moyens locaux ; la plateforme constate et notifie.

4. **La qualite des donnees d'entree.** Une source mal configuree produit des
   evenements errones sur lesquels le systeme agira. La deduplication et la
   correlation limitent l'amplification, elles ne corrigent pas la source.

## Consequence a verifier hors du champ technique

La conformite legale camerounaise sur l'action corrective automatisee doit
etre revalidee avec le maitre d'ouvrage CIRT/ANTIC. L'assistance a la decision
et l'action autonome n'engagent pas les memes responsabilites, et le CDCF §4.1
signale ce point comme ouvert. **Cette validation ne releve pas de
l'implantation** et conditionne le passage en posture de production.
