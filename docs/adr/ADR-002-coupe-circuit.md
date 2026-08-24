# ADR-002 — Inclusion du coupe-circuit global (EF-26)

**Statut** : acte — EF-26 est **incluse** au perimetre.
**Question ouverte tranchee** : plan de lancement §6.

---

## Contexte

Le plan de lancement laissait ouverte l'inclusion d'un arret d'urgence global,
en notant que son absence serait probablement questionnee en soutenance :
« comment arretez-vous le systeme si l'IA se trompe en boucle ? ».

## Decision

EF-26 est incluse. Le coupe-circuit est un interrupteur **global**, actionnable
par l'administrateur et **declenchable automatiquement** par le systeme
lui-meme.

## Justification

**Il ne contredit pas l'autonomie totale.** C'est le point qui compte. Un
coupe-circuit n'est pas un point de controle sur le chemin d'une action : il
n'existe aucun etat ou une action attendrait un humain. Le circuit est ferme —
toutes les actions partent sans validation — ou ouvert — aucune ne part. La
granularite est le systeme, pas l'action. EF-07 est integralement preservee.

**L'alternative est pire.** Sans coupe-circuit, la seule facon d'arreter un
systeme qui s'emballe serait d'eteindre le service. On perdrait alors la
journalisation en cours et la capacite d'annuler les actions deja engagees —
c'est-a-dire exactement les deux moyens dont on a besoin au pire moment.

**Le declenchement automatique est le mecanisme reel.** La voie manuelle
repond a la question de soutenance ; la voie automatique repond au probleme.
Par construction, un systeme autonome fonctionne quand personne ne regarde :
un garde-fou qui suppose un humain devant l'ecran ne garde rien. Le systeme
s'arrete donc lui-meme quand il constate qu'il se trompe en rafale —
annulations repetees dans une fenetre glissante, ou echecs d'actuateurs en
serie.

**Il rend le systeme discutable.** Un dispositif autonome sans arret d'urgence
est difficile a defendre devant une autorite de tutelle. Le coupe-circuit
offre une reponse concrete a une objection legitime, sans ceder sur le
principe.

## Consequences

- L'etat est **persistant** : un redemarrage ne relance pas une autonomie que
  le coupe-circuit venait d'interrompre. Sans cela, un simple redemarrage
  contournerait le garde-fou.
- Le **rearmement est exclusivement manuel**. Le systeme ne peut pas juger que
  la cause de son propre emballement a disparu ; un rearmement automatique
  produirait un cycle emballement / arret / emballement.
- Le declenchement, comme le rearmement, sont journalises avec leur motif et
  les compteurs observes au moment de la decision.
- Le cas d'utilisation « Configurer le coupe-circuit d'autonomie
  (Administrateur) » est ajoute au diagramme revise.

## Si l'exclusion avait ete retenue

Elle aurait exige une justification au CDCF §1.4.3 expliquant pourquoi aucun
arret d'urgence n'est prevu, et une procedure d'exploitation decrivant l'arret
du service comme unique recours, avec ses consequences sur la journalisation
et sur les actions en cours. Cette option a ete jugee plus couteuse a defendre
que le mecanisme lui-meme.
