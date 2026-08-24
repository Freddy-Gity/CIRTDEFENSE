# ADR-004 — Journal d'audit chaine et immuable a deux niveaux

**Statut** : acte

---

## Contexte

Le CDCF demande de repositionner le journal d'audit des decisions comme
mecanisme de tracabilite **central** et non secondaire. Le motif est direct :
en v3.0, c'est la seule trace de ce que le systeme a fait sans intervention
humaine.

Un journal applicatif ordinaire ne suffit pas a cet usage. Il peut etre purge
par rotation, reecrit par un defaut de programmation, ou altere par quiconque
accede a la base.

## Decision

Le journal d'audit est protege a deux niveaux independants :

1. **Chainage applicatif** — chaque entree contient l'empreinte SHA-256 de la
   precedente. `verify_chain()` rejoue la chaine depuis l'origine et localise
   la premiere entree alteree.
2. **Immuabilite en base** — deux declencheurs SQL interdisent `UPDATE` et
   `DELETE` sur la table `audit_log`.

Le journal technique (`logging_setup.py`) reste distinct et n'a aucune valeur
probante.

## Justification de la redondance

Les deux niveaux couvrent des menaces differentes, et c'est pour cela qu'ils
coexistent :

- Les **declencheurs** arretent une modification passant par l'application :
  erreur de programmation, requete malveillante via une injection. Ils ne
  protegent pas contre un acces direct au fichier de base.
- Le **chainage** ne peut rien empecher, mais detecte toute alteration, y
  compris faite hors de l'application — ou les declencheurs, precisement, ne
  s'appliquent pas.

Aucun des deux ne rend l'autre superflu.

## Ce qui est journalise

Chaque etape de la chaine autonome, avec son motif :

| Type | Moment |
|---|---|
| `event.ingested` | Un evenement est accepte apres deduplication |
| `context.enriched` | Le contexte documentaire et son verdict de fondement |
| `decision.made` | La decision, sa trace, les actions ecartees et leur motif |
| `action.executed` / `action.failed` | Chaque action, avec son mode d'actionnement |
| `analyst.notified` | La notification a posteriori |
| `rollback.triggered` / `rollback.completed` / `rollback.failed` | La boucle EF-25 |
| `manual.rollback` | L'annulation par un analyste |
| `breaker.tripped` / `breaker.reset` | Le coupe-circuit, avec ses compteurs |
| `policy.compiled` | Une politique activee, avec son empreinte |
| `degraded.enter` / `degraded.replay` | Le mode degrade |

Le **mode d'actionnement** (`simulation` ou `live`) est consigne avec chaque
action : un auditeur doit pouvoir dire si une action tracee a reellement eu
lieu.

## Consequences

- Les ecritures sont serialisees par un verrou : le chainage impose un ordre
  total. C'est un cout de debit, acceptable a l'echelle visee.
- La table croit sans limite. Un archivage devra decouper la chaine par
  periodes en conservant l'empreinte de jonction — a traiter au deploiement.
- `GET /api/v1/audit/verify` doit toujours rendre `valid: true`. Un resultat
  negatif est un incident de securite sur la plateforme elle-meme, pas une
  anomalie de fonctionnement.
