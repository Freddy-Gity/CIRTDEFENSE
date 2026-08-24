# Architecture

## 1. Le probleme pose par le pivot v3.0

Le CDCT v2.0/v2.1 posait comme principe *non negociable* l'absence de toute
execution automatique (EF-07) et la validation manuelle des recommandations
par l'analyste (EF-13). La v3.0 inverse ces deux principes.

Ce n'est pas un changement de module, c'est un changement de nature du
systeme. En v2.1, une erreur du moteur produisait une recommandation
douteuse qu'un humain ecartait ; le cout d'une erreur etait le temps de
lecture d'un analyste. En v3.0, la meme erreur produit une regle de pare-feu
qui coupe un service de production.

**L'architecture repond a une question unique : par quoi remplace-t-on
l'analyste qui relisait ?**

Quatre mecanismes s'y substituent, et ils ne sont pas interchangeables — ils
couvrent des modes de defaillance differents :

| Mode de defaillance | Mecanisme | Fichier |
|---|---|---|
| Le systeme agit sur une menace qu'il ne comprend pas | Garde de non-invention (EF-04) | `enrichment/grounding.py` |
| Le systeme fait quelque chose d'irrattrapable | Catalogue de reversibilite (EF-14) | `orchestration/reversibility.py` |
| Le systeme fait quelque chose que le CIRT ne veut pas | Politique compilee (EF-15) | `orchestration/policy_compiler.py` |
| Le systeme a raison sur la menace mais nuit a la cible | Boucle de controle fermee (EF-25) | `orchestration/rollback.py` |
| Le systeme se trompe en boucle | Coupe-circuit (EF-26) | `orchestration/circuit_breaker.py` |

Aucun de ces mecanismes ne reintroduit d'attente humaine. Ce sont des refus
ou des corrections, jamais des mises en attente : le systeme ne possede aucun
etat « en attente de validation ».

---

## 2. Flux nominal

```
    Source externe            Sources internes
    (Wazuh, Suricata,         (UEBA, surveillance
     syslog, SIEM)             infrastructure)
          │                          │
          └──────────┬───────────────┘
                     ▼
        ┌────────────────────────────┐
        │  Adaptateur d'ingestion    │  EF-18/19/20
        │  normalise → dedoublonne   │
        │  → correle en incident     │
        └────────────┬───────────────┘
                     ▼
        ┌────────────────────────────┐
        │  Enrichissement (RAG)      │  EF-03/04
        │  recherche documentaire    │
        │  + garde de non-invention  │
        └────────────┬───────────────┘
                     │  contexte non fonde ──▶ REFUS D'AGIR
                     ▼
        ┌────────────────────────────┐
        │  Planificateur             │  EF-05/06
        │  playbook YAML → actions   │
        └────────────┬───────────────┘
                     │  hors catalogue ──────▶ REFUS D'AGIR
                     ▼
        ┌────────────────────────────┐
        │  Politique compilee        │  EF-15
        └────────────┬───────────────┘
                     │  action refusee ──────▶ REFUS D'AGIR
                     ▼
        ┌────────────────────────────┐
        │  Coupe-circuit             │  EF-26
        └────────────┬───────────────┘
                     │  circuit ouvert ──────▶ REFUS D'AGIR
                     ▼
        ┌────────────────────────────┐
        │  MESURE DE REFERENCE       │  ◀── indispensable a EF-25
        │  de la cible, AVANT action │
        └────────────┬───────────────┘
                     ▼
        ┌────────────────────────────┐
        │  EXECUTION                 │  EF-07 — sans validation
        └────────────┬───────────────┘
                     ├──────────▶ Journal d'audit (chaine)
                     └──────────▶ Notification a posteriori  EF-13
                     ▼
        ┌────────────────────────────┐
        │  Surveillance post-action  │  EF-25 — apres le delai de garde
        │  etat d'apres vs reference │
        └────────────┬───────────────┘
                     │  degradation imputee
                     ▼
        ┌────────────────────────────┐
        │  ANNULATION AUTONOME       │  delai borne et mesure
        └────────────┬───────────────┘
                     ▼
              Coupe-circuit : trop d'annulations ? → ouverture
```

---

## 3. Decisions structurantes

### 3.1 La mesure de reference precede l'execution

L'ordre des operations dans `executor.py` n'est pas negociable :

1. mesurer l'etat de la cible ;
2. executer ;
3. journaliser ;
4. notifier.

Inverser 1 et 2 rendrait toute imputation impossible. Le systeme constaterait
qu'une cible va mal *apres* avoir agi, sans pouvoir dire si c'est l'attaque ou
sa propre action qui en est la cause. Il annulerait alors soit tout, soit
rien — les deux etant inacceptables.

Une precision qui a son importance : la cible **surveillee** n'est pas la
cible **de l'action**. Bloquer `41.202.1.9` se mesure sur la sante de
`srv-web-01`, le service qu'on protege. Une premiere implantation comparait
la sante de la machine a celle de l'adresse bloquee — deux grandeurs sans
rapport — et annulait de ce fait des confinements parfaitement sains.

### 3.2 La reversibilite est une condition, pas une metadonnee

En v2.1, `Reversibility` aidait l'analyste a prioriser. En v3.0, c'est le
predicat qui autorise l'execution. Trois consequences :

- `ActionSpec.__post_init__` refuse la construction d'une action declaree
  reversible sans verbe d'annulation ;
- `Executor._preflight` verifie le catalogue au point de non-retour, et pas
  seulement a la planification — une action peut arriver par un autre chemin ;
- `IRREVERSIBLE_GUARD` est injecte dans **toute** politique compilee, y
  compris une politique qui dirait « autoriser tout ».

Trois entrees irreversibles figurent au catalogue (`wipe_disk`,
`delete_account`, `shutdown_host`) non pas pour etre executees, mais pour
rendre visible ce que l'autonomie ne couvre pas.

### 3.3 Le langage naturel n'est jamais sur le chemin d'execution

La politique de l'administrateur est compilee **une fois**, a priori, en
predicats. Au moment ou une action est evaluee, il n'y a plus de texte.

Cela garantit qu'une meme situation produit toujours la meme decision, et que
la decision est rejugeable. Le compilateur refuse par ailleurs de deviner :
une phrase non reconnue est rapportee comme non compilee. Une politique qui
paraitrait appliquee sans l'etre serait le pire resultat possible.

### 3.4 Le journal est chaine et immuable a deux niveaux

- **Applicatif** : chaque entree contient l'empreinte de la precedente ;
  `verify_chain()` rejoue la chaine et localise toute alteration.
- **Base** : deux declencheurs SQL interdisent `UPDATE` et `DELETE` sur la
  table.

La defense est redondante a dessein. Les declencheurs arretent une erreur de
programmation ou un acces applicatif malveillant ; le chainage detecte une
alteration faite directement sur le fichier de base, ou les declencheurs ne
s'appliquent pas.

### 3.5 En mode degrade, le systeme observe mais n'agit pas

Agir sans pouvoir mesurer l'effet de son action reviendrait a desactiver
EF-25 en silence. La regle retenue est donc : mise en file, puis rejeu a la
reprise, par la **chaine nominale** — pas par un chemin parallele qui
finirait par en diverger.

Les elements de plus de six heures ne sont pas rejoues : la situation qu'ils
decrivent a probablement change, et agir dessus serait agir sur une
photographie ancienne.

---

## 4. Modele de donnees

```
DetectionEvent ──┐
                 ├──▶ Incident ──▶ Decision ──▶ ActionResult
DetectionEvent ──┘        │            │              │
                          │            │              ▼
                          │            │        rollback_token
                          │            │              │
                          ▼            ▼              ▼
                     ┌──────────────────────────────────┐
                     │   audit_log (chaine, immuable)   │
                     └──────────────────────────────────┘
```

Points d'attention :

- `DetectionEvent` est **immuable** : c'est une observation, pas un etat.
- `Incident` est muable : c'est un agregat qui evolue.
- `ActionResult.rollback_token` est rendu par l'actuateur et identifie
  precisement ce qui a ete fait. Sans lui, l'annulation serait un geste
  inverse approximatif, pas un retour arriere.
- Les compteurs du portefeuille sont lus dans la table `actions`, jamais dans
  l'instantane stocke avec l'incident : cet instantane est fige au moment de
  l'execution et ignore les annulations survenues ensuite.

---

## 5. Extension

L'architecture est concue pour que l'ajout le plus frequent — une source, une
menace, une action — ne touche pas le moteur. Voir `docs/STRUCTURE.md` §3.

Le point d'extension le plus delicat est l'ajout d'un **actuateur reel**. Le
contrat exige deux proprietes que l'implantation doit garantir :

- **idempotence** : rejouer une action deja appliquee ne doit pas echouer ;
- **jeton d'annulation** : l'execution rend de quoi annuler exactement ce qui
  a ete fait.

Sans ces deux proprietes, la boucle EF-25 ne peut rien garantir, et
l'autonomie perd sa contrepartie.
