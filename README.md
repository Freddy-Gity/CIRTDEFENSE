# CIRTDEFENSE

**Plateforme d'orchestration autonome de la reponse aux incidents de securite**
CDCF-CIRT-2026-01 / CDCT v3.0

La plateforme detecte, decide et **execute** les actions correctives sans
validation humaine prealable. L'analyste est informe apres coup et peut
annuler ; il n'autorise rien en amont.

---

## Le pivot v3.0, en une phrase

Les versions anterieures posaient l'absence d'execution automatique comme un
principe *non negociable* (EF-07, EF-13). La v3.0 l'inverse, parce que le
delai d'attente d'un analyste etait devenu le facteur dominant du delai de
confinement — et c'est precisement ce delai que l'attaquant exploite.

**Ce qui remplace l'analyste qui relisait :**

| Mode de defaillance | Garde-fou | Exigence |
|---|---|---|
| Agir sur une menace qu'on ne comprend pas | Refus d'agir sans fondement documentaire | EF-04 |
| Faire quelque chose d'irrattrapable | Perimetre borne aux actions annulables | EF-14 |
| Faire ce que le CIRT ne veut pas | Politique compilee par l'administrateur | EF-15 |
| Avoir raison sur la menace, nuire a la cible | Annulation autonome sur degradation | EF-25 |
| Se tromper en boucle | Coupe-circuit global | EF-26 |
| Ne pas pouvoir reconstituer les faits | Journal chaine et immuable | — |

Aucun de ces mecanismes ne met une action en attente d'un humain. Ce sont des
refus ou des corrections. Le systeme ne possede aucun etat « en attente de
validation » — et `tests/acceptance` le verifie sur le code.

Le raisonnement complet est dans [`docs/adr/ADR-001`](docs/adr/ADR-001-execution-autonome.md),
qui redige la section §1.4.3 attendue au CDCF.

---

## Demarrage

```bash
make install          # installation
make demo             # scenario de demonstration en 5 etapes
make test             # 162 tests
make test-recette     # les seuls criteres de recette (CDCF §5)
make run              # API sur http://localhost:8000
```

La suite est rejouee automatiquement sur Python 3.11 et 3.12 a chaque push
(`.github/workflows/ci.yml`), scenario de demonstration compris : une
regression qui ne casserait aucun test unitaire mais empecherait la
demonstration serait autrement decouverte le jour de la soutenance.

Puis `http://localhost:8000` pour le tableau de bord, `/docs` pour l'API.

Avec Docker :

```bash
docker compose up --build
```

La pile inclut un declencheur periodique de la boucle de controle : sans lui,
le rollback autonome ne serait pas reellement autonome.

---

## La demonstration en 5 etapes

`make demo` rejoue, sans aucun equipement reel :

1. **Une attaque est confinee sans intervention humaine.** Force brute
   detectee, adresse bloquee, sessions revoquees. Delai decision → action :
   quelques millisecondes.
2. **Une menace inconnue ne declenche rien.** Le contexte n'est pas fonde
   documentairement, le systeme s'abstient — la limite assumee du perimetre.
3. **Un confinement errone est annule seul.** Le service protege tombe apres
   l'action ; la boucle de controle l'impute, annule, et mesure son delai.
4. **Un emballement ouvre le coupe-circuit.** Trois annulations dans la
   fenetre : l'autonomie se suspend d'elle-meme. Seul l'administrateur rearme.
5. **Le journal est verifie de bout en bout.** Chaine d'empreintes intacte.

---

## Postures de deploiement

| Posture | Autonomie | Actionnement | Usage |
|---|---|---|---|
| Observation | `false` | `simulation` | Comparer les decisions du systeme a celles des analystes |
| Repetition | `true` | `simulation` | Recette et soutenance — journaux identiques a la production, aucun effet reel |
| Production | `true` | `live` | Actions reelles sur les equipements |

Posture par defaut : **repetition**. Le passage en production exige de brancher
les clients d'actuateurs du site (classes `Live*` dans `actuators/`) et la
validation de conformite legale signalee au CDCF §4.1.

Posture effective lisible en un appel : `GET /api/v1/status`.

---

## Ce que le systeme fait, et ne fait pas

**Couvert** — 11 familles de menaces documentees : force brute, C2, code
malveillant, exfiltration, deplacement lateral, attaque web, balayage, deni de
service, elevation de privileges, anomalie comportementale, degradation
d'infrastructure. 12 actions autonomes sur 15 au catalogue.

**Non couvert, et assume** :

- **Les menaces non documentees.** Une categorie absente de la base de
  connaissance rend le contexte non fonde : le systeme refuse d'agir. Un
  vecteur inedit ne sera pas traite automatiquement. C'est un choix — agir sur
  une hypothese serait pire.
- **Les actions irreversibles.** `wipe_disk`, `delete_account`,
  `shutdown_host` figurent au catalogue pour etre explicitement exclues. Elles
  restent des gestes humains.
- **Les attaques volumetriques distribuees.** Aucun moyen local ne suffit ; la
  plateforme constate et notifie.
- **Le deploiement en production reelle**, hors perimetre du CDCF : les
  actuateurs reels sont des squelettes portant les verifications independantes
  de l'equipement.

---

## Documentation

| Document | Contenu |
|---|---|
| [`docs/STRUCTURE.md`](docs/STRUCTURE.md) | Constitution du dossier : pourquoi ce decoupage, ou ajouter quoi |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Flux, decisions structurantes, modele de donnees |
| [`docs/TRACABILITE.md`](docs/TRACABILITE.md) | Matrice exigence → fichier → test |
| [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md) | Deploiement, supervision, incidents courants |
| [`docs/adr/`](docs/adr/) | Decisions d'architecture argumentees |
| [`docs/diagrams/`](docs/diagrams/) | Cas d'utilisation revise, sequences, composants |

---

## Structure

```
src/cirtdefense/
├── domain/          modele metier pur — invariants incontournables
├── ingestion/       adaptateur multi-sources          EF-18 a EF-20
├── detection/       UEBA + surveillance, dont EF-25
├── enrichment/      RAG + garde de non-invention      EF-03 · EF-04
├── orchestration/   le moteur autonome                EF-05 a EF-07, EF-14 a EF-26
├── actuators/       frontiere avec le monde reel
├── audit/           journal immuable + notification   EF-13
├── degraded/        mode degrade                      Axe 5
├── persistence/     schema et depots
└── api/             interface applicative             EF-11 · EF-12
```

Detail commente dans [`docs/STRUCTURE.md`](docs/STRUCTURE.md).

---

## Ligne de commande

```bash
cirtd status                          # posture d'autonomie et etat
cirtd ingest wazuh alerte.json        # ingerer et repondre
cirtd control-loop                    # passage de la boucle EF-25
cirtd compile-policy politique.txt    # verifier une politique avant activation
cirtd catalog --autonomous-only       # perimetre exact de l'autonomie
cirtd audit --verify                  # integrite du journal
cirtd breaker trip --reason "..."     # arret d'urgence
```

---

## Avertissement

Cette plateforme execute des actions correctives sans validation humaine
prealable. En posture `live`, elle modifie l'etat d'equipements de production.

Ne la deployer en production qu'apres :

1. une periode d'observation documentee ;
2. la validation de conformite legale avec le maitre d'ouvrage CIRT/ANTIC —
   l'assistance a la decision et l'action autonome n'engagent pas les memes
   responsabilites ;
3. le remplacement des jetons d'authentification par defaut ;
4. le branchement et le test des actuateurs reels sur un perimetre restreint.
