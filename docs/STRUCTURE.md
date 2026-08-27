# Constitution du dossier de projet

Ce document explique **pourquoi** l'arborescence est ainsi et non autrement.
Chaque decision de decoupage repond a une contrainte du CDCF/CDCT v3.0, et en
particulier au pivot d'autonomie totale : quand plus personne ne relit une
action avant qu'elle ne parte, la structure du code devient elle-meme un
dispositif de securite.

---

## 1. Arborescence complete

```
CIRTDEFENSE/
├── README.md                     Presentation, demarrage rapide, posture
├── pyproject.toml                Dependances, outillage, points d'entree
├── Makefile                      Commandes d'exploitation et de recette
├── Dockerfile                    Image d'execution
├── docker-compose.yml            Pile complete + declencheur de la boucle EF-25
├── .env.example                  Configuration commentee, posture d'autonomie
├── .gitignore
│
├── docs/                         Documentation d'ingenierie
│   ├── STRUCTURE.md              Ce document
│   ├── ARCHITECTURE.md           Vue d'ensemble, flux, decisions structurantes
│   ├── TRACABILITE.md            Exigence -> fichier -> test (matrice)
│   ├── EXPLOITATION.md           Deploiement, supervision, incidents d'exploitation
│   ├── adr/                      Decisions d'architecture argumentees
│   │   ├── ADR-001-execution-autonome.md
│   │   ├── ADR-002-coupe-circuit.md
│   │   ├── ADR-003-playbooks-versus-generation.md
│   │   └── ADR-004-journal-immuable.md
│   └── diagrams/                 Diagrammes source (Mermaid)
│       ├── cas-utilisation-v3.mmd
│       ├── sequence-reponse-autonome.mmd
│       ├── sequence-boucle-controle.mmd
│       └── composants.mmd
│
├── src/cirtdefense/
│   ├── __init__.py
│   ├── main.py                   Application FastAPI
│   ├── cli.py                    Ligne de commande (exploitation, recette)
│   ├── config.py                 Configuration, posture d'autonomie explicite
│   ├── logging_setup.py          Journalisation technique (≠ journal d'audit)
│   ├── platform.py               Assemblage : ou toutes les pieces se branchent
│   │
│   ├── domain/                   ── Modele metier pur, sans aucune E/S ──
│   │   ├── enums.py              Vocabulaire ferme du domaine
│   │   ├── taxonomy.py           Catalogue CIRT : les 22 types d'attaques
│   │   ├── events.py             DetectionEvent, Asset (schema pivot EF-18/20)
│   │   ├── incident.py           Agregat de correlation, score de risque (Axe 4)
│   │   ├── action.py             ActionSpec, ActionResult, invariants EF-14
│   │   ├── decision.py           Decision et sa trace explicative
│   │   └── policy.py             Politique compilee, garde-fou d'irreversibilite
│   │
│   ├── ingestion/                ── Adaptateur d'ingestion (EF-18 a EF-20) ──
│   │   ├── adapter.py            Deduplication puis correlation
│   │   ├── registry.py           Enregistrement des normaliseurs
│   │   └── normalizers/
│   │       ├── mapping.py        Tables de correspondance partagees
│   │       ├── generic_json.py   Schema pivot, rejeu du mode degrade
│   │       ├── wazuh.py          Alertes Wazuh
│   │       ├── suricata.py       EVE JSON
│   │       └── syslog.py         RFC 5424 / RFC 3164
│   │
│   ├── detection/                ── Sources de detection internes ──
│   │   ├── ueba/                 EF-08 a EF-10
│   │   │   ├── features.py       Attributs comportementaux interpretables
│   │   │   ├── baseline.py       Profils de reference (Welford)
│   │   │   └── scorer.py         Score d'ecart -> DetectionEvent
│   │   └── infra/                EF-21 a EF-23 et EF-25
│   │       ├── health.py         Sondes de sante (contrat + simulation)
│   │       ├── monitors.py       Degradation subie
│   │       └── post_action_watch.py  Degradation PROVOQUEE (boucle EF-25)
│   │
│   ├── enrichment/               ── Enrichissement documentaire (EF-03/EF-04) ──
│   │   ├── vector_store.py       Index lexical BM25, sans dependance externe
│   │   ├── grounding.py          Garde de non-invention
│   │   ├── rag.py                Service d'enrichissement
│   │   └── knowledge/            Base de connaissance (11 familles de menaces)
│   │
│   ├── orchestration/            ── Le moteur autonome ──
│   │   ├── planner.py            Evenement -> actions candidates (EF-05/06)
│   │   ├── playbooks/            Reponses documentees, en YAML versionne
│   │   ├── reversibility.py      Catalogue de reversibilite (EF-14)
│   │   ├── policy_compiler.py    Langage naturel -> contraintes (EF-15)
│   │   ├── circuit_breaker.py    Coupe-circuit global (EF-26)
│   │   ├── executor.py           Execution sans validation (EF-07)
│   │   ├── rollback.py           Annulation autonome et manuelle (EF-25)
│   │   ├── classifier.py         Type, famille, criticite, dangerosite
│   │   ├── portfolio.py          Portefeuille priorise (Axe 4)
│   │   └── engine.py             Chaine complete et conditions d'arret
│   │
│   ├── actuators/                ── Frontiere avec le monde reel ──
│   │   ├── base.py               Contrat : idempotence + jeton d'annulation
│   │   ├── simulation.py         Implantation de reference du contrat
│   │   ├── firewall.py           Blocage, limitation de debit
│   │   ├── edr.py                Isolement, arret de processus, quarantaine
│   │   ├── iam.py                Comptes, sessions, mots de passe
│   │   ├── network.py            Debit sortant, VLAN
│   │   └── notify.py             Notification comme action tracable
│   │
│   ├── audit/                    ── Tracabilite ──
│   │   ├── ledger.py             Journal chaine par empreinte, verifiable
│   │   └── notifier.py           Notification a posteriori (EF-13 revisee)
│   │
│   ├── degraded/                 ── Mode degrade (Axe 5) ──
│   │   └── queue.py              File persistante et rejeu
│   │
│   ├── demo/                     ── Mode demonstration ──
│   │   └── scenarios.py          Une charge utile realiste par type d'attaque
│   │
│   ├── assistant/                ── Bilan et rapports ──
│   │   ├── facts.py              Collecte des faits, depuis les seuls depots
│   │   ├── service.py            Intentions reconnues et redaction
│   │   └── reports.py            Rapport d'operations transmissible
│   │
│   ├── llm/                      ── Redaction optionnelle ──
│   │   └── client.py             Repli deterministe par defaut
│   │
│   ├── persistence/
│   │   ├── db.py                 Schema SQLite, declencheurs d'immuabilite
│   │   └── repositories.py       Seul endroit du code qui connait le SQL
│   │
│   └── api/                      ── Interface applicative (EF-11/EF-12) ──
│       ├── deps.py               Roles, injection de la plateforme
│       ├── schemas.py            Contrats d'entree/sortie
│       └── routes/
│           ├── events.py         Ingestion et declenchement
│           ├── incidents.py      Portefeuille et detail
│           ├── actions.py        Consultation + rollback a posteriori
│           ├── policy.py         Politique et catalogue (administrateur)
│           ├── audit.py          Journal, verification, notifications
│           ├── admin.py          Coupe-circuit, mode degrade, sondes
│           ├── monitoring.py     Etat du parc surveille (EF-21 a EF-23)
│           ├── demo.py           Declenchement des scenarios du catalogue
│           ├── assistant.py      Questions, bilan, export du rapport
│           └── health.py         Etat et posture d'autonomie
│
├── tests/
│   ├── conftest.py               Plateforme isolee par test
│   ├── unit/                     Invariants, normalisation, garde EF-04,
│   │                             compilation de politique, catalogue, UEBA,
│   │                             journal d'audit
│   ├── integration/              Chaine complete, boucle de controle,
│   │                             coupe-circuit, API, mode degrade, portefeuille
│   └── acceptance/
│       └── test_criteres_recette.py   CR-01 a CR-18 (CDCF §5)
│
├── scripts/
│   ├── demo_attaque.py           Scenario de soutenance en 5 etapes
│   └── seed_demo.py              Jeu d'incidents varie pour l'interface
│
└── web/                          ── Interface de supervision ──
    ├── index.html                Coquille : rail de navigation, palette,
    │                             theme clair/sombre
    └── static/
        └── app.js                Neuf vues, routage par History API,
                                  icones SVG en ligne
```

L'interface est une application a page unique servie par le meme processus :
aucun CDN, aucune dependance distante, conformement au mode degrade (Axe 5).
Les neuf vues suivent la navigation demandee :

| Vue | Route | Ce qu'elle montre |
|---|---|---|
| Vue d'ensemble | `/dashboard` | Flux des actions executees et statistiques 24 h |
| Portefeuille | `/incidents/portfolio` | Incidents priorises (Axe 4), vue etendue |
| Surveillance | `/monitoring` | Etat de securite des plateformes surveillees |
| Reversibilite | `/reversibility-catalog` | Metadonnees de reversibilite (Axe 2) |
| Demonstration | `/demo` | Declenchement des 22 types du catalogue |
| Assistant | `/assistant` | Interface conversationnelle |
| Rapports | `/reports` | Generation et export |
| Journal d'audit | `/audit-log` | Journal des decisions |
| Reglages | `/settings` | Preferences de compte et de session |

Un separateur souple isole les deux dernieres : les fonctions courantes en
haut, l'audit et les reglages en bas. Le serveur rend la meme page pour
chacune de ces routes, sans quoi un lien profond ou un rafraichissement
renverrait une 404.

**Separation des roles.** Avant toute vue, l'interface passe par une page de
connexion (logos ANTIC + plateforme, centres) et une page d'accueil
personnalisee. Quatre roles : super-administrateur (cree a la premiere mise en
service), administrateur (analyste promu), analyste (s'inscrit, attend une
validation), decideur (identifiants remis par l'administrateur). `access.py`
porte la matrice role -> vues : l'analyste et le decideur voient les memes
vues sauf la Demonstration, mais le decideur est en lecture stricte ; seul
l'administrateur ouvre la politique, le coupe-circuit, la gestion des comptes
et des postes. `GET /api/v1/auth/me` renvoie `allowed_routes`, la navigation
et les gardes de route s'y conforment ; les gardes d'`api/deps.py` continuent
de proteger les actions.

---

## 2. Les cinq principes de decoupage

### 2.1 Le domaine ne connait ni base, ni reseau, ni framework

`domain/` ne contient que des structures de donnees et des regles. Aucun
import de FastAPI, de SQLite ou de bibliotheque HTTP.

*Pourquoi.* Les invariants qui protegent contre une action destructrice — une
action reversible doit porter son verbe d'annulation, un rayon d'impact vaut
au moins 1 — doivent tenir **quel que soit le chemin d'appel** : API, rejeu du
mode degrade, ligne de commande, test. En les placant dans le domaine, il
devient impossible de les contourner en ajoutant un point d'entree.

### 2.2 Une exigence, un fichier identifiable

Les exigences les plus sensibles ont chacune leur fichier :

| Exigence | Fichier |
|---|---|
| EF-04 non-invention | `enrichment/grounding.py` |
| EF-07 execution autonome | `orchestration/executor.py` |
| EF-14 reversibilite | `orchestration/reversibility.py` |
| EF-15 politique compilee | `orchestration/policy_compiler.py` |
| EF-25 boucle fermee | `detection/infra/post_action_watch.py` + `orchestration/rollback.py` |
| EF-26 coupe-circuit | `orchestration/circuit_breaker.py` |

*Pourquoi.* Un jury, un auditeur ou un successeur doit pouvoir ouvrir **un**
fichier pour verifier **une** exigence. Un garde-fou disperse dans cinq
modules n'est pas verifiable, et un garde-fou non verifiable ne compense rien.

### 2.3 La detection de degradation *subie* est separee de la degradation *provoquee*

`monitors.py` et `post_action_watch.py` partagent le meme mecanisme de mesure
mais sont deux fichiers distincts.

*Pourquoi.* Ce sont deux questions differentes. « Le service va-t-il mal ? »
produit un incident. « Est-ce **nous** qui l'avons casse ? » produit une
annulation. Les confondre conduirait le systeme a annuler ses confinements
chaque fois qu'une attaque degrade sa cible — c'est-a-dire a desarmer
precisement quand il faut agir.

### 2.4 La decision vient d'un fichier versionne, jamais d'un texte genere

`orchestration/playbooks/*.yaml` porte le choix de l'action. Le modele de
langage, quand il est utilise, ne sert qu'a compiler une politique **une
fois**, hors du chemin d'execution.

*Pourquoi.* Voir `docs/adr/ADR-003`. En resume : la question « pourquoi le
systeme a-t-il fait cela ? » doit trouver sa reponse dans un fichier relisible
et versionne, pas dans les poids d'un modele.

### 2.5 Le journal d'audit est un sous-systeme, pas une fonction utilitaire

`audit/` est un paquet a part, avec sa table protegee par des declencheurs SQL
et sa verification d'integrite.

*Pourquoi.* En v2.1, la tracabilite documentait des decisions qu'un humain
avait de toute facon validees. En v3.0 elle est la **seule** trace de ce que
le systeme a fait seul. Elle change de nature : elle devient une piece
probante, et se traite comme telle.

---

## 3. Ou ajouter quoi

| Besoin | Emplacement | Reste-t-il quelque chose a modifier ? |
|---|---|---|
| Nouvelle source de detection | `ingestion/normalizers/` + `registry.load_builtin()` | Non |
| Nouvelle famille de menace | `domain/taxonomy.py` + `enrichment/knowledge/` + `orchestration/playbooks/` + `demo/scenarios.py` | Non |
| Nouvelle action corrective | `actuators/` + catalogue `reversibility.py` + vocabulaire `policy_compiler.py` | Non |
| Nouvel equipement du meme type | Classe `Live*` de l'actuateur concerne | Non |
| Nouvelle regle de politique | Aucune : l'administrateur l'ecrit en langage naturel | — |
| Nouveau critere de recette | `tests/acceptance/` | Non |

Cette colonne de droite est le vrai test d'une architecture. Si ajouter une
source obligeait a toucher le moteur d'orchestration, le decoupage serait a
refaire.

---

## 4. Ce que la structure ne resout pas

Trois limites, a assumer explicitement plutot qu'a decouvrir en soutenance :

1. **Les classes `Live*` des actuateurs sont des squelettes.** Elles portent
   les verifications independantes de l'equipement (validite d'une adresse,
   refus d'un isolement qui couperait le canal de l'agent) mais leves
   `NotImplementedError` a l'endroit ou le client du site doit etre branche.
   Le CDCF exclut le deploiement en production reelle du perimetre.

2. **La sonde de sante par defaut est alimentee de l'exterieur.** Une sonde
   reelle (ICMP, HTTP, SNMP, agent) implante la meme interface `HealthProbe`.
   Le choix a ete fait pour que la boucle EF-25 soit demontrable sans casser
   un service.

3. **L'authentification tient dans la plateforme, pas dans un annuaire.**
   Comptes locaux, mots de passe haches (PBKDF2, bibliotheque standard),
   sessions porteuses. Suffisant pour un poste interne au CIRT ; l'integration
   a un annuaire d'entreprise (LDAP, SSO) reste un travail de deploiement.
