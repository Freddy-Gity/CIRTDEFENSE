# Matrice de tracabilite — exigence → code → test

Cette matrice sert deux usages : la revue academique (montrer que chaque
exigence est implantee **et** demontree) et la maintenance (savoir ce qui
casse quand on touche un fichier).

Convention : « — » signifie que l'exigence est portee par la conception et non
par un fichier unique.

---

## 1. Exigences fonctionnelles

| EF | Intitule (v3.0) | Implantation | Demonstration |
|---|---|---|---|
| EF-03 | Enrichissement documentaire du contexte | `enrichment/rag.py` | `unit/test_grounding.py::TestContexteFonde` |
| EF-04 | Non-invention : pas d'action sur contexte non fonde | `enrichment/grounding.py` | `unit/test_grounding.py::TestContexteNonFonde`, `acceptance::TestCR04` |
| EF-05 | Selection de l'action selon la menace | `orchestration/planner.py`, `orchestration/playbooks/` | `integration/test_engine.py::TestGraduationDeLaReponse` |
| EF-06 | Parametrage de l'action depuis l'evenement | `orchestration/planner.py` (`_resolve`) | `integration/test_engine.py` |
| **EF-07** | **Execution automatique sans validation prealable** | `orchestration/executor.py` | `acceptance::TestCR05`, `integration/test_engine.py::TestExecutionAutonome` |
| EF-08 | Profil comportemental de reference | `detection/ueba/baseline.py` | `unit/test_ueba.py::TestStatistiques` |
| EF-09 | Detection d'ecart comportemental | `detection/ueba/scorer.py` | `unit/test_ueba.py::TestDetection` |
| EF-10 | Score d'anomalie explicable | `detection/ueba/scorer.py` (`explain`) | `unit/test_ueba.py::test_l_alerte_porte_son_explication` |
| EF-11 | Consultation de l'etat du systeme | `api/routes/health.py`, `api/routes/incidents.py` | `integration/test_api.py::TestConsultation` |
| EF-12 | Consultation du journal des decisions | `api/routes/audit.py` | `integration/test_api.py::TestConsultation` |
| **EF-13** | **Notification a posteriori, sans blocage** | `audit/notifier.py` | `acceptance::TestCR08` |
| **EF-14** | **Reversibilite comme condition operationnelle** | `orchestration/reversibility.py`, `domain/action.py` | `unit/test_reversibility.py`, `acceptance::TestCR06` |
| **EF-15** | **Politique en langage naturel compilee a priori** | `orchestration/policy_compiler.py` | `unit/test_policy_compiler.py`, `acceptance::TestCR07` |
| EF-16 | Priorisation du portefeuille | `orchestration/portfolio.py`, `domain/incident.py` | `integration/test_portfolio.py::TestPriorisation` |
| EF-17 | Indicateurs de pilotage | `orchestration/portfolio.py` (`statistics`) | `integration/test_portfolio.py::TestIndicateurs` |
| EF-18 | Adaptateur multi-sources | `ingestion/adapter.py`, `ingestion/normalizers/` | `unit/test_normalizers.py`, `acceptance::TestCR01` |
| EF-19 | Deduplication des observations | `ingestion/adapter.py`, `domain/events.py` (`fingerprint`) | `acceptance::TestCR02` |
| EF-20 | Correlation en incidents | `domain/incident.py`, `ingestion/adapter.py` | `acceptance::TestCR03` |
| EF-21 | Surveillance de l'etat des services | `detection/infra/monitors.py` | `unit` (sondes), `integration/test_engine.py` |
| EF-22 | Seuils de service par cible | `detection/infra/monitors.py` (`ServiceThresholds`) | `integration/test_engine.py` |
| EF-23 | Degradation traitee comme incident | `orchestration/playbooks/infrastructure_degradation.yaml` | `integration/test_engine.py::test_degradation_infra_ne_declenche_aucune_correction` |
| **EF-25** | **Rollback autonome sur degradation post-action** | `detection/infra/post_action_watch.py`, `orchestration/rollback.py` | `integration/test_control_loop.py`, `acceptance::TestCR11`, `TestCR14` |
| **EF-26** | **Coupe-circuit global de l'autonomie** | `orchestration/circuit_breaker.py` | `integration/test_control_loop.py::TestCoupeCircuit`, `acceptance::TestCR12` |

Les exigences en gras sont celles que le pivot v3.0 a creees ou reecrites.

---

## 2. Criteres de recette

| CR | Objet | Test |
|---|---|---|
| CR-01 | Normalisation multi-sources | `TestCR01_NormalisationMultiSources` |
| CR-02 | Deduplication | `TestCR02_Deduplication` |
| CR-03 | Correlation | `TestCR03_Correlation` |
| CR-04 | Enrichissement fonde, refus sinon | `TestCR04_EnrichissementFonde` |
| CR-05 | Execution autonome | `TestCR05_ExecutionAutonome` |
| CR-06 | Perimetre reversible uniquement | `TestCR06_PerimetreReversible` |
| CR-07 | Politique compilee appliquee | `TestCR07_PolitiqueCompilee` |
| CR-08 | Notification a posteriori | `TestCR08_NotificationAPosteriori` |
| CR-09 | Portefeuille priorise | `TestCR09_PortefeuillePriorise` |
| CR-10 | Mode degrade | `TestCR10_ModeDegrade` |
| CR-11 | Rollback autonome | `TestCR11_RollbackAutonome` |
| CR-12 | Coupe-circuit | `TestCR12_CoupeCircuit` |
| CR-13 | Journal immuable et verifiable | `TestCR13_JournalImmuable` |
| **CR-14** | **Non-regression securitaire (CDCF §5.3)** | `TestCR14_NonRegressionSecuritaire` |
| CR-15 | Absence de validation prealable | `TestCR15_AbsenceDeValidationPrealable` |
| **CR-16** | **Classification des 22 types du catalogue CIRT** | `TestCR16_ClassificationDesAttaques` |
| **CR-17** | **Mode demonstration eprouvable depuis l'interface** | `TestCR17_ModeDemonstration` |
| **CR-18** | **Assistant fonde sur les faits et rapports exportables** | `TestCR18_AssistantEtRapports` |

Execution : `make test-recette`.

---

## 3. Criteres v2.1 retires ou reformules

La checklist du CDCF §5 demande que les criteres supposant une validation
humaine soient retires ou reformules. Etat :

| Critere v2.1 | Sort en v3.0 | Motif |
|---|---|---|
| « L'analyste valide une recommandation » | **Retire** | La validation prealable n'existe plus (EF-07/EF-13 revisees) |
| « L'analyste modifie une recommandation » | **Retire** | Idem |
| « L'analyste rejette une recommandation » | **Remplace** par CR-15 + rollback a posteriori | Le recours humain est deplace apres l'action |
| « Les recommandations sont priorisees pour decision » | **Reformule** en CR-09 | Le portefeuille montre ce qui a ete traite, il n'ordonne plus une file d'attente |
| « Aucune action n'est executee automatiquement » | **Inverse** en CR-05 | C'est le pivot lui-meme |

CR-15 verifie ce retrait **sur le code** — en inspectant les chemins exposes
par l'API — et pas seulement sur le diagramme de cas d'utilisation. Un
diagramme mis a jour et une API restee inchangee seraient une incoherence que
le jury releverait.

---

## 4. Points d'attention pour la maintenance

| Si vous modifiez… | Verifiez… |
|---|---|
| `domain/action.py` | Les invariants d'irreversibilite tiennent toujours (`unit/test_domain.py`) |
| `detection/infra/post_action_watch.py` | La cible surveillee reste celle de la mesure de reference (`test_degradation_imputee_a_la_bonne_cible`) |
| `orchestration/policy_compiler.py` | Le garde-fou d'irreversibilite reste injecte et prioritaire |
| `orchestration/portfolio.py` | Les compteurs viennent de la table `actions`, pas de l'instantane d'incident |
| `api/routes/` | CR-15 : aucun chemin de validation prealable n'apparait |
| `domain/taxonomy.py` | Aucune entree irreversible n'est introduite (`test_aucune_action_irreversible_au_catalogue`) |
| Un actuateur, un verbe | Le catalogue de reversibilite ET le vocabulaire de politique sont completes — sinon l'action devient non interdictible |
| `assistant/` | Aucun chiffre ne provient d'ailleurs que des depots (`test_aucun_nombre_non_nul_invente`) |
| `enrichment/knowledge/` | Chaque document declare les codes de categorie qu'il couvre |
