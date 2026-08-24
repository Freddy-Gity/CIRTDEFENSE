# Catalogue CIRT — 22 types d'attaques et leurs réponses

Transcription du document *« Classification des réactions autonomes par type
d'attaque/intrusion »*. Chaque ligne du document est devenue trois artefacts
dans le code :

| Artefact | Emplacement | Rôle |
|---|---|---|
| Entrée de taxonomie | `domain/taxonomy.py` | code, famille, signal, réversibilité, priorité Axe 4 |
| Fiche de connaissance | `enrichment/knowledge/<catégorie>.md` | fonde la décision (EF-04) |
| Playbook | `orchestration/playbooks/<catégorie>.yaml` | actions prescrites, versionnées |

Un type sans ces trois artefacts ne déclenche rien : le contexte est déclaré
non fondé et le système s'abstient.

---

## Principe de conception, vérifié par les tests

**Aucune ligne du catalogue ne déclenche d'action irréversible en automatique.**
Ce n'est pas une convention de rédaction mais un invariant : le test
`TestPrincipeDeConception::test_aucune_action_irreversible_au_catalogue`
échoue si une entrée ajoutée plus tard franchit la limite.

Pour le rançongiciel (A6) — le cas où la tentation d'aller plus loin est la
plus forte — la réponse automatique reste l'isolation réseau. La remédiation
(restauration, réinstallation) relève d'une décision humaine.

---

## A — Attaques réseau

| Code | Type | Réponse automatique | Réversibilité | Priorité | Dangerosité |
|---|---|---|---|---|---|
| A1 | DDoS volumétrique | scrubbing en bordure, blackhole des sources | réversible | haute | 7/10 |
| A2 | DDoS applicatif | limitation de débit WAF, fermeture des connexions inactives | réversible | haute | 6/10 |
| A3 | Scan de reconnaissance | blocage temporaire de l'IP source | réversible | basse | 3/10 |
| A4 | Brute force / credential stuffing | verrouillage du compte, blocage IP, forçage MFA | partielle | haute | 6/10 |
| A5 | Exfiltration de données | coupure de la connexion sortante, quarantaine réseau | partielle | haute | 9/10 |
| A6 | **Rançongiciel** | isolation VLAN, blocage latéral, snapshot — **jamais de remédiation** | partielle | **critique** | **10/10** |
| A7 | Command & Control | sinkhole DNS, blocage IP/domaine, isolation si confirmé | partielle | haute | 8/10 |

## B — Attaques applicatives

| Code | Type | Réponse automatique | Réversibilité | Priorité | Dangerosité |
|---|---|---|---|---|---|
| B1 | Injection SQL | blocage du motif au WAF, blocage de la source | réversible | haute | 8/10 |
| B2 | XSS | blocage du motif, sanitisation ; **signalement** si déjà stocké | partielle | moyenne | 5/10 |
| B3 | **RCE** | isolation immédiate, arrêt du processus | partielle | **critique** | **10/10** |
| B4 | Path traversal / LFI / RFI | blocage du motif et du point d'entrée | réversible | moyenne | 6/10 |
| B5 | Webshell téléversé | quarantaine du fichier (**déplacement, pas suppression**), blocage IP | réversible | haute | 9/10 |
| B6 | Abus d'API | révocation du jeton, limitation renforcée | réversible | moyenne | 4/10 |
| B7 | Session hijacking | révocation de session, forçage MFA | réversible | haute | 8/10 |

## C — Comportemental / insider

| Code | Type | Réponse automatique | Réversibilité | Priorité | Dangerosité |
|---|---|---|---|---|---|
| C1 | Élévation de privilège | révocation du privilège, restauration du rôle antérieur | réversible | haute | 8/10 |
| C2 | Accès hors profil | blocage de l'accès — **pas de révocation de compte** | réversible | moyenne | 4/10 |
| C3 | Exfiltration lente | restriction des droits d'export | partielle | haute | 7/10 |
| C4 | Compte compromis | verrouillage, révocation des sessions, forçage MFA | partielle | haute | 8/10 |

## D — Infrastructure

| Code | Type | Réponse automatique | Réversibilité | Priorité | Dangerosité |
|---|---|---|---|---|---|
| D1 | Certificat TLS expiré/faible | **notification seule** — dépend d'une autorité externe | — | basse | 3/10 |
| D2 | Port inattendu ouvert | fermeture si sous contrôle, sinon alerte de dérive | réversible | moyenne | 5/10 |
| D3 | Service indisponible | bascule vers le nœud de secours, sinon redémarrage | partielle | haute | 6/10 |
| D4 | Dérive de configuration | restauration **si le delta est mineur** | réversible | moyenne | 4/10 |

---

## Trois lignes où le système s'abstient délibérément

Ce sont les plus instructives, parce qu'elles montrent que l'autonomie totale
n'est pas l'automatisme aveugle.

**D1 — certificat TLS.** Aucune action corrective n'est possible : le
renouvellement dépend d'une autorité de certification externe. Le système
constate, notifie, produit le rapport. Inventer une action ici reviendrait à
promettre ce qu'on ne peut pas tenir.

**C2 — accès hors profil.** Le document exclut explicitement la révocation de
compte : le risque de faux positif y est plus élevé qu'ailleurs (un changement
de mission produit exactement la même observation). Immobiliser un utilisateur
légitime coûterait plus que l'accès constaté.

**B2 — XSS déjà stocké.** Le retrait toucherait des données applicatives, hors
du périmètre des actions réversibles maîtrisées. Le système bloque la suite et
signale l'existant.

---

## Criticité et dangerosité : deux mesures distinctes

Les confondre conduirait à mal prioriser.

- **Criticité** — la gravité effective de ce qui se passe, croisée avec
  l'importance de l'actif touché.
- **Dangerosité** — le dommage potentiel *si l'attaque aboutit*, sur 10.

Un balayage (A3) casse peu — criticité basse — mais annonce une intrusion : sa
dangerosité n'est pas nulle. Une panne de service (D3) est l'inverse : elle
gêne fortement sans donner la main à un attaquant.

La dangerosité se calcule par trois facteurs explicites, tous restitués dans
la trace de décision : base du catalogue, criticité de l'actif, confiance de
la source. La confiance module sans jamais annuler — une détection incertaine
de rançongiciel reste plus dangereuse qu'un scan certain.

---

## Ajouter un type

1. Une entrée dans `domain/taxonomy.py` — avec sa réversibilité et sa priorité.
2. Une fiche `enrichment/knowledge/<catégorie>.md`, déclarant en en-tête
   `categories: <catégorie>`. Sans cette déclaration, la garde EF-04 bloquera
   toute action.
3. Un playbook `orchestration/playbooks/<catégorie>.yaml`.
4. Si l'action prescrite n'existe pas : un verbe d'actuateur, son entrée au
   catalogue de réversibilité, **et** son vocabulaire dans le compilateur de
   politique — sans quoi l'administrateur ne pourrait pas l'interdire.
5. Un scénario dans `demo/scenarios.py`, pour le rendre éprouvable.

Les tests vérifient chacun de ces points ; en oublier un fait échouer la suite.
