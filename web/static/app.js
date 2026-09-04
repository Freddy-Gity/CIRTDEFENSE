/* Poste de supervision CIRTDEFENSE — navigation laterale et routage.

   Aucune dependance externe, y compris pour les icones : la plateforme doit
   rester utilisable hors connexion, contrainte du mode degrade (Axe 5). Les
   icones sont des traces SVG en ligne. */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// Coupe sur la derniere frontiere de mot : tronquer au caractere pres donne
// « tunneling DNS, transf », qui se lit comme une erreur d'affichage.
const court = (texte, max) => {
  const t = String(texte ?? "");
  if (t.length <= max) return t;
  const coupe = t.slice(0, max);
  const espace = coupe.lastIndexOf(" ");
  return (espace > max * 0.6 ? coupe.slice(0, espace) : coupe).replace(/[ ,;(]+$/, "") + "\u2026";
};

// Jeton de session : les gestes sensibles — declarer une plateforme, basculer
// l'autonomie — restent reserves a l'administrateur. Le jeton est saisi dans
// les Reglages et ne quitte jamais ce navigateur.
const JETON = "cirt-jeton";
const jeton = () => { try { return localStorage.getItem(JETON) || ""; } catch { return ""; } };
const poserJeton = (v) => {
  try { v ? localStorage.setItem(JETON, v) : localStorage.removeItem(JETON); }
  catch { /* stockage indisponible : la session reste en lecture seule */ }
};

async function api(url, options = {}) {
  const porteur = jeton();
  if (porteur) {
    options = { ...options, headers: { ...(options.headers || {}),
      Authorization: `Bearer ${porteur}` } };
  }
  const r = await fetch(url, options);
  if (!r.ok) {
    const detail = await r.json().catch(() => ({}));
    throw new Error(detail.detail || `${url} → ${r.status}`);
  }
  return r.json();
}
const post = (url, body) => api(url, body
  ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
  : { method: "POST" });

const heure = (iso) => iso ? new Date(iso).toLocaleString("fr-FR",
  { dateStyle: "short", timeStyle: "medium" }) : "—";
const heureCourte = (iso) => iso ? new Date(iso).toLocaleTimeString("fr-FR",
  { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";

const bandeDanger = (d) => d >= 9 ? "critique" : d >= 7 ? "haute" : d >= 4 ? "moyenne" : "basse";
const LIB_FAMILLE = {
  A: "Attaques réseau", B: "Attaques applicatives",
  C: "Comportemental / insider", D: "Infrastructure",
};

// ------------------------------------------------------------------ icones
const ICONES = {
  Activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  ListChecks: '<path d="m3 17 2 2 4-4"/><path d="m3 7 2 2 4-4"/><path d="M13 6h8"/><path d="M13 12h8"/><path d="M13 18h8"/>',
  Radar: '<circle cx="12" cy="12" r="1.6"/><path d="M12 12 19.5 6"/><path d="M16.2 16.2a6 6 0 1 0-8.5-8.5"/><path d="M19.8 19.8a11 11 0 1 0-15.6-15.6"/>',
  BookLock: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H14v6H6.5A2.5 2.5 0 0 1 4 5.5v-1A2.5 2.5 0 0 1 6.5 2z"/><rect x="14" y="11" width="8" height="6" rx="1"/><path d="M16 11V9.5a2 2 0 0 1 4 0V11"/><path d="M6.5 17H20v5H6.5"/>',
  MessagesSquare: '<path d="M14 9a2 2 0 0 1-2 2H6l-4 4V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2z"/><path d="M18 9h2a2 2 0 0 1 2 2v11l-4-4h-6a2 2 0 0 1-2-2v-1"/>',
  FileText: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/><path d="M14 2v5h5"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/>',
  ScrollText: '<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>',
  SlidersHorizontal: '<path d="M21 4h-7"/><path d="M10 4H3"/><path d="M21 12h-9"/><path d="M8 12H3"/><path d="M21 20h-5"/><path d="M12 20H3"/><circle cx="12" cy="4" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="14" cy="20" r="2"/>',
  Zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
};
const icone = (nom) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONES[nom] || ""}</svg>`;

// ------------------------------------------------------------------ routes
const VUES = [
  { route: "/dashboard", icone: "Activity", label: "Vue d'ensemble",
    titre: "Vue d'ensemble",
    sous: "Flux des actions exécutées et statistiques sur 24 heures", rendu: vueDashboard },
  { route: "/incidents/portfolio", icone: "ListChecks", label: "Portefeuille",
    titre: "Portefeuille d'incidents",
    sous: "Priorisé par enjeu — Axe 4", rendu: vuePortefeuille },
  { route: "/monitoring", icone: "Radar", label: "Surveillance",
    titre: "Surveillance",
    sous: "État de sécurité des plateformes supervisées", rendu: vueSurveillance },
  { route: "/reversibility-catalog", icone: "BookLock", label: "Réversibilité",
    titre: "Catalogue de réversibilité",
    sous: "Métadonnées de réversibilité — Axe 2", rendu: vueCatalogue },
  { route: "/demo", icone: "Zap", label: "Démonstration",
    titre: "Démonstration",
    sous: "Simuler les 22 types d'attaques du catalogue CIRT", rendu: vueDemo },
  { route: "/reports", icone: "FileText", label: "Rapports",
    titre: "Rapports d'opérations",
    sous: "Génération et export", rendu: vueRapports },
  { separateur: true },
  { route: "/audit-log", icone: "ScrollText", label: "Journal d'audit",
    titre: "Journal d'audit des décisions",
    sous: "Seule trace de ce que le système a fait seul", rendu: vueAudit },
  { route: "/settings", icone: "SlidersHorizontal", label: "Réglages",
    titre: "Réglages",
    sous: "Préférences de compte et de session", rendu: vueReglages },
];
const ROUTES = VUES.filter((v) => v.route);
const trouver = (chemin) => ROUTES.find((v) => v.route === chemin) || ROUTES[0];

let vueCourante = null;
let etatGlobal = null;

// État de la bulle assistant. Déclaré ici parce que la première navigation,
// plus bas, l'interroge avant d'avoir atteint le bas du fichier.
let chatOuvert = false;
let chatOccupe = false;
let flux = null;
const CHAT_MASQUE = ["/settings"];

function construireNav() {
  const liste = SESSION
    ? VUES.filter((v) => v.separateur || (SESSION.allowed_routes || []).includes(v.route))
    : VUES;
  $("nav").innerHTML = liste.map((v) => {
    if (v.separateur) return '<div class="flex"></div><div class="sep"></div>';
    return `<a class="lien-nav" href="${v.route}" data-route="${v.route}">
      ${icone(v.icone)}<span>${esc(v.label)}</span>
      <span class="pastille" data-badge="${v.route}" hidden></span></a>`;
  }).join("");

  $("nav").querySelectorAll("a[data-route]").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); naviguer(a.dataset.route); }));
}

function naviguer(chemin, remplacer = false) {
  // Page d'accueil : logos, message personnalisé et redirections autorisées.
  if (chemin === "/accueil") {
    if (location.pathname !== "/accueil") {
      history[remplacer ? "replaceState" : "pushState"]({}, "", "/accueil");
    }
    vueCourante = { route: "/accueil" };
    // Sur l'accueil : ni rail, ni barre du haut — la page se suffit.
    document.body.classList.add("sur-accueil");
    $("nav").querySelectorAll("a[data-route]").forEach((a) =>
      a.setAttribute("aria-current", "false"));
    majVisibiliteChat();
    vueAccueil();
    return;
  }
  document.body.classList.remove("sur-accueil");
  // L'assistant n'a plus d'onglet, mais son adresse reste valide : un lien
  // profond ou un signet existant doit ouvrir la conversation, pas une 404.
  if (chemin === "/assistant") {
    ouvrirChat();
    chemin = "/dashboard";
  }
  // Garde de rôle : une route non autorisée renvoie à l'accueil (le serveur
  // refuse de toute façon les actions correspondantes).
  if (SESSION && !(SESSION.allowed_routes || []).includes(chemin)) {
    naviguer("/accueil", true);
    return;
  }
  const vue = trouver(chemin);
  if (location.pathname !== vue.route) {
    history[remplacer ? "replaceState" : "pushState"]({}, "", vue.route);
  }
  vueCourante = vue;
  $("titre-vue").textContent = vue.titre;
  $("sous-vue").textContent = vue.sous;
  document.title = `${vue.titre} — CIRTDEFENSE`;
  $("nav").querySelectorAll("a[data-route]").forEach((a) =>
    a.setAttribute("aria-current", a.dataset.route === vue.route ? "page" : "false"));
  $("vue").innerHTML = '<div class="vide">Chargement…</div>';
  majVisibiliteChat();
  rafraichir();
}
window.addEventListener("popstate", () => {
  if (!SESSION) {
    if (location.pathname === "/register") ecranInscription();
    else ecranConnexion();
    return;
  }
  naviguer(location.pathname, true);
});

const themeSombre = () => {
  const forcé = document.documentElement.getAttribute("data-theme");
  return forcé ? forcé === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
};
const majIconeTheme = () => $("theme").classList.toggle("sombre", themeSombre());

$("theme").addEventListener("click", () => {
  const cible = themeSombre() ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", cible);
  try { localStorage.setItem("cirt-theme", cible); } catch { /* stockage indisponible */ }
  majIconeTheme();
});
try {
  const memo = localStorage.getItem("cirt-theme");
  if (memo) document.documentElement.setAttribute("data-theme", memo);
} catch { /* stockage indisponible */ }
majIconeTheme();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", majIconeTheme);

// ------------------------------------------------- bascule d'autonomie
// Activer ou suspendre, c'est le coupe-circuit EF-26 sous un nom lisible.
// Suspendre fait cesser d'agir : cela n'ajoute aucune validation par action.
const listeAutonomie = () => $("autonomie-liste");

$("autonomie").addEventListener("click", (e) => {
  e.stopPropagation();
  const ouvert = !listeAutonomie().hidden;
  listeAutonomie().hidden = ouvert;
  $("autonomie").setAttribute("aria-expanded", String(!ouvert));
});

document.addEventListener("click", () => {
  listeAutonomie().hidden = true;
  $("autonomie").setAttribute("aria-expanded", "false");
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  listeAutonomie().hidden = true;
  fermerModale();
});

listeAutonomie().querySelectorAll("[data-autonomie]").forEach((b) =>
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    listeAutonomie().hidden = true;
    await basculerAutonomie(b.dataset.autonomie === "1");
  }));

async function basculerAutonomie(actif) {
  const motif = actif ? "réactivation depuis l'interface" : "suspension depuis l'interface";
  try {
    await post("/api/v1/admin/autonomy", { enabled: actif, reason: motif });
    await rafraichir();
  } catch (e) {
    // Le geste est reserve a l'administrateur : le dire plutot que d'echouer
    // en silence, sinon le bouton parait cassé.
    const cause = /403|401/.test(e.message)
      ? "Ce geste est réservé à l'administrateur : la session courante ne porte pas ce rôle."
      : e.message;
    ouvrirModale({
      titre: actif ? "Activation refusée" : "Suspension refusée",
      sous: "Bascule du mode autonomie",
      corps: `<div class="bandeau suspendu">${esc(cause)}</div>`,
      actions: '<button data-fermer>Fermer</button>',
    });
  }
}

// ---------------------------------------------------------------- modales
// Le fond passe en arriere-plan floute : pendant une saisie, la fenetre est
// le seul point net de l'ecran.
function ouvrirModale({ titre, sous = "", corps, actions = "", large = false, apres }) {
  $("modales").innerHTML = `
    <div class="voile" role="dialog" aria-modal="true" aria-label="${esc(titre)}">
      <div class="modale${large ? " large" : ""}">
        <header>
          <div><h2>${esc(titre)}</h2>${sous ? `<div class="sous">${esc(sous)}</div>` : ""}</div>
          <button class="fermer" data-fermer aria-label="Fermer">&times;</button>
        </header>
        <div class="corps">${corps}</div>
        ${actions ? `<div class="pied">${actions}</div>` : ""}
      </div>
    </div>`;

  const voile = $("modales").querySelector(".voile");
  voile.addEventListener("click", (e) => { if (e.target === voile) fermerModale(); });
  $("modales").querySelectorAll("[data-fermer]").forEach((b) =>
    b.addEventListener("click", fermerModale));

  const premier = $("modales").querySelector("input, select, textarea, button:not(.fermer)");
  if (premier) premier.focus();
  if (apres) apres($("modales"));
}

const fermerModale = () => { $("modales").innerHTML = ""; };

// --------------------------------------------------------------- fragments
function tuile(valeur, libelle, note = "", couleur = "") {
  return `<div class="carte tuile">
    <div class="valeur" ${couleur ? `style="color:${couleur}"` : ""}>${esc(valeur)}</div>
    <div class="libelle">${esc(libelle)}</div>
    ${note ? `<div class="note">${esc(note)}</div>` : ""}</div>`;
}

function barres(entrees, couleurDe) {
  if (!entrees.length) return '<div class="vide">Aucune donnée.</div>';
  const max = Math.max(1, ...entrees.map((e) => e.valeur));
  return `<div class="barres">${entrees.map((e) => `
    <div class="barre">
      <div class="nom">${esc(e.nom)}</div>
      <div class="piste"><div class="remplissage"
        style="width:${(e.valeur / max) * 100}%;background:${couleurDe(e)}"></div></div>
      <div class="val">${e.valeur}</div>
    </div>`).join("")}</div>`;
}

function markdown(src) {
  const lignes = String(src).split("\n");
  const out = []; let liste = false, table = false;
  const fermer = () => {
    if (liste) { out.push("</ul>"); liste = false; }
    if (table) { out.push("</tbody></table>"); table = false; }
  };
  const inline = (t) => esc(t).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`(.+?)`/g, "<code>$1</code>");
  for (const ligne of lignes) {
    const l = ligne.trimEnd();
    if (!l.trim()) { fermer(); continue; }
    if (/^\|[-\s|:]+\|$/.test(l.trim())) continue;
    if (l.trim().startsWith("|")) {
      const cells = l.trim().slice(1, -1).split("|").map((c) => c.trim());
      if (!table) {
        fermer();
        out.push(`<table><thead><tr>${cells.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>`);
        table = true;
      } else out.push(`<tr>${cells.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`);
      continue;
    }
    if (l.startsWith("- ")) {
      if (!liste) { fermer(); out.push("<ul>"); liste = true; }
      out.push(`<li>${inline(l.slice(2))}</li>`); continue;
    }
    fermer();
    if (l.startsWith("### ")) out.push(`<h4>${inline(l.slice(4))}</h4>`);
    else if (l.startsWith("## ")) out.push(`<h3>${inline(l.slice(3))}</h3>`);
    else if (l.startsWith("# ")) out.push(`<h3>${inline(l.slice(2))}</h3>`);
    else if (l.startsWith("> ")) out.push(`<blockquote>${inline(l.slice(2))}</blockquote>`);
    else if (l.trim() === "---") out.push("<hr>");
    else out.push(`<p>${inline(l)}</p>`);
  }
  fermer();
  return out.join("");
}

// ------------------------------------------------------------------- rendu
async function rafraichir() {
  try {
    etatGlobal = await api("/api/v1/status");
    majEntete(etatGlobal);
    await vueCourante.rendu();
  } catch (e) {
    $("vue").innerHTML = `<div class="carte" style="border-color:var(--critical)">
      <b style="color:var(--critical)">Interface injoignable</b>
      <div class="muet">${esc(e.message)}</div></div>`;
  }
}

function majEntete(etat) {
  const actif = etat.autonomy.effective;
  const bouton = $("autonomie");
  bouton.className = "bascule " + (actif ? "actif" : "suspendu");
  // L'etat est ecrit, pas seulement colore : vert et rouge ne se distinguent
  // pas pour tout le monde.
  $("autonomie-texte").textContent = actif ? "Autonomie active" : "Autonomie suspendue";
  bouton.title = actif
    ? `Actionnement « ${etat.autonomy.actuation_mode} » — les actions partent sans validation préalable.`
    : `Suspendue — ${etat.circuit_breaker.reason || "coupe-circuit ouvert"}.`;
}

function badge(route, valeur) {
  const el = $("nav").querySelector(`[data-badge="${route}"]`);
  if (!el) return;
  el.hidden = !valeur;
  el.textContent = valeur || "";
}

// =========================================================== /dashboard
async function vueDashboard() {
  const [portefeuille, stats, audit, attentes, fiches] = await Promise.all([
    api("/api/v1/incidents?limit=200"),
    api("/api/v1/incidents/statistics"),
    api("/api/v1/audit?limit=40"),
    api("/api/v1/pending").catch(() => ({ count: 0, pending: [] })),
    api("/api/v1/qualifications").catch(() => ({ count: 0, qualifications: [] })),
  ]);
  const etat = etatGlobal;
  const cb = etat.circuit_breaker;

  const actions = audit.entries.filter((e) =>
    ["action.executed", "action.failed", "rollback.completed", "rollback.failed",
     "breaker.tripped"].includes(e.event_type));

  const parFamille = {}, parDanger = { basse: 0, moyenne: 0, haute: 0, critique: 0 };
  portefeuille.incidents.forEach((i) => {
    const f = (i.attack_code || "?").charAt(0);
    if (LIB_FAMILLE[f]) parFamille[f] = (parFamille[f] || 0) + 1;
    parDanger[bandeDanger(i.dangerousness || 0)]++;
  });

  badge("/incidents/portfolio", portefeuille.count || 0);
  badge("/dashboard", (attentes.count || 0) + (fiches.count || 0));

  $("vue").innerHTML = `
    ${blocAttentes(attentes)}
    ${blocQualifications(fiches)}
    <h2>Statistiques sur 24 heures</h2>
    <div class="grille six">
      ${tuile(stats.incidents_total, "Incidents traités", "toutes familles confondues")}
      ${tuile(stats.actions_executed, "Actions exécutées", "confinements en place")}
      ${tuile(stats.actions_rolled_back, "Actions annulées",
        "dont annulations autonomes (EF-25)",
        stats.actions_rolled_back ? "var(--serious)" : "")}
      ${tuile((stats.rollback_ratio * 100).toFixed(0) + " %", "Taux d'annulation",
        "fréquence à laquelle le système se corrige",
        stats.rollback_ratio > 0.2 ? "var(--critical)" : "var(--success-text)")}
      ${tuile(cb.state === "closed" ? "fermé" : "OUVERT", "Coupe-circuit (EF-26)",
        `${cb.observations.rollbacks_in_window}/${cb.observations.rollback_threshold} annulations `
        + `sur ${cb.observations.window_seconds} s`,
        cb.state === "closed" ? "var(--success-text)" : "var(--critical)")}
      ${tuile(etat.audit_chain.valid ? "intacte" : "ROMPUE", "Chaîne d'audit",
        `${etat.audit_chain.entries_checked} entrées vérifiées`,
        etat.audit_chain.valid ? "var(--success-text)" : "var(--critical)")}
    </div>

    <div class="deux" style="margin-top:18px">
      <div>
        <h2>Incidents par famille d'attaque</h2>
        <div class="carte">${barres(
          ["A", "B", "C", "D"].filter((f) => parFamille[f])
            .map((f) => ({ nom: `${f} — ${LIB_FAMILLE[f]}`, valeur: parFamille[f], code: f })),
          (e) => `var(--fam-${e.code})`)}</div>
      </div>
      <div>
        <h2>Incidents par niveau de dangerosité</h2>
        <div class="carte">${barres(
          Object.entries(parDanger).filter(([, v]) => v).map(([k, v]) => ({ nom: k, valeur: v, cle: k })),
          (e) => ({ basse: "var(--good)", moyenne: "var(--warning)",
                    haute: "var(--serious)", critique: "var(--critical)" }[e.cle]))}</div>
      </div>
    </div>

    <h2>Flux des actions exécutées</h2>
    <div class="carte">
      ${actions.length ? `<div class="flux">${actions.map((e) => `
        <div class="evt">
          <div class="quand">${heureCourte(e.recorded_at)}</div>
          <div class="quoi">
            ${etiquetteEvenement(e)}
            <span class="mono">${esc(e.payload.actuator ? `${e.payload.actuator}:${e.payload.verb}` : "")}</span>
            ${e.payload.target ? `<span class="muet">→ ${esc(e.payload.target)}</span>` : ""}
            ${e.payload.reason ? `<span class="muet">${esc(court(e.payload.reason, 90))}</span>` : ""}
          </div>
        </div>`).join("")}</div>`
        : `<div class="vide">Aucune action encore exécutée —
             <a href="/demo" data-lien>lancez une attaque depuis la Démonstration</a>.</div>`}
    </div>`;
  brancherLiens();
  brancherDecisions();
}

// ------------------------------------------- EF-28 : decisions requises
// Une notification se lit une fois et se perd. Ces blocs restent affiches
// tant qu'aucune decision n'a ete prise : c'est ce qui en fait une alerte
// persistante au sens ou le CIRT l'a demandee.
function blocAttentes(attentes) {
  if (!attentes.count) return "";
  const enCours = attentes.pending.filter((a) => a.status === "taken_over").length;
  return `
    <div class="carte alerte-durable">
      <div class="tete-alerte">
        <span class="etat critique">décision requise</span>
        <b>${attentes.count} geste${attentes.count > 1 ? "s" : ""} à effet durable
           ${attentes.count > 1 ? "attendent" : "attend"} votre décision</b>
        ${enCours ? `<span class="etat moyenne">${enCours} pris en charge</span>` : ""}
      </div>
      <div class="muet" style="margin:6px 0 14px">
        Ils n'ont pas été exécutés : la plateforme n'engage seule que ce qu'elle sait
        annuler entièrement. Ils resteront ici tant que personne n'aura tranché.
      </div>
      ${attentes.pending.map(ficheAttente).join("")}
    </div>`;
}

// Une fiche par geste. Le motif se saisit dans la page : passer par prompt()
// rendait la decision impossible des que le navigateur supprimait les
// dialogues — il rendait null, le code sortait en silence, et l'exploitant
// voyait un bouton qui ne faisait rien.
function ficheAttente(a) {
  const prise = a.status === "taken_over";
  const esc_id = esc(a.pending_id);
  return `
    <div class="fiche-decision${prise ? " prise" : ""}" data-fiche-att="${esc_id}">
      <div class="entete-decision">
        <b>${esc(a.expected_effect || `${a.actuator} : ${a.verb}`)}</b>
        <span class="muet mono">sur ${esc(a.target)}</span>
        ${prise ? `<span class="etat moyenne">prise en charge par
           ${esc((a.taken_over_by || "").replace("human:", ""))}</span>` : ""}
      </div>
      <div class="motifs-decision">
        <div><span class="muet">Pourquoi la plateforme le propose :</span> ${esc(a.basis)}</div>
        <div><span class="muet">Ce qui subsisterait après annulation :</span>
             ${esc(a.residual_effect || "annulation partielle")}</div>
      </div>
      ${prise ? `
        <div class="muet" style="margin:8px 0">
          Vous vous êtes chargé de ce geste. Indiquez ce qui a été fait sur
          l'équipement pour refermer le dossier.
        </div>
        <textarea data-motif="${esc_id}" rows="2"
          placeholder="Ce que vous avez fait sur l'équipement…"></textarea>
        <div class="choix">
          <button class="primaire" data-att="${esc_id}" data-issue="resolved">
            Rendre compte et clore</button>
        </div>`
      : `
        <textarea data-motif="${esc_id}" rows="2"
          placeholder="Motif de votre décision — consigné au journal…"></textarea>
        <div class="choix">
          <button class="primaire" data-att="${esc_id}" data-issue="confirm">
            Confirmer — la plateforme exécute</button>
          <button data-att="${esc_id}" data-issue="handled">Je m'en charge</button>
          <button data-att="${esc_id}" data-issue="decline">Écarter</button>
        </div>`}
      <div class="suite-decision" data-suite="${esc_id}"></div>
    </div>`;
}

// Ce que la plateforme a fait de son cote apres un refus. C'est la reponse a
// « et maintenant ? » : sans elle, ecarter un geste ressemblerait a un abandon.
function blocEscalade(id, escalade) {
  if (!escalade) return "";
  const alt = escalade.alternative;
  const conseil = escalade.conseil || {};
  const applique = !!escalade.action;
  return `
    <div class="escalade ${esc(escalade.mesure)}">
      <div class="titre-escalade">
        ${escalade.mesure === "quarantaine" ? "Confinement de substitution appliqué"
                                            : "Surveillance rapprochée"}
      </div>
      <p>${esc(escalade.motif)}</p>
      ${alt ? `
        <div class="proposition">
          <div class="tete-proposition">
            <b>${esc(alt.description)}</b>
            <span class="muet">sur ${esc(alt.target)}</span>
            ${applique ? `<span class="etat bonne">appliqué</span>` : ""}
          </div>
          <div class="muet">Objectif servi : ${esc(alt.but)} —
            annulable entièrement, ${esc(String(alt.blast_radius))} équipement(s) touché(s).</div>
          <div class="muet reserve">${esc(alt.reserve)}</div>
          ${conseil.explication_niveau
            ? `<div class="muet provenance">${esc(conseil.explication_niveau)}</div>` : ""}
          ${!applique ? `
            <div class="choix">
              <button class="primaire" data-att="${esc(id)}" data-issue="substitute">
                Appliquer ce geste à la place</button>
            </div>` : ""}
        </div>` : ""}
      ${(escalade.propositions || []).length ? `
        <details class="autres-propositions">
          <summary>${escalade.propositions.length} autre(s) geste(s) possible(s)</summary>
          <ul>${escalade.propositions.map((x) =>
            `<li>${esc(x.description)} <span class="muet">— ${esc(x.but)}</span></li>`).join("")}</ul>
        </details>` : ""}
    </div>`;
}

// ------------------------------------------- EF-29 : fiches a qualifier
function blocQualifications(fiches) {
  if (!fiches.count) return "";
  return `
    <div class="carte alerte-qualif">
      <div class="tete-alerte">
        <span class="etat moyenne">à qualifier</span>
        <b>${fiches.count} menace(s) hors catalogue attendent d'être nommée(s)</b>
      </div>
      <div class="muet" style="margin:6px 0 12px">
        La plateforme propose un nom à partir de ce qu'elle a observé. Elle ne pose
        pas de diagnostic : c'est vous qui décidez si le nom porte un sens métier.
        Une fiche validée rejoint le catalogue appris et la menace sera reconnue
        à sa prochaine occurrence.
      </div>
      ${fiches.qualifications.map((f) => `
        <div class="fiche">
          <div class="champ-fiche">
            <label>Nom proposé</label>
            <input data-fiche="${esc(f.qualification_id)}" data-champ="label"
                   value="${esc(f.label)}">
          </div>
          <div class="ligne-fiche">
            <span class="muet">famille <b>${esc(f.family)}</b></span>
            <span class="muet">gravité <b>${esc(f.severity)}</b></span>
            <span class="muet">dangerosité <b>${esc(String(f.dangerousness))}/10</b></span>
            <span class="muet mono">clé ${esc(f.category)}</span>
          </div>
          <div class="muet" style="margin:6px 0">
            <b>Observé :</b> ${esc(f.signal)}
          </div>
          <div class="muet" style="font-size:11px">${esc(f.rationale || "")}</div>
          <div class="choix" style="margin-top:10px">
            <button data-fiche-act="${esc(f.qualification_id)}" data-issue="adopt">
              Valider et cataloguer</button>
            <button data-fiche-act="${esc(f.qualification_id)}" data-issue="dismiss">
              Rejeter</button>
          </div>
        </div>`).join("")}
    </div>`;
}

function brancherDecisions() {
  $("vue").querySelectorAll("button[data-att]").forEach((b) =>
    b.addEventListener("click", () => trancher(b)));
  $("vue").querySelectorAll("button[data-fiche-act]").forEach((b) =>
    b.addEventListener("click", () => qualifier(b)));
}

const LIBELLE_ISSUE = {
  confirm: "geste confirmé et exécuté",
  handled: "intervention notée à votre nom",
  resolved: "dossier clos",
  decline: "geste écarté",
  substitute: "geste de remplacement appliqué",
};

// Le motif se lit dans la page. Aucun dialogue natif n'est employe : un
// navigateur qui les supprime rendait toute decision impossible, sans le
// moindre message.
async function trancher(bouton) {
  const id = bouton.dataset.att;
  const issue = bouton.dataset.issue;
  const champ = $("vue").querySelector(`textarea[data-motif="${id}"]`);
  const motif = (champ?.value || "").trim();

  if (motif.length < 3) {
    if (champ) {
      champ.classList.add("manquant");
      champ.placeholder = "Un motif est nécessaire : il est consigné au journal.";
      champ.focus();
      champ.addEventListener("input", () => champ.classList.remove("manquant"), { once: true });
    }
    toast("indiquez un motif avant de décider", "erreur");
    return;
  }

  const fiche = $("vue").querySelector(`[data-fiche-att="${id}"]`);
  fiche?.querySelectorAll("button").forEach((b) => (b.disabled = true));
  const suite = $("vue").querySelector(`[data-suite="${id}"]`);
  if (suite) suite.innerHTML = `<div class="muet">La plateforme traite votre décision…</div>`;

  try {
    const r = await post(`/api/v1/pending/${id}/${issue}`, { reason: motif });
    toast(LIBELLE_ISSUE[issue] || "décision enregistrée");

    // Un refus produit une suite : la plateforme dit ce qu'elle a fait a la
    // place. On l'affiche avant de rafraichir, sinon le rafraichissement
    // l'effacerait et l'exploitant ne saurait jamais ce qui a ete decide.
    if (r.escalade && suite) {
      suite.innerHTML = blocEscalade(id, r.escalade);
      brancherDecisions();
      return;
    }
    await rafraichir();
  } catch (e) {
    toast(e.message, "erreur");
    fiche?.querySelectorAll("button").forEach((b) => (b.disabled = false));
    if (suite) suite.innerHTML = "";
  }
}

async function qualifier(bouton) {
  const id = bouton.dataset.fiche_act || bouton.dataset["ficheAct"];
  const issue = bouton.dataset.issue;
  const champ = $("vue").querySelector(`input[data-fiche="${id}"][data-champ="label"]`);
  const corps = issue === "adopt" && champ ? { label: champ.value.trim() } : {};
  bouton.disabled = true;
  try {
    const r = await post(`/api/v1/qualifications/${id}/${issue}`, corps);
    toast(issue === "adopt"
      ? `type ${r.qualification.code} inscrit au catalogue appris`
      : "proposition rejetée");
    await rafraichir();
  } catch (e) { toast(e.message, "erreur"); bouton.disabled = false; }
}

function etiquetteEvenement(e) {
  const map = {
    "action.executed": ["basse", "exécutée"],
    "action.failed": ["critique", "échec"],
    "rollback.completed": ["moyenne", "annulée"],
    "rollback.failed": ["critique", "ANNULATION IMPOSSIBLE"],
    "breaker.tripped": ["critique", "coupe-circuit ouvert"],
  };
  const [classe, libelle] = map[e.event_type] || ["info", e.event_type];
  return `<span class="etat ${classe}">${esc(libelle)}</span>`;
}

function brancherLiens() {
  document.querySelectorAll("a[data-lien]").forEach((a) =>
    a.addEventListener("click", (ev) => { ev.preventDefault(); naviguer(a.getAttribute("href")); }));
}

// ================================================== /incidents/portfolio
async function vuePortefeuille() {
  const [portefeuille, stats] = await Promise.all([
    api("/api/v1/incidents?limit=200"),
    api("/api/v1/incidents/statistics"),
  ]);
  const incidents = portefeuille.incidents;
  badge("/incidents/portfolio", portefeuille.count || 0);

  $("vue").innerHTML = `
    <div class="grille" style="margin-bottom:18px">
      ${tuile(stats.incidents_total, "Incidents au portefeuille")}
      ${tuile(stats.by_priority?.critique || 0, "Priorité critique", "à traiter en premier",
        stats.by_priority?.critique ? "var(--critical)" : "")}
      ${tuile(stats.actions_executed, "Actions exécutées")}
      ${tuile(stats.actions_rolled_back, "Actions annulées")}
    </div>

    <div class="carte" style="margin-bottom:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <span class="muet">Filtrer :</span>
      <select id="f-famille">
        <option value="">Toutes les familles</option>
        ${Object.entries(LIB_FAMILLE).map(([k, v]) =>
          `<option value="${k}">${esc(k)} — ${esc(v)}</option>`).join("")}
      </select>
      <select id="f-priorite">
        <option value="">Toutes les priorités</option>
        ${["critique", "haute", "moyenne", "basse"].map((p) =>
          `<option value="${p}">${p}</option>`).join("")}
      </select>
      <span class="spacer"></span>
      <span class="muet" id="compte-filtre"></span>
    </div>

    <div class="carte" style="padding:0;overflow:auto">
      <table><thead><tr>
        <th>Type</th><th>Libellé</th><th>Famille</th><th>Criticité</th>
        <th>Dangerosité</th><th>Priorité</th><th>Risque</th><th>État</th>
        <th>Exéc.</th><th>Annul.</th><th>Mise à jour</th>
      </tr></thead><tbody id="lignes-incidents"></tbody></table>
    </div>`;

  const rendre = () => {
    const famille = $("f-famille").value, priorite = $("f-priorite").value;
    const filtres = incidents.filter((i) =>
      (!famille || (i.attack_code || "").startsWith(famille))
      && (!priorite || i.priority === priorite));
    $("compte-filtre").textContent = `${filtres.length} incident(s) affiché(s) sur ${incidents.length}`;
    $("lignes-incidents").innerHTML = filtres.length ? filtres.map((i) => {
      const f = (i.attack_code || "?").charAt(0);
      return `<tr>
        <td><b>${esc(i.attack_code || "?")}</b></td>
        <td>${esc(court(i.attack_label || i.category, 46))}</td>
        <td><span class="fam"><span class="puce ${esc(f)}"></span>${esc(i.family_label || "—")}</span></td>
        <td><span class="etat ${esc(i.severity)}">${esc(i.severity)}</span></td>
        <td><span class="etat ${bandeDanger(i.dangerousness || 0)}">${i.dangerousness ?? "—"}/10</span></td>
        <td><span class="etat ${esc(i.priority || "")}">${esc(i.priority || "—")}</span></td>
        <td class="num">${i.risk_score}</td>
        <td><span class="etat ${i.status === "rolled_back" ? "moyenne" : "basse"}">${esc(i.status)}</span></td>
        <td class="num">${i.actions_executed}</td>
        <td class="num">${i.actions_rolled_back || "—"}</td>
        <td class="muet">${heure(i.updated_at)}</td>
      </tr>`;
    }).join("") : `<tr><td colspan="11" class="vide">Aucun incident ne correspond au filtre.</td></tr>`;
  };
  $("f-famille").addEventListener("change", rendre);
  $("f-priorite").addEventListener("change", rendre);
  rendre();
}

// =========================================================== /monitoring
async function vueSurveillance() {
  const m = await api("/api/v1/monitoring");
  const s = m.summary;
  badge("/monitoring", s.degrade + s.injoignable || 0);

  $("vue").innerHTML = `
    <div class="grille" style="margin-bottom:18px">
      ${tuile(s.total, "Plateformes supervisées")}
      ${tuile(s.nominal, "État nominal", "dans les seuils de service",
        s.nominal ? "var(--success-text)" : "")}
      ${tuile(s.degrade, "Dégradées", "hors seuils, joignables",
        s.degrade ? "var(--serious)" : "")}
      ${tuile(s.injoignable, "Injoignables", "sonde en échec",
        s.injoignable ? "var(--critical)" : "")}
    </div>

    ${carteSurveillance(m.targets, m.anchor)}

    ${enteteSection("parc", "Parc supervisé", m.targets.length)}
    <div class="repliable" data-section="parc">
      <div style="display:flex;justify-content:flex-end;margin-bottom:10px">
        <button class="primaire reserve-action" id="ajouter-plateforme">+ Ajouter une plateforme</button>
      </div>
      <div class="carte" style="padding:0;overflow:auto">
        <table><thead><tr>
          <th>Plateforme</th><th>Type</th><th>Segment</th><th>Propriétaire</th>
          <th>Criticité</th><th>État</th><th>Latence</th><th>Erreurs</th>
          <th>Incidents</th><th>Actions</th><th></th>
        </tr></thead><tbody>
        ${m.targets.map((t) => `<tr>
          <td><button class="lien" data-detail="${esc(t.target)}"><b>${esc(t.target)}</b></button>
              ${t.ip ? `<div class="muet mono">${esc(t.ip)}</div>` : ""}</td>
          <td class="muet">${esc(t.kind || "actif")}</td>
          <td class="muet">${esc(t.zone)}</td>
          <td class="muet">${esc(court(t.owner, 26) || "—")}</td>
          <td class="num">${t.criticality}/5</td>
          <td><span class="etat ${esc(t.state)}">${esc(t.state)}</span></td>
          <td class="num">${t.health.latency_ms ? Math.round(t.health.latency_ms) + " ms" : "—"}</td>
          <td class="num">${(t.health.error_rate * 100).toFixed(1)} %</td>
          <td class="num">${t.incidents || "—"}</td>
          <td class="num">${t.actions_executed || "—"}${
            t.actions_rolled_back ? ` <span class="muet">(${t.actions_rolled_back} ann.)</span>` : ""}</td>
          <td style="white-space:nowrap">
            <button data-detail="${esc(t.target)}">Ouvrir</button>
            ${t.declared ? `<button data-retirer="${esc(t.target)}"
              title="Retirer du parc surveillé">Retirer</button>` : ""}</td>
        </tr>`).join("")}
        </tbody></table>
      </div>
    </div>

    ${enteteSection("veille", "Surveillance post-action (EF-25)", m.post_action_watches.length)}
    <div class="repliable" data-section="veille">
      <div class="carte">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
          <span class="muet">${m.post_action_watches.length} action(s) réversible(s) encore
            appliquée(s).</span>
          <span class="spacer"></span>
          <button class="primaire reserve-action" id="boucle">Lancer la boucle de contrôle</button>
        </div>
        <div id="resultat-boucle"></div>
        ${m.post_action_watches.length ? `<table><thead><tr>
          <th>Action</th><th>Geste</th><th>Cible</th><th>Référence prise</th>
        </tr></thead><tbody>
          ${m.post_action_watches.map((w) => `<tr>
            <td class="mono">${esc(w.action_id.slice(0, 18))}</td>
            <td class="mono">${esc(w.verb)}</td>
            <td>${esc(w.target)}</td>
            <td>${w.watched
              ? '<span class="etat basse">oui</span>'
              : '<span class="etat moyenne">non — la boucle s\'abstiendra</span>'}</td>
          </tr>`).join("")}
        </tbody></table>` : '<div class="vide">Aucune action sous surveillance.</div>'}
      </div>
    </div>`;

  brancherSections();
  initCarte();
  $("vue").querySelectorAll("[data-detail]").forEach((b) =>
    b.addEventListener("click", () => ouvrirDetail(b.dataset.detail)));
  $("vue").querySelectorAll("[data-retirer]").forEach((b) =>
    b.addEventListener("click", () => retirerPlateforme(b.dataset.retirer)));
  $("ajouter-plateforme").addEventListener("click", formulairePlateforme);
  brancherBoucle();
}

// ============================================== carte de surveillance
// Projection Web Mercator, deplacement et zoom. Aucun fond de tuiles : la
// plateforme reste utilisable hors connexion, le reperage se fait au
// graticule lat/lon et aux anneaux de portee autour du siege. Le balayage
// radar (CSS, .geo-balayage) tourne sans fin autour d'un centre accroche a
// la COORDONNEE du siege — jamais a un point de l'ecran : zoom et
// deplacement le laissent sur place.

const CARTE = {
  lat: null, lon: null, zoom: 15,
  ancre: { lat: 3.8747, lon: 11.5203, label: "Siège" },
  cibles: [],
};
const CARTE_ZMIN = 3, CARTE_ZMAX = 19, CARTE_TUILE = 256, CARTE_R = 6378137;
const clampLat = (v) => Math.min(85, Math.max(-85, v));
const wrapLon = (v) => ((((v + 180) % 360) + 360) % 360) - 180;

function merc(lat, lon) {
  const s = Math.min(Math.max(Math.sin((lat * Math.PI) / 180), -0.9999), 0.9999);
  return { x: (lon + 180) / 360, y: 0.5 - Math.log((1 + s) / (1 - s)) / (4 * Math.PI) };
}
function mercInv(x, y) {
  const k = Math.exp((0.5 - y) * 4 * Math.PI);
  return { lat: (Math.asin((k - 1) / (k + 1)) * 180) / Math.PI, lon: x * 360 - 180 };
}

function cadrageInitial(situees) {
  const lats = situees.map((t) => t.latitude).concat(CARTE.ancre.lat);
  const lons = situees.map((t) => t.longitude).concat(CARTE.ancre.lon);
  const dLat = Math.max(...lats) - Math.min(...lats);
  const dLon = Math.max(...lons) - Math.min(...lons);
  const etendue = Math.max(dLat, dLon * 0.6, 0.006);
  return Math.min(CARTE_ZMAX, Math.max(CARTE_ZMIN, Math.floor(Math.log2(360 / etendue)) - 1));
}

function carteSurveillance(cibles, ancre) {
  if (!cibles.length) return "";
  CARTE.cibles = cibles;
  if (ancre && ancre.lat != null) CARTE.ancre = ancre;
  const situees = cibles.filter((t) => t.latitude != null && t.longitude != null);
  if (CARTE.lat == null) {
    CARTE.lat = CARTE.ancre.lat;
    CARTE.lon = CARTE.ancre.lon;
    CARTE.zoom = situees.length ? cadrageInitial(situees) : 15;
  }
  const hors = cibles.length - situees.length;
  return `
    <div class="carte-geo" id="carte-geo" tabindex="0"
         aria-label="Carte des plateformes supervisées — déplacer, zoomer">
      <svg class="geo-grille" id="geo-grille" aria-hidden="true"></svg>
      <div class="geo-radar" id="geo-radar" aria-hidden="true"><span class="geo-balayage"></span></div>
      <div class="geo-calque" id="geo-calque"></div>
      <div class="geo-rose" aria-hidden="true">N</div>
      <div class="geo-commandes">
        <button type="button" data-zoom="1" aria-label="Zoomer">+</button>
        <button type="button" data-zoom="-1" aria-label="Dézoomer">−</button>
        <button type="button" id="geo-recentrer" title="Recentrer sur le siège"
                aria-label="Recentrer sur le siège">⌖</button>
      </div>
      <div class="geo-infos">
        <span id="geo-echelle" class="geo-echelle" data-lib=""></span>
        <span id="geo-coord" class="mono"></span>
      </div>
    </div>
    <div class="legende-plan">
      <span><i class="point vert"></i>nominal</span>
      <span><i class="point" style="background:var(--warning)"></i>dégradé</span>
      <span><i class="point rouge"></i>injoignable</span>
      <span><i class="geo-pin-siege"></i>${esc(CARTE.ancre.label)} — centre du balayage</span>
      <span>${situees.length}/${cibles.length} plateforme(s) géolocalisée(s)${
        hors ? ` ; ${hors} sans coordonnées, dans le tableau seulement` : ""}</span>
    </div>`;
}

function pasGrille(mpp) {
  const brut = (100 * mpp) / 111320; // degres pour ~100 px a l'ecran
  const jolis = [0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10];
  return jolis.find((d) => d >= brut) || 10;
}

function grilleSvg(w, h, versEcran, versLatLon, siege, mpp) {
  const a = versLatLon(0, 0), b = versLatLon(w, h);
  const latMin = Math.min(a.lat, b.lat), latMax = Math.max(a.lat, b.lat);
  const lonMin = Math.min(a.lon, b.lon), lonMax = Math.max(a.lon, b.lon);
  const pas = pasGrille(mpp);
  const dec = pas < 0.01 ? 3 : pas < 0.1 ? 2 : pas < 1 ? 1 : 0;
  let g = "";
  for (let lon = Math.ceil(lonMin / pas) * pas; lon <= lonMax; lon += pas) {
    const x = versEcran(latMin, lon).x;
    if (x < -20 || x > w + 20) continue;
    g += `<line x1="${x.toFixed(1)}" y1="0" x2="${x.toFixed(1)}" y2="${h}" class="gl"/>`
      + `<text x="${(x + 3).toFixed(1)}" y="11" class="gt">${lon.toFixed(dec)}°E</text>`;
  }
  for (let lat = Math.ceil(latMin / pas) * pas; lat <= latMax; lat += pas) {
    const y = versEcran(lat, lonMin).y;
    if (y < -20 || y > h + 20) continue;
    g += `<line x1="0" y1="${y.toFixed(1)}" x2="${w}" y2="${y.toFixed(1)}" class="gl"/>`
      + `<text x="3" y="${(y - 3).toFixed(1)}" class="gt">${lat.toFixed(dec)}°N</text>`;
  }
  const diag = Math.hypot(w, h);
  for (const km of [1, 2, 5, 10, 20, 50]) {
    const r = (km * 1000) / mpp;
    if (r < 14 || r > diag) continue;
    g += `<circle cx="${siege.x.toFixed(1)}" cy="${siege.y.toFixed(1)}" r="${r.toFixed(1)}" class="ga"/>`
      + `<text x="${siege.x.toFixed(1)}" y="${(siege.y - r - 3).toFixed(1)}" class="gt gac">${km} km</text>`;
  }
  return g;
}

function initCarte() {
  const el = $("carte-geo");
  if (!el) return;
  const calque = $("geo-calque"), grille = $("geo-grille"), radar = $("geo-radar");

  const dims = () => ({ w: el.clientWidth || 1, h: el.clientHeight || 1 });
  const mondePx = () => CARTE_TUILE * 2 ** CARTE.zoom;
  const mpp = () =>
    (2 * Math.PI * CARTE_R * Math.cos((CARTE.lat * Math.PI) / 180)) / mondePx();

  function versEcran(lat, lon) {
    const { w, h } = dims(), c = merc(CARTE.lat, CARTE.lon), p = merc(lat, lon), m = mondePx();
    return { x: (p.x - c.x) * m + w / 2, y: (p.y - c.y) * m + h / 2 };
  }
  function versLatLon(px, py) {
    const { w, h } = dims(), c = merc(CARTE.lat, CARTE.lon), m = mondePx();
    return mercInv(c.x + (px - w / 2) / m, c.y + (py - h / 2) / m);
  }
  // dxPx > 0 : le contenu suit vers la droite (le centre part vers l'ouest).
  function deplacer(dxPx, dyPx) {
    const c = merc(CARTE.lat, CARTE.lon), m = mondePx();
    const d = mercInv(c.x - dxPx / m, c.y - dyPx / m);
    CARTE.lat = clampLat(d.lat);
    CARTE.lon = wrapLon(d.lon);
  }
  function appliquerZoom(vise, px, py) {
    vise = Math.min(CARTE_ZMAX, Math.max(CARTE_ZMIN, vise));
    if (vise === CARTE.zoom) return;
    const { w, h } = dims();
    if (px == null) { px = w / 2; py = h / 2; }
    const sous = versLatLon(px, py); // point geo sous le curseur
    CARTE.zoom = vise;
    const apres = versEcran(sous.lat, sous.lon);
    deplacer(px - apres.x, py - apres.y); // le ramener sous le curseur
    demanderRendu();
  }

  let planifie = false;
  const demanderRendu = () => {
    if (planifie) return;
    planifie = true;
    requestAnimationFrame(rendre);
  };

  function rendre() {
    planifie = false;
    const { w, h } = dims(), m = mpp();
    const situees = CARTE.cibles.filter((t) => t.latitude != null && t.longitude != null);
    const pos = (lat, lon) => {
      const s = versEcran(lat, lon);
      return `translate(calc(${s.x.toFixed(1)}px - 50%), calc(${s.y.toFixed(1)}px - 50%))`;
    };

    calque.innerHTML =
      situees.map((t) => `<button class="geo-plot" data-detail="${esc(t.target)}"
        data-etat="${esc(t.state)}" style="transform:${pos(t.latitude, t.longitude)}"
        title="${esc(t.target)} — ${esc(t.state)}">
        <span class="geo-pastille"></span><span class="geo-nom">${esc(t.target)}</span></button>`).join("")
      + `<div class="geo-siege" style="transform:${pos(CARTE.ancre.lat, CARTE.ancre.lon)}"
          title="${esc(CARTE.ancre.label)}"><span></span>
          <span class="geo-nom">${esc(CARTE.ancre.label)}</span></div>`;
    calque.querySelectorAll("[data-detail]").forEach((b) =>
      b.addEventListener("click", () => ouvrirDetail(b.dataset.detail)));

    // balayage : le CENTRE est accroche a la coordonnee du siege (c'est la
    // consigne) ; le rayon suit la fenetre — les anneaux de portee, eux,
    // donnent l'echelle geographique reelle.
    const cs = versEcran(CARTE.ancre.lat, CARTE.ancre.lon);
    const cote = (Math.hypot(w, h) * 2.3).toFixed(0);
    radar.style.width = radar.style.height = `${cote}px`;
    radar.style.left = `${cs.x.toFixed(1)}px`;
    radar.style.top = `${cs.y.toFixed(1)}px`;

    grille.setAttribute("viewBox", `0 0 ${w} ${h}`);
    grille.innerHTML = grilleSvg(w, h, versEcran, versLatLon, cs, m);

    $("geo-coord").textContent =
      `${Math.abs(CARTE.lat).toFixed(5)}°${CARTE.lat >= 0 ? "N" : "S"} ` +
      `${Math.abs(CARTE.lon).toFixed(5)}°${CARTE.lon >= 0 ? "E" : "O"} · z${CARTE.zoom.toFixed(CARTE.zoom % 1 ? 1 : 0)}`;
    const bar = $("geo-echelle");
    const paliers = [10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000];
    let choisi = paliers[0];
    for (const p of paliers) if (p / m <= 120) choisi = p;
    bar.style.width = `${(choisi / m).toFixed(1)}px`;
    bar.dataset.lib = choisi >= 1000 ? `${choisi / 1000} km` : `${choisi} m`;
  }

  // --- deplacement (souris + tactile) et pincement --------------------
  const pointeurs = new Map();
  let pince = 0;
  el.addEventListener("pointerdown", (e) => {
    if (e.target.closest(".geo-commandes")) return;
    pointeurs.set(e.pointerId, { x: e.clientX, y: e.clientY });
    try { el.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    el.classList.add("attrape");
  });
  el.addEventListener("pointermove", (e) => {
    const p = pointeurs.get(e.pointerId);
    if (!p) return;
    const dx = e.clientX - p.x, dy = e.clientY - p.y;
    p.x = e.clientX; p.y = e.clientY;
    if (pointeurs.size === 1) {
      deplacer(dx, dy);
      demanderRendu();
    } else if (pointeurs.size === 2) {
      const [a, b] = [...pointeurs.values()];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      if (pince) {
        const r = el.getBoundingClientRect();
        appliquerZoom(CARTE.zoom + Math.log2(dist / pince),
          (a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top);
      }
      pince = dist;
    }
  });
  const relacher = (e) => {
    pointeurs.delete(e.pointerId);
    if (pointeurs.size < 2) pince = 0;
    if (!pointeurs.size) el.classList.remove("attrape");
    try { el.releasePointerCapture(e.pointerId); } catch { /* ignore */ }
  };
  el.addEventListener("pointerup", relacher);
  el.addEventListener("pointercancel", relacher);

  el.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = el.getBoundingClientRect();
    appliquerZoom(CARTE.zoom + (e.deltaY < 0 ? 0.5 : -0.5), e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });

  el.querySelectorAll("[data-zoom]").forEach((b) =>
    b.addEventListener("click", () => appliquerZoom(Math.round(CARTE.zoom) + Number(b.dataset.zoom))));
  $("geo-recentrer").addEventListener("click", () => {
    CARTE.lat = CARTE.ancre.lat;
    CARTE.lon = CARTE.ancre.lon;
    CARTE.zoom = 15;
    demanderRendu();
  });

  el.addEventListener("keydown", (e) => {
    const d = { ArrowUp: [0, 60], ArrowDown: [0, -60], ArrowLeft: [60, 0], ArrowRight: [-60, 0] }[e.key];
    if (d) { e.preventDefault(); deplacer(d[0], d[1]); demanderRendu(); }
    else if (e.key === "+" || e.key === "=") appliquerZoom(Math.round(CARTE.zoom) + 1);
    else if (e.key === "-" || e.key === "_") appliquerZoom(Math.round(CARTE.zoom) - 1);
  });

  if (window.ResizeObserver) new ResizeObserver(demanderRendu).observe(el);
  rendre();
}

// --------------------------------------------------------- sections repliables
const REPLIEES = new Set();

function enteteSection(cle, titre, compte) {
  const ouvert = !REPLIEES.has(cle);
  return `<button class="entete-section" data-repli="${cle}" aria-expanded="${ouvert}">
    <h2>${esc(titre)}</h2><span class="compte">${compte}</span>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
         stroke-linecap="round" class="chevron"><path d="m6 9 6 6 6-6"/></svg>
  </button>`;
}

function brancherSections() {
  $("vue").querySelectorAll("[data-repli]").forEach((entete) => {
    const cle = entete.dataset.repli;
    const corps = $("vue").querySelector(`[data-section="${cle}"]`);
    if (corps) corps.hidden = REPLIEES.has(cle);
    entete.addEventListener("click", () => {
      const replie = REPLIEES.has(cle);
      if (replie) REPLIEES.delete(cle); else REPLIEES.add(cle);
      entete.setAttribute("aria-expanded", String(replie));
      if (corps) corps.hidden = !replie;
    });
  });
}

// --------------------------------------------- declaration d'une plateforme
const TYPES_PLATEFORME = [
  "serveur web", "serveur applicatif", "base de données", "serveur de fichiers",
  "serveur de messagerie", "pare-feu", "routeur", "commutateur",
  "poste de travail", "équipement industriel", "service infonuagique", "autre",
];

function formulairePlateforme() {
  const champ = (nom, libelle, indice, extra = "") => `
    <div class="champ" data-champ="${nom}">
      <label for="p-${nom}">${esc(libelle)}</label>
      <input id="p-${nom}" name="${nom}" ${extra}>
      <span class="indice">${esc(indice)}</span>
      <span class="erreur" hidden></span>
    </div>`;

  ouvrirModale({
    titre: "Ajouter une plateforme à surveiller",
    sous: "Ces informations entrent au journal d'audit : elles définissent le périmètre surveillé",
    corps: `
      <div class="champs">
        ${champ("label", "Nom ou libellé", "Sert d'identifiant dans le journal", 'maxlength="80"')}
        <div class="champ" data-champ="kind">
          <label for="p-kind">Type</label>
          <select id="p-kind" name="kind">
            ${TYPES_PLATEFORME.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("")}
          </select>
          <span class="indice">Nature de l'équipement</span>
          <span class="erreur" hidden></span>
        </div>
        ${champ("ip", "Adresse IP", "IPv4 ou IPv6", 'placeholder="10.0.2.60"')}
        ${champ("segment", "Segment réseau", "Zone : dmz, interne, bureautique…")}
        ${champ("owner", "Propriétaire", "À qui une alerte sur cet actif est adressée")}
        <div class="champ" data-champ="criticality">
          <label for="p-criticality">Criticité</label>
          <select id="p-criticality" name="criticality">
            <option value="1">1 — négligeable</option>
            <option value="2">2 — faible</option>
            <option value="3" selected>3 — moyenne</option>
            <option value="4">4 — forte</option>
            <option value="5">5 — vitale</option>
          </select>
          <span class="indice">Pèse sur la dangerosité et la priorité</span>
          <span class="erreur" hidden></span>
        </div>
        ${champ("latitude", "Latitude (facultatif)", "Pour le placement sur le plan",
          'type="number" step="0.0001" placeholder="3.8670"')}
        ${champ("longitude", "Longitude (facultatif)", "Laissée vide, la position est indicative",
          'type="number" step="0.0001" placeholder="11.5190"')}
      </div>
      <div id="erreur-formulaire" style="margin-top:14px"></div>`,
    actions: `<button data-fermer>Annuler</button>
              <button class="primaire" id="enregistrer">Enregistrer</button>`,
    apres: (racine) => {
      racine.querySelector("#enregistrer")
        .addEventListener("click", () => enregistrerPlateforme(racine));
    },
  });
}

async function enregistrerPlateforme(racine) {
  const lire = (n) => racine.querySelector(`[name="${n}"]`).value.trim();
  const marquer = (n, message) => {
    const bloc = racine.querySelector(`[data-champ="${n}"]`);
    bloc.classList.toggle("invalide", Boolean(message));
    const erreur = bloc.querySelector(".erreur");
    erreur.hidden = !message;
    erreur.textContent = message || "";
  };

  const corps = {
    label: lire("label"), kind: lire("kind"), ip: lire("ip"),
    segment: lire("segment"), owner: lire("owner"),
    criticality: Number(lire("criticality")),
  };
  const lat = lire("latitude"), lon = lire("longitude");
  if (lat) corps.latitude = Number(lat);
  if (lon) corps.longitude = Number(lon);

  // Verifier avant d'envoyer : un champ manquant se signale a cote du champ,
  // pas dans un message d'erreur global qu'il faut decoder.
  let complet = true;
  for (const [nom, libelle] of [["label", "Le nom"], ["ip", "L'adresse IP"],
       ["segment", "Le segment"], ["owner", "Le propriétaire"]]) {
    const manque = !corps[nom] || corps[nom].length < 2;
    marquer(nom, manque ? `${libelle} est obligatoire.` : "");
    if (manque) complet = false;
  }
  if (!complet) return;

  const bouton = racine.querySelector("#enregistrer");
  bouton.disabled = true; bouton.textContent = "Enregistrement…";
  try {
    await post("/api/v1/monitoring/targets", corps);
    fermerModale();
    await vueSurveillance();
  } catch (e) {
    const cause = /403|401/.test(e.message)
      ? "Déclarer une plateforme est réservé à l'administrateur : la session courante ne porte pas ce rôle."
      : e.message;
    racine.querySelector("#erreur-formulaire").innerHTML =
      `<div class="bandeau suspendu">${esc(cause)}</div>`;
    bouton.disabled = false; bouton.textContent = "Enregistrer";
  }
}

async function retirerPlateforme(cible) {
  ouvrirModale({
    titre: "Retirer du parc surveillé ?",
    sous: cible,
    corps: `<p>Cette plateforme ne sera plus mesurée ni affichée. Les incidents
      déjà enregistrés sur elle restent au portefeuille et au journal d'audit :
      retirer un actif du périmètre n'efface pas son histoire.</p>
      <div id="erreur-retrait"></div>`,
    actions: `<button data-fermer>Annuler</button>
              <button class="primaire" id="confirmer-retrait">Retirer</button>`,
    apres: (racine) => {
      racine.querySelector("#confirmer-retrait").addEventListener("click", async () => {
        try {
          await api(`/api/v1/monitoring/targets/${encodeURIComponent(cible)}`,
            { method: "DELETE" });
          fermerModale();
          await vueSurveillance();
        } catch (e) {
          racine.querySelector("#erreur-retrait").innerHTML =
            `<div class="bandeau suspendu">${esc(e.message)}</div>`;
        }
      });
    },
  });
}

// ------------------------------------------------ fenetre d'une plateforme
async function ouvrirDetail(cible) {
  ouvrirModale({
    titre: cible, sous: "Chargement…", large: true,
    corps: '<div class="vide">Lecture des mesures…</div>',
  });
  try {
    const d = await api(`/api/v1/monitoring/targets/${encodeURIComponent(cible)}`);
    afficherDetail(d);
  } catch (e) {
    ouvrirModale({
      titre: cible, large: true,
      corps: `<div class="bandeau suspendu">${esc(e.message)}</div>`,
      actions: "<button data-fermer>Fermer</button>",
    });
  }
}

function afficherDetail(d) {
  const r = d.summary;
  const sain = d.state === "nominal";

  ouvrirModale({
    titre: d.hostname || d.target,
    sous: `${d.kind || "actif"} · ${d.zone} · ${d.ip || "sans adresse"}${
      d.owner ? ` · ${d.owner}` : ""}`,
    large: true,
    corps: `
      <div class="grille" style="margin-bottom:16px">
        ${tuile(d.state, "État courant", (d.breaches || []).join(" ; ") || "dans les seuils",
          sain ? "var(--success-text)" : d.state === "degrade" ? "var(--serious)" : "var(--critical)")}
        ${tuile(r.incidents, "Incidents sur cet actif",
          r.worst_priority ? `pire priorité : ${r.worst_priority}` : "aucun")}
        ${tuile(r.actions_executed, "Actions exécutées",
          r.actions_rolled_back ? `${r.actions_rolled_back} annulée(s)` : "aucune annulation")}
        ${tuile(d.criticality + "/5", "Criticité déclarée", `${r.audit_entries} entrée(s) d'audit`)}
      </div>

      <div class="carte" id="d-simulation" style="margin-bottom:16px;display:flex;gap:10px;
           align-items:center;flex-wrap:wrap">
        <b>Simulation sur cette plateforme</b>
        <span class="spacer"></span>
        <button id="d-degrader">${sain ? "Dégrader" : "Rétablir"}</button>
        <select id="d-scenario" style="padding:7px 9px;border-radius:8px;
          border:1px solid var(--grid);background:var(--plane);color:var(--ink-1)">
          <option value="">— scénario du catalogue —</option>
        </select>
        <button class="primaire" id="d-lancer">Lancer</button>
      </div>
      <div id="d-resultat" style="margin-bottom:16px"></div>

      <h3 style="margin:0 0 8px">Mesure</h3>
      <div class="carte" style="padding:0;overflow:auto;margin-bottom:18px">
        <table><thead><tr><th>Indicateur</th><th>Mesuré</th><th>Seuil</th></tr></thead>
        <tbody>
          <tr><td>Latence</td><td class="num">${d.health.latency_ms
            ? Math.round(d.health.latency_ms) + " ms" : "—"}</td>
            <td class="num muet">${d.thresholds.max_latency_ms} ms</td></tr>
          <tr><td>Taux d'erreur</td><td class="num">${(d.health.error_rate * 100).toFixed(1)} %</td>
            <td class="num muet">${(d.thresholds.max_error_rate * 100).toFixed(0)} %</td></tr>
          <tr><td>Débit</td><td class="num">${d.health.throughput || "—"}</td>
            <td class="num muet">${d.thresholds.min_throughput}</td></tr>
          <tr><td>Joignable</td><td>${d.health.reachable ? "oui" : "non"}</td>
            <td class="muet">—</td></tr>
        </tbody></table>
      </div>

      <h3 style="margin:0 0 8px">Incidents (${d.incidents.length})</h3>
      <div class="carte" style="padding:0;overflow:auto;margin-bottom:18px">
        ${d.incidents.length ? `<table><thead><tr>
          <th>Type</th><th>Libellé</th><th>Criticité</th><th>Dangerosité</th>
          <th>Priorité</th><th>État</th><th>Actions</th><th>Mise à jour</th>
        </tr></thead><tbody>
        ${d.incidents.map((i) => `<tr>
          <td class="mono"><b>${esc(i.attack_code || "—")}</b></td>
          <td>${esc(court(i.attack_label || i.category, 38))}</td>
          <td><span class="etat ${esc(i.severity)}">${esc(i.severity)}</span></td>
          <td><span class="etat ${bandeDanger(i.dangerousness)}">${i.dangerousness}/10</span></td>
          <td>${esc(i.priority || "—")}</td>
          <td><span class="etat ${i.status === "contained" ? "basse" : "moyenne"}">${
            esc(i.status)}</span></td>
          <td class="num">${i.actions}</td>
          <td class="muet">${heureCourte(i.updated_at)}</td>
        </tr>`).join("")}</tbody></table>`
        : '<div class="vide">Aucun incident sur cette plateforme.</div>'}
      </div>

      <h3 style="margin:0 0 8px">Chronologie d'audit (${d.timeline.length})</h3>
      <div class="carte" style="padding:0;overflow:auto;max-height:280px">
        ${d.timeline.length ? `<table><thead><tr>
          <th>Horodatage</th><th>Événement</th><th>Acteur</th>
        </tr></thead><tbody>
        ${d.timeline.map((e) => `<tr>
          <td class="muet mono">${heureCourte(e.recorded_at)}</td>
          <td class="mono">${esc(e.event_type)}</td>
          <td class="muet">${esc(e.actor)}</td>
        </tr>`).join("")}</tbody></table>`
        : '<div class="vide">Aucune entrée.</div>'}
      </div>`,
    actions: "<button data-fermer>Fermer</button>",
    apres: (racine) => brancherDetail(racine, d),
  });
}

async function brancherDetail(racine, d) {
  // La simulation (dégrader, rejouer un scénario) est un geste d'administrateur :
  // ses points d'entrée lui sont réservés. On retire la carte pour les autres.
  if (!estAdmin()) {
    racine.querySelector("#d-simulation")?.remove();
    racine.querySelector("#d-resultat")?.remove();
    return;
  }
  const resultat = racine.querySelector("#d-resultat");

  // Le catalogue n'est charge qu'a l'ouverture de la fenetre : la liste des
  // scenarios ne sert a rien tant qu'aucune plateforme n'est selectionnee.
  try {
    const { by_family: familles } = await api("/api/v1/demo/scenarios");
    const select = racine.querySelector("#d-scenario");
    if (select) {
      Object.entries(familles).forEach(([code, liste]) => {
        const groupe = document.createElement("optgroup");
        groupe.label = `${code} — ${LIB_FAMILLE[code] || code}`;
        liste.forEach((sc) => {
          const opt = document.createElement("option");
          opt.value = sc.code;
          opt.textContent = `${sc.code} — ${court(sc.title, 44)}`;
          groupe.appendChild(opt);
        });
        select.appendChild(groupe);
      });
    }
  } catch { /* le catalogue est un confort : la degradation reste possible */ }

  racine.querySelector("#d-degrader").addEventListener("click", async (e) => {
    e.target.disabled = true;
    const degrader = d.state === "nominal";
    try {
      await post(`/api/v1/monitoring/simulate/${encodeURIComponent(d.target)}?degraded=${degrader}`);
      await ouvrirDetail(d.target);
      vueSurveillance();
    } catch (err) {
      resultat.innerHTML = `<div class="bandeau suspendu">${esc(err.message)}</div>`;
      e.target.disabled = false;
    }
  });

  racine.querySelector("#d-lancer").addEventListener("click", async (e) => {
    const code = racine.querySelector("#d-scenario").value;
    if (!code) {
      resultat.innerHTML = '<div class="bandeau suspendu">Choisissez un scénario à lancer.</div>';
      return;
    }
    e.target.disabled = true; e.target.textContent = "Exécution…";
    try {
      const r = await post(`/api/v1/demo/run/${code}`);
      resultat.innerHTML = resultatCible(r, d.target);
      const raz = resultat.querySelector("#d-raz");
      if (raz) {
        raz.addEventListener("click", async () => {
          raz.disabled = true;
          await post("/api/v1/demo/reset");
          await ouvrirDetail(d.target);
          vueSurveillance();
        });
      }
      // Les chiffres de la fenetre datent d'avant le lancement : les relire.
      const frais = await api(`/api/v1/monitoring/targets/${encodeURIComponent(d.target)}`);
      majChiffresDetail(racine, frais);
      vueSurveillance();
    } catch (err) {
      resultat.innerHTML = `<div class="bandeau suspendu">${esc(err.message)}</div>`;
    } finally {
      e.target.disabled = false; e.target.textContent = "Lancer";
    }
  });
}

function resultatCible(r, cible) {
  if (!r.accepted) {
    // Le rejet vient de la deduplication (EF-19) : rejouer la meme observation
    // dans la meme minute ne doit pas faire agir deux fois. Ce n'est pas une
    // panne, c'est la garantie qui s'exerce — mais il faut dire quoi faire.
    const duplique = /duplic/i.test(r.reason || "");
    return `<div class="bandeau suspendu">
      ${esc(r.reason || "scénario non traité")}
      ${duplique ? `<div style="margin-top:8px;font-weight:400">
        La même observation a déjà été traitée : le moteur refuse d'agir deux fois
        sur un événement identique. Remettez la démonstration à zéro, ou attendez
        la minute suivante, ou choisissez un autre scénario.
        <button id="d-raz" style="margin-left:8px">Remettre à zéro</button>
      </div>` : ""}
    </div>`;
  }
  const c = r.decision.classification || {};
  const actions = (r.execution?.results || []);
  const surCible = actions.filter((a) => String(a.target || "").includes(cible));

  return `<div class="carte" style="background:var(--plane)">
    <b>${esc(r.code)} — ${esc(r.scenario.title)}</b>
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin:9px 0">
      <span>Catégorie : <b>${esc(c.category || "—")}</b></span>
      <span>Criticité : <span class="etat ${esc(c.severity || "moyenne")}">${
        esc(c.severity || "—")}</span></span>
      <span>Dangerosité : <span class="etat ${bandeDanger(c.dangerousness || 0)}">${
        c.dangerousness ?? "—"}/10</span></span>
      <span>Priorité : <b>${esc(c.priority || "—")}</b></span>
    </div>
    <div class="muet">${actions.length} action(s) exécutée(s)${
      surCible.length ? `, dont ${surCible.length} visant ${esc(cible)}` : ""}.
      Incident ${esc(r.incident_id || "—")}.</div>
    ${actions.length ? `<div style="margin-top:9px">${actions.map((a) =>
      `<div class="mono" style="font-size:12px">${esc(a.verb || "")} →
        ${esc(a.target || "")} <span class="muet">(${esc(a.status)})</span></div>`)
      .join("")}</div>` : ""}
  </div>`;
}

function majChiffresDetail(racine, d) {
  const tuiles = racine.querySelectorAll(".tuile .valeur");
  if (tuiles.length < 3) return;
  tuiles[1].textContent = d.summary.incidents;
  tuiles[2].textContent = d.summary.actions_executed;
}

function brancherBoucle() {
  $("boucle").addEventListener("click", async () => {
    const bouton = $("boucle");
    bouton.disabled = true; bouton.textContent = "Exécution…";
    try {
      const r = await post("/api/v1/actions/control-loop/run");
      $("resultat-boucle").innerHTML = `<div class="carte" style="background:var(--plane);margin-bottom:12px">
        <b>${r.checked}</b> action(s) vérifiée(s) · <b>${r.degraded}</b> dégradation(s) imputée(s)
        · <b>${r.rolled_back}</b> annulation(s)${
          r.rollback_failures ? ` · <span style="color:var(--critical)"><b>${r.rollback_failures}</b> ÉCHEC(S) d'annulation</span>` : ""}
        ${r.outcomes.length ? `<div class="muet" style="margin-top:8px">${
          r.outcomes.map((o) => `${esc(o.action_id.slice(0, 16))} — ${o.latency_seconds.toFixed(3)} s
            (délai ${o.within_bound ? "respecté" : "DÉPASSÉ"})`).join("<br>")}</div>` : ""}
      </div>`;
      await rafraichir();
    } catch (e) {
      $("resultat-boucle").innerHTML = `<div class="carte" style="border-color:var(--critical)">${esc(e.message)}</div>`;
    } finally {
      bouton.disabled = false; bouton.textContent = "Lancer la boucle de contrôle";
    }
  });
}

// ================================================= /reversibility-catalog
async function vueCatalogue() {
  const c = await api("/api/v1/catalog");
  const entrees = c.entries;
  const autonomes = entrees.filter((e) => e.autonomously_executable);
  const exclues = entrees.filter((e) => !e.autonomously_executable);

  const ligne = (e) => `<tr>
    <td class="mono"><b>${esc(e.key)}</b></td>
    <td>${esc(e.description)}</td>
    <td><span class="etat ${e.reversibility === "reversible" ? "basse"
      : e.reversibility === "partially_reversible" ? "moyenne" : "critique"}">${
      esc({ reversible: "réversible", partially_reversible: "partielle",
            irreversible: "irréversible" }[e.reversibility] || e.reversibility)}</span></td>
    <td class="mono muet">${esc(e.rollback_verb || "—")}</td>
    <td class="num">${e.typical_blast_radius}</td>
    <td class="num">${e.max_rollback_seconds ? e.max_rollback_seconds + " s" : "—"}</td>
    <td class="muet">${esc(e.residual_effect || "aucun")}</td>
  </tr>`;

  $("vue").innerHTML = `
    <div class="grille" style="margin-bottom:18px">
      ${tuile(c.total, "Actions au catalogue")}
      ${tuile(c.autonomously_executable, "Exécutables en autonomie",
        "réversibles et dotées d'un verbe d'annulation", "var(--success-text)")}
      ${tuile(exclues.length, "Hors périmètre autonome",
        "irréversibles — geste humain requis", "var(--critical)")}
    </div>

    <h2>Actions exécutables en autonomie (${autonomes.length})</h2>
    <div class="carte" style="padding:0;overflow:auto">
      <table><thead><tr>
        <th>Action</th><th>Description</th><th>Réversibilité</th><th>Annulation</th>
        <th>Rayon</th><th>Délai max</th><th>Effet résiduel</th>
      </tr></thead><tbody>${autonomes.map(ligne).join("")}</tbody></table>
    </div>

    <h2>Exclues du périmètre autonome (${exclues.length})</h2>
    <div class="carte" style="padding:0;overflow:auto">
      <table><thead><tr>
        <th>Action</th><th>Description</th><th>Réversibilité</th><th>Annulation</th>
        <th>Rayon</th><th>Délai max</th><th>Effet résiduel</th>
      </tr></thead><tbody>${exclues.map(ligne).join("")}</tbody></table>
    </div>`;
}

// ================================================================= /demo
// Le lancement d'un scenario rafraichit l'etat global, ce qui re-rend la vue :
// sans memoire, le compte rendu disparaissait aussitot affiche. On le garde
// donc ici et on le repose apres chaque rendu.
let resultatDemo = "";
const poserResultat = (html) => {
  resultatDemo = html;
  const hote = $("resultat");
  if (!hote) return;
  hote.innerHTML = html;
  hote.scrollIntoView({ behavior: "smooth", block: "start" });
};

async function vueDemo() {
  const [data, inconnus] = await Promise.all([
    api("/api/v1/demo/scenarios"),
    api("/api/v1/demo/unknown").catch(() => ({ scenarios: [] })),
  ]);

  $("vue").innerHTML = `
    <div class="carte" style="margin-bottom:16px">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="primaire" data-famille="">Tout le catalogue (${data.count})</button>
        ${Object.entries(LIB_FAMILLE).map(([k, v]) =>
          `<button data-famille="${k}">${esc(k)} — ${esc(v)}</button>`).join("")}
        <span class="spacer"></span>
        <button id="reset">Remettre à zéro</button>
      </div>
    </div>
    <div id="resultat"></div>
    ${Object.entries(data.by_family).map(([code, items]) => `
      <h2><span class="puce ${esc(code)}" style="display:inline-block;margin-right:6px"></span>
        Famille ${esc(code)} — ${esc(LIB_FAMILLE[code] || "")} (${items.length})</h2>
      <div class="attaques">${items.map((s) => `
        <div class="attaque">
          <div class="tete">
            <span class="code">${esc(s.code)}</span>
            <span class="etat ${esc(s.priority)}">${esc(s.priority)}</span>
          </div>
          <div class="titre">${esc(s.title)}</div>
          <div class="recit">${esc(s.narrative)}</div>
          <div class="pied">
            <button data-code="${esc(s.code)}">Lancer</button>
            <span class="muet">dangerosité ${s.dangerousness}/10</span>
            ${s.no_direct_action ? '<span class="muet">· sans action corrective</span>' : ""}
          </div>
        </div>`).join("")}</div>`).join("")}

    ${inconnus.scenarios.length ? `
      <h2 style="margin-top:26px">Hors catalogue (${inconnus.scenarios.length})</h2>
      <div class="carte" style="margin-bottom:12px">
        Ces menaces ne figurent dans aucune des 22 lignes du catalogue. La plateforme
        ne devine pas leur type : elle part des <b>indicateurs observés</b> et n'engage
        seule que des gestes réversibles. Ce qui a un effet durable lui est proposé,
        et attend une décision humaine.
      </div>
      <div class="attaques">${inconnus.scenarios.map((s) => `
        <div class="attaque">
          <div class="tete">
            <span class="code">${esc(s.code)}</span>
            <span class="etat critique">non catalogué</span>
          </div>
          <div class="titre">${esc(s.title)}</div>
          <div class="recit">${esc(s.narrative)}</div>
          <div class="pied">
            <button data-inconnu="${esc(s.code)}">Lancer</button>
            <span class="muet">${esc(s.indicators.join(" · "))}</span>
          </div>
        </div>`).join("")}</div>` : ""}`;

  $("vue").querySelectorAll("button[data-inconnu]").forEach((b) =>
    b.addEventListener("click", () => lancerInconnu(b)));

  if (resultatDemo) $("resultat").innerHTML = resultatDemo;

  $("vue").querySelectorAll("button[data-code]").forEach((b) =>
    b.addEventListener("click", () => lancerUne(b)));
  $("vue").querySelectorAll("button[data-famille]").forEach((b) =>
    b.addEventListener("click", () => lancerLot(b)));
  $("reset").addEventListener("click", async () => {
    const r = await post("/api/v1/demo/reset");
    resultatDemo = "";
    poserResultat(`<div class="carte" style="border-color:var(--good);margin-bottom:16px">
      Remise à zéro effectuée. ${r.audit_entries_kept} entrées d'audit conservées —
      le journal est immuable par construction.</div>`);
    await rafraichir();
  });
}

// Menace hors catalogue : le resultat doit montrer les deux volets, sans quoi
// on ne comprend pas ce qui a ete fait ni ce qui reste a decider.
async function lancerInconnu(bouton) {
  bouton.disabled = true;
  const texte = bouton.textContent;
  bouton.textContent = "Traitement…";
  try {
    const r = await post(`/api/v1/demo/run-unknown/${bouton.dataset.inconnu}`);
    afficherInconnu(r);
    await rafraichir();
  } catch (e) {
    erreur(e.message);
  } finally {
    bouton.disabled = false;
    bouton.textContent = texte;
  }
}

function afficherInconnu(r) {
  if (!r.accepted) {
    poserResultat(`<div class="carte" style="border-color:var(--serious);margin-bottom:16px">
        ${esc(r.reason || "scénario non traité")}</div>`);
    return;
  }

  const geste = (s, partie) => `<tr>
    <td class="mono"><b>${esc(s.actuator)}:${esc(s.verb)}</b></td>
    <td class="mono">${esc(s.target)}</td>
    <td class="muet">${esc(s.basis)}</td>
    <td><span class="etat ${partie ? "basse" : "moyenne"}">${
      esc(s.reversibility)}</span></td>
    ${partie ? "" : `<td class="muet">${esc(s.residual_effect || "annulation partielle")}</td>`}
  </tr>`;

  poserResultat(`
    <div class="carte" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
        <b>${esc(r.code)} — ${esc(r.scenario.title)}</b>
        <span class="etat critique">non catalogué</span>
        <span class="spacer"></span>
        <span class="muet">incident ${esc(r.incident_id || "—")}</span>
      </div>

      <div class="muet" style="margin-bottom:14px">${esc(r.rationale)}</div>

      <h3 style="margin:0 0 6px;font-size:12px">Ce que la plateforme a observé</h3>
      <ul class="muet" style="margin:0 0 16px;padding-left:18px">
        ${(r.observations || []).map((o) => `<li>${esc(o)}</li>`).join("")}
      </ul>

      <h3 style="margin:0 0 6px;font-size:12px;color:var(--success-text)">
        Engagé seule — réversible (${(r.autonomous || []).length})</h3>
      ${(r.autonomous || []).length ? `<table style="margin-bottom:16px"><thead><tr>
        <th>Geste</th><th>Cible</th><th>Fondement observé</th><th>Réversibilité</th>
      </tr></thead><tbody>${r.autonomous.map((s) => geste(s, true)).join("")}</tbody></table>`
        : '<div class="vide">Aucun geste réversible applicable.</div>'}

      <h3 style="margin:0 0 6px;font-size:12px;color:var(--serious)">
        En attente d'une décision humaine — effet durable (${
          (r.requires_confirmation || []).length})</h3>
      ${(r.requires_confirmation || []).length ? `<table><thead><tr>
        <th>Geste</th><th>Cible</th><th>Fondement observé</th><th>Réversibilité</th>
        <th>Effet résiduel</th>
      </tr></thead><tbody>${
        r.requires_confirmation.map((s) => geste(s, false)).join("")}</tbody></table>`
        : '<div class="vide">Aucun geste durable proposé.</div>'}
    </div>`);
}

async function lancerUne(bouton) {
  bouton.disabled = true; const libelle = bouton.textContent; bouton.textContent = "…";
  try {
    afficherResultat(await post(`/api/v1/demo/run/${bouton.dataset.code}`));
    await rafraichir();
  } catch (e) { erreur(e.message); }
  finally { bouton.disabled = false; bouton.textContent = libelle; }
}

async function lancerLot(bouton) {
  bouton.disabled = true; const libelle = bouton.textContent; bouton.textContent = "Exécution…";
  try {
    const f = bouton.dataset.famille;
    afficherLot(await post(`/api/v1/demo/run-all${f ? `?family=${f}` : ""}`));
    await rafraichir();
  } catch (e) { erreur(e.message); }
  finally { bouton.disabled = false; bouton.textContent = libelle; }
}

const erreur = (m) => {
  poserResultat(`<div class="carte" style="border-color:var(--critical);margin-bottom:16px">${esc(m)}</div>`);
};

// Notification ephemere : confirme un geste des qu'il aboutit. `genre` vaut
// "ok" (defaut), "erreur" ou "info".
const ICONES_TOAST = {
  ok: '<path d="M20 6 9 17l-5-5"/>',
  erreur: '<circle cx="12" cy="12" r="9"/><path d="M12 8v5"/><path d="M12 16h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/>',
};
function toast(message, genre = "ok") {
  const hote = $("toasts");
  if (!hote) return;
  const el = document.createElement("div");
  el.className = `toast ${genre}`;
  el.innerHTML = `
    <svg class="t-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      ${ICONES_TOAST[genre] || ICONES_TOAST.ok}</svg>
    <span class="t-txt">${esc(message)}</span>
    <button class="t-fermer" aria-label="Fermer">&times;</button>`;
  const retirer = () => {
    el.classList.add("sortie");
    setTimeout(() => el.remove(), 220);
  };
  el.querySelector(".t-fermer").addEventListener("click", retirer);
  hote.appendChild(el);
  setTimeout(retirer, genre === "erreur" ? 6500 : 4200);
}

function afficherResultat(r) {
  if (!r.accepted) {
    poserResultat(`<div class="carte" style="margin-bottom:16px">
      <b>${esc(r.code)}</b> — non traité : ${esc(r.reason)}</div>`);
    return;
  }
  const c = r.decision.classification;
  const actions = r.execution?.results || [];
  const ecartees = r.decision.trace?.rejected_actions || [];

  poserResultat(`<div class="carte" style="margin-bottom:16px">
    <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:12px;flex-wrap:wrap">
      <span style="font-size:15px;font-weight:700">${esc(c.code)}</span>
      <span style="font-weight:600">${esc(c.label)}</span>
      <span class="fam"><span class="puce ${esc(c.family_code)}"></span>${esc(c.family_label)}</span>
    </div>
    <div class="etape">
      <div class="quoi2">1 · Classification</div>
      <div>Criticité <span class="etat ${esc(c.severity)}">${esc(c.severity)}</span>
        &nbsp; Dangerosité <span class="etat ${bandeDanger(c.dangerousness)}">${
          c.dangerousness}/10 — ${esc(c.danger_band)}</span>
        &nbsp; Priorité Axe 4 <span class="etat ${esc(c.priority)}">${esc(c.priority)}</span></div>
      <div class="muet" style="margin-top:6px">${(c.factors || []).map(esc).join(" · ")}</div>
    </div>
    <div class="etape">
      <div class="quoi2">2 · Décision</div>
      <div>${esc(r.decision.outcome)}</div>
      <div class="muet" style="margin-top:4px">${esc(r.decision.rationale)}</div>
    </div>
    <div class="etape">
      <div class="quoi2">3 · Actions exécutées sans validation préalable</div>
      ${actions.length ? actions.map((a) => `
        <div style="display:flex;gap:8px;align-items:baseline;font-size:12px;margin-top:4px">
          <span class="mono" style="font-weight:600">${esc(a.actuator)}:${esc(a.verb)}</span>
          <span class="muet">→ ${esc(a.target)}</span>
          <span class="etat ${a.status === "executed" ? "basse" : "critique"}">${esc(a.status)}</span>
          <span class="muet">${esc(a.reversibility)}</span>
        </div>`).join("")
        : '<div class="muet">Aucune action — voir le motif ci-dessus.</div>'}
      ${ecartees.length ? `<div class="muet" style="margin-top:8px">Écartées : ${
        ecartees.map((s) => `${esc(s.action)} (${esc(s.reason)})`).join(" · ")}</div>` : ""}
    </div>
    <div class="etape">
      <div class="quoi2">4 · Prescription du catalogue CIRT</div>
      <div class="muet">${esc(r.scenario.prescribed_actions)}</div>
    </div>
  </div>`);
}

function afficherLot(r) {
  poserResultat(`<div class="carte" style="margin-bottom:16px">
    <div style="margin-bottom:10px"><b>${r.scenarios_run}</b> scénario(s) rejoué(s),
      <b>${r.actions_executed}</b> action(s) exécutée(s)${r.family ? ` — famille ${esc(r.family)}` : ""}.</div>
    <table><thead><tr><th>Type</th><th>Criticité</th><th>Dang.</th><th>Priorité</th><th>Actions</th></tr></thead>
    <tbody>${r.results.map((x) => `<tr>
      <td><b>${esc(x.code)}</b> ${esc(court(x.label, 40))}</td>
      <td>${x.classification.severity
        ? `<span class="etat ${esc(x.classification.severity)}">${esc(x.classification.severity)}</span>` : "—"}</td>
      <td class="num">${x.classification.dangerousness ?? "—"}</td>
      <td>${x.classification.priority
        ? `<span class="etat ${esc(x.classification.priority)}">${esc(x.classification.priority)}</span>` : "—"}</td>
      <td class="mono">${esc(x.actions.join(", ") || "—")}</td>
    </tr>`).join("")}</tbody></table></div>`);
}


// ============================================================== /reports
// Rien n'est produit a l'ouverture de l'ecran. Un rapport que personne n'a
// demande n'a pas d'objet, et en generer un d'office laisse croire que la
// plateforme ne sait en faire qu'un seul.

let optionsRapport = null;

async function vueRapports() {
  if (!optionsRapport) optionsRapport = await api("/api/v1/rapports/options");
  const o = optionsRapport;

  // Les interventions proposees viennent du portefeuille : on ne demande pas
  // a l'exploitant de retenir un numero de dossier.
  let interventions = [];
  try {
    const pf = await api("/api/v1/incidents?limit=200");
    interventions = pf.incidents || [];
  } catch { interventions = []; }

  const menu = (id, choix) => `<select id="${id}">${choix.map((c) =>
    `<option value="${esc(c.cle)}">${esc(c.libelle)}</option>`).join("")}</select>`;

  $("vue").innerHTML = `
    <div class="carte" style="margin-bottom:16px">
      <h3 style="margin:0 0 4px">Éditer un rapport</h3>
      <p class="muet" style="margin:0 0 14px">
        Choisissez ce que le rapport doit couvrir, puis le format sous lequel
        vous souhaitez l'obtenir. Le document reprend la présentation des
        actes officiels et peut être signé en l'état.
      </p>

      <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end">
        <div class="champ">
          <label for="perimetre">Ce que doit couvrir le rapport</label>
          ${menu("perimetre", o.perimetres)}
        </div>
        <div class="champ" id="bloc-valeur" hidden>
          <label for="valeur" id="etiquette-valeur">Précision</label>
          <select id="valeur"></select>
        </div>
        <div class="champ" id="bloc-fenetre">
          <label for="fenetre">Sur quelle durée</label>
          ${menu("fenetre", o.fenetres)}
        </div>
        <div class="champ">
          <label for="format">Format du fichier</label>
          ${menu("format", o.formats)}
        </div>
        <button class="primaire" id="previsualiser">Prévisualiser</button>
        <button id="telecharger">Télécharger</button>
      </div>
    </div>
    <div id="apercu">
      <div class="vide">
        Aucun rapport n'est généré tant que vous n'en avez pas demandé un.
        Précisez le périmètre ci-dessus, puis lancez la prévisualisation.
      </div>
    </div>`;

  const valeursPour = (perimetre) => {
    switch (perimetre) {
      case "incident": return { etiquette: "Quelle intervention",
        choix: interventions.map((i) => ({ cle: i.incident_id,
          libelle: `${numeroCourt(i.incident_id)} — ${i.attack_label || "menace non qualifiée"}` })) };
      case "famille": return { etiquette: "Quelle famille d'attaque", choix: o.familles };
      case "criticite": return { etiquette: "À partir de quelle gravité", choix: o.criticites };
      case "type": return { etiquette: "Quel type du catalogue", choix: o.types };
      default: return null;
    }
  };

  const majFormulaire = () => {
    const perimetre = $("perimetre").value;
    const detail = valeursPour(perimetre);
    $("bloc-valeur").hidden = !detail;
    // Une intervention porte sa propre date : lui appliquer une fenêtre de
    // temps n'aurait aucun sens et laisserait croire qu'on peut la manquer.
    $("bloc-fenetre").hidden = perimetre === "incident";
    if (detail) {
      $("etiquette-valeur").textContent = detail.etiquette;
      $("valeur").innerHTML = detail.choix.length
        ? detail.choix.map((c) => `<option value="${esc(c.cle)}">${esc(c.libelle)}</option>`).join("")
        : `<option value="">Aucun élément disponible</option>`;
    }
  };

  const parametres = () => {
    const p = new URLSearchParams({ perimetre: $("perimetre").value,
      fenetre: $("fenetre").value });
    if (!$("bloc-valeur").hidden) p.set("valeur", $("valeur").value || "");
    return p;
  };

  const previsualiser = async () => {
    $("apercu").innerHTML = '<div class="vide">Composition du rapport…</div>';
    try {
      const r = await api(`/api/v1/rapports/apercu?${parametres()}`);
      $("apercu").innerHTML = rendreFeuille(r.document);
    } catch (e) {
      $("apercu").innerHTML = `<div class="carte" style="border-color:var(--critical)">${esc(e.message)}</div>`;
    }
  };

  const telecharger = () => {
    const p = parametres();
    p.set("format", $("format").value);
    // Une redirection plutôt qu'un fetch : le navigateur enregistre alors le
    // fichier sous le nom que le serveur lui donne.
    window.location.href = `/api/v1/rapports/editer?${p}`;
  };

  $("perimetre").addEventListener("change", majFormulaire);
  $("previsualiser").addEventListener("click", previsualiser);
  $("telecharger").addEventListener("click", telecharger);
  majFormulaire();
}

const numeroCourt = (id) => {
  const empreinte = String(id || "").split("_")[1] || "";
  return empreinte ? `INT-${empreinte.slice(0, 8).toUpperCase()}` : String(id || "");
};

// Rendu a l'ecran du document compose. Il suit bloc pour bloc la structure
// que le serveur renvoie : l'ecran et l'imprime disent la même chose, dans la
// même mise en page.
function rendreFeuille(doc) {
  const e = doc.entete || {};
  const colonne = (langue) => [
    e.republique?.[langue], e.devise?.[langue], "", e.ministere?.[langue], "",
    e.agence?.[langue], "", e.service?.[langue],
  ].filter(Boolean).map((t) => `<div>${esc(t)}</div>`).join("");

  return `<div class="feuille">
    <div class="titulature">
      <div>${colonne("fr")}</div>
      <div><img src="/static/logo-antic.png" alt="Emblème de l'Agence"
        onerror="this.outerHTML='&lt;div class=\\'reserve\\'&gt;EMBLÈME&lt;/div&gt;'"></div>
      <div>${colonne("en")}</div>
    </div>
    <hr class="filet">
    <div class="titre-doc">${esc(doc.titre)}</div>
    <div class="cartouche">
      <div><b>Référence :</b> ${esc(doc.reference)}</div>
      <div><b>Objet :</b> ${esc(doc.objet)}</div>
      <div><b>Établi le :</b> ${heure(doc.etabli_le)} — <b>par :</b> ${esc(doc.etabli_par)}</div>
    </div>
    ${(doc.contenu || []).map(blocFeuille).join("")}
    ${doc.mention_finale ? `<p class="mention">${esc(doc.mention_finale)}</p>` : ""}
    <div class="signature">
      <div>${esc(doc.lieu)}, le ${heure(doc.etabli_le)}</div>
      <div class="qui">${esc(doc.signataire)}</div>
    </div>
  </div>`;
}

function blocFeuille(b) {
  switch (b.type) {
    case "titre": {
      const intitule = esc(b.numero ? `${b.numero}. ${b.texte}` : b.texte);
      return b.niveau <= 1 ? `<h3>${intitule}</h3>` : `<h4>${intitule}</h4>`;
    }
    case "paragraphe":
      return `<p${b.accent ? ' class="accent"' : ""}>${esc(b.texte)}</p>`;
    case "liste": {
      const items = (b.elements || []).map((x) => `<li>${esc(x)}</li>`).join("");
      return b.numerotee ? `<ol>${items}</ol>` : `<ul>${items}</ul>`;
    }
    case "tableau":
      return `<table><thead><tr>${(b.entetes || []).map((h) =>
        `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
        (b.lignes || []).map((l) => `<tr>${l.map((c) =>
          `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>${
        b.legende ? `<p class="legende">${esc(b.legende)}</p>` : ""}`;
    case "graphique": {
      const valeurs = b.valeurs || [];
      const max = Math.max(...valeurs.map((v) => v.valeur), 1);
      return `<h4>${esc(b.titre)}</h4><div class="graphe">${valeurs.map((v) => `
        <div class="ligne">
          <div>${esc(v.libelle)}</div>
          <div class="piste"><div class="remplissage"
            style="width:${(v.valeur / max) * 100}%"></div></div>
          <div class="val">${esc(v.valeur)}</div>
        </div>`).join("")}</div>`;
    }
    case "encadre":
      return `<div class="encadre ${esc(b.ton)}">
        <div class="intitule">${esc(b.titre)}</div>${esc(b.texte)}</div>`;
    case "saut_de_page":
      return `<hr class="coupure">`;
    default:
      return "";
  }
}

// ============================================================ /audit-log
async function vueAudit() {
  const [audit, verification] = await Promise.all([
    api("/api/v1/audit?limit=200"),
    api("/api/v1/audit/verify"),
  ]);
  const entrees = audit.entries;
  const types = [...new Set(entrees.map((e) => e.event_type))].sort();

  $("vue").innerHTML = `
    <div class="grille" style="margin-bottom:18px">
      ${tuile(verification.entries_checked, "Entrées vérifiées")}
      ${tuile(verification.valid ? "intacte" : "ROMPUE", "Chaîne d'empreintes",
        verification.detail, verification.valid ? "var(--success-text)" : "var(--critical)")}
      ${tuile(types.length, "Types d'événements")}
    </div>

    ${!verification.valid ? `<div class="bandeau suspendu" style="margin-bottom:16px">
      La chaîne du journal est rompue à l'entrée ${verification.first_broken_seq}.
      Une entrée a été altérée hors de l'application : c'est un incident de sécurité
      portant sur la plateforme elle-même, pas une anomalie de fonctionnement.
    </div>` : ""}

    <div class="carte" style="margin-bottom:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <span class="muet">Filtrer :</span>
      <select id="f-type">
        <option value="">Tous les types</option>
        ${types.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("")}
      </select>
      <input id="f-incident" placeholder="Identifiant d'incident…" style="min-width:220px">
      <span class="spacer"></span>
      <span class="muet" id="compte-audit"></span>
    </div>

    <div class="carte" style="padding:0;overflow:auto">
      <table><thead><tr>
        <th>#</th><th>Horodatage</th><th>Type</th><th>Acteur</th><th>Incident</th><th>Empreinte</th>
      </tr></thead><tbody id="lignes-audit"></tbody></table>
    </div>`;

  const rendre = () => {
    const type = $("f-type").value;
    const incident = $("f-incident").value.trim().toLowerCase();
    const filtres = entrees.filter((e) =>
      (!type || e.event_type === type)
      && (!incident || (e.incident_id || "").toLowerCase().includes(incident)));
    $("compte-audit").textContent = `${filtres.length} entrée(s) sur ${entrees.length}`;
    $("lignes-audit").innerHTML = filtres.length ? filtres.map((e) => `<tr>
      <td class="mono num">${e.seq}</td>
      <td class="muet">${heure(e.recorded_at)}</td>
      <td class="mono">${esc(e.event_type)}</td>
      <td class="mono muet">${esc(e.actor)}</td>
      <td class="mono">${esc((e.incident_id || "—").slice(0, 22))}</td>
      <td class="mono muet">${esc(e.entry_hash.slice(0, 12))}…</td>
    </tr>`).join("") : `<tr><td colspan="6" class="vide">Aucune entrée ne correspond au filtre.</td></tr>`;
  };
  $("f-type").addEventListener("change", rendre);
  $("f-incident").addEventListener("input", rendre);
  rendre();
}

// ============================================================= /settings
async function vueReglages() {
  const notifications = await api("/api/v1/notifications?limit=50");
  const etat = etatGlobal;
  badge("/settings", notifications.count || 0);

  const themeActuel = document.documentElement.getAttribute("data-theme") || "système";

  $("vue").innerHTML = `
    <h2>Préférences de session</h2>
    <div class="carte" style="margin-bottom:18px">
      <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
        <span>Thème</span>
        <select id="choix-theme">
          <option value="">Suivre le système</option>
          <option value="light" ${themeActuel === "light" ? "selected" : ""}>Clair</option>
          <option value="dark" ${themeActuel === "dark" ? "selected" : ""}>Sombre</option>
        </select>
        <span class="muet">Le choix est conservé dans ce navigateur uniquement.</span>
      </div>
    </div>

    <h2>Mon compte</h2>
    <div class="carte" style="margin-bottom:18px">
      <table><tbody>
        <tr><td>Nom d'utilisateur</td><td class="mono">${esc(SESSION?.username || "—")}</td></tr>
        <tr><td>Identité</td><td>${esc(
          [SESSION?.prenom, SESSION?.nom].filter(Boolean).join(" ") || "—")}</td></tr>
        <tr><td>Rôle</td><td>${esc(roleLisible(SESSION?.role || ""))}</td></tr>
        ${SESSION?.poste ? `<tr><td>Poste</td><td>${esc(SESSION.poste)}</td></tr>` : ""}
        ${SESSION?.email ? `<tr><td>E-mail</td><td class="mono">${esc(SESSION.email)}</td></tr>` : ""}
      </tbody></table>
      <div style="margin-top:12px"><button id="reg-deconnexion">Se déconnecter</button></div>
    </div>

    <div class="admin-only" id="section-comptes"></div>
    <div class="admin-only" id="section-postes"></div>

    <h2>Notifications a posteriori non acquittées (${notifications.count})</h2>
    <div class="carte" style="padding:0;overflow:auto;margin-bottom:18px">
      ${notifications.count ? `<table><thead><tr>
        <th>Émise</th><th>Gravité</th><th>Objet</th><th>Incident</th><th></th>
      </tr></thead><tbody>
        ${notifications.notifications.map((n) => `<tr>
          <td class="muet">${heure(n.created_at)}</td>
          <td><span class="etat ${esc(n.severity)}">${esc(n.severity)}</span></td>
          <td>${esc(n.subject)}</td>
          <td class="mono">${esc((n.incident_id || "—").slice(0, 20))}</td>
          <td><button data-ack="${esc(n.notification_id)}">Acquitter</button></td>
        </tr>`).join("")}
      </tbody></table>` : '<div class="vide">Aucune notification en attente.</div>'}
    </div>

    <h2>Posture de déploiement (lecture seule)</h2>
    <div class="carte">
      <table><tbody>
        <tr><td>Site</td><td class="mono">${esc(etat.site_id)}</td></tr>
        <tr><td>Environnement</td><td class="mono">${esc(etat.environment)}</td></tr>
        <tr><td>Autonomie</td><td>${etat.autonomy.enabled
          ? '<span class="etat basse">activée</span>' : '<span class="etat critique">désactivée</span>'}</td></tr>
        <tr><td>Mode d'actionnement</td><td><span class="etat ${
          etat.autonomy.actuation_mode === "live" ? "critique" : "basse"}">${
          esc(etat.autonomy.actuation_mode)}</span>${
          etat.autonomy.actuation_mode === "live"
            ? ' <span class="muet">— les actions ont des effets réels</span>'
            : ' <span class="muet">— aucun effet réel sur les équipements</span>'}</td></tr>
        <tr><td>Coupe-circuit</td><td><span class="etat ${
          etat.circuit_breaker.state === "closed" ? "basse" : "critique"}">${
          esc(etat.circuit_breaker.state)}</span></td></tr>
        <tr><td>Politique active</td><td class="mono">${esc(etat.policy.policy_id)} v${
          esc(etat.policy.version)} — empreinte ${esc(etat.policy.checksum)}</td></tr>
        <tr><td>Périmètre autonome</td><td>${etat.catalog.autonomously_executable} actions sur ${
          etat.catalog.total} au catalogue</td></tr>
        <tr><td>Base de connaissance</td><td>${etat.knowledge_base} fiches</td></tr>
      </tbody></table>
      <div class="muet" style="margin-top:12px">
        Ces paramètres se règlent par variables d'environnement au démarrage et sont
        journalisés : un auditeur doit pouvoir dire sous quelle configuration le
        système a agi.
      </div>
    </div>`;

  $("reg-deconnexion").addEventListener("click", seDeconnecter);
  if (estAdmin()) rendreSectionsAdmin();

  $("choix-theme").addEventListener("change", (e) => {
    const v = e.target.value;
    if (v) {
      document.documentElement.setAttribute("data-theme", v);
      try { localStorage.setItem("cirt-theme", v); } catch { /* indisponible */ }
    } else {
      document.documentElement.removeAttribute("data-theme");
      try { localStorage.removeItem("cirt-theme"); } catch { /* indisponible */ }
    }
  });
  $("vue").querySelectorAll("button[data-ack]").forEach((b) =>
    b.addEventListener("click", async () => {
      b.disabled = true;
      await post(`/api/v1/notifications/${b.dataset.ack}/acknowledge`);
      await vueReglages();
    }));
}

// -- Reglages : sections reservees a l'administrateur -------------------
// Validation des inscriptions, promotion analyste -> administrateur,
// suspension, et gestion des postes (dont les identifiants des decideurs).
async function rendreSectionsAdmin() {
  let users = [];
  let postes = [];
  try {
    users = (await api("/api/v1/admin/users")).users || [];
    postes = (await api("/api/v1/admin/postes")).postes || [];
  } catch (e) {
    $("section-comptes").innerHTML = `<div class="muet">Gestion des comptes indisponible : ${esc(e.message)}</div>`;
    return;
  }
  const superAdmin = SESSION.role === "super_admin";
  const enAttente = users.filter((u) => u.status === "pending");
  const actifs = users.filter((u) => u.status !== "pending");

  const rangeeCompte = (u) => {
    const nom = [u.prenom, u.nom].filter(Boolean).join(" ") || u.username;
    const moi = u.user_id === SESSION.user_id;
    // Promotion et transfert du rôle de super-administrateur : super-admin seul.
    const promo = superAdmin && u.role === "analyste"
      ? `<button data-promo="${esc(u.user_id)}">Promouvoir admin</button>` : "";
    const retro = superAdmin && !moi && u.role === "admin"
      ? `<button data-retro="${esc(u.user_id)}">Rétrograder</button>` : "";
    const transf = superAdmin && !moi && u.role === "admin"
      ? `<button data-transf="${esc(u.user_id)}" data-nom="${esc(nom)}">Transférer super-admin</button>`
      : "";
    const susp = !moi && u.role !== "super_admin" && u.status === "active"
      ? `<button data-susp="${esc(u.user_id)}">Suspendre</button>` : "";
    const rea = ["suspended", "refused"].includes(u.status)
      ? `<button data-rea="${esc(u.user_id)}">Réactiver</button>` : "";
    // Suppression definitive : super-admin seul, jamais son propre compte.
    const suppr = superAdmin && !moi && u.role !== "super_admin"
      ? `<button class="danger" data-suppr="${esc(u.user_id)}" data-nom="${esc(nom)}">Supprimer</button>`
      : "";
    return `<div class="rangee-compte">
      <div>
        <div class="ppal">${esc(nom)}
          <span class="puce-statut ${esc(u.status)}">${esc(u.status)}</span></div>
        <div class="meta">${esc(u.username)} · ${esc(roleLisible2(u.role))}${
          u.poste ? " · " + esc(u.poste) : ""}${u.email ? " · " + esc(u.email) : ""}</div>
      </div>
      <div class="actions-compte">${promo}${retro}${transf}${susp}${rea}${suppr}</div>
    </div>`;
  };

  $("section-comptes").innerHTML = `
    <h2>Inscriptions en attente (${enAttente.length})</h2>
    <div class="carte" style="margin-bottom:18px">
      ${enAttente.length ? enAttente.map((u) => `<div class="rangee-compte">
        <div>
          <div class="ppal">${esc([u.prenom, u.nom].filter(Boolean).join(" ") || u.username)}</div>
          <div class="meta">${esc(u.username)} · ${esc(u.poste)} · ${esc(u.email)}</div>
        </div>
        <div class="actions-compte">
          <button class="primaire" data-admit="${esc(u.user_id)}">Valider</button>
          <button data-decline="${esc(u.user_id)}">Écarter</button>
        </div>
      </div>`).join("") : '<div class="vide">Aucune inscription en attente.</div>'}
    </div>

    <h2>Comptes (${actifs.length})</h2>
    <div class="carte" style="margin-bottom:18px">
      ${actifs.map(rangeeCompte).join("") || '<div class="vide">Aucun compte.</div>'}
    </div>`;

  const postesDe = (k) => postes.filter((p) => p.kind === k);
  const listePostes = (k) => postesDe(k).map((p) => `<div class="rangee-compte">
      <div><div class="ppal">${esc(p.label)}
        ${p.active ? "" : '<span class="puce-statut refused">fermé</span>'}</div>
        ${p.civility ? `<div class="meta">${esc(p.civility)}</div>` : ""}</div>
      <div class="actions-compte">
        ${k === "decideur" ? `<button data-decideur="${esc(p.poste_id)}" data-civ="${esc(p.civility)}"
          data-label="${esc(p.label)}">Créer les identifiants</button>` : ""}
        <button data-poste-toggle="${esc(p.poste_id)}" data-active="${p.active}">${
          p.active ? "Fermer" : "Rouvrir"}</button>
        <button data-poste-suppr="${esc(p.poste_id)}">Supprimer</button>
      </div>
    </div>`).join("");

  $("section-postes").innerHTML = `
    <h2>Postes d'analyste</h2>
    <div class="carte" style="margin-bottom:14px">
      ${listePostes("analyste") || '<div class="vide">Aucun poste.</div>'}
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        <input id="np-analyste" placeholder="Nouveau poste d'analyste" style="flex:1;min-width:200px">
        <button class="primaire" data-new-poste="analyste">Ajouter</button>
      </div>
    </div>

    <h2>Postes de décideur</h2>
    <div class="carte" style="margin-bottom:18px">
      ${listePostes("decideur") || '<div class="vide">Aucun poste.</div>'}
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        <input id="np-decideur" placeholder="Nouveau poste (ex. Directeur du CIRT)" style="flex:1;min-width:220px">
        <select id="np-decideur-civ"><option value="Monsieur">Monsieur</option>
          <option value="Madame">Madame</option></select>
        <button class="primaire" data-new-poste="decideur">Ajouter</button>
      </div>
    </div>`;

  const recharger = () => rendreSectionsAdmin();
  const agir = async (url, ok) => {
    try {
      await post(url);
      if (ok) toast(ok);
    } catch (e) {
      toast(e.message, "erreur");
    }
    recharger();
  };

  $("vue").querySelectorAll("[data-admit]").forEach((b) =>
    b.addEventListener("click", () =>
      agir(`/api/v1/admin/users/${b.dataset.admit}/admit`, "Inscription validée.")));
  $("vue").querySelectorAll("[data-decline]").forEach((b) =>
    b.addEventListener("click", () =>
      agir(`/api/v1/admin/users/${b.dataset.decline}/decline`, "Inscription écartée.")));
  $("vue").querySelectorAll("[data-promo]").forEach((b) =>
    b.addEventListener("click", () =>
      agir(`/api/v1/admin/users/${b.dataset.promo}/promote`, "Analyste promu administrateur.")));
  $("vue").querySelectorAll("[data-retro]").forEach((b) =>
    b.addEventListener("click", () =>
      agir(`/api/v1/admin/users/${b.dataset.retro}/demote`, "Administrateur rétrogradé.")));
  $("vue").querySelectorAll("[data-susp]").forEach((b) =>
    b.addEventListener("click", () =>
      agir(`/api/v1/admin/users/${b.dataset.susp}/suspend`, "Compte suspendu.")));
  $("vue").querySelectorAll("[data-rea]").forEach((b) =>
    b.addEventListener("click", () =>
      agir(`/api/v1/admin/users/${b.dataset.rea}/reactivate`, "Compte réactivé.")));

  $("vue").querySelectorAll("[data-suppr]").forEach((b) =>
    b.addEventListener("click", () => ouvrirModale({
      titre: "Supprimer ce compte ?",
      sous: "Cette action est définitive",
      corps: `<p>Le compte <b>${esc(b.dataset.nom)}</b> et ses sessions seront effacés.</p>
        <p class="muet">Les gestes déjà inscrits au journal d'audit à son nom, eux, restent.</p>`,
      actions: `<button data-fermer>Annuler</button>
        <button class="primaire" id="ok-suppr-compte">Supprimer</button>`,
      apres: (racine) => racine.querySelector("#ok-suppr-compte").addEventListener("click", async () => {
        try {
          await api(`/api/v1/admin/users/${b.dataset.suppr}`, { method: "DELETE" });
          toast("Compte supprimé.");
        } catch (e) { toast(e.message, "erreur"); }
        fermerModale();
        recharger();
      }),
    })));

  $("vue").querySelectorAll("[data-transf]").forEach((b) =>
    b.addEventListener("click", () => ouvrirModale({
      titre: "Transférer le rôle de super-administrateur ?",
      sous: b.dataset.nom,
      corps: `<p><b>${esc(b.dataset.nom)}</b> deviendra super-administrateur.
        Vous redeviendrez administrateur : vous perdrez la promotion, la
        suppression de comptes et ce transfert.</p>`,
      actions: `<button data-fermer>Annuler</button>
        <button class="primaire" id="ok-transf">Transférer</button>`,
      apres: (racine) => racine.querySelector("#ok-transf").addEventListener("click", async () => {
        try {
          const r = await post(`/api/v1/admin/users/${b.dataset.transf}/transfer-superadmin`);
          fermerModale();
          toast(`${b.dataset.nom} est désormais super-administrateur.`, "info");
          await rafraichirSession();
        } catch (e) { toast(e.message, "erreur"); fermerModale(); recharger(); }
      }),
    })));

  $("vue").querySelectorAll("[data-new-poste]").forEach((b) =>
    b.addEventListener("click", async () => {
      const kind = b.dataset.newPoste;
      const champ = $(kind === "analyste" ? "np-analyste" : "np-decideur");
      const label = champ.value.trim();
      if (label.length < 2) { toast("Libellé trop court.", "erreur"); return; }
      const civility = kind === "decideur" ? $("np-decideur-civ").value : "";
      try {
        await poster("/api/v1/admin/postes", { kind, label, civility });
        champ.value = "";
        toast(`Poste ${kind === "decideur" ? "de décideur" : "d'analyste"} « ${label} » créé.`);
      } catch (e) { toast(e.message, "erreur"); }
      recharger();
    }));
  $("vue").querySelectorAll("[data-poste-toggle]").forEach((b) =>
    b.addEventListener("click", async () => {
      const ouvrir = b.dataset.active !== "true";
      try {
        await api(`/api/v1/admin/postes/${b.dataset.posteToggle}`, {
          method: "PATCH", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ active: ouvrir }),
        });
        toast(ouvrir ? "Poste rouvert." : "Poste fermé.");
      } catch (e) { toast(e.message, "erreur"); }
      recharger();
    }));
  $("vue").querySelectorAll("[data-poste-suppr]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        await api(`/api/v1/admin/postes/${b.dataset.posteSuppr}`, { method: "DELETE" });
        toast("Poste supprimé.");
      } catch (e) { toast(e.message, "erreur"); }
      recharger();
    }));
  $("vue").querySelectorAll("[data-decideur]").forEach((b) =>
    b.addEventListener("click", () => formulaireDecideur(
      b.dataset.decideur, b.dataset.label, b.dataset.civ, recharger)));
}

const roleLisible2 = (r) => ({
  super_admin: "Super-administrateur", admin: "Administrateur",
  analyste: "Analyste", decideur: "Décideur",
}[r] || r);

function formulaireDecideur(posteId, label, civ, apres) {
  ouvrirModale({
    titre: "Identifiants du décideur",
    sous: label,
    corps: `
      <div class="champ-auth"><label>Civilité</label>
        <select id="d-civ">
          <option value="Monsieur" ${civ === "Monsieur" ? "selected" : ""}>Monsieur</option>
          <option value="Madame" ${civ === "Madame" ? "selected" : ""}>Madame</option>
        </select></div>
      <div class="grille-champs">
        <div class="champ-auth"><label>Nom (facultatif)</label><input id="d-nom"></div>
        <div class="champ-auth"><label>Prénom (facultatif)</label><input id="d-prenom"></div>
      </div>
      <div class="champ-auth"><label>Nom d'utilisateur</label><input id="d-user"></div>
      <div class="champ-auth"><label>Mot de passe provisoire</label><input id="d-mdp"></div>
      <div class="erreur-auth" id="d-err"></div>`,
    actions: `<button data-fermer>Annuler</button>
              <button class="primaire" id="d-creer">Créer le compte</button>`,
    apres: (racine) => {
      racine.querySelector("#d-creer").addEventListener("click", async () => {
        racine.querySelector("#d-err").textContent = "";
        try {
          await poster("/api/v1/admin/decideurs", {
            poste_id: posteId,
            civility: racine.querySelector("#d-civ").value,
            nom: racine.querySelector("#d-nom").value.trim(),
            prenom: racine.querySelector("#d-prenom").value.trim(),
            username: racine.querySelector("#d-user").value.trim(),
            password: racine.querySelector("#d-mdp").value,
          });
          fermerModale();
          toast(`Compte du poste « ${label} » créé.`);
          apres();
        } catch (e) {
          racine.querySelector("#d-err").textContent = e.message;
        }
      });
    },
  });
}

// Le demarrage est appele en toute fin de fichier : sur un lien profond vers
// /assistant, `naviguer` ouvre la conversation, ce qui lit `AMORCES` — une
// const declaree plus bas. L'amorcer ici la prendrait dans sa zone morte.

// ============================================================ bulle assistant
// Une conversation, pas un formulaire. Quatre choses la distinguent d'un champ
// de recherche : le fil garde le contexte de la seance, la reflexion est
// montree au lieu d'etre masquee, le texte s'ecrit pendant qu'on le lit, et
// chaque reponse porte de quoi etre copiee et jugee.
//
// Le texte n'est pas redige au fil de l'eau par un modele : la reponse est
// deterministe, le rythme sert la lecture. Les etapes annoncees sont celles
// que l'assistant a reellement suivies, elles sont donc contestables.

// Identifiant du fil : il rattache les questions entre elles cote serveur,
// pour que « et sur sept jours ? » sache de quoi il parle.
let filId = `web-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

const ICONES_CHAT = {
  copier: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  pouceHaut: '<path d="M7 10v12"/><path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h2.76a2 2 0 0 0 1.79-1.11L12 2a3.13 3.13 0 0 1 3 3.88z"/>',
  pouceBas: '<path d="M17 14V2"/><path d="M9 18.12 10 14H4.17a2 2 0 0 1-1.92-2.56l2.33-8A2 2 0 0 1 6.5 2H20a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-2.76a2 2 0 0 0-1.79 1.11L12 22a3.13 3.13 0 0 1-3-3.88z"/>',
  valide: '<path d="M20 6 9 17l-5-5"/>',
};
const iconeChat = (nom) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONES_CHAT[nom]}</svg>`;

function majVisibiliteChat() {
  const masquer = CHAT_MASQUE.includes(location.pathname);
  $("lanceur-chat").hidden = masquer || chatOuvert;
  if (masquer && chatOuvert) fermerChat();
}

function ouvrirChat() {
  chatOuvert = true;
  $("chat").hidden = false;
  $("lanceur-chat").hidden = true;
  $("question").focus();
  if (!$("fil").children.length) accueil();
  chargerFils();
}

function fermerChat() {
  chatOuvert = false;
  $("chat").hidden = true;
  fermerTiroir();
  majVisibiliteChat();
  if (flux) { flux.close(); flux = null; }
}

// -- tiroir d'historique (bulle reduite) -----------------------------------
// En mode agrandi (#chat.plein) le rail est affiche en permanence ; tant que
// la conversation tient dans la bulle reduite, il devient un tiroir qui entre
// par la gauche, declenche par le bouton #ouvrir-rail.

function fermerTiroir() {
  $("chat").classList.remove("tiroir");
  $("ouvrir-rail").setAttribute("aria-expanded", "false");
}

function basculerTiroir() {
  const ouvert = $("chat").classList.toggle("tiroir");
  $("ouvrir-rail").setAttribute("aria-expanded", String(ouvert));
  if (ouvert) chargerFils();
}

$("lanceur-chat").addEventListener("click", ouvrirChat);
$("fermer-chat").addEventListener("click", fermerChat);
$("agrandir").addEventListener("click", () => {
  // Passer en mode agrandi affiche le rail en dur : le tiroir n'a plus lieu
  // d'etre, on le referme pour ne pas laisser le voile par-dessus.
  fermerTiroir();
  $("chat").classList.toggle("plein");
});
$("ouvrir-rail").addEventListener("click", basculerTiroir);
$("voile-rail").addEventListener("click", fermerTiroir);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("chat").classList.contains("tiroir")) fermerTiroir();
});
const nouvelleDiscussion = () => {
  // Un fil neuf cote serveur aussi : sinon la nouvelle conversation heriterait
  // du contexte de l'ancienne sans que rien ne l'indique a l'ecran.
  filId = `web-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  fermerTiroir();
  $("fil").innerHTML = "";
  accueil();
  chargerFils();
};
$("vider-chat").addEventListener("click", nouvelleDiscussion);
$("nouvelle-discussion").addEventListener("click", nouvelleDiscussion);

// -- fil de discussion -------------------------------------------------------

const maintenant = () =>
  new Date().toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });

function tour(role, contenu = "") {
  const bloc = document.createElement("div");
  bloc.className = `tour ${role}`;
  bloc.innerHTML = role === "machine"
    ? `<div class="signature"><span class="jeton">C</span>Assistant</div>
       <div class="bulle"></div>
       <div class="pied-message"></div>`
    : `<div class="bulle"></div><div class="pied-message"></div>`;
  bloc.querySelector(".bulle").innerHTML = contenu;
  $("fil").appendChild(bloc);
  defiler();
  return bloc;
}

// Le pied n'apparait qu'une fois le message ecrit : horodater un texte encore
// en cours de frappe donnerait une heure fausse.
function poserPied(bloc, { avecOutils = true, heure = null } = {}) {
  const pied = bloc.querySelector(".pied-message");
  // Une conversation relue porte l'heure d'origine, pas celle de la relecture :
  // horodater a la relecture donnerait une chronologie fausse.
  const marque = heure
    ? new Date(heure).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })
    : maintenant();
  pied.innerHTML = `<span class="heure">${marque}</span>` + (avecOutils ? `
    <span class="outils">
      <button data-outil="copier" title="Copier le message" aria-label="Copier">
        ${iconeChat("copier")}</button>
      <button data-outil="pour" title="Réponse utile" aria-label="Réponse utile">
        ${iconeChat("pouceHaut")}</button>
      <button data-outil="contre" class="contre" title="Réponse à revoir"
        aria-label="Réponse à revoir">${iconeChat("pouceBas")}</button>
    </span>` : "");

  if (!avecOutils) return;
  // Copier la reponse, pas l'en-tete du raisonnement : c'est le texte qu'on
  // veut coller dans un rapport ou un courriel.
  const texte = () =>
    (bloc.querySelector(".texte") || bloc.querySelector(".bulle")).innerText.trim();

  pied.querySelector('[data-outil="copier"]').addEventListener("click", async (e) => {
    const bouton = e.currentTarget;
    try {
      await navigator.clipboard.writeText(texte());
    } catch {
      // Le presse-papier peut etre refuse (contexte non securise) : la
      // selection manuelle reste possible, mais il faut le dire.
      bouton.title = "Copie refusée par le navigateur — sélectionnez le texte";
      return;
    }
    bouton.innerHTML = iconeChat("valide");
    bouton.classList.add("actif");
    setTimeout(() => {
      bouton.innerHTML = iconeChat("copier");
      bouton.classList.remove("actif");
    }, 1400);
  });

  for (const sens of ["pour", "contre"]) {
    pied.querySelector(`[data-outil="${sens}"]`).addEventListener("click", (e) => {
      const bouton = e.currentTarget;
      const autre = pied.querySelector(`[data-outil="${sens === "pour" ? "contre" : "pour"}"]`);
      const deja = bouton.classList.contains("actif");
      bouton.classList.toggle("actif", !deja);
      autre.classList.remove("actif");
      // L'appreciation reste dans cet ecran : rien n'est envoye ni conserve.
      // Le dire evite de laisser croire a un retour d'experience collecte.
      const accuse = pied.querySelector(".accuse");
      if (accuse) accuse.remove();
      if (!deja) {
        pied.insertAdjacentHTML("beforeend",
          '<span class="accuse">noté</span>');
        setTimeout(() => pied.querySelector(".accuse")?.remove(), 1600);
      }
    });
  }
}

const defiler = () => { $("fil").scrollTop = $("fil").scrollHeight; };

// Salutation selon l'heure. Rien d'autre : ouvrir l'assistant n'est pas
// demander un bilan, et lui en servir un d'office impose une lecture que
// personne n'a sollicitee.
function salutationDuMoment() {
  const h = new Date().getHours();
  if (h >= 5 && h < 12) return "Bonjour";
  if (h >= 12 && h < 18) return "Bon après-midi";
  if (h >= 18 && h < 22) return "Bonsoir";
  return "Belle nuitée";
}

const AMORCES = [
  "Fais le bilan des opérations du jour",
  "Déclenche une simulation de rançongiciel",
  "Quelle est la posture d'autonomie ?",
  "Génère un rapport sur 7 jours",
];

function accueil() {
  $("chat").classList.add("vierge");
  $("pistes").innerHTML = "";
  $("fil").innerHTML = `
    <div class="accueil">
      <div class="salut">${esc(salutationDuMoment())}<b>.</b></div>
      <div class="invite">Posez votre question, ou choisissez une piste.
        Je m'appuie uniquement sur les données de la plateforme.</div>
      <div class="amorces">
        ${AMORCES.map((a) => `<button data-q="${esc(a)}">${esc(a)}</button>`).join("")}
      </div>
    </div>`;
  $("fil").querySelectorAll("[data-q]").forEach((b) =>
    b.addEventListener("click", () => envoyer(b.dataset.q)));
  $("question").focus();
}

// Ecriture progressive du message d'accueil : il n'arrive pas par le flux,
// mais doit se presenter comme les autres.
function ecrire(cible, texte) {
  return new Promise((resolve) => {
    const mots = texte.split(" ");
    let index = 0;
    const pas = () => {
      index += 2;
      cible.innerHTML = markdown(mots.slice(0, index).join(" "))
        + (index < mots.length ? '<span class="curseur"></span>' : "");
      defiler();
      if (index < mots.length) setTimeout(pas, 26); else resolve();
    };
    pas();
  });
}

function afficherPistes(suggestions) {
  // Trois pistes suffisent : au-dela, elles mangent la hauteur du fil et la
  // reponse qu'on vient de lire sort de l'ecran.
  $("pistes").innerHTML = (suggestions || []).slice(0, 3)
    .map((q) => `<button data-q="${esc(q)}">${esc(q)}</button>`).join("");
  $("pistes").querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", () => envoyer(b.dataset.q)));
  defiler();
}

// -- envoi et reception en flux ---------------------------------------------

function envoyer(question) {
  if (chatOccupe || !question.trim()) return;
  chatOccupe = true;
  $("envoyer").disabled = true;
  $("question").value = "";
  $("question").style.height = "auto";
  $("pistes").innerHTML = "";
  if ($("chat").classList.contains("vierge")) {
    $("chat").classList.remove("vierge");
    $("fil").innerHTML = "";
  }

  poserPied(tour("humain", esc(question)), { avecOutils: false });

  const bloc = tour("machine", "");
  const bulle = bloc.querySelector(".bulle");
  bulle.innerHTML = `
    <details class="pense" open>
      <summary><span class="sablier"></span>Réflexion en cours…</summary>
      <div class="reflexion"></div>
    </details>
    <div class="texte"></div>`;
  const pense = bulle.querySelector(".pense");
  const reflexion = bulle.querySelector(".reflexion");
  const texte = bulle.querySelector(".texte");
  let brut = "";

  const adresse = `/api/v1/assistant/stream?question=${encodeURIComponent(question)}`
    + `&conversation_id=${encodeURIComponent(filId)}`;
  flux = new EventSource(adresse);

  flux.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    switch (ev.type) {
      case "ack":
        bloc.querySelector(".signature").insertAdjacentHTML("afterend",
          `<div class="ack">${esc(ev.text)}</div>`);
        defiler();
        break;
      case "thinking": {
        reflexion.querySelectorAll(".etape.encours")
          .forEach((x) => x.className = "etape faite");
        const etape = document.createElement("div");
        etape.className = "etape encours";
        etape.innerHTML = `<div><b>${esc(ev.label)}</b>${
          ev.detail ? `<span>${esc(ev.detail)}</span>` : ""}</div>`;
        reflexion.appendChild(etape);
        defiler();
        break;
      }
      case "action":
        texte.insertAdjacentHTML("beforebegin", resultatEffet(ev.result));
        defiler();
        break;
      case "answer_start":
        // La reponse commence : la reflexion se replie d'elle-meme. Elle reste
        // ouvrable, mais ce n'est plus elle qu'on vient lire.
        reflexion.querySelectorAll(".etape.encours")
          .forEach((x) => x.className = "etape faite");
        pense.open = false;
        pense.classList.add("finie");
        pense.querySelector("summary").innerHTML =
          `<span class="sablier"></span>Voir le raisonnement (${
            reflexion.children.length} étape${reflexion.children.length > 1 ? "s" : ""})`;
        break;
      case "delta":
        brut += ev.text;
        texte.innerHTML = markdown(brut) + '<span class="curseur"></span>';
        defiler();
        break;
      case "done":
        texte.innerHTML = markdown(brut);
        if (ev.sources && ev.sources.length) {
          texte.insertAdjacentHTML("beforeend",
            `<div class="muet" style="margin-top:10px;font-size:11.5px">Sources : ${
              ev.sources.map(esc).join(", ")}</div>`);
        }
        poserPied(bloc);
        terminer(ev);
        chargerFils();
        if (ev.intent === "simulation") rafraichir();
        break;
    }
  };

  flux.onerror = () => {
    if (!brut) {
      pense.remove();
      texte.innerHTML = '<span style="color:var(--critical)">Assistant injoignable.</span>';
    } else {
      texte.innerHTML = markdown(brut);
    }
    poserPied(bloc, { avecOutils: Boolean(brut) });
    terminer(null);
  };

  function terminer(ev) {
    if (flux) { flux.close(); flux = null; }
    chatOccupe = false;
    $("envoyer").disabled = false;
    // Les suites viennent de la reponse : elles dependent de l'etat constate,
    // pas d'une liste figee. A defaut, on retombe sur les suggestions.
    if (ev && ev.follow_ups && ev.follow_ups.length) {
      afficherPistes(ev.follow_ups);
    } else {
      api("/api/v1/assistant/suggestions")
        .then((p) => afficherPistes(p.suggestions))
        .catch(() => { /* les pistes sont un confort, pas une dependance */ });
    }
    defiler();
  }
}

function resultatEffet(r) {
  if (!r || !r.executed) {
    return `<div class="effet"><div class="titre-effet">Effet non appliqué</div>
      ${esc(r && r.reason ? r.reason : "aucun effet")}</div>`;
  }
  if (r.kind === "report") {
    // La fenêtre demandée est reportée sur le lien : télécharger un rapport
    // sur une autre période que celle qu'on vient de lire serait déroutant.
    const fenetre = r.hours <= 24 ? "24h" : r.hours <= 168 ? "7j"
      : r.hours <= 720 ? "30j" : r.hours <= 2160 ? "90j" : "1an";
    const lien = (format, libelle) =>
      `<a href="/api/v1/rapports/editer?perimetre=periode&fenetre=${fenetre}&format=${format}"
         download>${libelle}</a>`;
    return `<div class="effet"><div class="titre-effet">Rapport établi</div>
      Période de ${r.hours} heures — télécharger en
      ${lien("pdf", "PDF")}, ${lien("docx", "Word")},
      ${lien("md", "Markdown")} ou ${lien("json", "JSON")}.</div>`;
  }
  const lignes = (r.results || []).map((x) => `<tr>
    <td class="mono"><b>${esc(x.code)}</b></td>
    <td>${esc(court(x.label, 40))}</td>
    <td class="num">${x.actions_executed}</td>
    <td><span class="etat ${x.outcome === "autonomous_execution" ? "basse" : "moyenne"}">${
      esc(x.outcome === "autonomous_execution" ? "traité" : x.outcome || "refusé")}</span></td>
  </tr>`).join("");

  return `<div class="effet">
    <div class="titre-effet">${r.scenarios_run} scénario(s) — ${
      r.actions_executed} action(s) exécutée(s)</div>
    <table><thead><tr><th>Code</th><th>Scénario</th><th>Actions</th><th>Issue</th></tr></thead>
    <tbody>${lignes}</tbody></table></div>`;
}

// -- saisie ------------------------------------------------------------------

$("envoyer").addEventListener("click", () => envoyer($("question").value));
$("question").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); envoyer($("question").value); }
});
$("question").addEventListener("input", () => {
  const zone = $("question");
  zone.style.height = "auto";
  zone.style.height = Math.min(zone.scrollHeight, 132) + "px";
});


// ====================================================== historique des fils
// Trois axes de filtrage, ceux dont on se sert reellement en poste : de quoi
// parlait la conversation, quand a-t-elle vecu, est-elle encore courante.

const FILTRES = { kind: "tous", activity: "tous", status: "active" };

const AXES = [
  { cle: "kind", titre: "Type de conversation", options: [
    ["tous", "Tous"], ["bilan", "Bilan"], ["simulation", "Simulation"],
    ["rapport", "Rapports"], ["echange", "Échange"]] },
  { cle: "activity", titre: "Dernière activité", options: [
    ["24h", "24 h"], ["7d", "7 jours"], ["21d", "21 jours"],
    ["30d", "30 jours"], ["tous", "Tous"]] },
  { cle: "status", titre: "Statut", options: [
    ["active", "Active"], ["archived", "Archivée"], ["tous", "Tous"]] },
];

const PAR_DEFAUT = { kind: "tous", activity: "tous", status: "active" };
const filtresActifs = () =>
  AXES.filter(({ cle }) => FILTRES[cle] !== PAR_DEFAUT[cle]).length;

let filsConnus = [];

async function chargerFils() {
  const requete = new URLSearchParams(FILTRES).toString();
  try {
    const { conversations } = await api(`/api/v1/assistant/conversations?${requete}`);
    filsConnus = conversations;
    peuplerFils(conversations);
  } catch {
    // L'historique est un confort : son absence ne doit pas empecher de
    // converser. On laisse la liste en l'etat plutot que d'afficher une erreur.
  }
}

function peuplerFils(conversations) {
  if (!conversations.length) {
    $("fils").innerHTML = '<div class="fil-vide">Aucune discussion pour ces filtres.</div>';
    return;
  }
  $("fils").innerHTML = conversations.map((c) => `
    <button class="fil-item" data-fil="${esc(c.conversation_id)}"
            aria-current="${c.conversation_id === filId}">
      <div class="titre-fil">${esc(c.title || "Discussion")}</div>
      <div class="meta-fil">
        <span class="genre ${esc(c.kind)}">${esc(c.kind)}</span>
        <span>${quand(c.last_activity)}</span>
        ${c.status === "archived" ? "<span>· archivée</span>" : ""}
      </div>
    </button>`).join("");
  $("fils").querySelectorAll("[data-fil]").forEach((b) =>
    b.addEventListener("click", () => rouvrirFil(b.dataset.fil)));
}

// « il y a 3 h » se lit plus vite qu'une date complete pour ce qui est recent ;
// au-dela, la date reste la seule information utile.
function quand(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  const minutes = Math.round((Date.now() - date.getTime()) / 60000);
  if (minutes < 1) return "à l'instant";
  if (minutes < 60) return `il y a ${minutes} min`;
  if (minutes < 1440) return `il y a ${Math.round(minutes / 60)} h`;
  if (minutes < 10080) return `il y a ${Math.round(minutes / 1440)} j`;
  return date.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
}

const quandComplet = (iso) => iso
  ? new Date(iso).toLocaleString("fr-FR",
      { dateStyle: "medium", timeStyle: "short" })
  : "—";

// -- reprise d'une conversation ---------------------------------------------

async function rouvrirFil(identifiant) {
  try {
    const fil = await api(`/api/v1/assistant/conversations/${encodeURIComponent(identifiant)}`);
    filId = identifiant;
    fermerTiroir();
    $("chat").classList.remove("vierge");
    $("fil").innerHTML = "";
    for (const message of fil.messages) {
      const bloc = tour(message.role === "humain" ? "humain" : "machine", "");
      const bulle = bloc.querySelector(".bulle");
      const trace = (message.payload && message.payload.reasoning) || [];
      bulle.innerHTML = (message.role === "humain")
        ? esc(message.text)
        : (trace.length ? traceRepliee(trace) : "") + `<div class="texte">${markdown(message.text)}</div>`;
      poserPied(bloc, { avecOutils: message.role !== "humain", heure: message.at });
    }
    afficherPistes([]);
    chargerFils();
    defiler();
  } catch (e) {
    erreur(e.message);
  }
}

const traceRepliee = (trace) => `
  <details class="pense finie">
    <summary><span class="sablier"></span>Voir le raisonnement (${trace.length} étape${
      trace.length > 1 ? "s" : ""})</summary>
    <div class="reflexion">${trace.map((e) => `<div class="etape faite">
      <div><b>${esc(e.label)}</b>${e.detail ? `<span>${esc(e.detail)}</span>` : ""}</div>
    </div>`).join("")}</div>
  </details>`;

// -- repli de la liste -------------------------------------------------------

$("basculer-fils").addEventListener("click", () => {
  const ouvert = $("basculer-fils").getAttribute("aria-expanded") === "true";
  $("basculer-fils").setAttribute("aria-expanded", String(!ouvert));
  $("fils").hidden = ouvert;
});

// -- menu de filtres --------------------------------------------------------
// Deux niveaux : la liste des trois axes, puis les options de celui qu'on
// ouvre. Deroules ensemble, ils depassaient la hauteur que #chat laisse voir.

const FLECHE_D = '<svg class="fleche" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>';
const FLECHE_G = '<svg class="fleche" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg>';
const COCHE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';

let axeOuvert = null;

function dessinerFiltres() {
  const liste = $("filtres-liste");

  if (!axeOuvert) {
    liste.innerHTML = AXES.map(({ cle, titre, options }) => {
      const actif = FILTRES[cle] !== PAR_DEFAUT[cle];
      const libelle = actif
        ? (options.find(([v]) => v === FILTRES[cle]) || ["", ""])[1] : "";
      return `<button class="axe-filtre" data-ouvrir="${cle}">
        <span class="nom-axe">${esc(titre)}</span>
        ${actif ? `<span class="val-axe">${esc(libelle)}</span>` : ""}
        ${FLECHE_D}
      </button>`;
    }).join("");

    liste.querySelectorAll("[data-ouvrir]").forEach((b) =>
      b.addEventListener("click", (e) => {
        e.stopPropagation();
        axeOuvert = b.dataset.ouvrir;
        dessinerFiltres();
      }));
    return;
  }

  const axe = AXES.find((a) => a.cle === axeOuvert);
  liste.innerHTML = `
    <button class="retour-filtre" data-retour>${FLECHE_G}<span>${esc(axe.titre)}</span></button>
    <div class="options-axe">
      ${axe.options.map(([valeur, libelle]) => `
        <button data-axe="${axe.cle}" data-valeur="${valeur}"
                aria-pressed="${FILTRES[axe.cle] === valeur}">
          <span>${esc(libelle)}</span>${FILTRES[axe.cle] === valeur ? COCHE : ""}
        </button>`).join("")}
    </div>`;

  liste.querySelector("[data-retour]").addEventListener("click", (e) => {
    e.stopPropagation();
    axeOuvert = null;
    dessinerFiltres();
  });

  liste.querySelectorAll("[data-axe]").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      FILTRES[b.dataset.axe] = b.dataset.valeur;
      majPastilleFiltres();
      chargerFils();
      axeOuvert = null;
      dessinerFiltres();
    }));
}

function majPastilleFiltres() {
  $("compte-filtres").hidden = filtresActifs() === 0;
}

$("filtrer").addEventListener("click", (e) => {
  e.stopPropagation();
  const ouvert = !$("filtres-liste").hidden;
  $("filtres-liste").hidden = ouvert;
  $("filtrer").setAttribute("aria-expanded", String(!ouvert));
  // A chaque ouverture, on repart de la liste des axes.
  if (!ouvert) { axeOuvert = null; dessinerFiltres(); }
});
document.addEventListener("click", () => {
  $("filtres-liste").hidden = true;
  $("filtrer").setAttribute("aria-expanded", "false");
  axeOuvert = null;
});

// -- historique detaille, dans le corps du panneau ---------------------------

$("voir-historique").addEventListener("click", async () => {
  await chargerFils();
  fermerTiroir();
  $("chat").classList.remove("vierge");
  $("pistes").innerHTML = "";

  const lignes = filsConnus.length ? filsConnus.map((c) => `
    <div class="ligne-fil" data-fil="${esc(c.conversation_id)}" role="button" tabindex="0">
      <span class="genre ${esc(c.kind)}">${esc(c.kind)}</span>
      <span class="titre-fil">${esc(c.title || "Discussion")}
        <div class="muet" style="font-size:11px">${c.turns} échange(s)</div></span>
      <span class="quand">${quandComplet(c.last_activity)}</span>
      <span class="outils-fil">
        <button data-archiver="${esc(c.conversation_id)}"
          data-etat="${c.status}">${c.status === "archived" ? "Réactiver" : "Archiver"}</button>
        <button data-supprimer="${esc(c.conversation_id)}">Supprimer</button>
      </span>
    </div>`).join("")
    : '<div class="fil-vide">Aucune discussion pour ces filtres.</div>';

  $("fil").innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
      <b style="font-size:14px">Discussions &amp; Tâches</b>
      <span class="muet" style="font-size:12px">${filsConnus.length} conversation(s)</span>
      <span class="spacer"></span>
      <button id="retour-fil">Retour à la discussion</button>
    </div>
    <div class="table-fils">${lignes}</div>`;

  $("fil").querySelectorAll(".ligne-fil").forEach((ligne) =>
    ligne.addEventListener("click", (e) => {
      if (e.target.closest("[data-archiver],[data-supprimer]")) return;
      rouvrirFil(ligne.dataset.fil);
    }));

  $("fil").querySelectorAll("[data-archiver]").forEach((b) =>
    b.addEventListener("click", async () => {
      const versArchive = b.dataset.etat !== "archived";
      await post(`/api/v1/assistant/conversations/${encodeURIComponent(b.dataset.archiver)}`
        + `/archive?archived=${versArchive}`);
      $("voir-historique").click();
    }));

  $("fil").querySelectorAll("[data-supprimer]").forEach((b) =>
    b.addEventListener("click", () => confirmerSuppression(b.dataset.supprimer)));

  $("retour-fil").addEventListener("click", () =>
    filsConnus.some((c) => c.conversation_id === filId) ? rouvrirFil(filId) : accueil());
});

function confirmerSuppression(identifiant) {
  ouvrirModale({
    titre: "Supprimer cette discussion ?",
    sous: "Cette action est définitive",
    corps: `<p>La discussion et ses messages seront effacés.</p>
      <p class="muet">Les actions qu'elle a déclenchées, elles, restent au
      journal d'audit : effacer la discussion n'efface pas ce qui a été fait.</p>`,
    actions: `<button data-fermer>Annuler</button>
              <button class="primaire" id="confirmer-suppression">Supprimer</button>`,
    apres: (racine) => {
      racine.querySelector("#confirmer-suppression").addEventListener("click", async () => {
        await api(`/api/v1/assistant/conversations/${encodeURIComponent(identifiant)}`,
          { method: "DELETE" });
        fermerModale();
        if (identifiant === filId) nouvelleDiscussion(); else $("voir-historique").click();
      });
    },
  });
}

// ==================================== connexion et separation des roles
// La plateforme distingue quatre roles (CDCF v3.0) : super-administrateur,
// administrateur, analyste, decideur. Avant la session, le rail et l'en-tete
// sont masques ; la vue occupe tout l'ecran (connexion / inscription /
// installation). Une fois connecte, la navigation est filtree sur les routes
// autorisees renvoyees par /api/v1/auth/me.

let SESSION = null;
const ROUTES_HORS_SESSION = ["/", "/login", "/register", "/accueil"];
const estAdmin = () => !!SESSION && (SESSION.role === "admin" || SESSION.role === "super_admin");
const peutAgir = () => !!SESSION && SESSION.role !== "decideur";

const ROLE_LISIBLE = {
  super_admin: "Super-administrateur",
  admin: "Administrateur",
  analyste: "Analyste",
  decideur: "Décideur",
};
const roleLisible = (r) =>
  r === "decideur" && SESSION?.poste ? SESSION.poste : (ROLE_LISIBLE[r] || r);

const LOGOS = `
  <div class="logos-auth">
    <img src="/static/logo-antic.png" alt="ANTIC" width="56" height="56">
    <span class="sep-logo"></span>
    <img src="/static/logo-cirtdefense.svg" alt="CIRTDEFENSE" width="56" height="56">
  </div>`;

function coquilleHorsSession(actif) {
  document.body.classList.toggle("hors-session", actif);
}

async function meSession() {
  const opts = jeton() ? { headers: { Authorization: `Bearer ${jeton()}` } } : {};
  const r = await fetch("/api/v1/auth/me", opts);
  if (r.status === 401) return { non_connecte: true };
  if (!r.ok) throw new Error("service d'authentification indisponible");
  return r.json();
}

async function poster(url, corps) {
  return api(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(corps),
  });
}

// -- ecran de connexion ---------------------------------------------------
function ecranConnexion(message = "") {
  coquilleHorsSession(true);
  if (location.pathname !== "/login") history.replaceState({}, "", "/login");
  document.title = "Connexion — CIRTDEFENSE";
  $("vue").innerHTML = `
    <div class="ecran-auth">
      ${LOGOS}
      <div class="carte-auth">
        <h1>Poste de supervision CIRT</h1>
        <div class="sous">Agence Nationale des Technologies de l'Information
          et de la Communication</div>
        <div class="champ-auth"><label for="c-ident">Nom d'utilisateur</label>
          <input id="c-ident" autocomplete="username"></div>
        <div class="champ-auth"><label for="c-mdp">Mot de passe</label>
          <input id="c-mdp" type="password" autocomplete="current-password"></div>
        <button class="primaire" id="c-go">Se connecter</button>
        <div class="erreur-auth" id="c-err">${esc(message)}</div>
      </div>
      <div class="lien-auth">Pas de compte ?
        <a id="c-inscription">Demander un accès analyste</a></div>
    </div>`;
  const go = async () => {
    $("c-err").textContent = "";
    try {
      const rep = await poster("/api/v1/auth/login", {
        username: $("c-ident").value.trim(),
        password: $("c-mdp").value,
      });
      poserJeton(rep.token);
      SESSION = rep;
      await entrerSession();
    } catch (e) {
      $("c-err").textContent = e.message;
    }
  };
  $("c-go").addEventListener("click", go);
  $("c-mdp").addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  $("c-inscription").addEventListener("click", ecranInscription);
  $("c-ident").focus();
}

// -- ecran d'inscription (analyste) ------------------------------------
async function ecranInscription() {
  coquilleHorsSession(true);
  if (location.pathname !== "/register") history.replaceState({}, "", "/register");
  document.title = "Inscription — CIRTDEFENSE";
  let postes = [];
  try { postes = (await api("/api/v1/auth/postes")).postes || []; } catch { /* liste vide */ }
  $("vue").innerHTML = `
    <div class="ecran-auth">
      ${LOGOS}
      <div class="carte-auth">
        <h1>Demande d'accès analyste</h1>
        <div class="sous">L'inscription est soumise à la validation de
          l'administrateur principal.</div>
        <div class="grille-champs">
          <div class="champ-auth"><label>Nom</label><input id="i-nom"></div>
          <div class="champ-auth"><label>Prénom</label><input id="i-prenom"></div>
        </div>
        <div class="champ-auth"><label>Nom d'utilisateur</label><input id="i-user"></div>
        <div class="champ-auth"><label>Adresse e-mail</label>
          <input id="i-email" type="email" autocomplete="email"></div>
        <div class="champ-auth"><label>Poste au sein du CIRT / ANTIC</label>
          <select id="i-poste">${postes.map((p) =>
            `<option value="${esc(p.poste_id)}">${esc(p.label)}</option>`).join("")}</select></div>
        <div class="grille-champs">
          <div class="champ-auth"><label>Mot de passe</label><input id="i-mdp" type="password"></div>
          <div class="champ-auth"><label>Confirmation</label><input id="i-mdp2" type="password"></div>
        </div>
        <button class="primaire" id="i-go">Envoyer la demande</button>
        <div class="erreur-auth" id="i-err"></div>
      </div>
      <div class="lien-auth">Déjà un compte ? <a id="i-connexion">Se connecter</a></div>
    </div>`;
  $("i-connexion").addEventListener("click", () => ecranConnexion());
  $("i-go").addEventListener("click", async () => {
    $("i-err").textContent = "";
    try {
      const rep = await poster("/api/v1/auth/register", {
        nom: $("i-nom").value.trim(),
        prenom: $("i-prenom").value.trim(),
        username: $("i-user").value.trim(),
        email: $("i-email").value.trim(),
        password: $("i-mdp").value,
        password_confirm: $("i-mdp2").value,
        poste_id: $("i-poste").value,
      });
      $("vue").querySelector(".carte-auth").innerHTML = `
        <h1>Demande enregistrée</h1>
        <div class="info-auth">${esc(rep.message)}<br><br>
          Vous pourrez vous connecter dès qu'un administrateur aura validé
          votre compte.</div>
        <div class="lien-auth" style="margin-top:14px">
          <a id="i-retour">Retour à la connexion</a></div>`;
      $("i-retour").addEventListener("click", () => ecranConnexion());
    } catch (e) {
      $("i-err").textContent = e.message;
    }
  });
}

// -- ecran d'installation (super-administrateur, 1er lancement) -----------
function ecranInstallation() {
  coquilleHorsSession(true);
  history.replaceState({}, "", "/login");
  document.title = "Installation — CIRTDEFENSE";
  $("vue").innerHTML = `
    <div class="ecran-auth">
      ${LOGOS}
      <div class="carte-auth">
        <h1>Première mise en service</h1>
        <div class="sous">Créez le compte super-administrateur de la plateforme.</div>
        <div class="grille-champs">
          <div class="champ-auth"><label>Nom</label><input id="s-nom"></div>
          <div class="champ-auth"><label>Prénom</label><input id="s-prenom"></div>
        </div>
        <div class="champ-auth"><label>Nom d'utilisateur</label><input id="s-user"></div>
        <div class="champ-auth"><label>Adresse e-mail</label><input id="s-email" type="email"></div>
        <div class="grille-champs">
          <div class="champ-auth"><label>Mot de passe</label><input id="s-mdp" type="password"></div>
          <div class="champ-auth"><label>Confirmation</label><input id="s-mdp2" type="password"></div>
        </div>
        <button class="primaire" id="s-go">Créer le compte</button>
        <div class="erreur-auth" id="s-err"></div>
      </div>
    </div>`;
  $("s-go").addEventListener("click", async () => {
    $("s-err").textContent = "";
    try {
      const rep = await poster("/api/v1/auth/setup", {
        nom: $("s-nom").value.trim(),
        prenom: $("s-prenom").value.trim(),
        username: $("s-user").value.trim(),
        email: $("s-email").value.trim(),
        password: $("s-mdp").value,
        password_confirm: $("s-mdp2").value,
      });
      poserJeton(rep.token);
      SESSION = rep;
      await entrerSession();
    } catch (e) {
      $("s-err").textContent = e.message;
    }
  });
}

// -- entree en session : coquille, nav filtree, page d'accueil -----------
async function entrerSession() {
  coquilleHorsSession(false);
  document.body.dataset.role = SESSION.role;
  construireNav();
  $("pied-session").hidden = false;
  $("lien-accueil").hidden = false;
  $("qui-session").innerHTML = `${esc(SESSION.display_name || SESSION.username)}
    <small>${esc(roleLisible(SESSION.role))}</small>`;

  const demandee = location.pathname;
  const cible = ROUTES_HORS_SESSION.includes(demandee)
    ? "/accueil"
    : (SESSION.allowed_routes || []).includes(demandee) ? demandee : "/accueil";
  naviguer(cible, true);
}

// Recharge /api/v1/auth/me et réapplique le rôle (après un transfert de
// super-administrateur, par exemple) sans re-connexion.
async function rafraichirSession() {
  let me;
  try { me = await meSession(); } catch { return; }
  if (me.non_connecte || me.setup_required) return seDeconnecter();
  SESSION = me;
  document.body.dataset.role = SESSION.role;
  construireNav();
  $("qui-session").innerHTML = `${esc(SESSION.display_name || SESSION.username)}
    <small>${esc(roleLisible(SESSION.role))}</small>`;
  const ici = vueCourante?.route || location.pathname;
  naviguer((SESSION.allowed_routes || []).includes(ici) ? ici : "/accueil", true);
}

async function seDeconnecter() {
  try { await poster("/api/v1/auth/logout", {}); } catch { /* session deja fermee */ }
  poserJeton("");
  SESSION = null;
  delete document.body.dataset.role;
  document.body.classList.remove("sur-accueil");
  $("pied-session").hidden = true;
  $("lien-accueil").hidden = true;
  if (flux) { flux.close(); flux = null; }
  fermerChat();
  ecranConnexion();
}

// -- page d'accueil (portail) ------------------------------------------
function vueAccueil() {
  document.title = "Accueil — CIRTDEFENSE";
  $("titre-vue").textContent = "Accueil";
  $("sous-vue").textContent = "";
  const tuiles = (SESSION.allowed_routes || [])
    .map((route) => VUES.find((v) => v.route === route))
    .filter(Boolean)
    .map((v) => `<button class="tuile-portail" data-route="${v.route}">
        ${icone(v.icone)}
        <span class="t-titre">${esc(v.label)}</span>
        <span class="t-sous">${esc(v.sous)}</span>
      </button>`).join("");
  $("vue").innerHTML = `
    <div class="portail">
      <h1 class="titre-accueil">Accueil</h1>
      ${LOGOS}
      <div class="salut">${esc(SESSION.welcome)}<b>.</b></div>
      <div class="role-badge">${esc(roleLisible(SESSION.role))}</div>
      <div class="tuiles-portail">${tuiles}</div>
      <button class="deco-portail" id="deco-portail" type="button">Se déconnecter</button>
    </div>`;
  $("vue").querySelectorAll("[data-route]").forEach((t) =>
    t.addEventListener("click", () => naviguer(t.dataset.route)));
  $("deco-portail").addEventListener("click", seDeconnecter);
}

$("deconnexion").addEventListener("click", seDeconnecter);
$("lien-accueil").addEventListener("click", () => naviguer("/accueil"));

// ---------------------------------------------------------------- démarrage
(async function demarrer() {
  let me;
  try {
    me = await meSession();
  } catch (e) {
    coquilleHorsSession(true);
    $("vue").innerHTML = `<div class="ecran-auth"><div class="carte-auth">
      <h1>Service indisponible</h1><div class="sous">${esc(e.message)}</div></div></div>`;
    return;
  }
  if (me.setup_required) return ecranInstallation();
  if (me.non_connecte) return ecranConnexion();
  SESSION = me;
  await entrerSession();
  setInterval(() => {
    if (vueCourante?.route === "/dashboard") rafraichir();
  }, 20000);
})();
