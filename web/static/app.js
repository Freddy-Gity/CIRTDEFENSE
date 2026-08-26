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
  $("nav").innerHTML = VUES.map((v) => {
    if (v.separateur) return '<div class="flex"></div><div class="sep"></div>';
    return `<a class="lien-nav" href="${v.route}" data-route="${v.route}">
      ${icone(v.icone)}<span>${esc(v.label)}</span>
      <span class="pastille" data-badge="${v.route}" hidden></span></a>`;
  }).join("");

  $("nav").querySelectorAll("a[data-route]").forEach((a) =>
    a.addEventListener("click", (e) => { e.preventDefault(); naviguer(a.dataset.route); }));
}

function naviguer(chemin, remplacer = false) {
  // L'assistant n'a plus d'onglet, mais son adresse reste valide : un lien
  // profond ou un signet existant doit ouvrir la conversation, pas une 404.
  if (chemin === "/assistant") {
    ouvrirChat();
    chemin = "/dashboard";
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
window.addEventListener("popstate", () => naviguer(location.pathname, true));

$("theme").addEventListener("click", () => {
  const actuel = document.documentElement.getAttribute("data-theme");
  const sombre = actuel ? actuel === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  const cible = sombre ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", cible);
  try { localStorage.setItem("cirt-theme", cible); } catch { /* stockage indisponible */ }
});
try {
  const memo = localStorage.getItem("cirt-theme");
  if (memo) document.documentElement.setAttribute("data-theme", memo);
} catch { /* stockage indisponible */ }

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
  $("site").textContent = `${etat.site_id} · ${etat.environment}`;
  $("pied-rail").textContent = `${etat.site_id} · ${etat.autonomy.actuation_mode}`;

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
  const [portefeuille, stats, audit] = await Promise.all([
    api("/api/v1/incidents?limit=200"),
    api("/api/v1/incidents/statistics"),
    api("/api/v1/audit?limit=40"),
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

  $("vue").innerHTML = `
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

    ${plan(m.targets)}

    ${enteteSection("parc", "Parc supervisé", m.targets.length)}
    <div class="repliable" data-section="parc">
      <div style="display:flex;justify-content:flex-end;margin-bottom:10px">
        <button class="primaire" id="ajouter-plateforme">+ Ajouter une plateforme</button>
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
          <button class="primaire" id="boucle">Lancer la boucle de contrôle</button>
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
  $("vue").querySelectorAll("[data-detail]").forEach((b) =>
    b.addEventListener("click", () => ouvrirDetail(b.dataset.detail)));
  $("vue").querySelectorAll("[data-retirer]").forEach((b) =>
    b.addEventListener("click", () => retirerPlateforme(b.dataset.retirer)));
  $("ajouter-plateforme").addEventListener("click", formulairePlateforme);
  brancherBoucle();
}

// ------------------------------------------------------- plan et balayage
// Ce n'est pas une carte du monde : c'est le plan du parc. Les points sont
// places par leurs coordonnees quand elles sont connues, et repartis par
// segment sinon — la position d'un actif non geolocalise ne doit jamais se
// lire comme une donnee.
function plan(cibles) {
  if (!cibles.length) return "";
  const situees = cibles.filter((t) => t.latitude != null && t.longitude != null);

  const lats = situees.map((t) => t.latitude);
  const lons = situees.map((t) => t.longitude);
  const etendue = (v) => {
    const min = Math.min(...v), max = Math.max(...v);
    const marge = Math.max((max - min) * 0.28, 0.004);
    return [min - marge, max + marge];
  };
  const [latMin, latMax] = situees.length ? etendue(lats) : [0, 1];
  const [lonMin, lonMax] = situees.length ? etendue(lons) : [0, 1];

  let rang = 0;
  const position = (t) => {
    if (t.latitude != null && t.longitude != null) {
      return {
        x: 10 + ((t.longitude - lonMin) / (lonMax - lonMin)) * 80,
        y: 10 + (1 - (t.latitude - latMin) / (latMax - latMin)) * 80,
        situe: true,
      };
    }
    // Sans coordonnees : une couronne reguliere, visiblement schematique.
    const n = cibles.length - situees.length;
    const angle = (rang++ / Math.max(n, 1)) * 2 * Math.PI;
    return { x: 50 + 36 * Math.cos(angle), y: 50 + 36 * Math.sin(angle), situe: false };
  };

  const places = cibles.map((t) => ({ cible: t, ...position(t) }));
  placerEtiquettes(places);

  const points = places.map(({ cible: t, x, y, situe, cote }) => `
    <button class="plot ${cote}" data-detail="${esc(t.target)}"
      data-etat="${esc(t.state)}" style="left:${x.toFixed(1)}%;top:${y.toFixed(1)}%"
      title="${esc(t.target)} — ${esc(t.state)}${situe ? "" : " (position indicative)"}">
      <span class="pastille-plan"></span>
      <span class="etiquette">${esc(t.target)}</span></button>`).join("");

  return `<div class="plan">
    <svg class="grille-plan" aria-hidden="true">
      <defs><pattern id="quadrillage" width="46" height="46" patternUnits="userSpaceOnUse">
        <path d="M46 0H0V46" fill="none" stroke="var(--grid)" stroke-width="1"/>
      </pattern></defs>
      <rect width="100%" height="100%" fill="url(#quadrillage)"/>
    </svg>
    <div class="cadran">
      <svg viewBox="0 0 100 100" style="position:absolute;inset:0;width:100%;height:100%"
           aria-hidden="true">
        <circle cx="50" cy="50" r="17" fill="none" stroke="var(--grid)"/>
        <circle cx="50" cy="50" r="32" fill="none" stroke="var(--grid)"/>
        <circle cx="50" cy="50" r="46" fill="none" stroke="var(--grid)"/>
        <path d="M50 4V96M4 50H96" stroke="var(--grid)" stroke-dasharray="2 4"/>
      </svg>
      <div class="balayage"></div>
      ${points}
    </div>
  </div>
  <div class="legende-plan">
    <span><i class="point vert"></i>nominal</span>
    <span><i class="point" style="background:var(--warning)"></i>dégradé</span>
    <span><i class="point rouge"></i>injoignable</span>
    <span>${situees.length}/${cibles.length} plateforme(s) géolocalisée(s) ;
      les autres sont placées de façon indicative</span>
  </div>`;
}

// Placement glouton : chaque etiquette prend la premiere direction libre.
// Alterner en aveugle laissait des noms superposes des que trois machines
// etaient voisines — et un nom illisible ne vaut pas mieux qu'un nom absent.
function placerEtiquettes(places) {
  const COTES = ["bas", "haut", "droite", "gauche"];
  const pris = [];

  const boite = (p, cote) => {
    // Le cadran fait environ 380 px de cote et l'etiquette 10,5 px : un
    // caractere occupe donc a peu pres 1,7 % de la largeur. Surestimer
    // ecarte un peu trop les noms ; sous-estimer les laisse se superposer.
    const largeur = p.cible.target.length * 1.7 + 2;
    const hauteur = 5.4;
    switch (cote) {
      case "haut": return { x: p.x - largeur / 2, y: p.y - 3.6 - hauteur, l: largeur, h: hauteur };
      case "droite": return { x: p.x + 2.4, y: p.y - hauteur / 2, l: largeur, h: hauteur };
      case "gauche": return { x: p.x - 2.4 - largeur, y: p.y - hauteur / 2, l: largeur, h: hauteur };
      default: return { x: p.x - largeur / 2, y: p.y + 3, l: largeur, h: hauteur };
    }
  };

  const chevauche = (a, b) =>
    a.x < b.x + b.l && a.x + a.l > b.x && a.y < b.y + b.h && a.y + a.h > b.y;

  // Les pastilles sont des obstacles au meme titre que les etiquettes : sans
  // cela un point voisin vient se poser au milieu d'un nom.
  for (const p of places) {
    pris.push({ x: p.x - 2.2, y: p.y - 2.2, l: 4.4, h: 4.4 });
  }

  places.sort((a, b) => a.y - b.y || a.x - b.x);
  for (const p of places) {
    const libre = COTES.find((c) => {
      const b = boite(p, c);
      return b.x > -6 && b.x + b.l < 106 && !pris.some((autre) => chevauche(b, autre));
    });
    // Aucune place libre : dans une grappe dense, mieux vaut un point net et
    // un nom au survol que deux noms illisibles l'un sur l'autre. Le tableau
    // en dessous nomme de toute facon chaque plateforme.
    p.cote = libre || "cache";
    if (libre) pris.push(boite(p, libre));
  }
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

      <div class="carte" style="margin-bottom:16px;display:flex;gap:10px;
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
async function vueDemo() {
  const data = await api("/api/v1/demo/scenarios");

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
        </div>`).join("")}</div>`).join("")}`;

  $("vue").querySelectorAll("button[data-code]").forEach((b) =>
    b.addEventListener("click", () => lancerUne(b)));
  $("vue").querySelectorAll("button[data-famille]").forEach((b) =>
    b.addEventListener("click", () => lancerLot(b)));
  $("reset").addEventListener("click", async () => {
    const r = await post("/api/v1/demo/reset");
    $("resultat").innerHTML = `<div class="carte" style="border-color:var(--good);margin-bottom:16px">
      Remise à zéro effectuée. ${r.audit_entries_kept} entrées d'audit conservées —
      le journal est immuable par construction.</div>`;
    await rafraichir();
  });
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
  $("resultat").innerHTML =
    `<div class="carte" style="border-color:var(--critical);margin-bottom:16px">${esc(m)}</div>`;
};

function afficherResultat(r) {
  if (!r.accepted) {
    $("resultat").innerHTML = `<div class="carte" style="margin-bottom:16px">
      <b>${esc(r.code)}</b> — non traité : ${esc(r.reason)}</div>`;
    return;
  }
  const c = r.decision.classification;
  const actions = r.execution?.results || [];
  const ecartees = r.decision.trace?.rejected_actions || [];

  $("resultat").innerHTML = `<div class="carte" style="margin-bottom:16px">
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
  </div>`;
}

function afficherLot(r) {
  $("resultat").innerHTML = `<div class="carte" style="margin-bottom:16px">
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
    </tr>`).join("")}</tbody></table></div>`;
}


// ============================================================== /reports
async function vueRapports() {
  const PERIODES = [
    { h: 24, label: "24 heures" }, { h: 168, label: "7 jours" },
    { h: 720, label: "30 jours" }, { h: 2160, label: "90 jours" },
  ];

  $("vue").innerHTML = `
    <div class="carte" style="margin-bottom:16px">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <span class="muet">Période :</span>
        <select id="periode">
          ${PERIODES.map((p, i) =>
            `<option value="${p.h}" ${i === 0 ? "selected" : ""}>${p.label}</option>`).join("")}
        </select>
        <button class="primaire" id="generer">Générer</button>
        <a class="btn" id="exporter" href="/api/v1/assistant/report.md?hours=24"
           download>Exporter en Markdown</a>
      </div>
    </div>
    <div id="apercu"></div>`;

  const majLien = () => {
    $("exporter").href = `/api/v1/assistant/report.md?hours=${$("periode").value}`;
  };
  $("periode").addEventListener("change", majLien);

  const generer = async () => {
    const heures = $("periode").value;
    $("apercu").innerHTML = '<div class="vide">Génération…</div>';
    try {
      const r = await api(`/api/v1/assistant/report?hours=${heures}`);
      $("apercu").innerHTML = `<div class="carte md">${markdown(r.markdown)}</div>`;
    } catch (e) {
      $("apercu").innerHTML = `<div class="carte" style="border-color:var(--critical)">${esc(e.message)}</div>`;
    }
  };
  $("generer").addEventListener("click", generer);
  majLien();
  await generer();
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

    <h2>Jeton de session</h2>
    <div class="carte" style="margin-bottom:18px">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input id="jeton" type="password" placeholder="Jeton administrateur ou analyste"
               value="${esc(jeton())}" style="flex:1;min-width:240px">
        <button class="primaire" id="poser-jeton">Enregistrer</button>
        <button id="oublier-jeton">Oublier</button>
        <span class="etat ${jeton() ? "basse" : "moyenne"}" id="etat-jeton">${
          jeton() ? "jeton présent" : "lecture seule"}</span>
      </div>
      <div class="muet" style="margin-top:9px">Sans jeton, l'interface reste consultable
        mais aucun geste réservé n'est possible : déclarer une plateforme, basculer
        l'autonomie ou annuler une action exigent un rôle.</div>
    </div>

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

  $("poser-jeton").addEventListener("click", async () => {
    poserJeton($("jeton").value.trim());
    await vueReglages();
  });
  $("oublier-jeton").addEventListener("click", async () => {
    poserJeton("");
    await vueReglages();
  });

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

// ---------------------------------------------------------------- démarrage
construireNav();
naviguer(location.pathname, true);
setInterval(() => {
  if (["/dashboard", "/monitoring"].includes(vueCourante?.route)) rafraichir();
}, 20000);

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
  majVisibiliteChat();
  if (flux) { flux.close(); flux = null; }
}

$("lanceur-chat").addEventListener("click", ouvrirChat);
$("fermer-chat").addEventListener("click", fermerChat);
$("agrandir").addEventListener("click", () => $("chat").classList.toggle("plein"));
const nouvelleDiscussion = () => {
  // Un fil neuf cote serveur aussi : sinon la nouvelle conversation heriterait
  // du contexte de l'ancienne sans que rien ne l'indique a l'ecran.
  filId = `web-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
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
    return `<div class="effet"><div class="titre-effet">Rapport généré</div>
      Période de ${r.hours} heures — <a href="/api/v1/assistant/report.md?hours=${r.hours}"
      download>télécharger en Markdown</a></div>`;
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

// -- menu de filtres ---------------------------------------------------------

function dessinerFiltres() {
  $("filtres-liste").innerHTML = AXES.map(({ cle, titre, options }) => `
    <div class="groupe-filtre">
      <b>${esc(titre)}</b>
      <div class="choix">
        ${options.map(([valeur, libelle]) => `
          <button data-axe="${cle}" data-valeur="${valeur}"
                  aria-pressed="${FILTRES[cle] === valeur}">${esc(libelle)}</button>`).join("")}
      </div>
    </div>`).join("");

  $("filtres-liste").querySelectorAll("[data-axe]").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      FILTRES[b.dataset.axe] = b.dataset.valeur;
      dessinerFiltres();
      majPastilleFiltres();
      chargerFils();
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
  if (!ouvert) dessinerFiltres();
});
document.addEventListener("click", () => {
  $("filtres-liste").hidden = true;
  $("filtrer").setAttribute("aria-expanded", "false");
});

// -- historique detaille, dans le corps du panneau ---------------------------

$("voir-historique").addEventListener("click", async () => {
  await chargerFils();
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
