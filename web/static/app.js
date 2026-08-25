/* Poste de supervision CIRTDEFENSE — navigation laterale et routage.

   Aucune dependance externe, y compris pour les icones : la plateforme doit
   rester utilisable hors connexion, contrainte du mode degrade (Axe 5). Les
   icones sont des traces SVG en ligne. */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(url, options) {
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
  { route: "/assistant", icone: "MessagesSquare", label: "Assistant",
    titre: "Assistant",
    sous: "Interroger le système en langage naturel", rendu: vueAssistant },
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
    $("bandeau").className = "bandeau suspendu";
    $("bandeau").textContent = "Interface injoignable : " + e.message;
  }
}

function majEntete(etat) {
  $("site").textContent = `${etat.site_id} · ${etat.environment}`;
  $("pied-rail").textContent = `${etat.site_id} · ${etat.autonomy.actuation_mode}`;
  const actif = etat.autonomy.effective;
  const b = $("bandeau");
  b.className = "bandeau " + (actif ? "actif" : "suspendu");
  b.textContent = actif
    ? `Autonomie ACTIVE — actionnement « ${etat.autonomy.actuation_mode} ». `
      + "Les actions partent sans validation préalable."
    : `Autonomie SUSPENDUE — ${etat.circuit_breaker.reason || "coupe-circuit ouvert"}. `
      + "Aucune action n'est exécutée jusqu'au réarmement par l'administrateur.";
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
            ${e.payload.reason ? `<span class="muet">${esc(String(e.payload.reason).slice(0, 90))}</span>` : ""}
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
        <td>${esc((i.attack_label || i.category).slice(0, 46))}</td>
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

    ${m.probe_is_manual ? `<div class="carte muet" style="margin-bottom:14px">
      La sonde active est alimentée à la main : l'état de santé est un paramètre
      du scénario. C'est ce qui permet d'éprouver la boucle de contrôle fermée
      (EF-25) sans casser un service réel — utilisez « Dégrader » puis lancez la
      boucle depuis le bouton en bas de page.
    </div>` : ""}

    <h2>Parc supervisé</h2>
    <div class="carte" style="padding:0;overflow:auto">
      <table><thead><tr>
        <th>Plateforme</th><th>Zone</th><th>Criticité</th><th>État</th>
        <th>Latence</th><th>Erreurs</th><th>Débit</th>
        <th>Incidents</th><th>Actions</th><th>Constat</th><th></th>
      </tr></thead><tbody>
      ${m.targets.map((t) => `<tr>
        <td><b>${esc(t.target)}</b>${t.ip ? `<div class="muet mono">${esc(t.ip)}</div>` : ""}</td>
        <td class="muet">${esc(t.zone)}</td>
        <td class="num">${t.criticality}/5</td>
        <td><span class="etat ${esc(t.state)}">${esc(t.state)}</span></td>
        <td class="num">${t.health.latency_ms ? Math.round(t.health.latency_ms) + " ms" : "—"}</td>
        <td class="num">${(t.health.error_rate * 100).toFixed(1)} %</td>
        <td class="num">${t.health.throughput || "—"}</td>
        <td class="num">${t.incidents || "—"}</td>
        <td class="num">${t.actions_executed || "—"}${
          t.actions_rolled_back ? ` <span class="muet">(${t.actions_rolled_back} annulée(s))</span>` : ""}</td>
        <td class="muet">${esc((t.breaches || []).join(" ; ") || "dans les seuils")}</td>
        <td>${m.probe_is_manual ? `<button data-degrade="${esc(t.target)}"
              data-etat="${t.state === "nominal" ? "1" : "0"}">${
              t.state === "nominal" ? "Dégrader" : "Rétablir"}</button>` : ""}</td>
      </tr>`).join("")}
      </tbody></table>
    </div>

    <h2>Surveillance post-action (EF-25)</h2>
    <div class="carte">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
        <span class="muet">${m.post_action_watches.length} action(s) réversible(s) encore
          appliquée(s). La boucle compare l'état actuel à la mesure prise AVANT chaque action.</span>
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
    </div>`;

  $("vue").querySelectorAll("button[data-degrade]").forEach((b) =>
    b.addEventListener("click", async () => {
      b.disabled = true;
      await post(`/api/v1/monitoring/simulate/${b.dataset.degrade}?degraded=${b.dataset.etat === "1"}`);
      await vueSurveillance();
    }));

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

    <div class="carte muet" style="margin-bottom:16px">
      La réversibilité n'est pas une métadonnée de priorisation mais la
      <b>condition opérationnelle</b> qui autorise le moteur à agir seul (Axe 2).
      Une action absente de ce catalogue, ou déclarée irréversible, n'est jamais
      exécutée automatiquement — quelle que soit la gravité de la menace.
    </div>

    <h2>Actions exécutables en autonomie (${autonomes.length})</h2>
    <div class="carte" style="padding:0;overflow:auto">
      <table><thead><tr>
        <th>Action</th><th>Description</th><th>Réversibilité</th><th>Annulation</th>
        <th>Rayon</th><th>Délai max</th><th>Effet résiduel</th>
      </tr></thead><tbody>${autonomes.map(ligne).join("")}</tbody></table>
    </div>

    <h2>Exclues du périmètre autonome (${exclues.length})</h2>
    <div class="carte muet" style="margin-bottom:10px">
      Ces entrées figurent au catalogue précisément pour rendre visible ce que
      l'autonomie ne couvre pas. Elles restent des gestes humains.
    </div>
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
      <div class="muet" style="margin-bottom:10px">
        Chaque bouton fabrique la charge utile qu'un collecteur émettrait réellement
        pour l'attaque décrite, puis la remet à l'adaptateur d'ingestion. La plateforme
        ne fait aucune différence avec une alerte venue d'un Wazuh de production.
      </div>
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
      <td><b>${esc(x.code)}</b> ${esc((x.label || "").slice(0, 40))}</td>
      <td>${x.classification.severity
        ? `<span class="etat ${esc(x.classification.severity)}">${esc(x.classification.severity)}</span>` : "—"}</td>
      <td class="num">${x.classification.dangerousness ?? "—"}</td>
      <td>${x.classification.priority
        ? `<span class="etat ${esc(x.classification.priority)}">${esc(x.classification.priority)}</span>` : "—"}</td>
      <td class="mono">${esc(x.actions.join(", ") || "—")}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

// ============================================================ /assistant
async function vueAssistant() {
  const { suggestions } = await api("/api/v1/assistant/suggestions");

  $("vue").innerHTML = `
    <div class="carte muet" style="margin-bottom:14px">
      L'assistant répond exclusivement à partir des données de la plateforme —
      journal d'audit, portefeuille, catalogue. Une question hors de ce périmètre
      reçoit un refus explicite, jamais une réponse fabriquée.
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      ${suggestions.map((s) => `<button data-q="${esc(s)}">${esc(s)}</button>`).join("")}
    </div>
    <div style="display:flex;gap:8px;margin-bottom:16px">
      <input id="question" placeholder="Posez une question sur les opérations…" style="flex:1">
      <button class="primaire" id="envoyer">Demander</button>
    </div>
    <div id="reponse" class="md"></div>`;

  const poser = async (question) => {
    $("reponse").innerHTML = '<div class="muet">…</div>';
    try {
      const r = await post("/api/v1/assistant/ask", { question });
      $("reponse").innerHTML = `<div class="carte">
        <div class="muet" style="margin-bottom:10px">${esc(question)}</div>
        <div class="md">${markdown(r.text)}</div>
        ${r.sources.length ? `<div class="muet" style="margin-top:12px;padding-top:10px;
          border-top:1px solid var(--grid)">Sources : ${r.sources.map(esc).join(", ")}
          · rédaction : ${esc(r.provider)}</div>` : ""}
      </div>`;
    } catch (e) {
      $("reponse").innerHTML = `<div class="carte" style="border-color:var(--critical)">${esc(e.message)}</div>`;
    }
  };

  $("vue").querySelectorAll("button[data-q]").forEach((b) =>
    b.addEventListener("click", () => poser(b.dataset.q)));
  $("envoyer").addEventListener("click", () => {
    const q = $("question").value.trim(); if (q) poser(q);
  });
  $("question").addEventListener("keydown", (e) => { if (e.key === "Enter") $("envoyer").click(); });

  const brief = await api("/api/v1/assistant/brief");
  $("reponse").innerHTML = `<div class="carte"><div class="md">${markdown(brief.text)}</div></div>`;
}

// ============================================================== /reports
async function vueRapports() {
  const PERIODES = [
    { h: 24, label: "24 heures" }, { h: 168, label: "7 jours" },
    { h: 720, label: "30 jours" }, { h: 2160, label: "90 jours" },
  ];

  $("vue").innerHTML = `
    <div class="carte" style="margin-bottom:16px">
      <div class="muet" style="margin-bottom:12px">
        Un rapport n'est pas un bilan plus long : c'est une pièce destinée à être
        transmise, archivée et opposée. Il porte son périmètre, sa période et
        l'état de la chaîne d'audit — de quoi être rejugé par quelqu'un qui
        n'était pas là.
      </div>
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

    <h2>Notifications a posteriori non acquittées (${notifications.count})</h2>
    <div class="carte muet" style="margin-bottom:10px">
      L'analyste est informé après coup de chaque action exécutée. Cette notification
      est son unique point d'entrée dans la boucle : il ne valide rien en amont.
    </div>
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
