/* Poste de supervision CIRTDEFENSE.
   Aucune dependance externe : la plateforme doit rester utilisable hors
   connexion, contrainte du mode degrade (Axe 5). */

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
const post = (url) => api(url, { method: "POST" });

const heure = (iso) => iso
  ? new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "medium" })
  : "—";

/* Bande de dangerosite -> couleur d'etat. La teinte ne porte jamais seule
   l'information : le libelle l'accompagne toujours. */
const bandeDanger = (d) =>
  d >= 9 ? "critique" : d >= 7 ? "haute" : d >= 4 ? "moyenne" : "basse";

// ---------------------------------------------------------------- navigation
const VUES = ["demo", "portefeuille", "journal", "assistant"];
let vueCourante = "demo";

document.querySelectorAll('nav button').forEach((b) => {
  b.addEventListener("click", () => {
    vueCourante = b.dataset.vue;
    document.querySelectorAll('nav button').forEach((x) =>
      x.setAttribute("aria-selected", String(x === b)));
    VUES.forEach((v) => { $(`vue-${v}`).hidden = v !== vueCourante; });
    rafraichir();
  });
});

$("theme").addEventListener("click", () => {
  const actuel = document.documentElement.getAttribute("data-theme");
  const sombre = actuel
    ? actuel === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.setAttribute("data-theme", sombre ? "light" : "dark");
});

// ------------------------------------------------------------------ catalogue
const LIBELLES_FAMILLE = {
  A: "Attaques réseau", B: "Attaques applicatives",
  C: "Comportemental / insider", D: "Infrastructure",
};

async function chargerCatalogue() {
  const data = await api("/api/v1/demo/scenarios");
  $("catalogue").innerHTML = Object.entries(data.by_family)
    .map(([code, items]) => `
      <div class="famille">
        <h3><span class="puce ${esc(code)}"></span>
            Famille ${esc(code)} — ${esc(LIBELLES_FAMILLE[code] || "")}
            <span class="muet" style="font-weight:400">(${items.length})</span></h3>
        <div class="attaques">
          ${items.map(carteAttaque).join("")}
        </div>
      </div>`).join("");

  $("catalogue").querySelectorAll("button[data-code]").forEach((b) =>
    b.addEventListener("click", () => lancer(b.dataset.code, b)));
}

function carteAttaque(s) {
  return `<div class="attaque">
    <div class="tete">
      <span class="code">${esc(s.code)}</span>
      <span class="etat ${esc(s.priority)}">${esc(s.priority)}</span>
    </div>
    <div class="titre">${esc(s.title)}</div>
    <div class="recit">${esc(s.narrative)}</div>
    <div class="pied">
      <button data-code="${esc(s.code)}">Lancer</button>
      <span class="dang">dangerosité ${s.dangerousness}/10</span>
      ${s.no_direct_action ? '<span class="dang">· sans action corrective</span>' : ""}
    </div>
  </div>`;
}

// --------------------------------------------------------------- declenchement
async function lancer(code, bouton) {
  bouton.disabled = true;
  bouton.textContent = "…";
  try {
    const r = await post(`/api/v1/demo/run/${code}`);
    afficherResultat(r);
    await rafraichir();
  } catch (e) {
    afficherErreur(e.message);
  } finally {
    bouton.disabled = false;
    bouton.textContent = "Lancer";
  }
}

document.querySelectorAll("button[data-famille]").forEach((b) =>
  b.addEventListener("click", async () => {
    b.disabled = true;
    const libelle = b.textContent;
    b.textContent = "Exécution…";
    try {
      const f = b.dataset.famille;
      const r = await post(`/api/v1/demo/run-all${f ? `?family=${f}` : ""}`);
      afficherLot(r);
      await rafraichir();
    } catch (e) {
      afficherErreur(e.message);
    } finally {
      b.disabled = false;
      b.textContent = libelle;
    }
  }));

$("reset").addEventListener("click", async () => {
  const r = await post("/api/v1/demo/reset");
  $("resultat").hidden = true;
  await rafraichir();
  afficherErreur(
    `Remise à zéro effectuée. ${r.audit_entries_kept} entrées d'audit conservées — `
    + `le journal est immuable par construction.`, "info");
});

function afficherErreur(message, ton = "erreur") {
  const zone = $("resultat");
  zone.hidden = false;
  zone.innerHTML = `<div class="carte" style="border-color:var(--${
    ton === "info" ? "good" : "critical"});margin-bottom:16px">${esc(message)}</div>`;
}

function afficherResultat(r) {
  const zone = $("resultat");
  zone.hidden = false;

  if (!r.accepted) {
    zone.innerHTML = `<div class="carte" style="margin-bottom:16px">
      <b>${esc(r.code)}</b> — non traité : ${esc(r.reason)}</div>`;
    return;
  }

  const c = r.decision.classification;
  const actions = (r.execution?.results || []);
  const ecartees = r.decision.trace?.rejected_actions || [];

  zone.innerHTML = `<div class="carte" style="margin-bottom:16px">
    <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:12px;flex-wrap:wrap">
      <span class="code" style="font-size:15px;font-weight:700">${esc(c.code)}</span>
      <span style="font-weight:600">${esc(c.label)}</span>
      <span class="fam"><span class="puce ${esc(c.family_code)}"></span>${esc(c.family_label)}</span>
    </div>

    <div class="chaine">
      <div class="etape">
        <div class="quoi">1 · Classification</div>
        <div class="detail">
          Criticité <span class="etat ${esc(c.severity)}">${esc(c.severity)}</span>
          &nbsp; Dangerosité <span class="etat ${bandeDanger(c.dangerousness)}">${
            c.dangerousness}/10 — ${esc(c.danger_band)}</span>
          &nbsp; Priorité Axe 4 <span class="etat ${esc(c.priority)}">${esc(c.priority)}</span>
        </div>
        <div class="muet" style="margin-top:6px">${
          (c.factors || []).map(esc).join(" · ")}</div>
      </div>

      <div class="etape">
        <div class="quoi">2 · Décision</div>
        <div class="detail">${esc(r.decision.outcome)}</div>
        <div class="muet" style="margin-top:4px">${esc(r.decision.rationale)}</div>
      </div>

      <div class="etape">
        <div class="quoi">3 · Actions exécutées sans validation préalable</div>
        <div class="actions-liste">
          ${actions.length ? actions.map((a) => `
            <div class="action-item">
              <span class="verbe">${esc(a.actuator)}:${esc(a.verb)}</span>
              <span class="muet">→ ${esc(a.target)}</span>
              <span class="etat ${a.status === "executed" ? "basse" : "critique"}">${esc(a.status)}</span>
              <span class="muet">${esc(a.reversibility)}</span>
            </div>`).join("")
            : '<div class="muet">Aucune action — voir le motif ci-dessus.</div>'}
        </div>
        ${ecartees.length ? `<div class="muet" style="margin-top:8px">
            Écartées : ${ecartees.map((s) => `${esc(s.action)} (${esc(s.reason)})`).join(" · ")}
          </div>` : ""}
      </div>

      <div class="etape">
        <div class="quoi">4 · Prescription du catalogue CIRT</div>
        <div class="muet">${esc(r.scenario.prescribed_actions)}</div>
      </div>
    </div>
  </div>`;
}

function afficherLot(r) {
  const zone = $("resultat");
  zone.hidden = false;
  zone.innerHTML = `<div class="carte" style="margin-bottom:16px">
    <div style="margin-bottom:10px"><b>${r.scenarios_run}</b> scénario(s) rejoué(s),
      <b>${r.actions_executed}</b> action(s) exécutée(s)${
        r.family ? ` — famille ${esc(r.family)}` : ""}.</div>
    <table><thead><tr><th>Type</th><th>Criticité</th><th>Dang.</th><th>Priorité</th><th>Actions</th></tr></thead>
      <tbody>${r.results.map((x) => `<tr>
        <td><b>${esc(x.code)}</b> ${esc(x.label)}</td>
        <td>${x.classification.severity
              ? `<span class="etat ${esc(x.classification.severity)}">${esc(x.classification.severity)}</span>` : "—"}</td>
        <td class="num">${x.classification.dangerousness ?? "—"}</td>
        <td>${x.classification.priority
              ? `<span class="etat ${esc(x.classification.priority)}">${esc(x.classification.priority)}</span>` : "—"}</td>
        <td class="mono">${x.actions.join(", ") || "—"}</td>
      </tr>`).join("")}</tbody></table>
  </div>`;
}

// ------------------------------------------------------------------ barres
function barres(conteneur, entrees, couleurDe) {
  const max = Math.max(1, ...entrees.map((e) => e.valeur));
  conteneur.innerHTML = entrees.length
    ? entrees.map((e) => `
      <div class="barre">
        <div class="nom">${esc(e.nom)}</div>
        <div class="piste">
          <div class="remplissage" style="width:${(e.valeur / max) * 100}%;
               background:${couleurDe(e)}"></div>
        </div>
        <div class="val">${e.valeur}</div>
      </div>`).join("")
    : '<div class="vide">Aucune donnée — lancez une attaque depuis l\'onglet Démonstration.</div>';
}

// ------------------------------------------------------------------ rendu
async function rafraichir() {
  try {
    const [etat, portefeuille, stats] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/incidents?limit=60"),
      api("/api/v1/incidents/statistics"),
    ]);

    $("site").textContent = `${etat.site_id} · ${etat.environment}`;
    majBandeau(etat);

    if (vueCourante === "portefeuille") majPortefeuille(etat, portefeuille, stats);
    if (vueCourante === "journal") await majJournal();
    if (vueCourante === "assistant" && window.majAssistant) await window.majAssistant();
  } catch (e) {
    $("bandeau").className = "bandeau suspendu";
    $("bandeau").textContent = "Interface injoignable : " + e.message;
  }
}

function majBandeau(etat) {
  const actif = etat.autonomy.effective;
  const b = $("bandeau");
  b.className = "bandeau " + (actif ? "actif" : "suspendu");
  b.textContent = actif
    ? `Autonomie ACTIVE — actionnement « ${etat.autonomy.actuation_mode} ». `
      + `Les actions partent sans validation préalable.`
    : `Autonomie SUSPENDUE — ${etat.circuit_breaker.reason || "coupe-circuit ouvert"}. `
      + `Aucune action n'est exécutée jusqu'au réarmement par l'administrateur.`;
}

function tuile(valeur, libelle, note = "", couleur = "") {
  return `<div class="carte tuile">
    <div class="valeur" ${couleur ? `style="color:${couleur}"` : ""}>${esc(valeur)}</div>
    <div class="libelle">${esc(libelle)}</div>
    ${note ? `<div class="note">${esc(note)}</div>` : ""}</div>`;
}

function majPortefeuille(etat, portefeuille, stats) {
  const cb = etat.circuit_breaker;
  $("posture").innerHTML = [
    tuile(cb.state === "closed" ? "fermé" : "OUVERT", "Coupe-circuit (EF-26)",
      `${cb.observations.rollbacks_in_window}/${cb.observations.rollback_threshold} annulations `
      + `sur ${cb.observations.window_seconds} s`,
      cb.state === "closed" ? "var(--success-text)" : "var(--critical)"),
    tuile(stats.actions_executed, "Actions exécutées", "confinements en place"),
    tuile(stats.actions_rolled_back, "Actions annulées", "dont annulations autonomes (EF-25)",
      stats.actions_rolled_back > 0 ? "var(--serious)" : ""),
    tuile((stats.rollback_ratio * 100).toFixed(0) + " %", "Taux d'annulation",
      "fréquence à laquelle le système se corrige",
      stats.rollback_ratio > 0.3 ? "var(--critical)" : "var(--success-text)"),
    tuile(`${etat.catalog.autonomously_executable}/${etat.catalog.total}`,
      "Périmètre autonome (EF-14)", "actions annulables sur total du catalogue"),
    tuile(etat.audit_chain.valid ? "intacte" : "ROMPUE", "Chaîne d'audit",
      `${etat.audit_chain.entries_checked} entrées vérifiées`,
      etat.audit_chain.valid ? "var(--success-text)" : "var(--critical)"),
  ].join("");

  const incidents = portefeuille.incidents;

  const parFamille = {};
  const parDanger = { basse: 0, moyenne: 0, haute: 0, critique: 0 };
  incidents.forEach((i) => {
    const f = (i.attack_code || "?").charAt(0);
    parFamille[f] = (parFamille[f] || 0) + 1;
    parDanger[bandeDanger(i.dangerousness || 0)]++;
  });

  barres($("par-famille"),
    ["A", "B", "C", "D"].filter((f) => parFamille[f])
      .map((f) => ({ nom: `${f} — ${LIBELLES_FAMILLE[f]}`, valeur: parFamille[f], code: f })),
    (e) => `var(--fam-${e.code})`);

  barres($("par-danger"),
    Object.entries(parDanger).filter(([, v]) => v)
      .map(([k, v]) => ({ nom: k, valeur: v, cle: k })),
    (e) => ({ basse: "var(--good)", moyenne: "var(--warning)",
              haute: "var(--serious)", critique: "var(--critical)" }[e.cle]));

  $("incidents").innerHTML = incidents.length
    ? incidents.map((i) => `<tr>
        <td><b>${esc(i.attack_code || "?")}</b> <span class="muet">${esc(i.category)}</span></td>
        <td><span class="fam"><span class="puce ${esc((i.attack_code || "?").charAt(0))}"></span>${
          esc(i.family_label || "—")}</span></td>
        <td><span class="etat ${esc(i.severity)}">${esc(i.severity)}</span></td>
        <td><span class="etat ${bandeDanger(i.dangerousness || 0)}">${i.dangerousness ?? "—"}/10</span></td>
        <td><span class="etat ${esc(i.priority || "")}">${esc(i.priority || "—")}</span></td>
        <td class="num">${i.risk_score}</td>
        <td><span class="etat ${i.status === "rolled_back" ? "moyenne" : "basse"}">${esc(i.status)}</span></td>
        <td class="num">${i.actions_executed}</td>
        <td class="num">${i.actions_rolled_back || "—"}</td>
      </tr>`).join("")
    : `<tr><td colspan="9" class="vide">Aucun incident — lancez une attaque depuis l'onglet Démonstration.</td></tr>`;
}

async function majJournal() {
  const audit = await api("/api/v1/audit?limit=60");
  $("audit").innerHTML = audit.entries.length
    ? audit.entries.map((e) => `<tr>
        <td class="mono num">${e.seq}</td>
        <td class="muet">${heure(e.recorded_at)}</td>
        <td class="mono">${esc(e.event_type)}</td>
        <td class="mono muet">${esc(e.actor)}</td>
        <td class="mono">${esc((e.incident_id || "—").slice(0, 22))}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="vide">Journal vide.</td></tr>`;
}

// ------------------------------------------------------------------ demarrage
chargerCatalogue().then(rafraichir);
setInterval(() => { if (vueCourante !== "demo") rafraichir(); }, 15000);

// ---------------------------------------------------------------- assistant
/* Rendu Markdown minimal : gras, listes, tableaux, titres. Suffisant pour ce
   que l'assistant produit, et sans dependance externe — la plateforme doit
   rester utilisable hors connexion. */
function markdown(src) {
  const lignes = String(src).split("\n");
  const sortie = [];
  let dansListe = false;
  let dansTable = false;

  const fermer = () => {
    if (dansListe) { sortie.push("</ul>"); dansListe = false; }
    if (dansTable) { sortie.push("</tbody></table>"); dansTable = false; }
  };
  const inline = (t) => esc(t)
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/`(.+?)`/g, '<code class="mono">$1</code>');

  for (const ligne of lignes) {
    const l = ligne.trimEnd();
    if (!l.trim()) { fermer(); continue; }

    if (/^\|[-\s|:]+\|$/.test(l.trim())) continue;          // separateur de tableau
    if (l.trim().startsWith("|")) {
      const cellules = l.trim().slice(1, -1).split("|").map((c) => c.trim());
      if (!dansTable) {
        fermer();
        sortie.push(`<table><thead><tr>${
          cellules.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>`);
        dansTable = true;
      } else {
        sortie.push(`<tr>${cellules.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`);
      }
      continue;
    }
    if (l.startsWith("- ")) {
      if (!dansListe) { fermer(); sortie.push("<ul>"); dansListe = true; }
      sortie.push(`<li>${inline(l.slice(2))}</li>`);
      continue;
    }
    fermer();
    if (l.startsWith("### ")) sortie.push(`<h4>${inline(l.slice(4))}</h4>`);
    else if (l.startsWith("## ")) sortie.push(`<h3>${inline(l.slice(3))}</h3>`);
    else if (l.startsWith("# ")) sortie.push(`<h3>${inline(l.slice(2))}</h3>`);
    else if (l.startsWith("> ")) sortie.push(`<blockquote>${inline(l.slice(2))}</blockquote>`);
    else if (l.trim() === "---") sortie.push("<hr>");
    else sortie.push(`<p>${inline(l)}</p>`);
  }
  fermer();
  return sortie.join("");
}

let assistantInitialise = false;

window.majAssistant = async function majAssistant() {
  if (assistantInitialise) return;
  assistantInitialise = true;

  const zone = $("assistant-zone");
  const { suggestions } = await api("/api/v1/assistant/suggestions");

  zone.innerHTML = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      ${suggestions.map((s) =>
        `<button data-q="${esc(s)}">${esc(s)}</button>`).join("")}
    </div>
    <div style="display:flex;gap:8px;margin-bottom:8px">
      <input id="question" placeholder="Posez une question sur les opérations…"
             style="flex:1;font:inherit;padding:8px 12px;border-radius:7px;
                    border:1px solid var(--ring);background:var(--plane);color:var(--ink-1)">
      <button class="primaire" id="envoyer">Demander</button>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <span class="muet" style="align-self:center">Rapport&nbsp;:</span>
      <a class="lien" href="/api/v1/assistant/report.md?hours=24"
         style="text-decoration:none">24 heures</a>
      <a class="lien" href="/api/v1/assistant/report.md?hours=168"
         style="text-decoration:none">7 jours</a>
      <a class="lien" href="/api/v1/assistant/report.md?hours=720"
         style="text-decoration:none">30 jours</a>
    </div>
    <div id="reponse"></div>`;

  const poser = async (question) => {
    const cible = $("reponse");
    cible.innerHTML = '<div class="muet">…</div>';
    try {
      const r = await api("/api/v1/assistant/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      cible.innerHTML = `
        <div class="carte" style="background:var(--plane)">
          <div class="muet" style="margin-bottom:8px">
            ${esc(question)}
          </div>
          <div>${markdown(r.text)}</div>
          ${r.sources.length ? `<div class="muet" style="margin-top:12px;
             padding-top:10px;border-top:1px solid var(--grid)">
             Sources : ${r.sources.map(esc).join(", ")} · rédaction :
             ${esc(r.provider)}</div>` : ""}
        </div>`;
    } catch (e) {
      cible.innerHTML = `<div class="carte" style="border-color:var(--critical)">${
        esc(e.message)}</div>`;
    }
  };

  zone.querySelectorAll("button[data-q]").forEach((b) =>
    b.addEventListener("click", () => poser(b.dataset.q)));
  $("envoyer").addEventListener("click", () => {
    const q = $("question").value.trim();
    if (q) poser(q);
  });
  $("question").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("envoyer").click();
  });

  // Le bilan du jour est affiche d'emblee : c'est l'usage principal.
  const brief = await api("/api/v1/assistant/brief");
  $("reponse").innerHTML = `<div class="carte" style="background:var(--plane)">${
    markdown(brief.text)}</div>`;
};
