// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

const ext = typeof browser !== "undefined" ? browser : chrome;

const ICONS = {
  endpoints: `<svg width="14" height="14" viewBox="0 0 16 16"><path d="M6 10 L10 6 M7 4 L4 4 A3 3 0 0 0 4 10 L5 10 M9 12 L12 12 A3 3 0 0 0 12 6 L11 6" stroke="#00ffb0" stroke-width="1.4" fill="none" stroke-linecap="round"/></svg>`,
  params: `<svg width="14" height="14" viewBox="0 0 16 16"><circle cx="6" cy="8" r="3" fill="none" stroke="#00ffb0" stroke-width="1.4"/><path d="M9 8 H14 M11 8 V11" stroke="#00ffb0" stroke-width="1.4" stroke-linecap="round"/></svg>`,
  idor: `<svg width="14" height="14" viewBox="0 0 16 16"><path d="M8 2 L14 13 H2 Z" fill="none" stroke="#fb923c" stroke-width="1.4" stroke-linejoin="round"/><line x1="8" y1="6" x2="8" y2="9.5" stroke="#fb923c" stroke-width="1.4" stroke-linecap="round"/><circle cx="8" cy="11.2" r="0.8" fill="#fb923c"/></svg>`,
  jwt: `<svg width="14" height="14" viewBox="0 0 16 16"><rect x="3" y="7" width="10" height="6" rx="1.5" fill="none" stroke="#00ffb0" stroke-width="1.4"/><path d="M5.5 7 V5 a2.5 2.5 0 0 1 5 0 V7" fill="none" stroke="#00ffb0" stroke-width="1.4"/></svg>`,
  secrets: `<svg width="14" height="14" viewBox="0 0 16 16"><circle cx="5.5" cy="10.5" r="2.5" fill="none" stroke="#f43f5e" stroke-width="1.4"/><path d="M7.3 8.7 L13 3 M11 5 L12.5 6.5 M9.3 6.7 L10.6 8" stroke="#f43f5e" stroke-width="1.4" stroke-linecap="round"/></svg>`,
  cors: `<svg width="14" height="14" viewBox="0 0 16 16"><path d="M8 2 L13.5 4.5 V8 C13.5 11.5 11 13.3 8 14 C5 13.3 2.5 11.5 2.5 8 V4.5 Z" fill="none" stroke="#4ade80" stroke-width="1.3" stroke-linejoin="round"/></svg>`,
};

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function sevBadge(sev) {
  const s = (sev || "info").toLowerCase();
  if (s === "info") return "";
  return `<span class="badge-sev ${s}">${s}</span>`;
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

const CATEGORY_DEFS = [
  {
    key: "endpoints",
    label: "Endpoints",
    icon: ICONS.endpoints,
    items: (data) =>
      Object.values(data.endpoints || {})
        .sort((a, b) => b.lastSeen - a.lastSeen)
        .map((e) => `${e.method} ${shortUrl(e.url)}`),
  },
  {
    key: "params",
    label: "Parámetros de interés",
    icon: ICONS.params,
    items: (data) =>
      Object.entries(data.params || {}).map(([param, val]) => {
        const hits = val.hits || val;
        return `${param} — ${hits.map((h) => h.name).join(", ")}`;
      }),
  },
  {
    key: "idor",
    label: "Candidatos IDOR",
    icon: ICONS.idor,
    items: (data) => (data.idorCandidates || []).map((c) => `${c.template} (${c.observedIds.length} IDs)`),
  },
  {
    key: "jwt",
    label: "JWTs vistos",
    icon: ICONS.jwt,
    items: (data) =>
      (data.jwts || []).map((j) => {
        // j.flags ya no existe (se renombró a j.findings con niveles
        // OBSERVED/SUSPICIOUS/CANDIDATE al implementar el sistema de
        // confianza) -- este mapeo quedó apuntando al campo viejo y el
        // resumen de JWT en el popup se mostraba vacío en silencio desde
        // ese cambio, sin ningún error visible.
        const notable = (j.findings || []).find((f) => f.tier !== "OBSERVED");
        const tierLabel = j.maxTier && j.maxTier !== "OBSERVED" ? ` [${j.maxTier}]` : "";
        const flag = notable ? ` — ${notable.msg}` : "";
        return `alg:${j.header?.alg || "?"}${tierLabel}${flag}`;
      }),
  },
  {
    key: "secrets",
    label: "Secretos",
    icon: ICONS.secrets,
    items: (data) => (data.secrets || []).map((s) => ({ badge: sevBadge(s.severity), text: s.name })),
  },
  {
    key: "cors",
    label: "CORS/CSP",
    icon: ICONS.cors,
    items: (data) => [...(data.corsFindings || []), ...(data.cspFindings || [])].map((f) => ({ badge: sevBadge(f.severity), text: f.msg })),
  },
];

const MAX_VISIBLE = 6;

function renderGrid(domain, data) {
  const grid = document.getElementById("grid");
  grid.innerHTML = "";

  for (const cat of CATEGORY_DEFS) {
    const items = cat.items(data);
    const card = document.createElement("div");
    card.className = "card";
    const countClass = items.length ? "has-items" : "";

    const visible = items.slice(0, MAX_VISIBLE);
    const remaining = items.length - visible.length;

    // Cada item puede ser un string plano (se escapa entero) o un objeto
    // { badge, text } donde `badge` es HTML de confianza generado por
    // nosotros (sevBadge) y `text` es dato que puede venir del sitio target
    // (nombre de secreto, mensaje de hallazgo CORS -- que puede incluir el
    // valor crudo de un header controlado por el servidor). Antes había un
    // atajo "rawHtml" que insertaba el string combinado completo SIN escapar
    // nada, dejando pasar HTML/JS controlado por el objetivo directo al DOM
    // del popup -- confirmado explotable con un header Access-Control-
    // Allow-Origin malicioso. Ahora el texto SIEMPRE se escapa, sin
    // excepciones, y solo el badge (que nosotros generamos) se inserta tal cual.
    function renderItem(it) {
      if (it && typeof it === "object" && "text" in it) {
        return `<div class="item">${it.badge || ""}${escapeHtml(it.text)}</div>`;
      }
      return `<div class="item">${escapeHtml(it)}</div>`;
    }

    card.innerHTML = `
      <div class="card-head">
        <div class="card-title">${cat.icon}<span>${cat.label}</span></div>
        <span class="card-count ${countClass}">${items.length}</span>
      </div>
      <div class="card-list">
        ${
          items.length
            ? visible.map(renderItem).join("") +
              (remaining > 0 ? `<div class="more">+${remaining} más — ver análisis completo</div>` : "")
            : `<div class="item" style="border:none;color:var(--muted)">Nada capturado todavía.</div>`
        }
      </div>
    `;

    card.addEventListener("click", (ev) => {
      // si clickean "+N más", abrir la vista completa en vez de solo expandir
      if (ev.target.classList.contains("more")) {
        openFullView(domain);
        return;
      }
      card.classList.toggle("open");
    });

    grid.appendChild(card);
  }
}

function openFullView(domain) {
  const url = ext.runtime.getURL("fullview/fullview.html") + "?domain=" + encodeURIComponent(domain);
  ext.tabs.create({ url });
}

(async () => {
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  let domain;
  try {
    domain = new URL(tab.url).hostname;
  } catch {
    document.getElementById("grid").innerHTML = `<div class="empty-msg">Esta pestaña no es una página web normal.</div>`;
    return;
  }

  document.getElementById("domain-name").textContent = domain;
  const key = `shx:${domain}`;
  const res = await ext.storage.local.get(key);
  const data = res[key] || {};

  renderGrid(domain, data);

  document.getElementById("open-full").addEventListener("click", () => openFullView(domain));
})();
