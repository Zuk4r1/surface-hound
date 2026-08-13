// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

// panel-core.js: toda la lógica de renderizado compartida entre el panel de
// DevTools (panel/) y la vista de pantalla completa (fullview/). Cada una
// solo aporta su propia forma de obtener el dominio a inspeccionar.

const ext = typeof browser !== "undefined" ? browser : chrome;

window.addEventListener("error", (e) => {
  showPanelError(`Error de JavaScript: ${e.message}`, `${e.filename}:${e.lineno}`);
});
window.addEventListener("unhandledrejection", (e) => {
  showPanelError(`Promesa sin manejar: ${e.reason?.message || e.reason}`);
});

let currentDomain = null;
let currentData = null;
let nativePort = null;
let getDomainFn = null;
let currentMode = "passive"; // passive | assisted | active
let currentScope = null; // { programName, allow: [], deny: [] } | null (no configurado)
const expanded = { endpoints: new Set(), params: new Set(), jwt: new Set(), secrets: new Set(), idor: new Set(), treeIds: new Set(), treeNodes: new Set(), responseSample: new Set(), cors: new Set(), corsExtra: new Map() };

const STORAGE_PREFIX = "shx:";
const CONFIG_PREFIX = "shxcfg:";
function domainKey(domain) {
  return STORAGE_PREFIX + domain;
}

// ---- Scope Guard (mismas reglas que background.js) ------------------------

function scopeMatch(hostname, pattern) {
  if (!pattern) return false;
  pattern = pattern.trim().toLowerCase();
  hostname = hostname.toLowerCase();
  if (!pattern) return false;
  if (pattern.startsWith("*.")) {
    const bare = pattern.slice(2);
    return hostname === bare || hostname.endsWith("." + bare);
  }
  return hostname === pattern;
}

function isInScope(hostname, scope) {
  if (!scope || !Array.isArray(scope.allow) || scope.allow.length === 0) return null;
  const deny = (scope.deny || []).some((p) => scopeMatch(hostname, p));
  if (deny) return false;
  return scope.allow.some((p) => scopeMatch(hostname, p));
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

// Devuelve null si la acción puede proceder, o un string con el motivo si debe bloquearse.
function checkActiveActionAllowed(targetUrl) {
  const host = hostnameOf(targetUrl);
  if (!host) return "URL inválida.";
  const inScope = isInScope(host, currentScope);
  if (inScope === false) {
    return `⚠ OUT OF SCOPE\n\nRecurso fuera del scope configurado (${escapeHtml(host)}).\n\nAnálisis pasivo: permitido\nPruebas activas: bloqueadas`;
  }
  return null;
}

async function loadConfig() {
  const res = await ext.storage.local.get([CONFIG_PREFIX + "mode", CONFIG_PREFIX + "scope"]);
  currentMode = res[CONFIG_PREFIX + "mode"] || "passive";
  currentScope = res[CONFIG_PREFIX + "scope"] || null;
  renderModeSwitch();
}

async function saveMode(mode) {
  try {
    currentMode = mode;
    await ext.storage.local.set({ [CONFIG_PREFIX + "mode"]: mode });
    renderModeSwitch();
    applyModeGating();
    renderStatusLine();
  } catch (err) {
    showPanelError(`No se pudo guardar el modo: ${err.message}`, err.stack);
  }
}

function renderModeSwitch() {
  document.querySelectorAll(".mode-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.mode === currentMode);
  });
}

function applyModeGating() {
  renderModeSwitch();
  // El resto de los controles (botones dentro de filas) se generan en cada
  // render() ya con el estado de currentMode aplicado, así que alcanza con
  // volver a pintar lo que ya está en pantalla.
}

// ---- Línea de estado: modo / scope / agente (ping real al native host) ----

let agentStatus = "checking"; // checking | online | offline
let agentPingTimer = null;

// Antes: abría un connectNative() nuevo cada 15s y lo cerraba al terminar.
// connectNative() lanza un PROCESO NUEVO del agente por cada llamada -- en
// una sesión de varias horas eso significa matar y levantar el proceso
// Python cada 15 segundos indefinidamente, sin necesidad. Ahora reusa la
// misma conexión persistente que ya se usa para los jobs (ensureNativePort),
// y solo abre una si todavía no hay ninguna.
function checkAgentStatus() {
  const port = ensureNativePort();
  if (!port) {
    agentStatus = "offline";
    renderStatusLine();
    return;
  }
  if (agentPingTimer) clearTimeout(agentPingTimer);
  agentPingTimer = setTimeout(() => {
    if (agentStatus !== "online") {
      agentStatus = "offline";
      renderStatusLine();
    }
  }, 1500);
  try {
    port.postMessage({ action: "ping" });
  } catch {
    agentStatus = "offline";
    renderStatusLine();
  }
}

function renderStatusLine() {
  const el = document.getElementById("status-line");
  if (!el) return;
  const modeLabel = { passive: "PASIVO", assisted: "ASISTIDO", active: "ACTIVO" }[currentMode] || "PASIVO";
  const modeColor = { passive: "var(--low)", assisted: "var(--med)", active: "var(--crit)" }[currentMode];
  const scopeOn = currentScope && (currentScope.allow || []).length > 0;
  const agentColor = agentStatus === "online" ? "var(--low)" : agentStatus === "offline" ? "var(--crit)" : "var(--muted)";
  const agentLabel = agentStatus === "online" ? "ONLINE" : agentStatus === "offline" ? "OFFLINE" : "verificando…";

  el.innerHTML = `
    <span style="color:${modeColor}">● ${modeLabel}</span>
    <span class="hint">·</span>
    <span>SCOPE: <b style="color:${scopeOn ? "var(--low)" : "var(--muted)"}">${scopeOn ? "ON" : "OFF"}</b>${scopeOn ? ` (${escapeHtml(currentScope.programName || "sin nombre")})` : ""}</span>
    <span class="hint">·</span>
    <span>AGENT: <b style="color:${agentColor}">${agentLabel}</b></span>
    <span style="margin-left:auto;color:var(--accent);text-shadow:var(--glow)">🕵️‍♂️ Zuk4r1 (Yordan Suárez)</span>
  `;
}

document.querySelectorAll(".mode-btn").forEach((btn) => {
  btn.addEventListener("click", () => saveMode(btn.dataset.mode));
});

// ---- Scope: cargar/guardar el formulario -----------------------------------

async function loadScopeForm() {
  const res = await ext.storage.local.get(CONFIG_PREFIX + "scope");
  const scope = res[CONFIG_PREFIX + "scope"];
  if (!scope) return;
  document.getElementById("scope-program").value = scope.programName || "";
  document.getElementById("scope-allow").value = (scope.allow || []).join("\n");
  document.getElementById("scope-deny").value = (scope.deny || []).join("\n");
  document.getElementById("scope-status").textContent = `Scope activo: ${scope.programName || "(sin nombre)"} — ${(scope.allow || []).length} patrón(es) permitido(s).`;
}

document.getElementById("scope-save")?.addEventListener("click", async () => {
  const programName = document.getElementById("scope-program").value.trim();
  const allow = document.getElementById("scope-allow").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const deny = document.getElementById("scope-deny").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const scope = { programName, allow, deny };
  await ext.storage.local.set({ [CONFIG_PREFIX + "scope"]: scope });
  currentScope = scope;
  document.getElementById("scope-status").textContent = `Guardado. Scope activo: ${programName || "(sin nombre)"} — ${allow.length} patrón(es) permitido(s), ${deny.length} exclusión(es).`;
  render();
});

loadScopeForm();

async function loadData() {
  try {
    await loadConfig();
    const domain = await getDomainFn();
    if (!domain) {
      showPanelError("No se pudo detectar el dominio a inspeccionar.");
      return;
    }
    currentDomain = domain;
    document.getElementById("domain-title").textContent = `Superficie de ataque — ${currentDomain}`;
    const key = domainKey(currentDomain);
    const res = await ext.storage.local.get(key);
    currentData = res[key] || emptyData(currentDomain);
    clearPanelError();
    render();
    applyModeGating();
    renderStatusLine();
  } catch (err) {
    showPanelError(`Error cargando datos: ${err.message}`, err.stack);
  }
}

function showPanelError(msg, stack) {
  let el = document.getElementById("panel-error");
  if (!el) {
    el = document.createElement("div");
    el.id = "panel-error";
    el.style.cssText = "background:#3d1a1a;border:1px solid #ff4d4f;color:#ffb3b3;padding:8px 10px;border-radius:6px;margin-bottom:10px;font-size:12px;white-space:pre-wrap";
    document.querySelector("main").prepend(el);
  }
  el.textContent = "⚠ " + msg + (stack ? "\n\n" + stack : "");
}

function clearPanelError() {
  document.getElementById("panel-error")?.remove();
}

function emptyData(domain) {
  return { domain, endpoints: {}, params: {}, secrets: [], jwts: [], corsFindings: [], cspFindings: [], idorCandidates: [], notes: [], entityGraph: { nodes: {}, edges: {} }, dismissedFindings: {} };
}

function sevBadge(sev) {
  const s = (sev || "info").toLowerCase();
  return `<span class="badge ${s}">${s}</span>`;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function render() {
  try {
    renderMapa();
    renderEndpoints();
    renderParams();
    renderIdor();
    renderEntidades();
    renderJwt();
    renderSecrets();
    renderCors();
    renderNotes();
  } catch (err) {
    showPanelError(`Error dibujando el panel: ${err.message}`, err.stack);
  }
}

// ---- Mapa: árbol interactivo de endpoints por path -------------------------

function levelBadge(level) {
  const map = { HIGH: "critical", MED: "high", LOW: "medium" };
  return `<span class="badge ${map[level] || "info"}">${level}</span>`;
}

function buildEndpointTree() {
  const root = { name: "", children: new Map(), endpoints: [] };
  for (const ep of Object.values(currentData.endpoints || {})) {
    let path;
    try {
      path = new URL(ep.url).pathname;
    } catch {
      continue;
    }
    const segments = path.split("/").filter(Boolean);
    let node = root;
    for (const seg of segments) {
      if (!node.children.has(seg)) node.children.set(seg, { name: seg, children: new Map(), endpoints: [] });
      node = node.children.get(seg);
    }
    node.endpoints.push(ep);
  }
  return root;
}

function idorLevelForTemplate(templateGuess) {
  const c = (currentData.idorCandidates || []).find((c) => c.template.includes(templateGuess));
  return c ? c.level : null;
}

function collectDescendantMethods(node) {
  const methods = new Set();
  for (const e of node.endpoints) methods.add(e.method);
  for (const child of node.children.values()) {
    for (const m of collectDescendantMethods(child)) methods.add(m);
  }
  return methods;
}

function collectDescendantEndpoints(node, out = []) {
  for (const e of node.endpoints) out.push(e);
  for (const child of node.children.values()) {
    if (out.length >= 50) break; // tope de seguridad para no listar cientos de filas en un solo clic
    collectDescendantEndpoints(child, out);
  }
  return out;
}

function renderTreeNode(node, pathSoFar) {
  const entries = Array.from(node.children.entries());
  if (!entries.length && !node.endpoints.length) return "";

  let html = "<ul class='tree'>";
  for (const [seg, child] of entries) {
    const fullPath = pathSoFar + "/" + seg;
    const isIdLike = /^\d+$/.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}/i.test(seg);
    // Antes solo reemplazaba IDs numéricos acá, así que aunque background.js
    // ya detecta candidatos IDOR con UUID (ver ID_SEGMENT_RE), el árbol del
    // Mapa nunca iba a encontrar el nivel de confianza para un segmento UUID
    // -- la búsqueda de template nunca coincidía con "{id}".
    const level = isIdLike
      ? idorLevelForTemplate(fullPath.replace(/\/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=[/?#]|$)/gi, "/{id}"))
      : null;
    const paramsHere = child.endpoints.length ? getParamsInUrl(child.endpoints[0].url) : [];
    const outOfScope = child.endpoints.some((e) => e.inScope === false);
    const revealed = expanded.treeIds.has(fullPath);
    const nodeOpen = expanded.treeNodes.has(fullPath);
    const directMethods = [...new Set(child.endpoints.map((e) => e.method))];
    // Un nodo intermedio (ej. la carpeta {id} antes de /preview) nunca recibe
    // una solicitud directa propia -- solo la reciben sus hijos. Antes eso
    // significaba "sin badge de método", inconsistente visualmente con las
    // hojas que sí tienen uno. Ahora, si no hay solicitud directa, se agrega
    // (atenuado, con flecha) el método de las rutas anidadas debajo.
    const descendantMethods = directMethods.length ? [] : [...collectDescendantMethods(child)];

    html += `<li>
      <div class="tree-node" ${directMethods.length || descendantMethods.length ? `data-node-path="${escapeHtml(fullPath)}" style="cursor:pointer"` : ""}>
        <span class="tree-seg ${isIdLike ? "tree-id" : ""}" ${isIdLike ? `data-full-value="${escapeHtml(seg)}" data-tree-id-path="${escapeHtml(fullPath)}" title="Doble clic para ver y copiar el valor completo"` : ""}>${
          isIdLike
            ? revealed
              ? escapeHtml(seg)
              : `{id} <span class="tree-id-suffix">···${escapeHtml(seg.slice(-6))}</span>`
            : escapeHtml(seg)
        }</span>
        ${level ? levelBadge(level) : ""}
        ${outOfScope ? `<span class="badge critical">fuera de scope</span>` : ""}
        ${directMethods.length ? `<span class="badge info">${escapeHtml(directMethods.join(", "))}</span>` : ""}
        ${!directMethods.length && descendantMethods.length ? `<span class="badge info" style="opacity:0.55" title="Sin solicitud directa acá; método(s) visto(s) en rutas anidadas debajo">↓ ${escapeHtml(descendantMethods.join(", "))}</span>` : ""}
        ${paramsHere.length ? paramsHere.map((p) => `<span class="badge info" title="${escapeHtml(p.hits.map((h) => h.name).join(', '))}">${escapeHtml(p.param)}</span>`).join("") : ""}
      </div>
      ${(directMethods.length || descendantMethods.length) && nodeOpen ? `
        <div class="tree-node-detail">
          ${
            directMethods.length
              ? child.endpoints.map((e) => `<div class="mono">${escapeHtml(e.method)} ${escapeHtml(e.url)}</div>`).join("")
              : (() => {
                  const nested = collectDescendantEndpoints(child);
                  return nested.map((e) => `<div class="mono">${escapeHtml(e.method)} ${escapeHtml(e.url)}</div>`).join("")
                    + (nested.length >= 50 ? `<div class="hint" style="margin-top:4px">Mostrando las primeras 50 — hay más rutas anidadas debajo, expandí el árbol para verlas todas.</div>` : "");
                })()
          }
        </div>
      ` : ""}
      ${renderTreeNode(child, fullPath)}
    </li>`;
  }
  html += "</ul>";
  return html;
}

function renderMapa() {
  const el = document.getElementById("mapa-tree");
  if (!el) return;
  const hasData = Object.keys(currentData.endpoints || {}).length > 0;
  if (!hasData) {
    el.innerHTML = `<div class="empty">Sin endpoints capturados todavía. Navega el sitio.</div>`;
    return;
  }
  const tree = buildEndpointTree();
  el.innerHTML = `<div class="tree-root">${currentDomain}</div>` + renderTreeNode(tree, "");

  // Doble clic en un segmento {id}: revela el valor completo (en vez del
  // sufijo corto) y lo copia al portapapeles de paso.
  el.querySelectorAll(".tree-seg.tree-id").forEach((span) => {
    span.addEventListener("dblclick", async (ev) => {
      ev.stopPropagation();
      const path = span.dataset.treeIdPath;
      const fullValue = span.dataset.fullValue;
      expanded.treeIds.has(path) ? expanded.treeIds.delete(path) : expanded.treeIds.add(path);
      try {
        await navigator.clipboard.writeText(fullValue);
      } catch {
        // portapapeles puede fallar sin foco en la página; no rompe el resto
      }
      renderMapa();
    });
  });

  // Clic en la fila (fuera del segmento {id}): muestra el/los endpoint(s)
  // completos con método + URL exacta que hay en ese punto del árbol.
  el.querySelectorAll(".tree-node[data-node-path]").forEach((row) => {
    row.addEventListener("click", (ev) => {
      if (ev.target.closest(".tree-seg.tree-id")) return; // el doble clic de arriba ya maneja esto
      const path = row.dataset.nodePath;
      expanded.treeNodes.has(path) ? expanded.treeNodes.delete(path) : expanded.treeNodes.add(path);
      renderMapa();
    });
  });
}

// ---- Entidades: grafo de correlación --------------------------------------

function renderEntidades() {
  const el = document.getElementById("entidades-list");
  if (!el) return;
  const graph = currentData.entityGraph;
  if (!graph || !Object.keys(graph.nodes || {}).length) {
    el.innerHTML = `<div class="empty">Sin entidades correlacionadas todavía. Se detectan cuando dos IDs distintos (ej. user_id y organization_id) aparecen juntos en el mismo JSON de request/response.</div>`;
    return;
  }

  const nodes = Object.entries(graph.nodes).sort((a, b) => b[1].count - a[1].count);
  el.innerHTML = nodes
    .map(([nodeId, node]) => {
      const related = Object.entries(graph.edges[nodeId] || {})
        .sort((a, b) => b[1] - a[1])
        .map(([otherId, count]) => {
          const other = graph.nodes[otherId];
          return other ? `<span class="mono" style="margin-right:8px">${escapeHtml(other.key)}=${escapeHtml(other.value)} <span class="hint">(x${count})</span></span>` : "";
        })
        .join("");
      return `<div class="row">
        <span class="title mono">${escapeHtml(node.key)} = ${escapeHtml(node.value)}</span>
        <span class="hint"> · visto ${node.count}x</span>
        ${related ? `<div class="hint" style="margin-top:6px"><b>Correlacionado con:</b></div><div style="margin-top:2px">${related}</div>` : `<div class="hint" style="margin-top:4px">Sin otras entidades correlacionadas todavía.</div>`}
        ${node.urls?.length ? `<div class="hint" style="margin-top:6px">Visto en: ${node.urls.map((u) => `<div class="mono">${escapeHtml(u)}</div>`).join("")}</div>` : ""}
      </div>`;
    })
    .join("");
}

// ---- Endpoints: clic para expandir y ver params/CORS/CSP asociados + acciones ----

function renderEndpoints() {
  const el = document.getElementById("endpoints-list");
  const entries = Object.values(currentData.endpoints || {}).sort((a, b) => b.lastSeen - a.lastSeen);
  if (!entries.length) return (el.innerHTML = `<div class="empty">Sin endpoints capturados todavía. Navega el sitio.</div>`);

  el.innerHTML = entries
    .map((e) => {
      const isOpen = expanded.endpoints.has(e.url + e.method);
      const relatedParams = getParamsInUrl(e.url);
      const relatedCors = [...(currentData.corsFindings || []), ...(currentData.cspFindings || [])].filter((f) => f.url === e.url);
      const outOfScope = e.inScope === false;
      const sampleKey = e.url + e.method + "::sample";
      const sampleOpen = expanded.responseSample.has(sampleKey);

      return `<div class="row ${outOfScope ? "out-of-scope" : ""}">
        <div class="row-head" data-kind="endpoints" data-key="${escapeHtml(e.url + e.method)}" style="cursor:pointer;display:flex;justify-content:space-between">
          <span class="title mono">${e.method} ${escapeHtml(e.url)}</span>
          <span class="hint">${isOpen ? "▲" : "▼"}</span>
        </div>
        <div class="hint">visto ${e.hits}x · último: ${new Date(e.lastSeen).toLocaleTimeString()}${e.status ? ` · HTTP ${e.status}` : ""}${e.hasAuth ? ` · <span class="badge info">autenticado</span>` : ""}${outOfScope ? ` · <span class="badge critical">fuera de scope</span>` : ""}</div>
        ${isOpen ? `
          <div class="detail">
            <div class="detail-block">
              <b>Metadata</b>
              <div class="hint" style="margin-top:4px">
                ${e.contentType ? `Content-Type: <span class="mono">${escapeHtml(e.contentType)}</span><br>` : ""}
                ${e.responseSize != null ? `Tamaño de respuesta: ${e.responseSize} bytes<br>` : ""}
                ${e.sourcePage ? `Página origen: <span class="mono">${escapeHtml(e.sourcePage)}</span><br>` : ""}
                ${e.jsSource ? `Script origen: <span class="mono">${escapeHtml(e.jsSource)}</span><br>` : ""}
                Primera vez visto: ${new Date(e.firstSeen).toLocaleString()}
              </div>
              ${e.sampleResponseBody ? `
                <div class="response-sample-toggle hint" data-sample-key="${escapeHtml(sampleKey)}" style="cursor:pointer;margin-top:6px">${sampleOpen ? "▼" : "▶"} Ver muestra de la respuesta</div>
                ${sampleOpen ? `<pre class="mono" style="margin-top:4px;background:var(--bg);padding:6px;border-radius:4px;overflow-x:auto;max-height:240px;overflow-y:auto">${escapeHtml(e.sampleResponseBody)}</pre>` : ""}
              ` : ""}
            </div>
            ${relatedParams.length ? `
              <div class="detail-block">
                <b>Parámetros de interés en este endpoint</b>
                ${relatedParams.map((p) => `<div style="margin-top:4px">${sevBadge("info")} <span class="mono">${escapeHtml(p.param)}</span> → ${p.hits.map((h) => h.name).join(", ")}</div>`).join("")}
              </div>` : `<div class="hint">Sin parámetros clasificados en este endpoint.</div>`}
            ${relatedCors.length ? `
              <div class="detail-block">
                <b>CORS/CSP en este endpoint</b>
                ${relatedCors.map((f) => `<div style="margin-top:4px">${sevBadge(f.severity)} ${escapeHtml(f.msg)}</div>`).join("")}
              </div>` : ""}
            <div class="detail-actions">
              <button class="btn-cors-check" data-url="${escapeHtml(e.url)}" ${currentMode === "passive" ? "disabled title='Cambia a modo Asistido o Activo'" : ""}>Probar CORS ahora</button>
              <button class="btn-send-cli" data-url="${escapeHtml(e.url)}" ${currentMode !== "active" ? "disabled title='Requiere modo Activo'" : ""}>Analizar con CLI (avanzado)</button>
            </div>
            <div class="cors-live-result mono hint" data-url="${escapeHtml(e.url)}"></div>
          </div>
        ` : ""}
      </div>`;
    })
    .join("");

  el.querySelectorAll(".row-head[data-kind='endpoints']").forEach((head) => {
    head.addEventListener("click", () => {
      const key = head.dataset.key;
      expanded.endpoints.has(key) ? expanded.endpoints.delete(key) : expanded.endpoints.add(key);
      renderEndpoints();
    });
  });

  el.querySelectorAll(".response-sample-toggle").forEach((div) => {
    div.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const key = div.dataset.sampleKey;
      expanded.responseSample.has(key) ? expanded.responseSample.delete(key) : expanded.responseSample.add(key);
      renderEndpoints();
    });
  });

  el.querySelectorAll(".btn-cors-check").forEach((btn) => {
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      const url = btn.dataset.url;
      const resultEl = el.querySelector(`.cors-live-result[data-url="${cssEscape(url)}"]`);
      try {
        const blocked = checkActiveActionAllowed(url);
        if (blocked) {
          resultEl.innerHTML = `<div class="scope-warning">${escapeHtml(blocked)}</div>`;
          return;
        }
        resultEl.textContent = "Probando…";
        const result = await activeCorsCheck(url);
        resultEl.textContent = result;
      } catch (err) {
        // Cualquier error inesperado (no solo los de fetch) ahora se ve acá
        // en vez de dejar el botón colgado en "Probando…" para siempre.
        resultEl.textContent = `Error inesperado: ${err.message}`;
      }
    });
  });

  el.querySelectorAll(".btn-send-cli").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const url = btn.dataset.url;
      const blocked = checkActiveActionAllowed(url);
      const resultEl = el.querySelector(`.cors-live-result[data-url="${cssEscape(url)}"]`);
      if (blocked) {
        resultEl.innerHTML = `<div class="scope-warning">${escapeHtml(blocked)}</div>`;
        return;
      }
      document.getElementById("native-target").value = url;
      document.getElementById("cli-section").open = true;
      document.getElementById("cli-section").scrollIntoView({ behavior: "smooth" });
    });
  });
}

function cssEscape(str) {
  return str.replace(/["\\]/g, "\\$&");
}

function getParamsInUrl(url) {
  try {
    const keys = Array.from(new URL(url).searchParams.keys());
    return keys
      .filter((k) => currentData.params[k])
      .map((k) => ({ param: k, hits: currentData.params[k].hits || currentData.params[k] }));
  } catch {
    return [];
  }
}

// Chequeo CORS activo: dispara el request real desde el panel y lee los
// headers de la respuesta al instante, sin necesidad de abrir una terminal
// o Burp para verlos. Nota: al tener host_permissions, la extensión no está
// sujeta a la misma política CORS que un sitio web normal, así que esto
// muestra los headers reales que devuelve el servidor -- la interpretación
// (ACAO=* + credentials=true, o reflejo de origin específico) es la misma
// lógica que usarías analizando la respuesta en Burp/DevTools.
async function activeCorsCheck(url) {
  // Antes: sin timeout. Si el fetch se colgaba (red lenta, algún borde con
  // credentials cross-origin, etc.), el botón se quedaba en "Probando…"
  // para siempre sin ningún feedback -- eso es indistinguible de "no
  // funciona" para quien lo está usando. Ahora corta a los 10s con un
  // mensaje explícito, y se distingue el motivo del fallo en vez de un
  // "Fetch falló" genérico.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(url, { credentials: "include", signal: controller.signal });
    clearTimeout(timeout);
    const acao = res.headers.get("access-control-allow-origin");
    const acac = res.headers.get("access-control-allow-credentials");
    if (!acao) return `Sin header Access-Control-Allow-Origin en esta respuesta (HTTP ${res.status}).`;
    let verdict = `HTTP ${res.status} · ACAO: ${acao}`;
    if (acac) verdict += ` · Allow-Credentials: ${acac}`;
    if (acao === "*" && acac?.toLowerCase() === "true") verdict += " → configuración inconsistente con la spec CORS: revisa manualmente con Origin arbitrario en Burp/Repeater para confirmar si el servidor de verdad refleja cualquier origen.";
    else if (acao !== "*") verdict += " → el servidor está devolviendo un origen específico. Repite el request en Burp con un header Origin distinto (ej. https://evil-test.example) para confirmar si lo refleja sin validar.";
    return verdict;
  } catch (e) {
    clearTimeout(timeout);
    if (e.name === "AbortError") return "Sin respuesta tras 10s (timeout). El servidor puede estar bloqueando el request o tardando demasiado.";
    if (e instanceof TypeError) return `No se pudo completar el fetch: ${e.message}. Si estás en Firefox, confirmá que el permiso de host esté concedido para este sitio.`;
    return `Error inesperado: ${e.message}`;
  }
}

// ---- Parámetros: clic para expandir payloads sugeridos ----

function isReflectionConfirmed(param, sources) {
  const reflected = currentData.reflectedValues || {};
  for (const srcUrl of sources || []) {
    try {
      const value = new URL(srcUrl).searchParams.get(param);
      if (value && reflected[`${param}=${value}`]) return true;
    } catch {}
  }
  return false;
}

function renderParams() {
  const el = document.getElementById("params-list");
  const entries = Object.entries(currentData.params || {});
  if (!entries.length) return (el.innerHTML = `<div class="empty">Sin parámetros clasificados aún.</div>`);

  el.innerHTML = entries
    .map(([param, val]) => {
      const hits = val.hits || val; // compat con datos viejos sin sources
      const sources = val.sources || [];
      const isOpen = expanded.params.has(param);
      const confirmed = isReflectionConfirmed(param, sources);
      return `<div class="row">
        <div class="row-head" data-kind="params" data-key="${escapeHtml(param)}" style="cursor:pointer;display:flex;justify-content:space-between">
          <span class="title mono">${escapeHtml(param)}</span>
          <span class="hint">${isOpen ? "▲" : "▼"}</span>
        </div>
        <div class="hint">${hits.map((h) => h.name).join(" · ")}</div>
        ${isOpen ? `
          <div class="detail">
            ${hits.map((h) => `
              <div class="detail-block">
                <b>${escapeHtml(h.name)}</b> (${h.cwe})
                ${h.needsReflection ? `<div style="margin-top:2px">${confirmed ? tierBadge("CANDIDATE") + ` <span class="hint">— el valor se vio reflejado literal en una respuesta</span>` : tierBadge("OBSERVED") + ` <span class="hint">— solo por el nombre del parámetro, sin reflexión confirmada todavía</span>`}</div>` : ""}
                <div class="hint" style="margin-top:2px">${escapeHtml(h.hint)}</div>
                ${(h.payloads || []).length ? `
                  <div class="hint" style="margin-top:4px"><b>Payloads sugeridos:</b></div>
                  <ul class="payload-list">${h.payloads.map((p) => `<li class="mono">${escapeHtml(p)}</li>`).join("")}</ul>
                ` : ""}
              </div>
            `).join("")}
            ${sources.length ? `<div class="hint">Visto en: ${sources.map((s) => `<div class="mono">${escapeHtml(s)}</div>`).join("")}</div>` : ""}
          </div>
        ` : ""}
      </div>`;
    })
    .join("");

  el.querySelectorAll(".row-head[data-kind='params']").forEach((head) => {
    head.addEventListener("click", () => {
      const key = head.dataset.key;
      expanded.params.has(key) ? expanded.params.delete(key) : expanded.params.add(key);
      renderParams();
    });
  });
}

function buildTestSpec(c) {
  const method = "GET"; // ajustable a mano si el endpoint real usa otro método
  const paramName = c.kind === "query" ? c.param : "id (segmento de path)";
  const exampleId = c.observedIds[0];
  const otherId = c.observedIds.find((id) => id !== exampleId) || "<otro ID observado o consecutivo>";
  const endpointDisplay = c.template.replace("{id}", exampleId);
  return [
    `Endpoint:`,
    `${method} ${endpointDisplay}`,
    ``,
    `Parameter:`,
    paramName,
    ``,
    `Suggested test:`,
    `${exampleId} → ${otherId} (otro ID observado; si solo viste uno, prueba consecutivos)`,
    ``,
    `Required:`,
    `different authorization context (otra sesión/usuario/rol, o sin sesión)`,
    ``,
    `Signals that motivated this test:`,
    ...(c.signals || []).map((s) => `  - ${s}`),
  ].join("\n");
}

// Formato tipo "raw request" que se puede pegar directo en Burp Repeater
// (no hay integración real con la API de Burp, pero esto es lo que de verdad
// se necesita pegar ahí para arrancar a probar).
function buildBurpRequest(c) {
  const exampleId = c.observedIds[0];
  const url = c.template.replace("{id}", exampleId);
  let u;
  try {
    u = new URL(url);
  } catch {
    return `GET ${url} HTTP/1.1`;
  }
  return [`GET ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`, `Cookie: <tu sesión actual>`, ``, `# Cambia el ID (${exampleId}) por otro observado, o por ${u.pathname.includes("{id}") ? "un consecutivo" : "un valor ajeno"}, y compará la respuesta con otra sesión.`].join("\n");
}

function renderIdor() {
  const el = document.getElementById("idor-list");
  const entries = currentData.idorCandidates || [];
  if (!entries.length) return (el.innerHTML = `<div class="empty">Sin candidatos IDOR detectados aún.</div>`);
  el.innerHTML = entries
    .map((c, i) => {
      const isOpen = expanded.idor.has(c.template);
      const exampleUrl = c.template.replace("{id}", c.observedIds[0]);
      return `<div class="row">
      <div class="row-head" style="display:flex;justify-content:space-between;align-items:center">
        <span class="title mono">🔎 ${escapeHtml(exampleUrl)}</span>
        ${levelBadge(c.level)}
      </div>
      <div class="hint" style="margin-top:4px"><b>Confidence:</b> ${c.confidence}% · <b>CWE:</b> CWE-639</div>
      <div class="hint" style="margin-top:6px"><b>Signals</b></div>
      <div style="margin-top:2px">
        ${(c.signals || []).map((s) => `<div class="hint">✓ ${escapeHtml(s)}</div>`).join("")}
      </div>
      <div class="hint" style="margin-top:6px">IDs observados: ${escapeHtml(c.observedIds.slice(0, 15).join(", "))}${c.observedIds.length > 15 ? "…" : ""}</div>
      <div class="detail-actions" style="margin-top:8px">
        <button class="btn-prepare-test" data-idx="${i}">${isOpen ? "Ocultar validación sugerida" : "Ver validación sugerida"}</button>
      </div>
      ${isOpen ? `
        <div class="detail">
          <div class="hint" style="margin-bottom:4px"><b>Suggested validation</b></div>
          <ol class="hint" style="margin:0 0 8px 18px;padding:0">
            <li>Capturá el request (Burp/DevTools)</li>
            <li>Cambiá el ID del recurso por otro observado</li>
            <li>Compará el contexto de autorización (misma sesión vs. otra)</li>
          </ol>
          <pre class="mono" style="background:var(--bg);padding:8px;border-radius:4px;overflow-x:auto">${escapeHtml(buildTestSpec(c))}</pre>
          <div class="detail-actions">
            <button class="btn-copy-burp" data-idx="${i}">Enviar a Burp (copiar)</button>
            <button class="btn-create-finding" data-idx="${i}">Crear hallazgo</button>
            <button class="btn-send-test-cli" data-idx="${i}" ${currentMode !== "active" ? "disabled title='Requiere modo Activo'" : ""}>Enviar a CLI</button>
          </div>
          <div class="idor-test-result hint mono" data-idx="${i}" style="margin-top:6px"></div>
        </div>
      ` : ""}
    </div>`;
    })
    .join("");

  el.querySelectorAll(".btn-prepare-test").forEach((btn) => {
    btn.addEventListener("click", () => {
      const c = entries[Number(btn.dataset.idx)];
      expanded.idor.has(c.template) ? expanded.idor.delete(c.template) : expanded.idor.add(c.template);
      renderIdor();
    });
  });

  el.querySelectorAll(".btn-copy-burp").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const c = entries[Number(btn.dataset.idx)];
      try {
        await navigator.clipboard.writeText(buildBurpRequest(c));
        btn.textContent = "Copiado ✓ (pegalo en Repeater)";
        setTimeout(() => (btn.textContent = "Enviar a Burp (copiar)"), 2000);
      } catch {
        // clipboard puede fallar sin permiso de foco; no rompe el resto del panel
      }
    });
  });

  el.querySelectorAll(".btn-create-finding").forEach((btn) => {
    btn.addEventListener("click", () => {
      const c = entries[Number(btn.dataset.idx)];
      const severityMap = { HIGH: "High", MED: "Medium", LOW: "Low" };
      currentData.notes = currentData.notes || [];
      currentData.notes.unshift({
        title: `IDOR candidato: ${c.template}`,
        severity: severityMap[c.level] || "Medium",
        body: buildTestSpec(c) + `\n\nConfidence: ${c.confidence}% (no confirmado — pendiente de validación activa)`,
        createdAt: Date.now(),
      });
      saveCurrent();
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      document.querySelector(".tab-btn[data-tab='notes']").classList.add("active");
      document.getElementById("tab-notes").classList.add("active");
      render();
    });
  });

  el.querySelectorAll(".btn-send-test-cli").forEach((btn) => {
    btn.addEventListener("click", () => {
      const c = entries[Number(btn.dataset.idx)];
      const idx = btn.dataset.idx;
      const resultEl = el.querySelector(`.idor-test-result[data-idx="${idx}"]`);
      const exampleUrl = c.template.replace("{id}", c.observedIds[0]);
      const blocked = checkActiveActionAllowed(exampleUrl);
      if (blocked) {
        resultEl.innerHTML = `<div class="scope-warning">${escapeHtml(blocked)}</div>`;
        return;
      }
      document.getElementById("native-target").value = exampleUrl;
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      document.querySelector(".tab-btn[data-tab='endpoints']").classList.add("active");
      document.getElementById("tab-endpoints").classList.add("active");
      document.getElementById("cli-section").open = true;
      document.getElementById("cli-section").scrollIntoView({ behavior: "smooth" });
    });
  });
}

function tierBadge(tier) {
  const map = { OBSERVED: "info", SUSPICIOUS: "medium", CANDIDATE: "high", CONFIRMED: "critical" };
  return `<span class="badge ${map[tier] || "info"}">${tier}</span>`;
}

function renderJwt() {
  const el = document.getElementById("jwt-list");
  const entries = currentData.jwts || [];
  if (!entries.length) return (el.innerHTML = `<div class="empty">Sin JWTs vistos aún.</div>`);
  el.innerHTML = entries
    .map((j, i) => {
      const isOpen = expanded.jwt.has(j.token);
      const findings = j.findings || [];
      const observed = findings.filter((f) => f.tier === "OBSERVED");
      const nonObserved = findings.filter((f) => f.tier !== "OBSERVED");
      return `<div class="row">
        <div class="row-head" data-kind="jwt" data-key="${i}" style="cursor:pointer;display:flex;justify-content:space-between">
          <div class="mono" style="word-break:break-all">${escapeHtml(j.token.slice(0, 60))}...</div>
          <span class="hint">${isOpen ? "▲" : "▼"}</span>
        </div>
        <div class="hint">${observed.map((f) => escapeHtml(f.msg)).join(" · ")}</div>
        <div style="margin-top:4px">
          ${nonObserved.length
            ? nonObserved.map((f) => `<div style="margin-top:3px">${tierBadge(f.tier)} ${escapeHtml(f.msg)}</div>`).join("")
            : `<div class="hint">Sin patrones sospechosos observados en este token.</div>`}
        </div>
        <div class="hint" style="margin-top:6px;font-style:italic">
          ${j.confirmedVulnerability ? "" : "Ningún hallazgo aquí está confirmado como vulnerabilidad — todo lo de arriba requiere validación activa (ver pestaña IDOR/Endpoints para preparar el test)."}
        </div>
        ${isOpen ? `
          <div class="detail">
            <div class="detail-block"><b>Header</b><pre class="mono">${escapeHtml(JSON.stringify(j.header, null, 2))}</pre></div>
            <div class="detail-block"><b>Payload</b><pre class="mono">${escapeHtml(JSON.stringify(j.payload, null, 2))}</pre></div>
          </div>
        ` : ""}
      </div>`;
    })
    .join("");

  el.querySelectorAll(".row-head[data-kind='jwt']").forEach((head) => {
    head.addEventListener("click", () => {
      const i = Number(head.dataset.key);
      const token = entries[i].token;
      expanded.jwt.has(token) ? expanded.jwt.delete(token) : expanded.jwt.add(token);
      renderJwt();
    });
  });
}

function renderSecrets() {
  const el = document.getElementById("secrets-list");
  const entries = [...(currentData.secrets || [])].sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
  if (!entries.length) return (el.innerHTML = `<div class="empty">Sin secretos detectados aún.</div>`);
  el.innerHTML = entries
    .map((s) => {
      const exposure = s.source && /\.js(\?|$)/.test(s.source) ? "JavaScript público" : "Código de la página";
      return `<div class="row">
      <div class="row-head" style="display:flex;justify-content:space-between;align-items:center">
        <span class="title">${escapeHtml(s.name)}</span>
        ${s.byDesignPublic ? `<span class="badge low">público por diseño</span>` : sevBadge(s.severity)}
      </div>
      <div class="hint" style="margin-top:4px">
        <b>Confianza:</b> ${s.confidence != null ? s.confidence + "%" : "?"} ·
        <b>Exposición:</b> ${escapeHtml(exposure)}
      </div>
      <div class="mono hint" style="margin-top:4px">${escapeHtml(s.match)}</div>
      <div class="hint">Ubicación: ${escapeHtml(s.source)}</div>
      ${s.note ? `<div class="hint" style="margin-top:4px;font-style:italic">${escapeHtml(s.note)}</div>` : ""}
    </div>`;
    })
    .join("");
}

const SEVERITY_IMPACT = { critical: "ALTO", high: "ALTO", medium: "MODERADO", low: "BAJO", info: "BAJO" };

function corsFindingKey(f) {
  return `${f.type}:${f.directive}:${f.url}:${f.msg}`;
}

function buildCorsEvidenceText(f) {
  return [
    `CORS/CSP — ${f.directive}`,
    `Valor observado: ${f.observedValue}`,
    `Origen: ${f.url || ""}`,
    `Tipo: ${f.type}`,
    `Severidad: ${(f.severity || "").toUpperCase()}`,
    `Confianza: ${f.confidence || "?"}`,
    ``,
    `Header:`,
    f.rawHeader || "(sin header capturado)",
  ].join("\n");
}

function renderCors() {
  const el = document.getElementById("cors-list");
  const all = [...(currentData.corsFindings || []), ...(currentData.cspFindings || [])];
  if (!all.length) return (el.innerHTML = `<div class="empty">Sin hallazgos CORS/CSP aún.</div>`);
  const dismissed = currentData.dismissedFindings || {};

  el.innerHTML = all
    .map((f, i) => {
      const key = corsFindingKey(f);
      const isOpen = expanded.cors?.has(key);
      const isDismissed = !!dismissed[key];
      const matchingEndpoint = f.url ? currentData.endpoints?.[`GET ${f.url}`] || Object.values(currentData.endpoints || {}).find((e) => e.url === f.url) : null;

      return `<div class="row ${isDismissed ? "out-of-scope" : ""}" data-cors-key="${escapeHtml(key)}">
        <div class="row-head cors-row-head" data-cors-idx="${i}" style="cursor:pointer;display:flex;justify-content:space-between">
          <span>${sevBadge(f.severity)} <b>${escapeHtml(f.directive || f.type)}</b>: ${escapeHtml(String(f.observedValue ?? ""))} ${isDismissed ? `<span class="badge low">falso positivo</span>` : ""}</span>
          <span class="hint">${isOpen ? "▲" : "▼ doble clic"}</span>
        </div>
        <div class="hint mono">${escapeHtml(f.url || "")}</div>
        ${isOpen ? `
          <div class="detail cors-card">
            <div class="cors-card-section">
              <div class="cors-card-row"><span class="hint">Directiva:</span> <b>${escapeHtml(f.directive || f.type)}</b></div>
              <div class="cors-card-row"><span class="hint">Valor observado:</span> <span class="mono">${escapeHtml(String(f.observedValue ?? ""))}</span></div>
              <div class="cors-card-row"><span class="hint">Origen:</span> <span class="mono">${escapeHtml(f.url || "")}</span></div>
              <div class="cors-card-row"><span class="hint">Tipo:</span> ${escapeHtml(f.type || "")}</div>
              <div class="cors-card-row"><span class="hint">Severidad:</span> ${sevBadge(f.severity)}</div>
              <div class="cors-card-row"><span class="hint">Confianza:</span> ${escapeHtml(f.confidence || "?")}</div>
            </div>
            <div class="cors-card-divider"></div>
            <div class="cors-card-section">
              <div class="hint"><b>¿Por qué importa?</b></div>
              <div style="margin-top:4px">${escapeHtml(f.whyItMatters || "Sin contexto adicional registrado para este hallazgo.")}</div>
            </div>
            <div class="cors-card-divider"></div>
            <div class="cors-card-section">
              <div class="hint"><b>Evidencia</b></div>
              <div class="hint" style="margin-top:4px">Header:</div>
              <pre class="mono" style="background:var(--bg);padding:6px;border-radius:4px;overflow-x:auto;margin:2px 0">${escapeHtml(f.rawHeader || "(sin header capturado)")}</pre>
              <div class="hint">Origen de la observación: HTTP response header</div>
            </div>
            <div class="cors-card-divider"></div>
            <div class="cors-card-section">
              <div class="hint" style="margin-bottom:6px"><b>Validación sugerida</b></div>
              <div class="detail-actions">
                <button class="btn-cors-view-response ${expanded.corsExtra?.get(key) === "respuesta" ? "active-toggle" : ""}" data-cors-idx="${i}">Ver respuesta</button>
                <button class="btn-cors-view-headers ${expanded.corsExtra?.get(key) === "headers" ? "active-toggle" : ""}" data-cors-idx="${i}">Ver headers</button>
                <button class="btn-cors-copy" data-cors-idx="${i}">Copiar evidencia</button>
                <button class="btn-cors-dismiss" data-cors-idx="${i}">${isDismissed ? "Quitar marca de falso positivo" : "Marcar como falso positivo"}</button>
              </div>
              ${(() => {
                const mode = expanded.corsExtra?.get(key);
                if (!mode) return "";
                let text;
                if (mode === "headers") {
                  text = f.rawHeader || "Sin headers capturados para este hallazgo.";
                } else {
                  const matchingEndpoint = f.url ? Object.values(currentData.endpoints || {}).find((e) => e.url === f.url) : null;
                  text = matchingEndpoint?.sampleResponseBody || "Sin muestra de respuesta capturada todavía para este endpoint (revisa la pestaña Endpoints, o navega el sitio de nuevo para capturarla).";
                }
                return `<div class="cors-extra-result hint mono" style="margin-top:6px;white-space:pre-wrap">${escapeHtml(text)}</div>`;
              })()}
            </div>
            <div class="cors-card-divider"></div>
            <div class="cors-card-footer hint">
              Impacto potencial: <b>${SEVERITY_IMPACT[f.severity] || "BAJO"}</b> · Confianza: <b>${escapeHtml(f.confidence || "?")}</b> · Estado: <b>REQUIERE VALIDACIÓN</b>
              <div style="margin-top:4px;font-style:italic">"Se encuentra una configuración CORS/CSP que merece revisión."</div>
            </div>
          </div>
        ` : ""}
      </div>`;
    })
    .join("");

  expanded.cors = expanded.cors || new Set();
  el.querySelectorAll(".cors-row-head").forEach((head) => {
    head.addEventListener("dblclick", (ev) => {
      ev.stopPropagation();
      const f = all[Number(head.dataset.corsIdx)];
      const key = corsFindingKey(f);
      expanded.cors.has(key) ? expanded.cors.delete(key) : expanded.cors.add(key);
      renderCors();
    });
  });

  el.querySelectorAll(".btn-cors-copy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const f = all[Number(btn.dataset.corsIdx)];
      try {
        await navigator.clipboard.writeText(buildCorsEvidenceText(f));
        btn.textContent = "Copiado ✓";
        setTimeout(() => (btn.textContent = "Copiar evidencia"), 1500);
      } catch {}
    });
  });

  el.querySelectorAll(".btn-cors-view-headers").forEach((btn) => {
    btn.addEventListener("click", () => {
      const f = all[Number(btn.dataset.corsIdx)];
      const key = corsFindingKey(f);
      // Alternar: si ya estaba en "headers", un segundo clic lo cierra.
      expanded.corsExtra.get(key) === "headers" ? expanded.corsExtra.delete(key) : expanded.corsExtra.set(key, "headers");
      renderCors();
    });
  });

  el.querySelectorAll(".btn-cors-view-response").forEach((btn) => {
    btn.addEventListener("click", () => {
      const f = all[Number(btn.dataset.corsIdx)];
      const key = corsFindingKey(f);
      expanded.corsExtra.get(key) === "respuesta" ? expanded.corsExtra.delete(key) : expanded.corsExtra.set(key, "respuesta");
      renderCors();
    });
  });

  el.querySelectorAll(".btn-cors-dismiss").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const f = all[Number(btn.dataset.corsIdx)];
      const key = corsFindingKey(f);
      currentData.dismissedFindings = currentData.dismissedFindings || {};
      if (currentData.dismissedFindings[key]) delete currentData.dismissedFindings[key];
      else currentData.dismissedFindings[key] = true;
      await saveCurrent();
      renderCors();
    });
  });
}

function renderNotes() {
  const el = document.getElementById("notes-list");
  const notes = currentData.notes || [];
  if (!notes.length) return (el.innerHTML = `<div class="empty">Sin hallazgos guardados aún.</div>`);
  el.innerHTML = notes
    .map(
      (n) => `<div class="row">
      <span class="title">${escapeHtml(n.title)}</span> ${sevBadge(n.severity)}
      <div style="white-space:pre-wrap;margin-top:4px">${escapeHtml(n.body)}</div>
      <div class="hint">${new Date(n.createdAt).toLocaleString()}</div>
    </div>`
    )
    .join("");
}

async function saveCurrent() {
  await ext.storage.local.set({ [domainKey(currentDomain)]: currentData });
}

document.getElementById("refresh").addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Actualizando…";
  try {
    await loadData();
    btn.textContent = "Actualizado ✓";
  } catch (err) {
    showPanelError(`Error al refrescar: ${err.message}`, err.stack);
    btn.textContent = "Error al actualizar";
  } finally {
    setTimeout(() => {
      btn.textContent = originalText;
      btn.disabled = false;
    }, 1200);
  }
});

document.getElementById("clear").addEventListener("click", async () => {
  try {
    if (!currentDomain) return;
    if (!confirm(`¿Limpiar todos los datos capturados de ${currentDomain}?`)) return;
    currentData = emptyData(currentDomain);
    await saveCurrent();
    render();
  } catch (err) {
    showPanelError(`Error al limpiar: ${err.message} — si dice "QUOTA_BYTES", el storage está lleno; probá "Limpiar TODOS los dominios".`, err.stack);
  }
});

document.getElementById("clear-all")?.addEventListener("click", async () => {
  try {
    if (!confirm("¿Borrar TODOS los dominios capturados (no solo el actual)? Esto libera espacio de almacenamiento si estaba lleno.")) return;
    const all = await ext.storage.local.get(null);
    const domainKeys = Object.keys(all).filter((k) => k.startsWith(STORAGE_PREFIX) && !k.startsWith(CONFIG_PREFIX));
    if (domainKeys.length) await ext.storage.local.remove(domainKeys);
    currentData = emptyData(currentDomain);
    render();
    showPanelError(`Se borraron ${domainKeys.length} dominio(s). Si el problema era de espacio, ya debería estar resuelto.`);
  } catch (err) {
    showPanelError(`Error al limpiar todo: ${err.message}`, err.stack);
  }
});

document.getElementById("add-note").addEventListener("click", async () => {
  const title = document.getElementById("note-title").value.trim();
  const severity = document.getElementById("note-severity").value;
  const body = document.getElementById("note-body").value.trim();
  if (!title) return;
  currentData.notes = currentData.notes || [];
  currentData.notes.unshift({ title, severity, body, createdAt: Date.now() });
  await saveCurrent();
  document.getElementById("note-title").value = "";
  document.getElementById("note-body").value = "";
  render();
});

document.getElementById("export").addEventListener("click", async () => {
  const report = buildReport();
  const blob = new Blob([report], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  if (ext.downloads?.download) {
    await ext.downloads.download({ url, filename: `report-${currentDomain}.md` });
  } else {
    window.open(url);
  }
});

function buildReport() {
  const notes = currentData.notes || [];
  const footer = `\n---\n\n_Generado con Surface Hound — creado por Zuk4r1 (Yordan Suárez)._\n`;
  let md = `# Reporte de Bug Bounty — ${currentDomain}\n\n`;
  if (!notes.length) {
    md += "_Sin hallazgos guardados. Agrega notas en la pestaña Notas/Reporte._\n";
    return md + footer;
  }
  for (const n of notes) {
    md += `## ${n.title}\n\n**Severity:** ${n.severity}\n\n**Summary / Steps to reproduce / Impact:**\n\n${n.body}\n\n---\n\n`;
  }
  return md + footer;
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ---- Puente nativo con cola de jobs (sección avanzada, opcional) ----
// Una sola conexión Port persistente hacia el agente; puede haber varios
// jobs corriendo a la vez, cada uno identificado por su job_id. La UI
// mantiene un mapa jobId -> { tool, target, status, lines, el } y actualiza
// solo la tarjeta correspondiente cuando llega un mensaje.

// Espejo (solo para mostrar) de los comandos reales definidos en
// native-host/host.py -- NO se usa para ejecutar nada, la ejecución real
// y la validación del target siguen pasando siempre por el agente. Esto es
// para que el hunter vea el comando exacto que va a correr, en vez de solo
// "nombre_herramienta → url" que no dice nada sobre qué hace la herramienta.
const CLI_COMMAND_TEMPLATES = {
  nuclei: (t, h) => `nuclei -u ${t} -silent -timeout 8`,
  arjun: (t, h) => `arjun -u ${t} -oT /tmp/surfacehound_arjun_out.txt`,
  dalfox: (t, h) => `dalfox url ${t} --silence`,
  gau: (t, h) => `gau ${h}`,
  ffuf: (t, h) => `ffuf -u ${t}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s`,
  httpx: (t, h) => `httpx -u ${t} -silent -title -tech-detect -status-code`,
  katana: (t, h) => `katana -u ${t} -silent -depth 2`,
  dnsx: (t, h) => `dnsx -d ${h} -silent -a -resp`,
  subfinder: (t, h) => `subfinder -d ${h} -silent`,
};

function buildCliCommandDisplay(tool, target) {
  let host = target;
  try {
    host = new URL(target).hostname;
  } catch {}
  const builder = CLI_COMMAND_TEMPLATES[tool];
  return builder ? builder(target, host) : `${tool} ${target}`;
}

const NATIVE_APP_ID = "com.surfacehound.host";
const runBtn = document.getElementById("native-run");
const jobsListEl = document.getElementById("jobs-list");
const jobs = new Map(); // job_id -> { tool, target, status, lines: [], el }

function ensureNativePort() {
  if (nativePort) return nativePort;
  try {
    nativePort = ext.runtime.connectNative(NATIVE_APP_ID);
  } catch (e) {
    return null;
  }
  nativePort.onMessage.addListener(handleNativeMessage);
  nativePort.onDisconnect.addListener(() => {
    if (ext.runtime.lastError) {
      renderJobsError(`Desconectado del host nativo: ${ext.runtime.lastError.message}. ¿Está instalado? Ver native-host/README.md`);
    }
    agentStatus = "offline";
    renderStatusLine();
    nativePort = null;
  });
  return nativePort;
}

function renderJobsError(msg) {
  const div = document.createElement("div");
  div.className = "scope-warning";
  div.textContent = msg;
  jobsListEl.prepend(div);
}

function handleNativeMessage(msg) {
  // Respuesta al ping de estado del agente (ver checkAgentStatus más abajo)
  if (msg.pong) {
    agentStatus = "online";
    renderStatusLine();
    return;
  }

  // Ack inicial de submit_job (sin job aún registrado del lado nuestro con datos)
  if (msg.status === "queued" && msg.job_id && !jobs.has(msg.job_id)) {
    // el job ya fue insertado optimistamente en runBtn.click con un id temporal;
    // acá lo re-mapeamos al id real que asignó el agente
    const pending = jobs.get("__pending__");
    if (pending) {
      jobs.delete("__pending__");
      pending.job_id = msg.job_id;
      jobs.set(msg.job_id, pending);
    }
  }
  const job = jobs.get(msg.job_id);
  if (!job) return;

  if (msg.status) job.status = msg.status;
  if (msg.line !== undefined) job.lines.push(msg.line);
  if (msg.done) {
    job.status = msg.blocked ? "blocked" : msg.ok ? "done" : "error";
    if (msg.error) job.lines.push(`[error] ${msg.error}`);
    if (msg.returncode != null) job.lines.push(`[exit code ${msg.returncode}]`);
  }
  renderJobs();
}

function renderJobs() {
  const entries = Array.from(jobs.values()).filter((j) => j.job_id).reverse();
  if (!entries.length) {
    jobsListEl.innerHTML = "";
    return;
  }
  jobsListEl.innerHTML = entries
    .map(
      (j) => `<div class="job-row ${j.open ? "expanded" : ""}" data-job="${j.job_id}">
        <div class="job-head" style="cursor:pointer">
          <span class="mono">${escapeHtml(buildCliCommandDisplay(j.tool, j.target))}</span>
          <span class="job-status ${j.status}">${j.status}</span>
        </div>
        <div class="job-output">${escapeHtml(j.lines.join("\n")) || "(sin salida todavía)"}</div>
      </div>`
    )
    .join("");

  jobsListEl.querySelectorAll(".job-head").forEach((head) => {
    head.addEventListener("click", () => {
      const row = head.closest(".job-row");
      const j = jobs.get(row.dataset.job);
      j.open = !j.open;
      renderJobs();
      if (j.open) {
        const out = jobsListEl.querySelector(`.job-row[data-job="${cssEscape(j.job_id)}"] .job-output`);
        if (out) out.scrollTop = out.scrollHeight;
      }
    });
  });
}

function runCliJob(tool, target) {
  if (currentMode !== "active") {
    renderJobsError("El modo Activo debe estar seleccionado para ejecutar herramientas CLI (arriba, junto al nombre del dominio).");
    return;
  }
  const blocked = checkActiveActionAllowed(target);
  if (blocked) {
    renderJobsError(blocked);
    return;
  }

  const port = ensureNativePort();
  if (!port) {
    renderJobsError("No se pudo conectar con el host nativo. ¿Está instalado? Ver native-host/README.md");
    return;
  }

  // Job optimista con id temporal hasta que el agente confirme el real
  jobs.set("__pending__", { job_id: null, tool, target, status: "queued", lines: [], open: true });
  renderJobs();

  port.postMessage({ action: "submit_job", tool, target, scope: currentScope || undefined });
}

// ---- Modal de confirmación antes de ejecutar (recomienda terminal propia) ----
// Correr una herramienta a través del puente de la extensión tiene
// limitaciones reales frente a correrla directo en tu terminal: timeout
// fijo por herramienta, salida con tope de líneas, sin control interactivo
// ni posibilidad de encadenar/redirigir. Se avisa esto explícitamente antes
// de ejecutar, en vez de dejar que el usuario lo descubra con un resultado
// truncado o cortado.

function showCliConfirmModal(tool, target) {
  const command = buildCliCommandDisplay(tool, target);
  const overlay = document.getElementById("cli-confirm-overlay");
  document.getElementById("cli-confirm-command").textContent = command;
  overlay.style.display = "flex";

  const copyBtn = document.getElementById("cli-confirm-copy");
  const runAnywayBtn = document.getElementById("cli-confirm-run-anyway");
  const cancelBtn = document.getElementById("cli-confirm-cancel");

  const cleanup = () => {
    overlay.style.display = "none";
    copyBtn.onclick = null;
    runAnywayBtn.onclick = null;
    cancelBtn.onclick = null;
  };

  copyBtn.onclick = async () => {
    try {
      await navigator.clipboard.writeText(command);
      copyBtn.textContent = "Copiado ✓";
      setTimeout(() => (copyBtn.textContent = "Copiar comando"), 1500);
    } catch {}
  };

  runAnywayBtn.onclick = () => {
    cleanup();
    runCliJob(tool, target);
  };

  cancelBtn.onclick = cleanup;
}

runBtn.addEventListener("click", () => {
  const target = document.getElementById("native-target").value.trim();
  const tool = document.getElementById("native-action").value;
  if (!target) return;
  showCliConfirmModal(tool, target);
});

// ---- Punto de entrada: cada página host (panel/fullview) llama a esto ----

window.PanelCore = {
  init(domainProvider) {
    getDomainFn = domainProvider;
    loadData();
    setInterval(loadData, 3000); // refresco automático mientras navegas
    checkAgentStatus();
    setInterval(checkAgentStatus, 15000); // ping liviano al agente, no en cada tick de loadData
  },
};
