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
let lastLoadedDomain = null;
let currentData = null;
let nativePort = null;
let getDomainFn = null;
let currentMode = "passive"; // passive | assisted | active
let currentScope = null; // { programName, allow: [], deny: [] } | null (no configurado)
const expanded = { endpoints: new Set(), params: new Set(), jwt: new Set(), secrets: new Set(), idor: new Set(), treeIds: new Set(), treeNodes: new Set(), responseSample: new Set(), cors: new Set(), corsExtra: new Map(), graphql: new Set(), sourcemaps: new Set(), tech: new Set() };

// Resultado de "Probar CORS ahora", en memoria (nunca se persiste a
// storage -- es una prueba puntual, no un hallazgo capturado). Sin esto,
// el refresco automático del panel (cada 3s, ver setInterval más abajo)
// reconstruye la fila desde currentData y el resultado desaparecía a los
// pocos segundos, aunque el usuario no hubiera hecho nada -- el elemento
// donde se mostraba siempre arrancaba vacío en cada render.
const corsLiveResults = new Map(); // url -> { html: boolean, text: string }

// El resultado normal/error se guarda como texto plano (nunca se confía
// en que ${acao} -- el header devuelto por el SERVIDOR OBJETIVO, no
// controlado por nosotros -- venga limpio); el caso "bloqueado" ya viene
// como HTML seguro (escapeHtml aplicado adentro al armarlo). Sin esta
// distinción, reinyectar un resultado guardado directo en la plantilla
// del render podría abrir una inyección HTML si el servidor devolviera
// algo malicioso en ese header.
function renderCorsLiveResult(url) {
  const r = corsLiveResults.get(url);
  if (!r) return "";
  return r.html ? r.text : escapeHtml(r.text);
}


// ---- Paginación ("mostrar más") para listas que pueden crecer a cientos de
// entradas en una sesión larga -- en vez de volcar todo a innerHTML de una
// (un nodo DOM por fila, sin importar cuántas haya), se renderiza solo un
// lote por vez y un botón trae más. No es virtualización real (eso
// necesitaría reciclar nodos al hacer scroll, más riesgo de romper algo
// para el beneficio marginal en los volúmenes reales que se vieron hasta
// ahora), pero evita el costo real: pintar cientos de filas con todo su
// detalle cuando el usuario ni las está mirando.
const PAGE_SIZE = 100;
const visibleCounts = {};
function getVisibleCount(listKey) {
  return visibleCounts[listKey] || PAGE_SIZE;
}
function loadMoreButtonHtml(listKey, shown, total) {
  if (shown >= total) return "";
  return `<button class="btn-load-more" data-list-key="${listKey}" style="margin-top:10px;width:100%;padding:8px">Mostrar más (${shown} de ${total})</button>`;
}
function wireLoadMoreButton(el, listKey, rerenderFn) {
  el.querySelector(`.btn-load-more[data-list-key="${listKey}"]`)?.addEventListener("click", () => {
    visibleCounts[listKey] = getVisibleCount(listKey) + PAGE_SIZE;
    rerenderFn();
  });
}

const STORAGE_PREFIX = "shx:";
const CONFIG_PREFIX = "shxcfg:";
function domainKey(domain) {
  return STORAGE_PREFIX + domain;
}

// entityGraph vive en su PROPIA clave de storage, separada del resto de los
// datos del dominio -- es la estructura más pesada con diferencia (llegó a
// medirse en varios MB en una sesión larga), y separarla evita que un
// cambio cualquiera sin relación (un hallazgo CORS nuevo, un endpoint más)
// tenga que reescribir ese blob grande de nuevo cada vez. El panel nunca
// ESCRIBE contenido nuevo acá (solo lo lee para mostrar la pestaña
// Entidades) -- background.js es el único dueño real de esta clave.
function entityGraphKey(domain) {
  return `${domainKey(domain)}::entities`;
}

// Lista centralizada de sufijos usados por claves de storage que son
// SUB-estructuras de un dominio (entityGraph, snapshot), no dominios en sí
// mismos. Antes esta exclusión estaba duplicada por separado en dos
// lugares (acá y en fullview.js) -- cuando se agregó snapshotKey, la
// exclusión correspondiente solo se sumó en uno de los dos, dejando al
// otro con el mismo bug que ya se había corregido para entityGraph
// (una clave interna apareciendo como si fuera un "dominio" real). Con
// una sola lista compartida y `listCapturedDomainsFrom()`, agregar un
// sufijo nuevo en el futuro alcanza con tocar este archivo.
const DOMAIN_SUBKEY_SUFFIXES = ["::entities", "::snapshot"];

function listCapturedDomainsFrom(all) {
  const domains = Object.keys(all)
    .filter((k) => k.startsWith(STORAGE_PREFIX) && !k.startsWith(CONFIG_PREFIX) && !DOMAIN_SUBKEY_SUFFIXES.some((suf) => k.endsWith(suf)))
    .map((k) => k.slice(STORAGE_PREFIX.length).replace(/^www\./i, ""));
  return [...new Set(domains)];
}

// Migración de una sola vez: hasta esta versión, "www.x.com" y "x.com"
// generaban claves de storage separadas -- si existe un bucket viejo bajo
// "www." + el dominio actual, se fusiona acá para no dejar hallazgos
// huérfanos ahí. No busca ser un merge perfecto entre datos en conflicto
// (si la MISMA tecnología aparece en ambos, se mantiene la del bucket
// actual); el objetivo es recuperar lo que falta, no reconciliar duplicados
// con precisión milimétrica -- esto corre una vez y el bucket viejo se
// borra después.
// Antes, mergeLegacyDomainData() solo se llamaba con datos que venían del
// PROPIO storage del navegador (la migración de fusión "www.") -- entrada
// confiable, aunque el patrón de asignación por corchetes fuera el mismo
// que ya se sabía riesgoso (ver isSafeObjectKey en background.js). Ahora
// "Importar sesión" alimenta esta MISMA función con el contenido de un
// archivo elegido por el usuario -- una fuente que puede ser hostil de
// verdad (un archivo de sesión manipulado a propósito). El check
// `!(k in target[field])` ya existente "protegía" __proto__/constructor
// por accidente (el operador `in` recorre la cadena de prototipos, así
// que esas claves siempre aparecen como "ya presentes" en cualquier
// objeto común) -- no por diseño. Esa protección desaparecería en
// silencio si alguien cambiara `in` por `hasOwnProperty` en el futuro (un
// refactor razonable que muchos linters sugerirían). Se hace explícita.
const DANGEROUS_MERGE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function isSafeMergeKey(key) {
  return typeof key === "string" && !DANGEROUS_MERGE_KEYS.has(key);
}

// typeof [] === "object" en JS -- un array pasa cualquier chequeo que solo
// verifique "typeof x === 'object'", disfrazado de objeto-mapa real. Sin
// este guard, importar un archivo donde (por accidente o a propósito)
// "endpoints"/"techFingerprint"/etc. sea un array en vez de `{}` mezclaba
// los ÍNDICES numéricos del array como si fueran claves de endpoint
// reales, dejando la UI con basura visible ("undefined undefined",
// "Invalid Date") sin ningún aviso de que el archivo estaba mal formado.
function isPlainObject(x) {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function mergeLegacyDomainData(target, legacy) {
  const objectMapFields = ["endpoints", "params", "techFingerprint", "graphqlOperations", "sourceMaps", "oauthFlows", "dismissedFindings", "entitySeenInResponse", "reflectedValues"];
  for (const field of objectMapFields) {
    if (!isPlainObject(legacy[field])) continue; // ver isPlainObject -- un array (u otro no-objeto) en este campo se descarta en vez de mezclarse por índice
    target[field] = target[field] || {};
    for (const [k, v] of Object.entries(legacy[field])) {
      if (!isSafeMergeKey(k)) continue;
      if (!(k in target[field])) target[field][k] = v;
    }
  }

  if (isPlainObject(legacy.entityGraph)) {
    target.entityGraph = target.entityGraph || { nodes: {}, edges: {} };
    for (const [k, v] of Object.entries(isPlainObject(legacy.entityGraph.nodes) ? legacy.entityGraph.nodes : {})) {
      if (!isSafeMergeKey(k)) continue;
      if (!(k in target.entityGraph.nodes)) target.entityGraph.nodes[k] = v;
    }
    for (const [k, v] of Object.entries(isPlainObject(legacy.entityGraph.edges) ? legacy.entityGraph.edges : {})) {
      if (!isSafeMergeKey(k)) continue;
      target.entityGraph.edges[k] = { ...(v || {}), ...(target.entityGraph.edges[k] || {}) };
    }
  }

  const dedupArrayFields = {
    secrets: (x) => x.match,
    jwts: (x) => x.token,
    corsFindings: (x) => x.msg,
    cspFindings: (x) => x.msg,
    securityHeaderFindings: (x) => x.msg,
    oauthFindings: (x) => x.msg,
    idorCandidates: (x) => x.template,
    notes: (x) => x.title + x.createdAt,
    graphqlIntrospection: (x) => x.url,
    // suppressionRules faltaba acá -- se perdía sin aviso al importar una
    // sesión que trajera reglas de supresión ya aprendidas. Se dedupea por
    // type+directive (no por createdAt, que sería casi siempre distinto
    // entre origen y destino) -- si la MISMA regla ya existe, no hace
    // falta una segunda copia.
    suppressionRules: (x) => `${x.type}::${x.directive}`,
  };
  for (const [field, keyFn] of Object.entries(dedupArrayFields)) {
    if (!legacy[field]?.length) continue;
    target[field] = target[field] || [];
    const seen = new Set(target[field].map(keyFn));
    for (const item of legacy[field]) {
      const k = keyFn(item);
      if (!seen.has(k)) {
        target[field].push(item);
        seen.add(k);
      }
    }
  }
}

// ---- Scope Guard (mismas reglas que background.js) ------------------------

function scopeMatch(hostname, pattern) {
  if (!pattern) return false;
  pattern = pattern.trim().toLowerCase();
  hostname = hostname.toLowerCase();
  if (!pattern) return false;
  // Misma lógica que la copia en background.js (que es la que hace el
  // enforcement real) -- ver el comentario ahí para el detalle completo.
  // Duplicada acá porque el panel corre en otro contexto y no puede
  // importar funciones de background.js directamente.
  const bare = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
  return hostname === bare || hostname.endsWith("." + bare);
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
  // Antes: solo se bloqueaba si inScope === false (fuera de scope
  // explícitamente). Cuando no había NINGÚN scope configurado, isInScope()
  // devuelve null -- y null !== false, así que nada se bloqueaba: fail-open.
  // Con el puente a un agente nativo capaz de ejecutar comandos reales
  // contra un target, "sin scope configurado" NO debería equivaler a "todo
  // permitido" -- es exactamente el escenario donde un olvido humano (subir
  // a modo Activo sin haber configurado el Scope todavía) termina generando
  // tráfico activo o ejecutando herramientas contra un objetivo por
  // accidente. Ahora solo se permite cuando inScope es explícitamente true;
  // cualquier otro estado (false o null) bloquea, fail-closed.
  if (inScope !== true) {
    if (inScope === false) {
      return `⚠ FUERA DE SCOPE\n\nRecurso fuera del scope configurado (${escapeHtml(host)}).\n\nAnálisis pasivo: permitido\nPruebas activas: bloqueadas`;
    }
    return `⚠ SIN SCOPE CONFIGURADO\n\nPor seguridad, las acciones activas están bloqueadas hasta que definas un scope en la pestaña "Scope" (allow con al menos un patrón). Sin esto, no hay forma de distinguir un objetivo autorizado de uno que no lo es.\n\nAnálisis pasivo: permitido\nPruebas activas: bloqueadas`;
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
    <span style="color:var(--accent);text-shadow:var(--glow)">🕵️‍♂️ Zuk4r1</span>
  `;

  // El scope es GLOBAL -- una sola configuración para toda la extensión,
  // no una por dominio -- y persiste a propósito entre reinicios del
  // navegador (chrome.storage.local existe justamente para eso, para no
  // perder la configuración de un engagement de varios días). Si el
  // dominio que se está mirando ahora no matchea NINGÚN patrón del scope
  // activo, es fácil pensar que hay un bug ("¿por qué todo aparece fuera
  // de scope?") cuando en realidad es el scope de un programa DISTINTO
  // que quedó activo de una sesión anterior. Se avisa explícitamente acá
  // para que no pase desapercibido.
  const warningEl = document.getElementById("scope-domain-mismatch-warning");
  if (warningEl) {
    const domainCovered = !scopeOn || !currentDomain || isInScope(currentDomain, currentScope) !== false;
    if (scopeOn && currentDomain && !domainCovered) {
      warningEl.style.display = "block";
      warningEl.textContent = `⚠ El scope activo ("${currentScope.programName || "sin nombre"}") no cubre a ${currentDomain} -- ¿es de otro programa? Revisá la pestaña Scope antes de dar nada por "fuera de scope" acá.`;
    } else {
      warningEl.style.display = "none";
    }
  }
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
  // Deduplicado (case-insensitive, ya que scopeMatch tampoco distingue
  // mayúsculas/minúsculas): antes, pegar el mismo dominio dos veces por
  // accidente hacía que el mensaje de estado dijera "3 patrón(es)
  // permitido(s)" cuando en realidad solo había 1 patrón único distinto
  // -- no afectaba el funcionamiento real (un patrón repetido no rompe
  // nada), pero el conteo mostrado era engañoso.
  const dedupPatterns = (lines) => {
    const seen = new Set();
    const out = [];
    for (const p of lines) {
      const key = p.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(p);
    }
    return out;
  };
  const allow = dedupPatterns(document.getElementById("scope-allow").value.split("\n").map((s) => s.trim()).filter(Boolean));
  const deny = dedupPatterns(document.getElementById("scope-deny").value.split("\n").map((s) => s.trim()).filter(Boolean));
  const scope = { programName, allow, deny };
  await ext.storage.local.set({ [CONFIG_PREFIX + "scope"]: scope });
  currentScope = scope;

  // inScope se guarda en cada endpoint en el momento en que se
  // captura -- si el usuario corrige el scope DESPUÉS de haber navegado el
  // sitio, todo lo que el navegador ya tenga en su propia caché (assets
  // estáticos que no vuelven a pasar por la red) se queda con el valor
  // viejo para siempre, sin importar cuántas veces se guarde el scope de
  // nuevo. Se recalcula acá mismo para todo lo ya capturado en el dominio
  // actual, usando el hostname real de cada URL (no el bucket
  // normalizado del dominio, que le saca el "www." y podía hacer que un
  // patrón escrito CON www nunca matcheara).
  let recalculated = 0;
  for (const ep of Object.values(currentData.endpoints || {})) {
    const host = hostnameOf(ep.url);
    if (!host) continue;
    const newInScope = isInScope(host, scope);
    if (ep.inScope !== newInScope) recalculated++;
    ep.inScope = newInScope;
  }
  await saveCurrent();

  document.getElementById("scope-status").textContent = `Guardado. Scope activo: ${programName || "(sin nombre)"} — ${allow.length} patrón(es) permitido(s), ${deny.length} exclusión(es).${recalculated ? ` Se actualizó el estado de scope de ${recalculated} endpoint(s) ya capturado(s).` : ""}`;
  render();
});

// ---- Vista agregada multi-dominio: muchos programas de bug bounty cubren
// varios subdominios, no solo el que se está mirando ahora -- esto agrega
// hallazgos de TODOS los dominios ya capturados que coincidan con el
// scope configurado, no solo el dominio activo. Bajo demanda (un botón,
// no automático) porque implica leer varios dominios de storage de una,
// algo que no vale la pena hacer en cada render normal.
document.getElementById("btn-program-summary")?.addEventListener("click", async () => {
  const el = document.getElementById("program-summary");
  if (!currentScope || !(currentScope.allow || []).length) {
    el.innerHTML = `<div class="empty" style="margin-top:8px">Configurá al menos un patrón "Permitido" arriba antes de ver el resumen del programa.</div>`;
    return;
  }
  el.innerHTML = `<div class="hint" style="margin-top:8px">Cargando…</div>`;

  const all = await ext.storage.local.get(null);
  const domains = listCapturedDomainsFrom(all).filter((d) => isInScope(d, currentScope) === true);

  if (!domains.length) {
    el.innerHTML = `<div class="empty" style="margin-top:8px">Ningún dominio capturado coincide con el scope configurado todavía.</div>`;
    return;
  }

  const summaries = domains
    .map((d) => {
      const data = all[domainKey(d)] || {};
      return {
        domain: d,
        endpoints: Object.keys(data.endpoints || {}).length,
        secrets: (data.secrets || []).filter((s) => !s.byDesignPublic).length,
        idorHigh: (data.idorCandidates || []).filter((c) => c.level === "HIGH").length,
        notes: (data.notes || []).length,
      };
    })
    .sort((a, b) => b.secrets + b.idorHigh - (a.secrets + a.idorHigh));

  const totals = summaries.reduce(
    (acc, s) => ({ endpoints: acc.endpoints + s.endpoints, secrets: acc.secrets + s.secrets, idorHigh: acc.idorHigh + s.idorHigh }),
    { endpoints: 0, secrets: 0, idorHigh: 0 }
  );

  el.innerHTML = `
    <div class="hint" style="margin-top:10px"><b>${domains.length} dominio(s) en scope</b> · ${totals.endpoints} endpoints · ${totals.secrets} secretos (no públicos por diseño) · ${totals.idorHigh} candidatos IDOR de alta confianza</div>
    ${summaries
      .map(
        (s) => `<div class="row" style="margin-top:6px">
          <b class="mono">${escapeHtml(s.domain)}</b>
          <div class="hint" style="margin-top:2px">${s.endpoints} endpoints · ${s.secrets} secretos · ${s.idorHigh} IDOR alta confianza · ${s.notes} notas</div>
        </div>`
      )
      .join("")}
  `;
});

loadScopeForm();

// ---- Historial acotado: snapshot manual + comparación contra el último
// guardado. A propósito NO es un historial completo con muchas versiones
// (eso reintroduciría el mismo problema de crecimiento sin control que ya
// se corrigió para entityGraph) -- un solo snapshot por dominio, que se
// pisa cada vez que se guarda uno nuevo. Vive en su propia clave separada
// (mismo patrón que entityGraphKey), así no infla el blob principal.
function snapshotKey(domain) {
  return `${domainKey(domain)}::snapshot`;
}

function buildSnapshotSummary(data) {
  const corsAll = [...(data.corsFindings || []), ...(data.cspFindings || []), ...(data.securityHeaderFindings || []), ...(data.oauthFindings || [])];
  return {
    takenAt: Date.now(),
    endpointKeys: Object.keys(data.endpoints || {}),
    secretMatches: (data.secrets || []).map((s) => s.match),
    idorTemplates: (data.idorCandidates || []).filter((c) => c.level === "HIGH").map((c) => c.template),
    techNames: Object.keys(data.techFingerprint || {}),
    corsFindingKeys: corsAll.map(corsFindingKey),
    sourceMapUrls: Object.keys(data.sourceMaps || {}),
  };
}

function diffAgainstSnapshot(current, snapshot) {
  return {
    newEndpoints: current.endpointKeys.filter((k) => !snapshot.endpointKeys.includes(k)),
    newSecrets: current.secretMatches.filter((m) => !snapshot.secretMatches.includes(m)),
    newIdor: current.idorTemplates.filter((t) => !snapshot.idorTemplates.includes(t)),
    newTech: current.techNames.filter((t) => !snapshot.techNames.includes(t)),
    newCorsFindings: current.corsFindingKeys.filter((k) => !snapshot.corsFindingKeys.includes(k)),
    newSourceMaps: current.sourceMapUrls.filter((u) => !snapshot.sourceMapUrls.includes(u)),
  };
}

document.getElementById("btn-save-snapshot")?.addEventListener("click", async () => {
  const summary = buildSnapshotSummary(currentData);
  await ext.storage.local.set({ [snapshotKey(currentDomain)]: summary });
  const el = document.getElementById("snapshot-diff");
  el.innerHTML = `<div class="hint" style="margin-top:8px">Snapshot guardado: ${new Date(summary.takenAt).toLocaleString()} (${summary.endpointKeys.length} endpoints, ${summary.secretMatches.length} secretos, ${summary.idorTemplates.length} IDOR alta confianza).</div>`;
});

document.getElementById("btn-diff-snapshot")?.addEventListener("click", async () => {
  const el = document.getElementById("snapshot-diff");
  const key = snapshotKey(currentDomain);
  const res = await ext.storage.local.get(key);
  const snapshot = res[key];
  if (!snapshot) {
    el.innerHTML = `<div class="empty" style="margin-top:8px">Sin snapshot guardado todavía para este dominio. Guardá uno primero.</div>`;
    return;
  }
  const current = buildSnapshotSummary(currentData);
  const diff = diffAgainstSnapshot(current, snapshot);
  const totalNew = diff.newEndpoints.length + diff.newSecrets.length + diff.newIdor.length + diff.newTech.length + diff.newCorsFindings.length + diff.newSourceMaps.length;

  const section = (title, items) =>
    items.length ? `<div class="detail-block" style="margin-top:6px"><b>${escapeHtml(title)} (${items.length})</b>${items.slice(0, 20).map((i) => `<div class="hint mono" style="margin-top:2px">${escapeHtml(i)}</div>`).join("")}</div>` : "";

  el.innerHTML = `
    <div class="hint" style="margin-top:8px">Comparando contra el snapshot del ${new Date(snapshot.takenAt).toLocaleString()} -- ${totalNew} cosa(s) nueva(s) desde entonces.</div>
    ${totalNew === 0 ? `<div class="empty" style="margin-top:6px">Sin cambios desde el último snapshot.</div>` : ""}
    ${section("Endpoints nuevos", diff.newEndpoints)}
    ${section("Secretos nuevos", diff.newSecrets)}
    ${section("Candidatos IDOR de alta confianza nuevos", diff.newIdor)}
    ${section("Tecnología nueva detectada", diff.newTech)}
    ${section("Hallazgos CORS/CSP/Security Header/OAuth nuevos", diff.newCorsFindings)}
    ${section("Source maps nuevos", diff.newSourceMaps)}
  `;
});

async function loadData() {
  try {
    await loadConfig();
    const domain = await getDomainFn();
    if (!domain) {
      showPanelError("No se pudo detectar el dominio a inspeccionar.");
      return;
    }
    // Se normaliza acá, en el único punto por el que pasan las tres fuentes
    // de dominio (panel de DevTools, popup, fullview) -- así "www.x.com" y
    // "x.com" siempre terminan operando sobre la misma clave de storage
    // que ahora usa background.js, sin tener que sincronizar la misma
    // normalización en cada uno de los tres archivos por separado.
    currentDomain = domain.replace(/^www\./i, "");
    if (currentDomain !== lastLoadedDomain) {
      // El estado "expandido" (qué tarjetas dejaste abiertas) vive en
      // variables de módulo que persisten mientras el panel sigue abierto
      // -- si no se resetean al cambiar de dominio, una tarjeta con la
      // misma clave en otro dominio (ej. "React" detectado en dos sitios
      // distintos, algo muy común) aparece expandida sin que el usuario
      // la haya tocado ahí. Cada Set/Map se vacía en vez de reasignar el
      // objeto completo, para no romper ninguna referencia que otro
      // código pueda tener guardada hacia estos mismos Sets.
      for (const v of Object.values(expanded)) v.clear();
      for (const k of Object.keys(visibleCounts)) delete visibleCounts[k];
      corsLiveResults.clear();
      lastLoadedDomain = currentDomain;
    }
    document.getElementById("domain-title").textContent = `Superficie de ataque — ${currentDomain}`;
    const key = domainKey(currentDomain);
    const egKey = entityGraphKey(currentDomain);
    const res = await ext.storage.local.get([key, egKey]);
    currentData = res[key] || emptyData(currentDomain);
    currentData.entityGraph = res[egKey] || { nodes: {}, edges: {} };

    // Migración de una sola vez: recuperar hallazgos que quedaron en un
    // bucket "www." separado antes de este fix (ver mergeLegacyDomainData).
    // Se fusiona también el entityGraph legado, que vive en su propia clave.
    const legacyKey = domainKey("www." + currentDomain);
    const legacyEgKey = entityGraphKey("www." + currentDomain);
    if (legacyKey !== key) {
      const legacyRes = await ext.storage.local.get([legacyKey, legacyEgKey]);
      if (legacyRes[legacyKey] || legacyRes[legacyEgKey]) {
        const legacyData = legacyRes[legacyKey] || {};
        if (legacyRes[legacyEgKey]) legacyData.entityGraph = legacyRes[legacyEgKey];
        mergeLegacyDomainData(currentData, legacyData);
        await ext.storage.local.remove([legacyKey, legacyEgKey]);
        const { entityGraph, ...restData } = currentData;
        await ext.storage.local.set({ [key]: restData, [egKey]: entityGraph });
      }
    }

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
  return { domain, endpoints: {}, params: {}, secrets: [], jwts: [], corsFindings: [], cspFindings: [], securityHeaderFindings: [], oauthFlows: {}, oauthFindings: [], idorCandidates: [], notes: [], entityGraph: { nodes: {}, edges: {} }, entitySeenInResponse: {}, reflectedValues: {}, dismissedFindings: {}, graphqlOperations: {}, graphqlIntrospection: [], techFingerprint: {}, sourceMaps: {} };
}

// ---- Severidad multi-plataforma: traducción de nuestra escala interna
// (Critical/High/Medium/Low/Informational) a las etiquetas reales que usa
// cada plataforma -- útil al armar el reporte final, porque "High" no
// significa lo mismo en todos lados (Bugcrowd usa su propia taxonomía de
// prioridad P1-P5, no CVSS directo).
const SEVERITY_PLATFORM_MAP = {
  Critical: { hackerone: "Critical", bugcrowd: "P1 — Critical", intigriti: "Critical", cvss: "9.0–10.0" },
  High: { hackerone: "High", bugcrowd: "P2 — High", intigriti: "High", cvss: "7.0–8.9" },
  Medium: { hackerone: "Medium", bugcrowd: "P3 — Medium", intigriti: "Medium", cvss: "4.0–6.9" },
  Low: { hackerone: "Low", bugcrowd: "P4 — Low", intigriti: "Low", cvss: "0.1–3.9" },
  Informational: { hackerone: "None", bugcrowd: "P5 — Informational", intigriti: "None", cvss: "0.0" },
};

function severityPlatformLine(severity) {
  const m = SEVERITY_PLATFORM_MAP[severity];
  if (!m) return null;
  return `HackerOne: ${m.hackerone} · Bugcrowd: ${m.bugcrowd} · Intigriti: ${m.intigriti} · CVSS aprox.: ${m.cvss}`;
}

// ---- Checklist explícito de "qué falta demostrar" por tipo de hallazgo,
// en vez de un texto genérico repetido en todos lados. Cada tipo tiene sus
// propios pasos reales de validación -- lo que hace falta confirmar para
// un IDOR no es lo mismo que para un BFLA de GraphQL o un CORS crítico.
const VALIDATION_CHECKLISTS = {
  idor: [
    "Probado con sesión de otro usuario (no admin, no la propia)",
    "Confirmado acceso a datos que no pertenecen al usuario que hizo el request",
    "Descartado que sea un recurso público intencional (perfil público, contenido compartido a propósito)",
    "Confirmado que el ID no es simplemente uno ya visto antes con la sesión propia",
  ],
  bfla: [
    "Probado con sesión de un usuario con rol/tenant de menor privilegio",
    "Probado sin ningún token de autenticación",
    "Confirmado que la operación realmente se ejecutó (no solo devolvió 200 con un error interno)",
  ],
  cors_critical: [
    "Confirmado con un header Origin arbitrario real (no solo observado pasivamente)",
    "Confirmado que el navegador de verdad acepta la respuesta (no la bloquea pese al header)",
    "Identificado un endpoint autenticado con datos sensibles alcanzable con esta configuración",
  ],
  oauth_state: [
    "Armado el flujo CSRF completo (link de inicio de sesión iniciado por el atacante)",
    "Confirmado que el proveedor no valida el origen de otra forma (ej. cookie de sesión previa)",
    "Confirmado el impacto real (vinculación de cuenta, fijación de sesión, etc.)",
  ],
  oauth_pkce: [
    "Confirmado que el cliente es público (SPA/app móvil, sin client_secret seguro)",
    "Probado interceptar/reutilizar el authorization code desde otro contexto",
    "Confirmado que el intercambio del code no exige ningún otro factor además del code mismo",
  ],
  sourcemap_secret: [
    "Confirmado que el secreto sigue activo (no rotado/revocado)",
    "Confirmado el alcance real de la clave (permisos concretos, no solo que existe)",
    "Descartado que sea una clave de entorno de pruebas o pública por diseño",
  ],
  rate_limit: [
    "Probado activamente el umbral real (no solo tráfico normal que nunca lo alcanzó)",
    "Confirmado que no hay throttling a nivel de IP/cuenta que no se vio en la sesión normal",
    "Evaluado el impacto real según el tipo de endpoint (OTP de pocos dígitos es mucho más grave que contraseña)",
  ],
  csp_generic: [
    "Identificado un punto de inyección real (reflejo de input del usuario en el HTML)",
    "Confirmado que la directiva relajada (unsafe-inline/unsafe-eval) es explotable desde ese punto de inyección",
    "Probado un payload concreto, no solo la configuración en abstracto",
  ],
};

function buildValidationChecklist(kind) {
  const items = VALIDATION_CHECKLISTS[kind];
  if (!items) return "";
  return items.map((i) => `☐ ${i}`).join("\n");
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
    renderPriorityScore();
    renderMapa();
    renderEndpoints();
    renderParams();
    renderIdor();
    renderEntidades();
    renderJwt();
    renderSourceMaps();
    renderSecrets();
    renderRateLimitFindings();
    renderCors();
    renderGraphQL();
    renderTech();
    renderChains();
    renderNotes();
  } catch (err) {
    showPanelError(`Error dibujando el panel: ${err.message}`, err.stack);
  }
}

// Score de prioridad del dominio actual -- pensado para cuando hay varios
// targets del mismo programa y hace falta decidir por dónde empezar sin
// releer las 13 pestañas de cada uno. No reemplaza el juicio del hunter,
// es una señal rápida junto al título. Pesos: severo=10, IDOR alto=8,
// secreto=8 (se cuentan aparte de "severo" abajo aunque haya overlap
// conceptual, porque un secreto amerita el mismo peso que un CORS crítico
// sin depender de que también haya un endpoint con auth para calificar),
// cadena sugerida=15 (una correlación confirmada vale más que la suma de
// sus partes sueltas, por eso pesa más que cualquier hallazgo individual).
// Score de prioridad del dominio actual -- pensado para cuando hay varios
// targets del mismo programa y hace falta decidir por dónde empezar sin
// releer las 13 pestañas de cada uno. No reemplaza el juicio del hunter,
// es una señal rápida junto al título. Pesos: severo=10, IDOR alto=8,
// secreto=8, cadena sugerida=5 (deliberadamente bajo, NO 15 como en un
// diseño anterior -- una cadena se arma a PARTIR de hallazgos que ya se
// cuentan por separado arriba, así que pesarla igual o más que un
// hallazgo individual sobre-representaba el mismo secreto/IDOR dos veces;
// acá funciona como un bonus modesto por tener una correlación
// confirmada, no como una categoría más a sumar de igual peso).
//
// Los hallazgos marcados como falso positivo (dismissedFindings) se
// excluyen del conteo -- de lo contrario, un dominio donde ya se
// descartaron todos los CORS/CSP mostraría el mismo score que si esos
// hallazgos siguieran vigentes.
function computeDomainPriorityScore(data) {
  const dismissed = data.dismissedFindings || {};
  const isActiveSevere = (f) => (f.severity === "critical" || f.severity === "high") && !dismissed[corsFindingKey(f)];
  let score = 0;
  score += (data.corsFindings || []).filter(isActiveSevere).length * 10;
  score += (data.cspFindings || []).filter(isActiveSevere).length * 10;
  score += (data.securityHeaderFindings || []).filter(isActiveSevere).length * 10;
  score += (data.oauthFindings || []).filter(isActiveSevere).length * 10;
  score += (data.idorCandidates || []).filter((c) => c.level === "HIGH").length * 8;
  score += (data.secrets || []).length * 8;
  score += computeSuggestedChains(data).length * 5;
  return score;
}

function renderPriorityScore() {
  const el = document.getElementById("domain-priority-score");
  if (!el) return;
  const score = computeDomainPriorityScore(currentData);
  if (score === 0) {
    el.textContent = "";
    el.title = "";
    return;
  }
  const level = score >= 30 ? "critical" : score >= 15 ? "high" : "medium";
  el.innerHTML = `<span class="badge ${level}" title="Score de prioridad: combina hallazgos severos, IDOR de confianza alta, secretos y cadenas sugeridas -- para comparar targets del mismo programa a simple vista, no un veredicto final.">Prioridad: ${score}</span>`;
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

  const allNodes = Object.entries(graph.nodes).sort((a, b) => b[1].count - a[1].count);
  // Sin esto, un dominio con el volumen que ya permite MAX_ENTITY_NODES
  // (3000) congelaba la pestaña varios segundos al abrirla -- Endpoints y
  // Parámetros ya paginan con este mismo patrón, Entidades había quedado
  // afuera al construirla.
  const nodes = allNodes.slice(0, getVisibleCount("entidades"));
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
    .join("") + loadMoreButtonHtml("entidades", nodes.length, allNodes.length);
  wireLoadMoreButton(el, "entidades", renderEntidades);
}

// ---- Endpoints: clic para expandir y ver params/CORS/CSP asociados + acciones ----

// ---- Ausencia de rate limiting en endpoints sensibles (inferido pasivamente:
// mismo endpoint pegado varias veces, nunca un 429) -- se muestra en la
// pestaña CORS/CSP (no en Endpoints): Endpoints es el listado neutral de
// tráfico capturado, sin ningún hallazgo con severidad; los hallazgos con
// badge de severidad (CORS, CSP, headers, OAuth, y este) viven todos
// juntos en CORS/CSP.

const SENSITIVE_AUTH_PATH_RE = /\/(login|signin|sign-in|log-in|auth|authenticate|otp|verify(-otp)?|verification|2fa|mfa|reset-password|resetpassword|forgot-password|forgotpassword|password-reset|change-password)(\/|\?|$)/i;
const RATE_LIMIT_HIT_THRESHOLD = 5;

function getRateLimitCandidates(data) {
  return Object.values(data.endpoints || {}).filter((e) => {
    if (e.hits < RATE_LIMIT_HIT_THRESHOLD || e.saw429) return false;
    let path = "";
    try { path = new URL(e.url).pathname; } catch { return false; }
    return SENSITIVE_AUTH_PATH_RE.test(path);
  });
}

function renderRateLimitFindings() {
  const el = document.getElementById("ratelimit-list");
  if (!el) return;
  const candidates = getRateLimitCandidates(currentData);
  if (!candidates.length) return (el.innerHTML = "");

  el.innerHTML = `<div class="detail-block">
    <b>Posible ausencia de rate limiting (${candidates.length})</b>
    <div class="hint" style="margin-bottom:6px">Endpoints sensibles (login/OTP/reset) vistos ${RATE_LIMIT_HIT_THRESHOLD}+ veces sin haber recibido nunca un HTTP 429. No confirma la ausencia -- solo que no se observó throttling en el tráfico normal capturado hasta ahora.</div>
    ${candidates
      .map(
        (e) => `<div class="row">
          ${sevBadge("medium")} <span class="mono">${escapeHtml(e.method)} ${escapeHtml(e.url)}</span>
          <div class="hint" style="margin-top:2px">visto ${e.hits}x, sin 429 en ninguna</div>
        </div>`
      )
      .join("")}
  </div>`;
}

function renderEndpoints() {
  const el = document.getElementById("endpoints-list");
  const allEntries = Object.values(currentData.endpoints || {}).sort((a, b) => b.lastSeen - a.lastSeen);
  if (!allEntries.length) return (el.innerHTML = `<div class="empty">Sin endpoints capturados todavía. Navega el sitio.</div>`);
  const entries = allEntries.slice(0, getVisibleCount("endpoints"));
  // Un endpoint expandido (fila abierta, posiblemente con un resultado de
  // "Probar CORS ahora" en curso) puede quedar fuera de este corte si
  // suficiente tráfico NUEVO llega mientras el hunter lo tiene abierto --
  // con tráfico activo real (ej. UUIDs por request, muy común) esto pasa
  // en minutos, no horas. Sin este ajuste, la fila desaparece del DOM por
  // completo en el siguiente refresco automático (cada 3s), llevándose el
  // resultado que se estaba mostrando -- se ve como si "se cerrara sola".
  // Se agregan al final, sin duplicar, los expandidos que el corte dejó
  // afuera; se mantienen visibles hasta que el hunter mismo los cierre.
  const visibleKeys = new Set(entries.map((e) => e.url + e.method));
  for (const e of allEntries) {
    if (visibleKeys.has(e.url + e.method)) continue;
    if (expanded.endpoints.has(e.url + e.method)) {
      entries.push(e);
      visibleKeys.add(e.url + e.method);
    }
  }

  el.innerHTML = entries
    .map((e) => {
      const isOpen = expanded.endpoints.has(e.url + e.method);
      const relatedParams = getParamsInUrl(e.url);
      const relatedCors = [...(currentData.corsFindings || []), ...(currentData.cspFindings || []), ...(currentData.securityHeaderFindings || []), ...(currentData.oauthFindings || [])].filter((f) => f.url === e.url);
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
            <div class="cors-live-result mono hint" data-url="${escapeHtml(e.url)}">${renderCorsLiveResult(e.url)}</div>
          </div>
        ` : ""}
      </div>`;
    })
    .join("") + loadMoreButtonHtml("endpoints", entries.length, allEntries.length);

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
          corsLiveResults.set(url, { html: true, text: `<div class="scope-warning">${escapeHtml(blocked)}</div>` });
          renderEndpoints();
          return;
        }
        if (resultEl) resultEl.textContent = "Probando…"; // transitorio, indicador momentáneo -- no es la fuente de verdad, así que no importa si este nodo puntual queda desactualizado
        const result = await activeCorsCheck(url);
        corsLiveResults.set(url, { html: false, text: result });
        // Re-renderizar desde corsLiveResults (la fuente de verdad), en vez
        // de actualizar directo el nodo `resultEl` capturado por closure --
        // si el panel se refrescó automáticamente (cada 3s) MIENTRAS este
        // fetch estaba en vuelo, ese nodo específico queda desconectado del
        // documento (el refresco reconstruye el HTML desde cero). Escribirle
        // directo seguía guardando el dato bien, pero no se veía en pantalla
        // hasta el siguiente ciclo de refresco -- hasta 3s de demora
        // silenciosa. Re-renderizar acá lo refleja al instante, sin
        // depender de que esa referencia siga siendo válida.
        renderEndpoints();
      } catch (err) {
        // Cualquier error inesperado (no solo los de fetch) ahora se ve acá
        // en vez de dejar el botón colgado en "Probando…" para siempre.
        const msg = `Error inesperado: ${err.message}`;
        corsLiveResults.set(url, { html: false, text: msg });
        renderEndpoints();
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
  wireLoadMoreButton(el, "endpoints", renderEndpoints);
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
  const allEntries = Object.entries(currentData.params || {});
  if (!allEntries.length) return (el.innerHTML = `<div class="empty">Sin parámetros clasificados aún.</div>`);
  const entries = allEntries.slice(0, getVisibleCount("params"));

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
    .join("") + loadMoreButtonHtml("params", entries.length, allEntries.length);

  el.querySelectorAll(".row-head[data-kind='params']").forEach((head) => {
    head.addEventListener("click", () => {
      const key = head.dataset.key;
      expanded.params.has(key) ? expanded.params.delete(key) : expanded.params.add(key);
      renderParams();
    });
  });
  wireLoadMoreButton(el, "params", renderParams);
}

function buildTestSpec(c) {
  const method = "GET"; // ajustable a mano si el endpoint real usa otro método
  const paramName = c.kind === "query" ? c.param : "id (segmento de path)";
  const exampleId = c.observedIds[0];
  const otherId = c.observedIds.find((id) => id !== exampleId) || "<otro ID observado o consecutivo>";
  const endpointDisplay = c.template.replaceAll("{id}", exampleId);
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
    ``,
    `Qué falta demostrar:`,
    buildValidationChecklist("idor"),
  ].join("\n");
}

// Formato tipo "raw request" que se puede pegar directo en Burp Repeater
// (no hay integración real con la API de Burp, pero esto es lo que de verdad
// se necesita pegar ahí para arrancar a probar).
function buildBurpRequest(c) {
  const exampleId = c.observedIds[0];
  // Se chequea la plantilla ORIGINAL (antes de reemplazar) para saber si
  // tiene más de un segmento {id} -- antes se chequeaba el resultado ya
  // reemplazado con un simple .replace(), que solo sustituía el PRIMERO,
  // así que esta misma condición coincidía por accidente con el bug en
  // vez de reflejar la plantilla real.
  const hasMultipleIds = (c.template.match(/\{id\}/g) || []).length > 1;
  const url = c.template.replaceAll("{id}", exampleId);
  let u;
  try {
    u = new URL(url);
  } catch {
    return `GET ${url} HTTP/1.1`;
  }
  return [`GET ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`, `Cookie: <tu sesión actual>`, ``, `# Cambia el ID (${exampleId}) por otro observado, o por ${hasMultipleIds ? "un consecutivo" : "un valor ajeno"}, y compará la respuesta con otra sesión.`].join("\n");
}

function renderIdor() {
  const el = document.getElementById("idor-list");
  const entries = currentData.idorCandidates || [];
  if (!entries.length) return (el.innerHTML = `<div class="empty">Sin candidatos IDOR detectados aún.</div>`);
  el.innerHTML = entries
    .map((c, i) => {
      const isOpen = expanded.idor.has(c.template);
      const exampleUrl = c.template.replaceAll("{id}", c.observedIds[0]);
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
      const idx = btn.dataset.idx;
      const c = entries[Number(idx)];
      try {
        await navigator.clipboard.writeText(buildBurpRequest(c));
        // Re-consultar el botón por su data-idx en vez de reusar la
        // referencia capturada por closure -- si el panel se refrescó
        // mientras el clipboard.writeText estaba en vuelo (ventana
        // minúscula pero real), ese nodo puede haber quedado desconectado
        // del documento; la copia se hace igual, pero el "Copiado ✓" no
        // se vería. Mismo patrón que el fix de "Probar CORS ahora".
        const liveBtn = el.querySelector(`.btn-copy-burp[data-idx="${idx}"]`);
        if (liveBtn) {
          liveBtn.textContent = "Copiado ✓ (pegalo en Repeater)";
          setTimeout(() => (liveBtn.textContent = "Enviar a Burp (copiar)"), 2000);
        }
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
      const exampleUrl = c.template.replaceAll("{id}", c.observedIds[0]);
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

// ---- Source maps: detección pasiva (siempre) + verificación activa (un clic,
// gateada por modo y Scope Guard, igual que "Probar CORS ahora") ----------

// Subconjunto compacto y de ALTA confianza -- no busca replicar la lista
// completa de patrones de content.js (que corre en otro contexto/mundo
// aislado). El objetivo acá es específico: si el código fuente original
// completo queda expuesto vía sourcesContent, ¿aparece alguna de las
// señales de mayor valor entre las que ya usamos en el resto de la
// extensión?
const SOURCEMAP_SECRET_PATTERNS = [
  { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g },
  { name: "Private Key block", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: "Stripe Secret Key", re: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: "GitHub Token", re: /gh[pousr]_[A-Za-z0-9]{36,}/g },
];

function scanSourceMapContentForSecrets(text) {
  const found = [];
  for (const p of SOURCEMAP_SECRET_PATTERNS) {
    const matches = text.match(p.re);
    if (matches?.length) found.push({ name: p.name, count: new Set(matches).size });
  }
  return found;
}

async function verifySourceMap(mapUrl) {
  const blocked = checkActiveActionAllowed(mapUrl);
  if (blocked) return { error: blocked };
  try {
    const res = await fetch(mapUrl, { credentials: "include" });
    if (!res.ok) return { accessible: false };
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      return { accessible: false }; // 200 pero no es un mapa válido -- no cuenta como expuesto de verdad
    }
    if (!json || !Array.isArray(json.sources)) return { accessible: false };

    const hasSourcesContent = Array.isArray(json.sourcesContent) && json.sourcesContent.some((c) => typeof c === "string" && c.length > 0);
    let endpointsFound = [];
    let secretsFound = [];
    if (hasSourcesContent) {
      // Tope de 300.000 caracteres para el escaneo -- un mapa de un bundle
      // grande puede traer megabytes de sourcesContent; no hace falta leerlo
      // entero para encontrar endpoints/secretos, y evita bloquear el panel.
      const combined = json.sourcesContent.filter((c) => typeof c === "string").join("\n").slice(0, 300000);
      endpointsFound = [...new Set(combined.match(/https?:\/\/[a-zA-Z0-9.\-]+(?:\/[^\s"'`)]*)?/g) || [])].slice(0, 30);
      secretsFound = scanSourceMapContentForSecrets(combined);
    }
    return {
      accessible: true,
      sourcesCount: json.sources.length,
      hasSourcesContent,
      sampleSourcePaths: json.sources.slice(0, 30),
      endpointsFound,
      secretsFound,
    };
  } catch (e) {
    return { accessible: false, error: e.message };
  }
}

function renderSourceMaps() {
  const el = document.getElementById("sourcemaps-list");
  if (!el) return;
  const maps = Object.values(currentData.sourceMaps || {});
  if (!maps.length) return (el.innerHTML = "");

  el.innerHTML = `<div class="detail-block">
    <b>Source maps referenciados (${maps.length})</b>
    <div class="hint" style="margin-bottom:6px">Detectados pasivamente por el comentario "//# sourceMappingURL=" al final de cada script. Verificar si de verdad están expuestos es una acción activa (requiere modo Asistido/Activo).</div>
    ${maps
      .map((m, i) => {
        const key = m.mapUrl;
        const isOpen = expanded.sourcemaps?.has(key);
        return `<div class="row">
          <div class="row-head" data-smap-key="${escapeHtml(key)}" style="cursor:pointer;display:flex;justify-content:space-between">
            <span>
              ${m.verified ? (m.accessible ? sevBadge(m.hasSourcesContent ? "high" : "medium") : `<span class="badge low">no accesible</span>`) : `<span class="badge info">sin verificar</span>`}
              <b class="mono">${escapeHtml(m.mapUrl)}</b>
            </span>
            <span class="hint">${isOpen ? "▲" : "▼"}</span>
          </div>
          <div class="hint">script: <span class="mono">${escapeHtml(m.scriptUrl)}</span></div>
          ${isOpen ? `
            <div class="detail">
              ${!m.verified ? `
                <button class="btn-verify-smap" data-smap-idx="${i}" ${currentMode === "passive" ? "disabled title='Cambia a modo Asistido o Activo'" : ""}>Verificar exposición</button>
                <div class="smap-verify-result hint" data-smap-idx="${i}" style="margin-top:6px"></div>
              ` : m.accessible ? `
                <div class="detail-block">
                  <div class="hint"><b>Accesible:</b> sí · ${m.sourcesCount} archivo(s) de código fuente revelados</div>
                  <div class="hint" style="margin-top:4px"><b>sourcesContent (código fuente completo, no solo nombres):</b> ${m.hasSourcesContent ? "presente" : "ausente"}</div>
                  ${m.sampleSourcePaths?.length ? `
                    <div class="hint" style="margin-top:6px"><b>Rutas reveladas (muestra):</b></div>
                    <pre class="mono" style="background:var(--bg);padding:6px;border-radius:4px;overflow-x:auto;max-height:180px;overflow-y:auto">${m.sampleSourcePaths.map(escapeHtml).join("\n")}</pre>
                  ` : ""}
                  ${m.endpointsFound?.length ? `
                    <div class="hint" style="margin-top:6px"><b>Endpoints encontrados en el código fuente:</b></div>
                    <pre class="mono" style="background:var(--bg);padding:6px;border-radius:4px;overflow-x:auto;max-height:180px;overflow-y:auto">${m.endpointsFound.map(escapeHtml).join("\n")}</pre>
                  ` : ""}
                  ${m.secretsFound?.length ? `
                    <div class="hint" style="margin-top:6px;color:var(--crit)"><b>⚠ Posibles secretos en el código fuente:</b></div>
                    ${m.secretsFound.map((s) => `<div class="hint">${sevBadge("critical")} ${escapeHtml(s.name)} (${s.count} ocurrencia(s))</div>`).join("")}
                  ` : ""}
                </div>
              ` : `<div class="hint">No se pudo acceder al mapa (bloqueado, 404, o no es un source map válido).</div>`}
            </div>
          ` : ""}
        </div>`;
      })
      .join("")}
  </div>`;

  expanded.sourcemaps = expanded.sourcemaps || new Set();

  el.querySelectorAll(".row-head[data-smap-key]").forEach((head) => {
    head.addEventListener("click", () => {
      const key = head.dataset.smapKey;
      expanded.sourcemaps.has(key) ? expanded.sourcemaps.delete(key) : expanded.sourcemaps.add(key);
      renderSourceMaps();
    });
  });

  el.querySelectorAll(".btn-verify-smap").forEach((btn) => {
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      const idx = Number(btn.dataset.smapIdx);
      const mapUrl = maps[idx].mapUrl;
      // Capturado ANTES del await: currentData/currentDomain son variables
      // de módulo que se REASIGNAN si el usuario cambia de dominio mientras
      // este fetch está en vuelo -- sin esto, el resultado (cuando por fin
      // llega) se escribiría en el dominio que esté activo EN ESE MOMENTO,
      // no en el dominio donde se disparó la verificación.
      const targetDomain = currentDomain;
      const resultEl = el.querySelector(`.smap-verify-result[data-smap-idx="${idx}"]`);
      btn.disabled = true;
      resultEl.textContent = "Verificando…";
      const result = await verifySourceMap(mapUrl);
      if (result.error) {
        resultEl.innerHTML = `<div class="scope-warning">${escapeHtml(result.error)}</div>`;
        btn.disabled = false;
        return;
      }
      if (currentDomain !== targetDomain) {
        // El usuario cambió de dominio mientras la verificación corría. El
        // resultado pertenece al dominio ORIGINAL -- se escribe directo a
        // su clave de storage, sin tocar currentData (que ahora es de otro
        // dominio) ni disparar un re-render de la pestaña equivocada.
        const targetKey = domainKey(targetDomain);
        const res = await ext.storage.local.get(targetKey);
        const targetData = res[targetKey] || emptyData(targetDomain);
        targetData.sourceMaps = targetData.sourceMaps || {};
        targetData.sourceMaps[mapUrl] = { ...targetData.sourceMaps[mapUrl], verified: true, ...result };
        await ext.storage.local.set({ [targetKey]: targetData });
        return;
      }
      currentData.sourceMaps[mapUrl] = { ...currentData.sourceMaps[mapUrl], verified: true, ...result };
      await saveCurrent();
      renderSourceMaps();
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

function checklistKeyForFinding(f) {
  if (f.type === "CORS" && f.severity === "critical") return "cors_critical";
  if (f.type === "CSP") return "csp_generic";
  if (f.type === "OAuth/OIDC" && f.directive === "state") return "oauth_state";
  if (f.type === "OAuth/OIDC" && f.directive?.includes("PKCE")) return "oauth_pkce";
  return null;
}

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

// ---- GraphQL: operaciones detectadas + candidatos BFLA + introspection ----

const GQL_TYPE_BADGE = { query: "info", mutation: "high", subscription: "med" };

// Nombre a mostrar para una operación: si es anónima, incluye los
// primeros caracteres del hash de su query -- sin esto, dos operaciones
// anónimas de contenido distinto (ya separadas correctamente en storage
// desde el fix de recordGraphQLOperations) se veían IGUALES en pantalla,
// ambas como "(anónima)", sin forma de distinguirlas a simple vista.
function graphqlOpDisplayName(op) {
  if (op.operationName) return op.operationName;
  return op.queryHash ? `(anónima:${op.queryHash.slice(0, 6)})` : "(anónima)";
}

function buildBflaSpec(op) {
  return [
    `Endpoint:`,
    `${op.method} ${op.endpoint}`,
    ``,
    `Operation:`,
    `${op.operationType} ${graphqlOpDisplayName(op)}`,
    ``,
    `Suggested test:`,
    `1. Repetí esta operación con una sesión de un usuario con MENOS privilegios que el actual (o de otro tenant/rol)`,
    `2. Si igual se ejecuta correctamente (aunque ese usuario no debería poder hacerlo), es un BFLA confirmado`,
    `3. Probá también sin ningún token de autenticación`,
    ``,
    `Required:`,
    `different authorization context (rol/sesión distinta, o sin sesión)`,
    ``,
    `Por qué esta operación es candidata:`,
    `  - Es una mutation: en GraphQL, la autorización a nivel de operación/campo`,
    `    se implementa a mano en cada resolver -- es fácil que alguna quede`,
    `    sin el chequeo, y nadie la prueba manualmente porque no aparece`,
    `    como una ruta REST separada.`,
    ``,
    `Qué falta demostrar:`,
    buildValidationChecklist("bfla"),
  ].join("\n");
}

// ---- Análisis del schema completo (mostrado al hacer doble clic en la
// tarjeta de introspection) -------------------------------------------------

function gqlListSection(title, items, renderItem, emptyText) {
  if (!items.length) return `<div class="cors-card-section"><div class="hint"><b>${escapeHtml(title)} (0)</b></div>${emptyText ? `<div class="hint" style="font-style:italic">${escapeHtml(emptyText)}</div>` : ""}</div>`;
  const cap = 15;
  const visible = items.slice(0, cap);
  return `<div class="cors-card-section">
    <div class="hint" style="margin-bottom:4px"><b>${escapeHtml(title)} (${items.length})</b></div>
    ${visible.map(renderItem).join("")}
    ${items.length > cap ? `<div class="hint">+${items.length - cap} más</div>` : ""}
  </div>`;
}

function renderGraphQLSchemaAnalysis(a) {
  const fieldRow = (f) => `<div class="mono" style="padding:1px 0">${escapeHtml(f.name || "(sin nombre)")}${f.args?.length ? `(${f.args.map((ar) => `${escapeHtml(ar.name)}: ${escapeHtml(ar.type)}`).join(", ")})` : "()"}: ${escapeHtml(f.returnType)}${f.looksPrivileged ? ` <span class="badge high">privilegiada?</span>` : ""}</div>`;

  return `
    <div class="detail cors-card">
      <div class="cors-card-section">
        <div class="hint" style="margin-bottom:4px"><b>Queries (${a.queryFields.length}) vs Mutations (${a.mutationFields.length}) vs Subscriptions (${a.subscriptionFields.length})</b></div>
      </div>
      <div class="cors-card-divider"></div>
      ${gqlListSection("Queries disponibles", a.queryFields, fieldRow)}
      <div class="cors-card-divider"></div>
      ${gqlListSection("Mutations disponibles", a.mutationFields, fieldRow, "Sin mutations en el schema.")}
      ${a.subscriptionFields.length ? `<div class="cors-card-divider"></div>${gqlListSection("Subscriptions disponibles", a.subscriptionFields, fieldRow)}` : ""}
      <div class="cors-card-divider"></div>
      ${gqlListSection(
        "Argumentos interesantes (candidatos IDOR/BOLA)",
        a.interestingArgs,
        (arg) => `<div class="mono" style="padding:1px 0">${escapeHtml(arg.typeName)}.${escapeHtml(arg.fieldName)}(<span style="color:var(--crit)">${escapeHtml(arg.argName)}: ${escapeHtml(arg.argType)}</span>)</div>`,
        "Sin argumentos tipo ID detectados."
      )}
      <div class="cors-card-divider"></div>
      ${gqlListSection(
        "Campos deprecados",
        a.deprecatedFields,
        (f) => `<div class="mono" style="padding:1px 0">${escapeHtml(f.typeName)}.${escapeHtml(f.fieldName)}${f.reason ? ` <span class="hint">— ${escapeHtml(f.reason)}</span>` : ""}</div>`,
        "Sin campos deprecados en el schema."
      )}
      <div class="cors-card-divider"></div>
      ${gqlListSection(
        "Posibles campos sensibles",
        a.sensitiveFields,
        (f) => `<div class="mono" style="padding:1px 0">${sevBadge("medium")} ${escapeHtml(f.typeName)}.${escapeHtml(f.fieldName)}</div>`,
        "Sin nombres de campo que sugieran datos sensibles."
      )}
      <div class="cors-card-divider"></div>
      ${gqlListSection(
        "Enums",
        a.enums,
        (e) => `<div class="mono" style="padding:1px 0">${escapeHtml(e.name)}: ${e.values.map(escapeHtml).join(" | ")}</div>`
      )}
      <div class="cors-card-divider"></div>
      ${gqlListSection(
        "Inputs",
        a.inputs,
        (inp) => `<div class="mono" style="padding:1px 0">${escapeHtml(inp.name)} { ${inp.fields.map((f) => `${escapeHtml(f.name)}: ${escapeHtml(f.type)}`).join(", ")} }</div>`
      )}
      <div class="cors-card-divider"></div>
      ${gqlListSection(
        "Interfaces",
        a.interfaces,
        (i) => `<div class="mono" style="padding:1px 0">${escapeHtml(i.name)} (${i.possibleTypesCount} tipos posibles)</div>`
      )}
      ${a.unions.length ? `<div class="cors-card-divider"></div>${gqlListSection("Unions", a.unions, (u) => `<div class="mono" style="padding:1px 0">${escapeHtml(u.name)} = ${u.possibleTypes.map(escapeHtml).join(" | ")}</div>`)}` : ""}
      <div class="cors-card-divider"></div>
      <div class="cors-card-footer hint">
        <b>Análisis de autorización:</b> las mutations marcadas "privilegiada?" tienen nombre de acción destructiva/administrativa
        (delete/ban/grant/promote/etc.) — son las primeras candidatas a probar BFLA, incluso si la UI de la app nunca las llama:
        el schema las expone igual si introspection está habilitada.
      </div>
    </div>
  `;
}

// ---- Fingerprinting de tecnología: headers, cookies, DOM y globales JS ----

// ---- Cadenas de explotación sugeridas: cruza datos que ya existen en
// distintas pestañas (nunca ejecuta nada nuevo, solo lee currentData) para
// sugerir combinaciones que valen la pena probar juntas, no aisladas. Cada
// regla exige DOS señales concretas presentes en la misma sesión, no una
// sola -- evita generar "cadenas" a partir de una única pista débil.

function computeSuggestedChains(data) {
  const chains = [];

  const ssrfParams = Object.entries(data.params || {}).filter(([, v]) => (v.hits || []).some((h) => h.name === "SSRF"));
  const awsSecret = (data.secrets || []).find((s) => /aws/i.test(s.name) && !s.byDesignPublic);
  if (ssrfParams.length && awsSecret) {
    chains.push({
      title: "SSRF hacia metadata de instancia + credenciales AWS ya vistas",
      severity: "high",
      description: `Parámetro candidato a SSRF (${ssrfParams.map(([p]) => p).join(", ")}) y por separado una clave AWS expuesta ("${awsSecret.name}") en esta misma sesión. Si el SSRF alcanza 169.254.169.254 (metadata de instancia), podría obtenerse un rol IAM adicional al de la clave ya encontrada — vale la pena probar ambos vectores juntos.`,
    });
  }

  const corsCritical = (data.corsFindings || []).find((f) => f.severity === "critical");
  const hasAuthEndpoint = Object.values(data.endpoints || {}).some((e) => e.hasAuth);
  if (corsCritical && hasAuthEndpoint) {
    chains.push({
      title: "CORS permisivo con credenciales + endpoints autenticados existentes",
      severity: "high",
      description: "Se observó ACAO: * combinado con Allow-Credentials: true. Si se confirma que el navegador realmente lo acepta, un sitio de terceros podría leer las respuestas de los endpoints autenticados ya capturados en esta sesión, sin necesitar robar la sesión de otra forma.",
    });
  }

  const idorHigh = (data.idorCandidates || []).find((c) => c.level === "HIGH");
  const highlyCorrelated = Object.entries(data.entityGraph?.edges || {}).find(([, edges]) => Object.keys(edges).length >= 2);
  if (idorHigh && highlyCorrelated) {
    chains.push({
      title: "IDOR de alta confianza + entidad correlacionada con múltiples recursos",
      severity: "high",
      description: `El candidato IDOR en "${idorHigh.template}" tiene confianza alta, y por separado "${highlyCorrelated[0]}" está correlacionado con ${Object.keys(highlyCorrelated[1]).length} otras entidades distintas (ver pestaña Entidades). Si el IDOR se confirma, podría dar acceso en cascada a los recursos correlacionados, no solo al que se prueba directamente.`,
    });
  }

  const hasMutation = Object.values(data.graphqlOperations || {}).some((op) => op.operationType === "mutation");
  const weakJwt = (data.jwts || []).find((j) => j.maxTier === "CANDIDATE");
  if (hasMutation && weakJwt) {
    chains.push({
      title: "Mutation GraphQL + JWT con hallazgo de nivel CANDIDATE",
      severity: "medium",
      description: "Se vio al menos una mutation GraphQL y, por separado, un JWT con hallazgos de nivel CANDIDATE (ver pestaña JWT). Si el JWT puede forjarse o manipularse, la mutation podría ejecutarse con un rol distinto al propio — confirmar el JWT primero suele ser el paso más corto para escalar desde acá.",
    });
  }

  const smapWithSecrets = Object.values(data.sourceMaps || {}).find((m) => (m.secretsFound || []).length > 0);
  if (smapWithSecrets) {
    chains.push({
      title: "Source map expuesto con secretos confirmados dentro",
      severity: "high",
      description: `El source map de ${smapWithSecrets.scriptUrl} reveló código fuente completo con posibles secretos (${smapWithSecrets.secretsFound.map((s) => s.name).join(", ")}). Vale la pena revisar a mano el resto del código fuente revelado (pestaña Secretos) — suelen aparecer más credenciales o endpoints internos cerca del mismo archivo.`,
    });
  }

  const pkceFinding = (data.oauthFindings || []).find((f) => f.directive?.includes("PKCE"));
  const openRedirectParam = Object.entries(data.params || {}).find(([, v]) => (v.hits || []).some((h) => h.name === "Open Redirect"));
  if (pkceFinding && openRedirectParam) {
    chains.push({
      title: "OAuth sin PKCE + candidato a Open Redirect en el mismo dominio",
      severity: "high",
      description: `El flujo OAuth no usa PKCE, y por separado se detectó un parámetro candidato a Open Redirect ("${openRedirectParam[0]}"). Si el Open Redirect se confirma, podría desviar el código de autorización a un dominio propio — sin PKCE, ese código interceptado alcanza para canjearlo por un token.`,
    });
  }

  // ---- 3 reglas nuevas (v0.28.0) -----------------------------------------

  const anySecret = (data.secrets || [])[0];
  const noAuthApiEndpoint = Object.values(data.endpoints || {}).find((e) => !e.hasAuth && /\/api\//i.test(e.url));
  if (anySecret && noAuthApiEndpoint) {
    chains.push({
      title: "Secreto expuesto + endpoint de API sin autenticación visible en el mismo dominio",
      severity: "high",
      description: `Se detectó "${anySecret.name}" expuesto en esta sesión, y por separado hay al menos un endpoint bajo /api/ (${noAuthApiEndpoint.url}) sin header de autenticación observado. No implica que el secreto sirva ahí directamente, pero vale la pena revisar si esa credencial (u otra similar reutilizada) da acceso a rutas que hoy parecen no requerir auth.`,
    });
  }

  const introspectionOn = (data.graphqlIntrospection || []).length > 0;
  const anyMutation = Object.values(data.graphqlOperations || {}).some((op) => op.operationType === "mutation");
  if (introspectionOn && anyMutation) {
    chains.push({
      title: "Introspection de GraphQL habilitada + mutations detectadas",
      severity: "high",
      description: "El schema completo es legible vía introspection (pestaña GraphQL), y por separado ya se capturó al menos una mutation real. Con introspection habilitada se puede listar TODAS las mutations disponibles -- incluidas las que la app nunca llegó a invocar en esta sesión de navegación -- lo que amplía mucho la superficie de BFLA a probar más allá de lo que el tráfico capturado mostró por sí solo.",
    });
  }

  const rateLimitCandidate = getRateLimitCandidates(data)[0];
  const weakJwtForBrute = (data.jwts || []).find((j) => j.maxTier === "CANDIDATE");
  if (rateLimitCandidate && weakJwtForBrute) {
    chains.push({
      title: "Posible ausencia de rate limiting en endpoint sensible + JWT con hallazgo de nivel CANDIDATE",
      severity: "high",
      description: `"${rateLimitCandidate.url}" acumuló tráfico repetido sin ver nunca un 429, y por separado hay un JWT con hallazgos de nivel CANDIDATE (pestaña JWT). Sin throttling visible, un ataque de fuerza bruta o credential stuffing contra ese endpoint es más viable -- y si el JWT resulta forjable, un token obtenido así podría además manipularse para escalar privilegios en vez de quedar limitado a la cuenta comprometida.`,
    });
  }

  return chains;
}

function renderChains() {
  const el = document.getElementById("chains-list");
  if (!el) return;
  const chains = computeSuggestedChains(currentData);
  if (!chains.length) {
    el.innerHTML = `<div class="empty">Sin cadenas sugeridas todavía — hacen falta al menos dos señales relacionadas en la misma sesión (ej. un SSRF candidato + un secreto AWS, o un IDOR de alta confianza + una entidad correlacionada).</div>`;
    return;
  }
  el.innerHTML = chains
    .map(
      (c, i) => `<div class="row">
        <div style="display:flex;justify-content:space-between;align-items:flex-start">
          <b>${escapeHtml(c.title)}</b>
          ${sevBadge(c.severity)}
        </div>
        <div class="hint" style="margin-top:6px">${escapeHtml(c.description)}</div>
        <div class="detail-actions" style="margin-top:6px">
          <button class="btn-create-finding-chain" data-idx="${i}">Crear hallazgo</button>
        </div>
      </div>`
    )
    .join("");

  el.querySelectorAll(".btn-create-finding-chain").forEach((btn) => {
    btn.addEventListener("click", () => {
      const c = chains[Number(btn.dataset.idx)];
      // Las cadenas son hipótesis de encadenamiento, no un tipo de hallazgo
      // con checklist propio en VALIDATION_CHECKLISTS -- se arma un
      // checklist genérico de "qué falta demostrar" apropiado para
      // cualquier cadena: confirmar CADA señal por separado antes de
      // asumir que se conectan de verdad.
      const checklist = [
        "Confirmada la primera señal de forma independiente (no solo observada pasivamente)",
        "Confirmada la segunda señal de forma independiente",
        "Probada la combinación real (no asumir que conectan solo porque coincidieron en la sesión)",
        "Evaluado el impacto real de la cadena completa, no solo de cada parte por separado",
      ].map((i) => `☐ ${i}`).join("\n");
      currentData.notes = currentData.notes || [];
      currentData.notes.unshift({
        title: `Cadena sugerida: ${c.title}`,
        severity: sevBadgeToNoteSeverity(c.severity),
        body: `${c.description}\n\nQué falta demostrar:\n${checklist}`,
        createdAt: Date.now(),
      });
      saveCurrent();
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((tc) => tc.classList.remove("active"));
      document.querySelector(".tab-btn[data-tab='notes']").classList.add("active");
      document.getElementById("tab-notes").classList.add("active");
      render();
    });
  });
}

// Las cadenas usan la escala de severidad interna (high/medium/low/info,
// minúscula, la misma que sevBadge) -- las notas usan la escala del
// selector del formulario (Critical/High/Medium/Low/Informational,
// capitalizada). Este mapeo evita escribir "high" literal en el campo
// severity de una nota, que no matchearía ninguna opción real del select
// ni la tabla de traducción a HackerOne/Bugcrowd/Intigriti.
function sevBadgeToNoteSeverity(sev) {
  const map = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };
  return map[sev] || "Medium";
}

// Intenta interpretar una línea de salida de nuclei (-jsonl) como un match
// estructurado. nuclei emite exactamente un objeto JSON por línea de match
// real (sin nada más en el stream, gracias a -silent) -- si la línea no es
// JSON válido, o no tiene la forma esperada, se trata como salida de texto
// normal (fallback seguro para cualquier otra herramienta o para una nuclei
// vieja que no soporte -jsonl).
function tryParseNucleiMatch(line) {
  let obj;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object" || !obj["template-id"] || !obj.info) return null;
  return {
    templateId: obj["template-id"],
    name: obj.info.name || obj["template-id"],
    severity: (obj.info.severity || "info").toLowerCase(),
    matchedAt: obj["matched-at"] || obj.host || "",
    description: obj.info.description || "",
    extracted: Array.isArray(obj["extracted-results"]) ? obj["extracted-results"] : [],
    curlCommand: obj["curl-command"] || "",
  };
}

// Un match de nuclei se convierte automáticamente en una nota -- mismo
// patrón que "Crear hallazgo" en IDOR/Cadenas, para que corra nuclei desde
// el panel y tener el resultado en Notas/Reporte sea un único paso, no dos.
//
// domain: el dominio REAL contra el que se corrió el job (job.domain), no
// necesariamente el que está visible en el panel en este momento -- ver
// fix de auditoría en runCliJob. Si domain === currentDomain, se escribe
// en memoria (currentData) y se re-renderiza para que se vea al instante.
// Si es un dominio distinto (el hunter cambió de pestaña mientras el job
// seguía corriendo), se lee/escribe DIRECTO en su clave de storage, sin
// tocar currentData -- que en ese momento pertenece a otro dominio.
async function autoCreateNoteFromNucleiMatch(match, target, domain) {
  const note = buildNucleiNote(match, target);
  if (domain === currentDomain) {
    currentData.notes = currentData.notes || [];
    if (currentData.notes.some((n) => n.nucleiDedupeKey === note.nucleiDedupeKey)) return false;
    currentData.notes.unshift(note);
    await saveCurrent();
    render();
    return true;
  }
  try {
    const key = domainKey(domain);
    const res = await ext.storage.local.get(key);
    const data = res[key] || emptyData(domain);
    data.notes = data.notes || [];
    if (data.notes.some((n) => n.nucleiDedupeKey === note.nucleiDedupeKey)) return false;
    data.notes.unshift(note);
    await ext.storage.local.set({ [key]: data });
    return true;
  } catch (e) {
    console.error("surface-hound: error guardando hallazgo de nuclei en otro dominio", e);
    return false;
  }
}

function buildNucleiNote(match, target) {
  const dedupeKey = `${match.templateId}::${match.matchedAt}`;
  const bodyParts = [
    `Template: ${match.templateId}`,
    `Target: ${match.matchedAt || target}`,
  ];
  if (match.description) bodyParts.push(`Descripción (nuclei): ${match.description}`);
  if (match.extracted.length) bodyParts.push(`Extraído: ${match.extracted.join(", ")}`);
  if (match.curlCommand) bodyParts.push(`\nReproducir:\n${match.curlCommand}`);
  bodyParts.push(`\n(Generado automáticamente desde un job de nuclei -- revisar antes de reportar.)`);
  return {
    title: `nuclei: ${match.name}`,
    severity: sevBadgeToNoteSeverity(match.severity),
    body: bodyParts.join("\n"),
    createdAt: Date.now(),
    nucleiDedupeKey: dedupeKey,
  };
}

function renderTech() {
  const el = document.getElementById("tech-list");
  if (!el) return;
  const techs = Object.values(currentData.techFingerprint || {});
  if (!techs.length) {
    el.innerHTML = `<div class="empty">Sin tecnología detectada aún.</div>`;
    return;
  }

  const byCategory = {};
  for (const t of techs) {
    if (!byCategory[t.category]) byCategory[t.category] = [];
    byCategory[t.category].push(t);
  }

  // Antes devolvía "med" -- el CSS define .badge.medium, no .badge.med, así
  // que ese caso nunca matcheaba ninguna regla y se veía sin color (blanco
  // plano). Corregido a los 3 nombres de clase reales, con los 3 rangos
  // pedidos: 80-100% alta confianza, 50-79% media, 1-49% baja.
  const confBadge = (c) => (c >= 80 ? "high" : c >= 50 ? "medium" : "low");

  expanded.tech = expanded.tech || new Set();

  el.innerHTML = Object.entries(byCategory)
    .sort(([, a], [, b]) => Math.max(...b.map((t) => t.confidence)) - Math.max(...a.map((t) => t.confidence)))
    .map(([category, items]) => `
      <div class="detail-block" style="margin-bottom:12px">
        <b>${escapeHtml(category)}</b>
        ${items
          .sort((a, b) => b.confidence - a.confidence)
          .map((t) => {
            const isOpen = expanded.tech.has(t.name);
            const count = t.evidence.length;
            const expandable = count > 2; // pocas evidencias no necesitan expandirse
            return `<div class="row" style="margin-top:6px">
              <div class="tech-row-head" data-tech-key="${escapeHtml(t.name)}" style="cursor:${expandable ? "pointer" : "default"};display:flex;justify-content:space-between;align-items:flex-start">
                <span><span class="badge ${confBadge(t.confidence)}">${t.confidence}%</span> <b>${escapeHtml(t.name)}</b></span>
                ${expandable ? `<span class="hint">${isOpen ? "▲ contraer" : `▼ ${count} evidencias (doble clic)`}</span>` : ""}
              </div>
              ${isOpen
                ? `<pre class="mono" style="background:var(--bg);padding:6px;border-radius:4px;overflow-x:auto;max-height:220px;overflow-y:auto;white-space:pre-wrap;margin-top:4px">${t.evidence.map(escapeHtml).join("\n")}</pre>`
                : `<div class="hint" style="margin-top:2px">${t.evidence.slice(0, 2).map(escapeHtml).join(" · ")}${count > 2 ? ` · +${count - 2} más` : ""}</div>`
              }
            </div>`;
          })
          .join("")}
      </div>
    `)
    .join("");

  el.querySelectorAll(".tech-row-head[data-tech-key]").forEach((head) => {
    head.addEventListener("dblclick", () => {
      const key = head.dataset.techKey;
      expanded.tech.has(key) ? expanded.tech.delete(key) : expanded.tech.add(key);
      renderTech();
    });
  });
}

function renderGraphQL() {
  const introEl = document.getElementById("graphql-introspection-list");
  const listEl = document.getElementById("graphql-list");
  if (!introEl || !listEl) return;

  const introspection = currentData.graphqlIntrospection || [];
  introEl.innerHTML = introspection.length
    ? introspection.map((f, i) => {
        const key = `intro:${f.url}`;
        const isOpen = expanded.graphql?.has(key);
        const a = f.schemaAnalysis;
        return `
      <div class="row">
        <div class="row-head" data-gql-key="${escapeHtml(key)}" style="cursor:pointer;display:flex;justify-content:space-between">
          <span>${sevBadge(f.severity)} <b>Introspection habilitada</b> · Confianza: ${f.confidence}%${a ? ` · ${a.totalTypes} tipos en el schema` : ""}</span>
          <span class="hint">${a ? (isOpen ? "▲" : "▼ doble clic para ver el schema") : ""}</span>
        </div>
        <div class="hint mono" style="margin-top:4px">${escapeHtml(f.url)}</div>
        <div class="hint" style="margin-top:4px">${escapeHtml(f.note)}</div>
        ${isOpen && a ? renderGraphQLSchemaAnalysis(a) : ""}
        ${isOpen && !a ? `<div class="hint" style="margin-top:8px;font-style:italic">No se pudo parsear el schema completo de esta respuesta (puede estar truncada).</div>` : ""}
      </div>
    `;
      }).join("")
    : "";

  introEl.querySelectorAll(".row-head[data-gql-key]").forEach((head) => {
    head.addEventListener("dblclick", () => {
      const key = head.dataset.gqlKey;
      expanded.graphql = expanded.graphql || new Set();
      expanded.graphql.has(key) ? expanded.graphql.delete(key) : expanded.graphql.add(key);
      renderGraphQL();
    });
  });

  const ops = Object.entries(currentData.graphqlOperations || {});
  if (!ops.length) {
    listEl.innerHTML = introspection.length ? "" : `<div class="empty">Sin operaciones GraphQL detectadas aún.</div>`;
    return;
  }

  // mutations primero (son las candidatas a BFLA, lo más accionable)
  const sorted = ops.sort(([, a], [, b]) => {
    if (a.operationType === "mutation" && b.operationType !== "mutation") return -1;
    if (b.operationType === "mutation" && a.operationType !== "mutation") return 1;
    return b.hits - a.hits;
  });

  listEl.innerHTML = sorted
    .map(([key, op]) => {
      const isOpen = expanded.graphql?.has(key);
      const isMutation = op.operationType === "mutation";
      return `<div class="row">
        <div class="row-head" data-gql-key="${escapeHtml(key)}" style="cursor:pointer;display:flex;justify-content:space-between">
          <span>
            <span class="badge ${GQL_TYPE_BADGE[op.operationType] || "info"}">${escapeHtml(op.operationType)}</span>
            <b>${escapeHtml(graphqlOpDisplayName(op))}</b>
            ${isMutation ? `<span class="badge high" title="Autorización a nivel de operación -- rara vez se prueba a mano">BFLA candidate</span>` : ""}
            ${op.introspectionRequested ? `<span class="badge med">introspection solicitada</span>` : ""}
          </span>
          <span class="hint">${isOpen ? "▲" : "▼"}</span>
        </div>
        <div class="hint mono">${escapeHtml(op.method)} ${escapeHtml(op.endpoint)}</div>
        <div class="hint">visto ${op.hits}x · último: ${new Date(op.lastSeen).toLocaleTimeString()}</div>
        ${isMutation && isOpen ? `
          <div class="detail">
            <pre class="mono" style="background:var(--bg);padding:8px;border-radius:4px;overflow-x:auto">${escapeHtml(buildBflaSpec(op))}</pre>
            <div class="detail-actions">
              <button class="btn-gql-copy" data-gql-key="${escapeHtml(key)}">Copiar</button>
            </div>
          </div>
        ` : ""}
      </div>`;
    })
    .join("");

  expanded.graphql = expanded.graphql || new Set();

  listEl.querySelectorAll(".row-head[data-gql-key]").forEach((head) => {
    head.addEventListener("click", () => {
      const key = head.dataset.gqlKey;
      expanded.graphql.has(key) ? expanded.graphql.delete(key) : expanded.graphql.add(key);
      renderGraphQL();
    });
  });

  listEl.querySelectorAll(".btn-gql-copy").forEach((btn) => {
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      const key = btn.dataset.gqlKey;
      const op = currentData.graphqlOperations[key];
      try {
        await navigator.clipboard.writeText(buildBflaSpec(op));
        btn.textContent = "Copiado ✓";
        setTimeout(() => (btn.textContent = "Copiar"), 1500);
      } catch {}
    });
  });
}

// ---- Aprendizaje de falsos positivos: si el mismo TIPO de hallazgo (type +
// directive, sin importar la URL puntual) se marcó falso positivo varias
// veces, se sugiere una regla de supresión automática. No es un sistema
// paralelo -- una regla aplicada simplemente auto-marca como "falso
// positivo" (mismo dismissedFindings de siempre) cualquier hallazgo nuevo
// que matchee el patrón, reusando el 100% de la lógica de filtrado/render
// que ya existe.
const SUPPRESSION_SUGGESTION_THRESHOLD = 3;

function findingPatternKey(type, directive) {
  return `${type}::${directive}`;
}

function computeSuppressionSuggestions(allFindings, dismissed, existingRules) {
  const alreadyRuled = new Set((existingRules || []).map((r) => findingPatternKey(r.type, r.directive)));
  const counts = {};
  for (const f of allFindings) {
    if (!dismissed[corsFindingKey(f)]) continue;
    const pk = findingPatternKey(f.type, f.directive);
    if (alreadyRuled.has(pk)) continue;
    counts[pk] = counts[pk] || { type: f.type, directive: f.directive, count: 0 };
    counts[pk].count++;
  }
  return Object.values(counts).filter((c) => c.count >= SUPPRESSION_SUGGESTION_THRESHOLD);
}

function renderCors() {
  const el = document.getElementById("cors-list");
  const all = [...(currentData.corsFindings || []), ...(currentData.cspFindings || []), ...(currentData.securityHeaderFindings || []), ...(currentData.oauthFindings || [])];
  if (!all.length) {
    // Si no hay hallazgos de CORS/CSP/headers/OAuth pero SÍ hay un hallazgo
    // de rate limiting (se renderiza aparte, en #ratelimit-list, arriba de
    // esta lista) -- dejar esto vacío en vez de mostrar "sin hallazgos",
    // que quedaría contradictorio justo debajo de un hallazgo real.
    return (el.innerHTML = getRateLimitCandidates(currentData).length ? "" : `<div class="empty">Sin hallazgos CORS/CSP aún.</div>`);
  }
  const dismissed = currentData.dismissedFindings || {};
  currentData.suppressionRules = currentData.suppressionRules || [];

  // Aplicar reglas ya creadas: cualquier hallazgo nuevo que matchee una
  // regla existente se marca "falso positivo" automáticamente, sin que el
  // usuario tenga que volver a marcarlo a mano cada vez que aparece.
  let rulesApplied = false;
  for (const f of all) {
    const key = corsFindingKey(f);
    if (dismissed[key]) continue;
    if (currentData.suppressionRules.some((r) => r.type === f.type && r.directive === f.directive)) {
      dismissed[key] = true;
      rulesApplied = true;
    }
  }
  if (rulesApplied) saveCurrent();

  const suggestions = computeSuppressionSuggestions(all, dismissed, currentData.suppressionRules);
  const suggestionsHtml = suggestions
    .map(
      (s) => `<div class="row" style="border-color:var(--info)">
        <span class="hint">Marcaste ${s.count} hallazgos de tipo "${escapeHtml(s.type)}: ${escapeHtml(s.directive)}" como falso positivo.</span>
        <button class="btn-suppress-pattern" data-type="${escapeHtml(s.type)}" data-directive="${escapeHtml(s.directive)}" style="margin-left:8px">Suprimir automáticamente este tipo</button>
      </div>`
    )
    .join("");

  el.innerHTML = suggestionsHtml + all

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
              ${(() => {
                const checklistKey = checklistKeyForFinding(f);
                const checklist = checklistKey ? buildValidationChecklist(checklistKey) : "";
                if (checklist) {
                  return `<div style="margin-top:6px"><b>Qué falta demostrar:</b></div><pre class="mono" style="margin-top:2px;white-space:pre-wrap">${escapeHtml(checklist)}</pre>`;
                }
                return `<div style="margin-top:4px;font-style:italic">"Se encuentra una configuración que merece revisión."</div>`;
              })()}
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
      const idx = btn.dataset.corsIdx;
      const f = all[Number(idx)];
      try {
        await navigator.clipboard.writeText(buildCorsEvidenceText(f));
        // Mismo motivo que btn-copy-burp: re-consultar por data-cors-idx
        // en vez de reusar la referencia capturada por closure.
        const liveBtn = el.querySelector(`.btn-cors-copy[data-cors-idx="${idx}"]`);
        if (liveBtn) {
          liveBtn.textContent = "Copiado ✓";
          setTimeout(() => (liveBtn.textContent = "Copiar evidencia"), 1500);
        }
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

  el.querySelectorAll(".btn-suppress-pattern").forEach((btn) => {
    btn.addEventListener("click", async () => {
      currentData.suppressionRules = currentData.suppressionRules || [];
      currentData.suppressionRules.push({ type: btn.dataset.type, directive: btn.dataset.directive, createdAt: Date.now() });
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
    .map((n, i) => {
      const platformLine = severityPlatformLine(n.severity);
      return `<div class="row">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span><span class="title">${escapeHtml(n.title)}</span> ${sevBadge(n.severity)}</span>
        <button class="btn-delete-note" data-idx="${i}" title="Eliminar esta nota">Eliminar</button>
      </div>
      ${platformLine ? `<div class="hint" style="margin-top:2px">${escapeHtml(platformLine)}</div>` : ""}
      <div style="white-space:pre-wrap;margin-top:4px">${escapeHtml(n.body)}</div>
      <div class="hint">${new Date(n.createdAt).toLocaleString()}</div>
    </div>`;
    })
    .join("");

  // Antes no existía ninguna forma de borrar una nota individual -- solo
  // "Limpiar dominio" completo, que se lleva TODO (endpoints, secretos,
  // etc.), no solo las notas. Con el volumen que se puede generar solo
  // con "Crear hallazgo" desde IDOR/Cadenas, era una limitación real.
  el.querySelectorAll(".btn-delete-note").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const idx = Number(btn.dataset.idx);
      if (!confirm("¿Eliminar esta nota? No se puede deshacer.")) return;
      currentData.notes.splice(idx, 1);
      await saveCurrent();
      renderNotes();
    });
  });
}

async function saveCurrent() {
  // entityGraph se excluye a propósito: background.js es el único dueño de
  // esa clave separada, el panel nunca la modifica -- si se incluyera acá,
  // se reintroduciría el blob grande en la clave principal (desperdiciando
  // el ahorro) o se pisaría la clave separada con una copia potencialmente
  // vieja.
  const { entityGraph, ...rest } = currentData;
  await ext.storage.local.set({ [domainKey(currentDomain)]: rest });
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

// Debe coincidir con SEVERE_NOTIFY_PREFIX en background.js -- se duplica
// acá (en vez de importarlo) porque panel-core.js y background.js corren
// en contextos de ejecución separados (panel de devtools vs. service
// worker) sin módulos compartidos entre sí; ambos leen/escriben el mismo
// storage.local, así que solo hace falta que el STRING coincida.
const SEVERE_NOTIFY_PREFIX = "shxnotif:";

document.getElementById("clear").addEventListener("click", async () => {
  try {
    if (!currentDomain) return;
    if (!confirm(`¿Limpiar todos los datos capturados de ${currentDomain}?`)) return;
    currentData = emptyData(currentDomain);
    await saveCurrent();
    // entityGraph y el snapshot manual viven en sus propias claves (ver
    // entityGraphKey/snapshotKey) -- saveCurrent() no las toca a
    // propósito, así que hay que borrarlas explícitamente acá o quedarían
    // huérfanas (entityGraph potencialmente varios MB sin limpiar nunca).
    // El contador de notificaciones (shxnotif:) también se borra acá --
    // sin esto, tras un reset intencional, volver a descubrir el MISMO
    // hallazgo no dispara una notificación nueva, porque se compara
    // contra un contador viejo que "Limpiar dominio" no había tocado.
    await ext.storage.local.remove([entityGraphKey(currentDomain), snapshotKey(currentDomain), SEVERE_NOTIFY_PREFIX + currentDomain]);
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
    // shxnotif: NO empieza con "shx:" (el 4to carácter difiere -- "shx:" vs
    // "shxn...") así que el filtro de arriba no lo alcanza por sí solo; se
    // busca aparte para no dejar contadores húerfanos que después
    // suprimirían notificaciones legítimas en un dominio recién reseteado.
    const notifKeys = Object.keys(all).filter((k) => k.startsWith(SEVERE_NOTIFY_PREFIX));
    const toRemove = [...domainKeys, ...notifKeys];
    if (toRemove.length) await ext.storage.local.remove(toRemove);
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

// ---- Exportar/importar sesión completa: no el reporte formateado, sino
// TODOS los datos crudos del dominio (incluido entityGraph) -- para
// respaldar el trabajo o continuarlo en otra máquina. La importación
// reusa mergeLegacyDomainData(), la misma función ya construida y probada
// para la fusión de "www." -- fusionar una sesión importada es
// exactamente el mismo problema: combinar datos de otro origen sin pisar
// lo que ya está.
document.getElementById("export-session")?.addEventListener("click", async () => {
  const payload = { version: 1, domain: currentDomain, exportedAt: Date.now(), data: currentData };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const filename = `surface-hound-session-${currentDomain}-${Date.now()}.json`;
  if (ext.downloads?.download) {
    await ext.downloads.download({ url, filename });
  } else {
    window.open(url);
  }
});

document.getElementById("import-session-btn")?.addEventListener("click", () => {
  document.getElementById("import-session-file")?.click();
});

// Lista de URLs en scope, una por línea -- formato que consumen directo
// `nuclei -l archivo.txt`, `httpx -l archivo.txt`, y sirve como base de
// targets para ffuf. Esto es lo que cierra el otro sentido de la
// integración: Surface Hound ALIMENTA a las herramientas externas con lo
// que ya capturó pasivamente, en vez de que el hunter tenga que copiar
// URL por URL a mano desde la pestaña Endpoints.
document.getElementById("export-urls")?.addEventListener("click", async () => {
  const endpoints = Object.values(currentData.endpoints || {});
  // Solo en scope: exportar TODO lo capturado (incluido fuera de scope,
  // que puede incluir CDNs/terceros de terceros) generaría una lista que,
  // si se corre sin revisar, dispara tráfico activo contra objetivos no
  // autorizados -- el mismo criterio fail-closed que ya rige "Enviar a CLI".
  const urls = [...new Set(endpoints.filter((e) => e.inScope === true).map((e) => e.url))].sort();
  if (!urls.length) {
    showPanelError("No hay endpoints en scope capturados todavía para exportar.");
    return;
  }
  const blob = new Blob([urls.join("\n") + "\n"], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const filename = `surface-hound-urls-${currentDomain}-${Date.now()}.txt`;
  if (ext.downloads?.download) {
    await ext.downloads.download({ url, filename });
  } else {
    window.open(url);
  }
});

document.getElementById("import-session-file")?.addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const payload = JSON.parse(text);
    // No confiar ciegamente en que el archivo sea "nuestro" solo porque
    // parseó como JSON -- se valida la forma mínima esperada antes de
    // fusionar nada.
    if (!payload || typeof payload !== "object" || !payload.data || !isPlainObject(payload.data) || !isPlainObject(payload.data.endpoints)) {
      showPanelError("El archivo no tiene el formato esperado de una sesión de Surface Hound exportada.");
      return;
    }
    const when = payload.exportedAt ? new Date(payload.exportedAt).toLocaleString() : "fecha desconocida";
    if (!confirm(`¿Fusionar los datos de "${payload.domain || "dominio desconocido"}" (exportados ${when}) con lo que ya tenés en ${currentDomain}? Esto NO borra nada existente, solo agrega lo que falte.`)) {
      return;
    }
    mergeLegacyDomainData(currentData, payload.data);
    // Igual que en la migración de "www.": entityGraph se separa y se
    // escribe explícito en su propia clave, ya que saveCurrent() lo
    // excluye a propósito (background.js es su dueño normalmente, pero acá
    // la fusión sí le agregó contenido nuevo que hay que persistir).
    const { entityGraph, ...restData } = currentData;
    await ext.storage.local.set({ [domainKey(currentDomain)]: restData, [entityGraphKey(currentDomain)]: entityGraph });
    render();
  } catch (e) {
    showPanelError(`Error al importar la sesión: ${e.message}`, e.stack);
  } finally {
    ev.target.value = "";
  }
});

// Neutraliza sintaxis estructural de Markdown (encabezados, separadores
// horizontales) al INICIO de una línea dentro del cuerpo de una nota --
// sin esto, una nota que por accidente tenga una línea "---" o "## algo"
// (ej. pegando una respuesta HTTP cruda) es visualmente indistinguible de
// la estructura propia del reporte, que también usa "---" como separador
// entre notas y "##" como encabezado de cada una.
function escapeMdStructural(text) {
  return String(text ?? "")
    // Neutraliza HTML embebido (no solo estructura de markdown): los
    // valores que entran acá (nombres de secretos, nombres de nuclei,
    // URLs, valores de headers) vienen de datos observados en el TARGET
    // -- un adversario que sepa que se está corriendo un scanner de bug
    // bounty podría intentar envenenar el reporte exportado con HTML/JS
    // embebido, para ejecutarse si el .md se abre en un visor que
    // renderiza HTML dentro de markdown (varios lo hacen por defecto).
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .split("\n")
    .map((line) => {
      if (/^#{1,6}\s/.test(line)) return "\\" + line; // encabezado falso
      if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line.trim())) return "\\" + line; // separador horizontal falso
      return line;
    })
    .join("\n");
}

// Resumen rápido de superficie -- cuenta lo capturado en cada categoría,
// para que quien lea el reporte tenga contexto de reconocimiento sin
// tener que abrir la extensión. Se omite cualquier categoría en 0 para
// no inflar el reporte con líneas vacías.
function buildReconSummary(data) {
  const rows = [
    ["Endpoints capturados", Object.keys(data.endpoints || {}).length],
    ["Parámetros distintos", Object.keys(data.params || {}).length],
    ["Candidatos IDOR", (data.idorCandidates || []).length],
    ["Secretos detectados", (data.secrets || []).length],
    ["JWTs vistos", (data.jwts || []).length],
    ["Hallazgos CORS/CSP/headers", (data.corsFindings || []).length + (data.cspFindings || []).length + (data.securityHeaderFindings || []).length],
    ["Operaciones GraphQL", Object.keys(data.graphqlOperations || {}).length],
    ["Tecnologías identificadas", Object.keys(data.techFingerprint || {}).length],
  ].filter(([, count]) => count > 0);
  if (!rows.length) return "";
  return `## Resumen de reconocimiento\n\n${rows.map(([label, count]) => `- ${label}: ${count}`).join("\n")}\n\n---\n\n`;
}

// Cadenas sugeridas que todavía no se promovieron a una nota manual --
// van en una sección aparte, claramente marcadas como NO confirmadas
// (son correlaciones automáticas, no hallazgos validados), para que el
// reporte final refleje el panorama completo sin mezclarlas con el
// cuerpo ya redactado a mano de cada nota.
function buildChainsAppendix(data) {
  const chains = computeSuggestedChains(data);
  if (!chains.length) return "";
  return `## Cadenas de explotación sugeridas (sin confirmar)\n\n_Correlaciones automáticas entre hallazgos independientes -- requieren validación manual antes de reportarse. No reemplazan una prueba activa._\n\n${chains
    .map((c) => `### ${escapeMdStructural(c.title)}\n\n**Severidad estimada:** ${c.severity}\n\n${escapeMdStructural(c.description)}\n`)
    .join("\n")}\n---\n\n`;
}

function buildReport() {
  const notes = currentData.notes || [];
  const footer = `\n---\n\n_Generado con Surface Hound — creado por Zuk4r1._\n`;
  let md = `# Reporte de Bug Bounty — ${currentDomain}\n\n`;
  md += buildReconSummary(currentData);
  if (!notes.length) {
    md += "_Sin hallazgos guardados. Agrega notas en la pestaña Notas/Reporte._\n\n";
  } else {
    for (const n of notes) {
      const platformLine = severityPlatformLine(n.severity);
      // El título también pasa por el mismo escape que el cuerpo -- una nota
      // creada automáticamente desde nuclei usa match.name (info.name de la
      // plantilla) sin ningún filtro previo, así que un título malicioso
      // llegaría directo a un encabezado ## sin este chequeo.
      const title = escapeMdStructural((n.title || "").trim()) || "(sin título)";
      md += `## ${title}\n\n**Severity:** ${n.severity}${platformLine ? `\n\n**Traducción por plataforma:** ${platformLine}` : ""}\n\n**Summary / Steps to reproduce / Impact:**\n\n${escapeMdStructural(n.body)}\n\n---\n\n`;
    }
  }
  md += buildChainsAppendix(currentData);
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
  nuclei: (t, h) => `nuclei -u ${t} -silent -jsonl -timeout 8`,
  // El agente genera un archivo temporal único e impredecible por job (no
  // una ruta fija) -- acá no se puede saber el nombre exacto de antemano,
  // así que se muestra el patrón real en vez de una ruta que induciría a
  // error. Los resultados de ese archivo se leen de vuelta automáticamente
  // y se muestran como parte de la salida del job.
  arjun: (t, h) => `arjun -u ${t} -oT <archivo temporal único, se lee de vuelta automáticamente>`,
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
  // Antes: cada llamada agregaba un cartel de error NUEVO al principio de
  // la lista, sin sacar los anteriores. Como checkAgentStatus() reintenta
  // conectar cada 15s de forma indefinida mientras el panel esté abierto
  // (ver setInterval más abajo), y CADA intento fallido dispara este
  // mismo error vía onDisconnect, el usuario terminaba viendo decenas de
  // carteles idénticos apilados con solo tener el panel abierto un rato
  // -- no hacía falta ni tocar "Ejecutar". Con uno solo alcanza para
  // notificar: se reemplaza el anterior en vez de acumularse.
  const existing = jobsListEl.querySelector(".native-host-error");
  if (existing) existing.remove();
  const div = document.createElement("div");
  div.className = "scope-warning native-host-error";
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
  if (msg.line !== undefined) {
    // Solo nuclei corre con -jsonl -- para el resto de las herramientas,
    // tryParseNucleiMatch descarta la línea (no es JSON o no tiene la forma
    // esperada) y sigue el camino normal de texto plano sin cambios.
    const match = job.tool === "nuclei" ? tryParseNucleiMatch(msg.line) : null;
    if (match) {
      job.findings = job.findings || [];
      job.findings.push(match);
      autoCreateNoteFromNucleiMatch(match, job.target, job.domain);
    } else {
      job.lines.push(msg.line);
    }
  }
  if (msg.done) {
    job.status = msg.blocked ? "blocked" : msg.ok ? "done" : "error";
    if (msg.error) job.lines.push(`[error] ${msg.error}`);
    if (msg.returncode != null) job.lines.push(`[exit code ${msg.returncode}]`);
    // -jsonl (usado desde v0.28.0 para poder parsear los matches) requiere
    // una versión de nuclei relativamente reciente -- una instalación
    // vieja rechaza el flag y el job termina en error sin ninguna pista
    // de qué pasó. Esto no es un bug del lado de la extensión (no hay
    // forma de controlar qué versión tiene instalada el hunter), pero al
    // menos se puede reconocer el patrón de error típico de un flag no
    // reconocido y dar una pista accionable en vez de un error genérico.
    if (job.tool === "nuclei" && job.status === "error") {
      const combined = job.lines.join("\n").toLowerCase();
      if (combined.includes("jsonl") && (combined.includes("not defined") || combined.includes("unknown flag") || combined.includes("flag provided but not defined"))) {
        job.lines.push("[hint] Este error suele indicar una versión de nuclei desactualizada -- -jsonl requiere una versión relativamente reciente. Probá `nuclei -version` y actualizá si hace falta.");
      }
    }
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
        ${j.findings?.length ? `<div class="job-findings">${j.findings
          .map(
            (f) => `<div class="row">
              <span class="badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
              <b>${escapeHtml(f.name)}</b>
              <div class="hint mono" style="margin-top:4px">${escapeHtml(f.matchedAt)}</div>
              ${f.extracted.length ? `<div class="hint" style="margin-top:2px">Extraído: ${escapeHtml(f.extracted.join(", "))}</div>` : ""}
            </div>`
          )
          .join("")}</div>` : ""}
        <div class="job-output">${escapeHtml(j.lines.join("\n")) || (j.findings?.length ? "" : "(sin salida todavía)")}</div>
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

  // Job optimista con id temporal hasta que el agente confirme el real.
  // domain: fix de auditoría (v0.29.0) -- se guarda el dominio contra el
  // que REALMENTE se corre el job, no el que esté visible cuando llegue
  // la respuesta. nuclei puede tardar hasta 180s; si el hunter cambia de
  // pestaña/dominio inspeccionado mientras un job sigue en vuelo, el
  // resultado debe seguir yendo al dominio original, no al que se esté
  // mirando en ese momento.
  jobs.set("__pending__", { job_id: null, tool, target, domain: currentDomain, status: "queued", lines: [], open: true });
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
