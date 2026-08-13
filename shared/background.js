// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

// ==========================================================================
// Motor de fondo: captura tráfico en vivo (webRequest) y corre los
// analizadores heurísticos. Sin dependencias externas, sin ES modules
// (para ser cargable tanto como service_worker de Chrome como background
// script clásico de Firefox).
// ==========================================================================

const ext = typeof browser !== "undefined" ? browser : chrome;
const STORAGE_PREFIX = "shx:";
const CONFIG_PREFIX = "shxcfg:";

// ---- Scope Guard -----------------------------------------------------------
// Configuración global (no por dominio): un programa de bug bounty activo con
// patrones allow/deny. Se usa para marcar cada endpoint capturado como
// dentro/fuera de scope, y para bloquear acciones activas (CLI, chequeos en
// vivo) contra objetivos que no están explícitamente permitidos.

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

// Devuelve true (en scope), false (fuera de scope) o null (scope no configurado,
// es decir el guard está inactivo y no debe bloquear nada).
function isInScope(hostname, scope) {
  if (!scope || !Array.isArray(scope.allow) || scope.allow.length === 0) return null;
  const deny = (scope.deny || []).some((p) => scopeMatch(hostname, p));
  if (deny) return false;
  return scope.allow.some((p) => scopeMatch(hostname, p));
}

// Cache en memoria con TTL corto: upsertEndpoint/handleNetEvent llaman a esto
// en CADA request capturado (potencialmente decenas por segundo en un sitio
// con mucho tráfico). Sin cache, cada uno dispara una lectura de
// storage.local -- innecesario cuando el scope casi nunca cambia entre un
// request y el siguiente.
let scopeCache = { value: null, fetchedAt: 0 };
let scopeCachePending = null; // evita "cache stampede": si 10 requests llegan
// casi simultáneos, sin esto los 10 verían la cache vacía (porque ninguno
// terminó de escribirla todavía) y dispararían 10 lecturas de storage en vez
// de 1 -- acá, si ya hay una lectura en curso, todos esperan esa misma promesa.
const SCOPE_CACHE_TTL_MS = 3000;

async function getScopeConfig() {
  const now = Date.now();
  if (now - scopeCache.fetchedAt < SCOPE_CACHE_TTL_MS) return scopeCache.value;
  if (scopeCachePending) return scopeCachePending;
  scopeCachePending = (async () => {
    const key = CONFIG_PREFIX + "scope";
    const res = await ext.storage.local.get(key);
    scopeCache = { value: res[key] || null, fetchedAt: Date.now() };
    scopeCachePending = null;
    return scopeCache.value;
  })();
  return scopeCachePending;
}

// ---- Clasificador de parámetros -----------------------------------------

const PARAM_RULES = [
  {
    name: "IDOR / Broken Access Control",
    cwe: "CWE-639",
    patterns: [/^id$/i, /_id$/i, /^uid$/i, /^user(name)?$/i, /^account/i, /^order/i, /^invoice/i, /^doc(ument)?/i, /^ref(erence)?$/i],
    hint: "Cambia el valor por un ID de otro usuario/objeto usando tu propia sesión o una sesión de menor privilegio.",
    payloads: ["Cambia el ID por uno consecutivo (n+1, n-1)", "Prueba el ID con la sesión de otro usuario", "Prueba con ID=0 o negativo", "Si es UUID, prueba un UUID válido pero ajeno"]
  },
  {
    name: "SSRF",
    cwe: "CWE-918",
    patterns: [/^url$/i, /^uri$/i, /^target$/i, /^dest(ination)?$/i, /^callback$/i, /^webhook$/i, /^feed$/i, /^src$/i, /^host$/i, /^endpoint$/i, /^image_url$/i, /^avatar/i],
    hint: "Redirige a http://169.254.169.254, a un listener propio (interactsh/Burp Collaborator) o a localhost con puertos internos.",
    payloads: ["http://169.254.169.254/latest/meta-data/", "http://localhost:6379 (o puertos internos comunes)", "http://<tu-listener>.oastify.com (interactsh/Collaborator)", "file:///etc/passwd (si el parser acepta otros esquemas)"]
  },
  {
    name: "Open Redirect",
    cwe: "CWE-601",
    patterns: [/^redirect(_?to)?$/i, /^next$/i, /^return(_?url)?$/i, /^continue$/i, /^dest(ination)?$/i, /^callback_url$/i, /^goto$/i],
    hint: "Prueba //evil.com, https:evil.com, /\\evil.com y variantes de bypass de whitelist.",
    payloads: ["//evil.example.com", "https:evil.example.com", "/\\evil.example.com", "https://target.com.evil.example.com (bypass de whitelist por substring)"]
  },
  {
    name: "LFI / Path Traversal",
    cwe: "CWE-22",
    patterns: [/^file$/i, /^path$/i, /^page$/i, /^template$/i, /^load$/i, /^include$/i, /^doc$/i, /^folder$/i, /^dir$/i],
    hint: "Prueba ../../../../etc/passwd, encoding doble, null byte y wrappers si aplica.",
    payloads: ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd (encoding)", "....//....//etc/passwd (bypass de filtro simple)", "php://filter/convert.base64-encode/resource=index.php (si es PHP)"]
  },
  {
    name: "SQLi",
    cwe: "CWE-89",
    patterns: [/^search$/i, /^query$/i, /^q$/i, /^filter$/i, /^sort$/i, /^order_by$/i, /^category$/i],
    hint: "Prueba comillas simples y payloads de time-based blind si no hay error visible.",
    payloads: ["' OR '1'='1", "' AND SLEEP(5)-- -", "\" OR \"1\"=\"1", "1; WAITFOR DELAY '0:0:5'-- (MSSQL)"]
  },
  {
    name: "SSTI",
    cwe: "CWE-1336",
    patterns: [/^template$/i, /^name$/i, /^title$/i, /^message$/i, /^comment$/i],
    hint: "Prueba {{7*7}}, ${7*7}, <%= 7*7 %> según el motor de plantillas detectado.",
    payloads: ["{{7*7}} (Jinja2/Twig)", "${7*7} (FreeMarker/Velocity)", "<%= 7*7 %> (ERB)", "#{7*7} (Ruby/Thymeleaf)"],
    needsReflection: true
  },
  {
    name: "Mass Assignment / Business Logic",
    cwe: "CWE-915",
    patterns: [/^role$/i, /^is_admin$/i, /^admin$/i, /^status$/i, /^price$/i, /^amount$/i, /^discount$/i, /^quantity$/i, /^permission/i],
    hint: "Agrega el parámetro en el body aunque no aparezca en el formulario, o manipula su valor directamente.",
    payloads: ['"role":"admin" agregado al body JSON', '"is_admin":true agregado al body', "Cambiar price/amount a un valor negativo o 0", "Cambiar quantity a un valor extremo"]
  },
  {
    name: "XSS reflejado/DOM",
    cwe: "CWE-79",
    patterns: [/^q$/i, /^search$/i, /^name$/i, /^comment$/i, /^msg$/i, /^text$/i, /^input$/i, /^callback$/i, /^jsonp$/i],
    hint: "Revisa reflexión en HTML/JS/atributos. Si hay JSONP (callback), prueba XSS vía ese parámetro.",
    payloads: ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)", "callback param: alert(1)// (si es JSONP)"],
    needsReflection: true
  },
  {
    name: "Command Injection",
    cwe: "CWE-78",
    patterns: [/^cmd$/i, /^exec$/i, /^ping$/i, /^host$/i, /^ip$/i, /^run$/i],
    hint: "Prueba encadenamiento: ; whoami, | id, $(whoami), backticks.",
    payloads: ["; whoami", "| id", "$(whoami)", "`id`"]
  },
  {
    name: "JWT / Session manipulation",
    cwe: "CWE-347",
    patterns: [/^token$/i, /^jwt$/i, /^auth$/i, /^session$/i, /^access_token$/i, /^refresh_token$/i, /^api_key$/i],
    hint: "Decodifica el JWT en la pestaña correspondiente y revisa alg, exp y validación de firma.",
    payloads: ["Cambiar alg a 'none' y quitar la firma", "Firmar con la clave pública como si fuera HS256 (alg confusion)", "Modificar claims (role/sub) sin firmar y ver si el backend valida"]
  }
];

function classifyParams(paramNames) {
  const results = {};
  for (const p of paramNames) {
    const hits = [];
    for (const rule of PARAM_RULES) {
      if (rule.patterns.some((re) => re.test(p))) {
        hits.push({ name: rule.name, cwe: rule.cwe, hint: rule.hint, payloads: rule.payloads || [], needsReflection: !!rule.needsReflection });
      }
    }
    if (hits.length) results[p] = hits;
  }
  return results;
}

// ---- Extracción de entidades y grafo de correlación ------------------------
// Detecta valores tipo "id" en JSON (bodies de request/response) y en URLs,
// y construye un grafo: si dos entidades aparecen juntas en el mismo JSON
// (ej. user_id + organization_id en la misma respuesta), quedan conectadas.
// Esto permite, más adelante, decir "este invoice_id ya lo vimos asociado a
// esta organization_id en otro endpoint" -- útil para BOLA/IDOR horizontal.

const ENTITY_KEY_RE = /(^id$)|(_id$)|(Id$)|(^uuid$)|(_uuid$)|(^ref(erence)?$)/i;
const KNOWN_RESOURCE_WORDS = new Set([
  "users", "user", "accounts", "account", "orders", "order", "invoices", "invoice",
  "projects", "project", "organizations", "organization", "orgs", "org", "tickets", "ticket",
  "payments", "payment", "transactions", "transaction", "messages", "message", "comments", "comment",
  "posts", "post", "products", "product", "teams", "team", "groups", "group", "sessions", "session",
  "tokens", "token", "files", "file", "documents", "document", "customers", "customer", "clients",
  "client", "subscriptions", "subscription", "tasks", "task", "reports", "report", "contacts", "contact"
]);

function isEntityValue(v) {
  if (typeof v === "number" && Number.isFinite(v)) return true;
  if (typeof v === "string" && v.length > 0 && v.length < 64 && /^[a-zA-Z0-9_-]+$/.test(v)) return true;
  return false;
}

// Filtro adicional para el GRAFO de entidades específicamente: no todo lo
// que tiene forma de "id: valor" es un identificador de recurso. Cosas como
// {"id": "activate-plan"} en un JSON de acciones de dashboard cumplen la
// forma pero no representan un recurso propiedad de un usuario/tenant --
// son ruido para el objetivo del grafo (detectar acceso horizontal tipo
// "este invoice_id está asociado a esta organization_id").
//
// Trade-off consciente: esto también descarta slugs alfabéticos que SÍ
// podrían ser identificadores reales en apps multi-tenant (ej.
// org_slug: "acme-corp"). Se prioriza reducir ruido; si hace falta ese
// caso puntual, se puede afinar con un ejemplo concreto.
function looksLikeRealIdentifier(value) {
  const v = String(value);
  if (/^\d+$/.test(v)) return true; // numérico puro
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return true; // UUID
  if (/[0-9]/.test(v) && /[a-zA-Z]/.test(v)) return true; // mezcla letras+números (hash/token típico)
  if (!/[-_]/.test(v) && v.length >= 8) return true; // token de una sola palabra, largo (hash corto probable)
  return false; // slug de varias palabras sin dígitos -> probable acción/feature, no recurso
}

function extractEntitiesFromObject(obj, depth = 0, out = []) {
  if (!obj || typeof obj !== "object" || depth > 3 || out.length > 60) return out;
  if (Array.isArray(obj)) {
    for (const item of obj.slice(0, 20)) extractEntitiesFromObject(item, depth + 1, out);
    return out;
  }
  for (const [key, val] of Object.entries(obj)) {
    if (ENTITY_KEY_RE.test(key) && isEntityValue(val) && looksLikeRealIdentifier(val)) {
      out.push({ key: normalizeEntityKey(key), value: String(val) });
    } else if (val && typeof val === "object") {
      extractEntitiesFromObject(val, depth + 1, out);
    }
  }
  return out;
}

function normalizeEntityKey(key) {
  // (antes tenía un .replace() con una regex que, por cómo estaba anclada,
  // siempre hacía match del string completo — no recortaba nada, solo
  // aparentaba hacerlo. Se deja solo lo que realmente hacía: minúsculas.)
  return key.toLowerCase();
}

const PATH_ID_RE = /\/([a-zA-Z][a-zA-Z0-9_-]*)\/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=[/?#]|$)/gi;

function extractEntitiesFromUrl(url) {
  const out = [];
  if (!url) return out;
  let m;
  const re = new RegExp(PATH_ID_RE.source, "gi");
  while ((m = re.exec(url.split("?")[0])) !== null) {
    out.push({ key: m[1].toLowerCase().replace(/s$/, "") + "_id", value: m[2] });
  }
  try {
    const u = new URL(url);
    for (const [k, v] of u.searchParams.entries()) {
      if (ENTITY_KEY_RE.test(k) && isEntityValue(v) && looksLikeRealIdentifier(v)) out.push({ key: normalizeEntityKey(k), value: v });
    }
  } catch {}
  return out;
}

function ensureEntityGraph(data) {
  if (!data.entityGraph) data.entityGraph = { nodes: {}, edges: {} };
  if (!data.entitySeenInResponse) data.entitySeenInResponse = {};
}

function updateEntityGraph(data, entities, sourceUrl) {
  ensureEntityGraph(data);
  const nodeIds = [];
  for (const e of entities) {
    const nodeId = `${e.key}:${e.value}`;
    nodeIds.push(nodeId);
    if (!data.entityGraph.nodes[nodeId]) {
      data.entityGraph.nodes[nodeId] = { key: e.key, value: e.value, count: 0, urls: [] };
    }
    const node = data.entityGraph.nodes[nodeId];
    node.count += 1;
    if (sourceUrl && !node.urls.includes(sourceUrl) && node.urls.length < 5) node.urls.push(sourceUrl);
  }
  // conectar cada par de entidades DISTINTAS (distinta key) vistas juntas en el mismo JSON
  for (let i = 0; i < nodeIds.length; i++) {
    for (let j = i + 1; j < nodeIds.length; j++) {
      const a = nodeIds[i], b = nodeIds[j];
      if (entities[i].key === entities[j].key) continue; // no conectar dos valores del mismo campo
      data.entityGraph.edges[a] = data.entityGraph.edges[a] || {};
      data.entityGraph.edges[b] = data.entityGraph.edges[b] || {};
      data.entityGraph.edges[a][b] = (data.entityGraph.edges[a][b] || 0) + 1;
      data.entityGraph.edges[b][a] = (data.entityGraph.edges[b][a] || 0) + 1;
    }
  }
}

function findRelatedEntities(data, key, value, limit = 5) {
  ensureEntityGraph(data);
  const nodeId = `${key}:${value}`;
  const edges = data.entityGraph.edges[nodeId];
  if (!edges) return [];
  return Object.entries(edges)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([otherId, count]) => {
      const node = data.entityGraph.nodes[otherId];
      return { key: node?.key, value: node?.value, count, urls: node?.urls || [] };
    });
}

// ---- Scoring de candidatos IDOR (multi-señal) ------------------------------

function summarizeStack(stack) {
  if (!stack) return null;
  // Se queda con el primer frame que parezca un archivo .js real y que NO
  // sea del propio interceptor/extensión (defensa en profundidad: aunque el
  // filtro de captureStack() en network-interceptor.js ya debería haber
  // sacado estos frames, si algo se cuela igual no queremos mostrar nuestro
  // propio código como si fuera el script de la app objetivo).
  const parts = stack.split(" | ").map((s) => s.trim());
  const frame =
    parts.find(
      (p) =>
        /\.js(:\d+)?/.test(p) &&
        !/network-interceptor\.js/i.test(p) &&
        !/^(chrome|moz)-extension:\/\//i.test(p)
    ) || null;
  if (!frame) return null;
  const match = frame.match(/([^\s(@]+\.js:\d+:\d+)/);
  return match ? match[1] : frame.slice(0, 120);
}

function scoreIdorCandidate(candidate, data) {
  const signals = [];
  let score = 0;
  const kind = candidate.kind || "path";

  signals.push("identificador numérico/UUID");
  score += 2;

  if (kind === "path") {
    signals.push("aparece como segmento de path (no query string)");
    score += 2;

    const segments = candidate.template.split("/");
    const idIdx = segments.indexOf("{id}");
    const resourceSeg = idIdx > 0 ? segments[idIdx - 1].toLowerCase() : "";
    if (KNOWN_RESOURCE_WORDS.has(resourceSeg)) {
      signals.push(`nombre de recurso reconocible ("${resourceSeg}")`);
      score += 2;
    }
  } else {
    signals.push(`parámetro de query ("${candidate.param}"), no forma parte del path`);
    // sin bonus: los query params son estadísticamente más ruidosos (paginación,
    // filtros, analytics) que los IDs que forman parte de la ruta REST
  }

  if (candidate.observedIds.length >= 4) {
    signals.push(`${candidate.observedIds.length} valores distintos observados`);
    score += 3;
  } else if (candidate.observedIds.length >= 2) {
    signals.push(`${candidate.observedIds.length} valores distintos observados`);
    score += 2;
  }

  const seenKeys = Object.keys(data.entitySeenInResponse || {});
  const echoed = candidate.observedIds.some((id) => seenKeys.some((k) => k.endsWith(":" + id)));
  if (echoed) {
    signals.push("valor visto también en un cuerpo de respuesta JSON (eco confirmado)");
    score += 3;
  }

  const level = score >= 9 ? "HIGH" : score >= 5 ? "MED" : "LOW";
  const confidence = Math.min(95, Math.round((score / 13) * 100)); // nunca 100%: es análisis pasivo, no confirmado
  return { ...candidate, kind, signals, score, level, confidence };
}

// ---- IDOR -----------------------------------------------------------------

// Reconoce tanto IDs numéricos como UUIDs como segmentos de path. Antes solo
// detectaba numéricos (\d{1,12}), así que cualquier API con IDs tipo UUID
// (muy común: Stripe, la mayoría de APIs REST modernas) nunca generaba
// candidatos IDOR por path, pese a que la señal decía "numérico/UUID".
const ID_SEGMENT_RE = /\/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=[/?#]|$)/gi;
const ID_OR_UUID_VALUE_RE = /^(\d{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;

function detectSequentialCandidates(urlHistory, data) {
  const byTemplate = new Map();
  for (const url of urlHistory) {
    // Se agrupa solo por el path (sin query string): la intención es detectar
    // el mismo patrón de endpoint (ej. /orders/{id}) sin que distintos
    // parámetros de query rompan la agrupación.
    const path = url.split("?")[0];
    const template = path.replace(ID_SEGMENT_RE, "/{id}");
    if (!byTemplate.has(template)) byTemplate.set(template, new Set());
    let m;
    const re = new RegExp(ID_SEGMENT_RE.source, "gi");
    while ((m = re.exec(path)) !== null) byTemplate.get(template).add(m[1]);
  }
  const candidates = [];
  for (const [template, ids] of byTemplate.entries()) {
    if (ids.size >= 2) {
      const base = {
        template,
        observedIds: Array.from(ids),
        confidence: ids.size >= 3 ? "high" : "medium", // se mantiene por compatibilidad
      };
      candidates.push(scoreIdorCandidate(base, data || { entitySeenInResponse: {} }));
    }
  }
  return candidates.sort((a, b) => b.score - a.score);
}

function buildAllIdorCandidates(urlHistory, data) {
  const pathCandidates = detectSequentialCandidates(urlHistory, data);
  const queryCandidates = Object.entries(data.queryIdorSeen || {}).map(([qKey, values]) => {
    const [path, param] = qKey.split("?");
    return scoreIdorCandidate({ template: `${qKey}={id}`, observedIds: values, kind: "query", param }, data);
  });
  return [...pathCandidates, ...queryCandidates].sort((a, b) => b.score - a.score);
}

// ---- JWT --------------------------------------------------------------

const JWT_RE = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;

function b64urlDecode(str) {
  try {
    const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
    return decodeURIComponent(
      atob(b64).split("").map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("")
    );
  } catch {
    return null;
  }
}

// Sistema de 4 niveles (OBSERVED/SUSPICIOUS/CANDIDATE/CONFIRMED). Un análisis
// PASIVO nunca puede confirmar explotabilidad -- eso requiere probarlo
// activamente (¿el backend de verdad acepta alg=none? ¿de verdad no valida
// la firma?). Por eso el decoder nunca asigna CONFIRMED; como mucho llega a
// CANDIDATE, con una nota explícita de que falta la validación activa.
function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const headerRaw = b64urlDecode(parts[0]);
  const payloadRaw = b64urlDecode(parts[1]);
  if (!headerRaw || !payloadRaw) return null;
  let header, payload;
  try {
    header = JSON.parse(headerRaw);
    payload = JSON.parse(payloadRaw);
  } catch {
    return null;
  }

  const findings = [];

  // OBSERVED: hechos objetivos sobre el token, sin implicar vulnerabilidad
  findings.push({ tier: "OBSERVED", msg: `alg: ${header.alg || "?"}` });
  findings.push({ tier: "OBSERVED", msg: payload.exp ? "exp: presente" : "exp: ausente" });
  findings.push({ tier: "OBSERVED", msg: payload.iss ? "iss: presente" : "iss: ausente" });
  findings.push({ tier: "OBSERVED", msg: payload.aud ? "aud: presente" : "aud: ausente" });

  if (payload.exp) {
    const days = Math.round((payload.exp * 1000 - Date.now()) / (1000 * 60 * 60 * 24));
    if (days > 0) findings.push({ tier: "OBSERVED", msg: `Vida del token: ~${days} día(s)` });
  }

  // SUSPICIOUS: patrones que ameritan revisión pero son comunes y a menudo benignos
  if (!payload.exp) {
    findings.push({ tier: "SUSPICIOUS", msg: "Sin claim exp: el token podría no expirar nunca (a veces es intencional en tokens de servicio)." });
  }
  if (!payload.aud) {
    findings.push({ tier: "SUSPICIOUS", msg: "Sin claim aud: si el backend no restringe la audiencia, el token podría reutilizarse entre servicios." });
  }
  if (payload.exp && payload.exp * 1000 - Date.now() > 1000 * 60 * 60 * 24 * 30) {
    findings.push({ tier: "SUSPICIOUS", msg: "Expiración larga (>30 días)." });
  }
  const sensitiveKeys = ["password", "secret", "ssn", "credit_card", "api_key"];
  const foundSensitive = Object.keys(payload).filter((k) => sensitiveKeys.includes(k.toLowerCase()));
  if (foundSensitive.length) {
    findings.push({ tier: "SUSPICIOUS", msg: `Claims con nombre sensible en el payload (no cifrado, solo codificado): ${foundSensitive.join(", ")}` });
  }

  // CANDIDATE: patrones con hipótesis de explotación concreta, pero sin confirmar
  if (header.alg && /^none$/i.test(header.alg)) {
    findings.push({ tier: "CANDIDATE", msg: "alg=none. SI el backend acepta este algoritmo sin validar firma, el token es forjable. No confirmado: requiere probarlo activamente (quitar la firma y reenviar)." });
  }
  if (header.alg && /^HS/i.test(header.alg)) {
    findings.push({ tier: "CANDIDATE", msg: "Algoritmo simétrico (HS*). SI el secreto es débil o reutilizado, el token es forjable por fuerza bruta/diccionario. No confirmado: requiere intentar crackearlo (jwt_tool/hashcat)." });
  }

  const maxTier = findings.some((f) => f.tier === "CANDIDATE") ? "CANDIDATE" : findings.some((f) => f.tier === "SUSPICIOUS") ? "SUSPICIOUS" : "OBSERVED";

  return { token, header, payload, findings, maxTier, confirmedVulnerability: false };
}

function findJwtsInText(text) {
  if (!text) return [];
  const matches = text.match(JWT_RE) || [];
  return [...new Set(matches)].map(decodeJwt).filter(Boolean);
}

// ---- CORS / CSP ---------------------------------------------------------

function analyzeCors(headers, contentType) {
  const findings = [];
  // CORS permisivo en assets estáticos (fuentes/imágenes) es práctica normal
  // de la web (por eso existe crossorigin="anonymous" para @font-face) — no
  // es un hallazgo, es ruido. Se omite el análisis para estos content-types.
  if (contentType && /^(font|image)\//i.test(contentType)) return findings;

  const acao = headers["access-control-allow-origin"];
  const acac = headers["access-control-allow-credentials"];
  const rawHeader = [
    acao ? `Access-Control-Allow-Origin: ${acao}` : null,
    acac ? `Access-Control-Allow-Credentials: ${acac}` : null,
  ].filter(Boolean).join("\n");

  if (acao === "*" && acac && acac.toLowerCase() === "true") {
    findings.push({
      severity: "critical", type: "CORS", directive: "Access-Control-Allow-Origin",
      observedValue: "*", confidence: "MEDIA", rawHeader,
      msg: "ACAO: * combinado con Allow-Credentials: true.",
      whyItMatters: "Esta combinación viola la especificación CORS (los navegadores no deberían aceptar '*' junto con credentials=true), pero algunos proxies o configuraciones intermedias la dejan pasar igual. Esto NO confirma por sí mismo que el navegador la esté aplicando — se requiere confirmar con un request real desde otro origen."
    });
  } else if (acao && acao !== "*" && acac && acac.toLowerCase() === "true") {
    findings.push({
      severity: "info", type: "CORS", directive: "Access-Control-Allow-Origin",
      observedValue: acao, confidence: "BAJA", rawHeader,
      msg: `ACAO refleja origen específico (${acao}) con credentials=true. Prueba con Origin arbitrario para confirmar si refleja cualquier valor.`,
      whyItMatters: "El servidor refleja un origen específico con credentials=true. Esto NO demuestra que refleje cualquier origen arbitrario — se requiere repetir el request con un header Origin distinto y comparar la respuesta."
    });
  }
  if (acao && /null/i.test(acao)) {
    findings.push({
      severity: "high", type: "CORS", directive: "Access-Control-Allow-Origin",
      observedValue: "null", confidence: "MEDIA", rawHeader,
      msg: "ACAO acepta origin 'null' (explotable vía iframe sandboxed / data: URI).",
      whyItMatters: "Aceptar el origen 'null' es potencialmente explotable desde un iframe sandboxed o un documento cargado vía data:URI, ambos capaces de generar ese origen. Requiere confirmar armando ese vector concreto."
    });
  }
  return findings;
}

function analyzeCsp(headers, contentType) {
  const findings = [];
  const csp = headers["content-security-policy"];
  // "Sin CSP" solo es un hallazgo razonable en el documento HTML principal:
  // CSP no aplica de la misma forma a respuestas JSON de una API o a un
  // archivo de fuente/imagen, así que reportarlo ahí es puro ruido.
  const isDocument = !contentType || /text\/html/i.test(contentType);
  if (!csp) {
    if (isDocument) {
      findings.push({
        severity: "low", type: "CSP", directive: "Content-Security-Policy",
        observedValue: "(ausente)", confidence: "ALTA", rawHeader: "(sin header Content-Security-Policy en la respuesta)",
        msg: "Sin header Content-Security-Policy.",
        whyItMatters: "Sin CSP, el navegador no aplica ninguna restricción adicional sobre qué scripts/estilos/recursos puede cargar la página. Esto por sí solo no es una vulnerabilidad confirmada — es la ausencia de una capa de mitigación."
      });
    }
    return findings;
  }
  if (/unsafe-inline/i.test(csp)) {
    findings.push({
      severity: "medium", type: "CSP", directive: "script-src / style-src",
      observedValue: "'unsafe-inline'", confidence: "BAJA / MEDIA", rawHeader: `Content-Security-Policy: ${csp}`,
      msg: "CSP permite 'unsafe-inline'.",
      whyItMatters: "'unsafe-inline' permite que se ejecuten scripts o estilos puestos directamente en el HTML, sin que la CSP los bloquee. Esto NO demuestra por sí mismo una XSS — se requiere un punto de inyección real para explotarlo."
    });
  }
  if (/unsafe-eval/i.test(csp)) {
    findings.push({
      severity: "medium", type: "CSP", directive: "script-src",
      observedValue: "'unsafe-eval'", confidence: "BAJA / MEDIA", rawHeader: `Content-Security-Policy: ${csp}`,
      msg: "CSP permite 'unsafe-eval'.",
      whyItMatters: "'unsafe-eval' permite determinadas formas de evaluación dinámica de código cuando son utilizadas por la aplicación. Esto NO demuestra por sí mismo una XSS. Se requiere analizar el contexto de ejecución."
    });
  }
  if (/\*\.googleapis\.com|\*\.amazonaws\.com|\bdata:/i.test(csp) && /script-src/i.test(csp)) {
    const match = csp.match(/script-src[^;]*/i);
    findings.push({
      severity: "info", type: "CSP", directive: "script-src",
      observedValue: match ? match[0] : "(wildcard/data: detectado)", confidence: "BAJA", rawHeader: `Content-Security-Policy: ${csp}`,
      msg: "script-src incluye wildcards amplios o 'data:', revisa JSONP/buckets abiertos en esos dominios.",
      whyItMatters: "Un script-src amplio (wildcards de dominio o 'data:') puede permitir cargar scripts desde ubicaciones que un atacante controle si existe un endpoint JSONP o un bucket de almacenamiento abierto en alguno de esos dominios. Requiere verificar cada dominio permitido individualmente."
    });
  }
  return findings;
}

// ---- Storage --------------------------------------------------------------

function domainKey(domain) {
  return STORAGE_PREFIX + domain;
}

async function getDomainData(domain) {
  const key = domainKey(domain);
  const res = await ext.storage.local.get(key);
  return (
    res[key] || {
      domain,
      endpoints: {},
      params: {},
      secrets: [],
      jwts: [],
      corsFindings: [],
      cspFindings: [],
      idorCandidates: [],
      notes: [],
      entityGraph: { nodes: {}, edges: {} },
      entitySeenInResponse: {},
      reflectedValues: {},
      dismissedFindings: {}
    }
  );
}

async function saveDomainData(domain, data) {
  await ext.storage.local.set({ [domainKey(domain)]: data });
}

// ---- Lock por dominio para evitar condiciones de carrera --------------
// webRequest puede disparar varios eventos casi simultáneos para el mismo
// dominio (ej. varios recursos cargando en paralelo). Sin serializar el
// read-modify-write de storage.local, dos updates concurrentes pueden
// pisarse y perder datos (el último en escribir gana, el resto se pierde).

const domainLocks = new Map();

function withDomainLock(domain, fn) {
  const prev = domainLocks.get(domain) || Promise.resolve();
  const next = prev.then(fn, fn).catch((err) => console.error("surface-hound lock error:", err));
  domainLocks.set(domain, next);
  return next;
}

// ---- Captura de tráfico ----------------------------------------------------

const urlHistoryByDomain = new Map();

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function extractParamsFromUrl(url) {
  try {
    return Array.from(new URL(url).searchParams.keys());
  } catch {
    return [];
  }
}

function headersToObject(headerArray) {
  const obj = {};
  for (const h of headerArray || []) obj[h.name.toLowerCase()] = h.value;
  return obj;
}

async function upsertEndpoint(domain, url, method) {
  const scope = await getScopeConfig();
  return withDomainLock(domain, async () => {
    const data = await getDomainData(domain);
    const key = `${method} ${url.split("?")[0]}`;
    const now = Date.now();
    const inScope = isInScope(domain, scope);
    if (!data.endpoints[key]) {
      data.endpoints[key] = { url, method, firstSeen: now, lastSeen: now, hits: 1, inScope };
    } else {
      data.endpoints[key].lastSeen = now;
      data.endpoints[key].hits += 1;
      data.endpoints[key].inScope = inScope;
    }

    const params = extractParamsFromUrl(url);
    const classified = classifyParams(params);
    for (const [param, hits] of Object.entries(classified)) {
      if (!data.params[param]) data.params[param] = { hits, sources: [] };
      if (!data.params[param].sources.includes(url) && data.params[param].sources.length < 8) {
        data.params[param].sources.push(url);
      }

      // Si el parámetro fue clasificado como candidato IDOR y su valor es
      // numérico/UUID, lo trackeamos también como candidato "de query" (ver
      // scoreIdorCandidate) para que aparezca junto a los de path, aunque
      // con menor score por defecto.
      const isIdorRule = hits.some((h) => h.name === "IDOR / Broken Access Control");
      if (isIdorRule) {
        let value = null;
        try {
          value = new URL(url).searchParams.get(param);
        } catch {}
        // Antes: /^[0-9a-fA-F-]{1,36}$/ -- aceptaba cualquier string hex+guiones
        // random (ej. tokens, hashes truncados) como si fuera un ID, generando
        // candidatos IDOR falsos. Ahora exige el formato real de un ID
        // (numérico) o de un UUID completo, igual que en el resto del código.
        if (value && ID_OR_UUID_VALUE_RE.test(value)) {
          const qKey = `${url.split("?")[0]}?${param}`;
          data.queryIdorSeen = data.queryIdorSeen || {};
          if (!data.queryIdorSeen[qKey]) data.queryIdorSeen[qKey] = [];
          if (!data.queryIdorSeen[qKey].includes(value) && data.queryIdorSeen[qKey].length < 20) {
            data.queryIdorSeen[qKey].push(value);
          }
        }
      }
    }

    if (!urlHistoryByDomain.has(domain)) urlHistoryByDomain.set(domain, []);
    const hist = urlHistoryByDomain.get(domain);
    hist.push(url);
    if (hist.length > 500) hist.splice(0, hist.length - 500); // cap de memoria
    ensureEntityGraph(data);
    data.idorCandidates = buildAllIdorCandidates(hist, data);

    await saveDomainData(domain, data);
  });
}

ext.webRequest.onBeforeRequest.addListener(
  (details) => {
    const domain = extractDomain(details.url);
    if (domain) upsertEndpoint(domain, details.url, details.method);
  },
  { urls: ["<all_urls>"] }
);

// "extraHeaders" es necesario en Chrome MV3 para poder leer Authorization/
// Cookie en requests cross-origin. Firefox (>=72) también lo soporta.
const EXTRA_HEADERS = ["extraHeaders"];

ext.webRequest.onSendHeaders.addListener(
  (details) => {
    const domain = extractDomain(details.url);
    if (!domain) return;
    withDomainLock(domain, async () => {
      const headers = headersToObject(details.requestHeaders);
      const authHeader = headers["authorization"] || "";
      const cookieHeader = headers["cookie"] || "";
      const hasAuth = !!(authHeader || cookieHeader);
      const jwts = findJwtsInText(authHeader + " " + cookieHeader);

      if (!jwts.length && !hasAuth) return;
      const data = await getDomainData(domain);

      if (hasAuth) {
        const epKey = `${details.method} ${details.url.split("?")[0]}`;
        if (data.endpoints[epKey]) data.endpoints[epKey].hasAuth = true;
      }
      if (jwts.length) {
        const existing = new Set(data.jwts.map((j) => j.token));
        for (const j of jwts) if (!existing.has(j.token)) data.jwts.push(j);
      }
      await saveDomainData(domain, data);
    });
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders", ...EXTRA_HEADERS]
);

ext.webRequest.onHeadersReceived.addListener(
  (details) => {
    const domain = extractDomain(details.url);
    if (!domain) return;
    withDomainLock(domain, async () => {
      const headers = headersToObject(details.responseHeaders);
      const contentType = headers["content-type"] || "";
      const corsFindings = analyzeCors(headers, contentType);
      const cspFindings = analyzeCsp(headers, contentType);
      if (!corsFindings.length && !cspFindings.length) return;
      const data = await getDomainData(domain);
      for (const f of corsFindings) if (!data.corsFindings.some((x) => x.msg === f.msg)) data.corsFindings.push({ ...f, url: details.url });
      for (const f of cspFindings) if (!data.cspFindings.some((x) => x.msg === f.msg)) data.cspFindings.push({ ...f, url: details.url });
      await saveDomainData(domain, data);
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", ...EXTRA_HEADERS]
);

// Mensajes desde content.js (secretos/JWTs vistos en JS/DOM de la página, y
// eventos de red del interceptor fetch/XHR)
ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "shx:findings") {
    // msg.pageUrl es location.href del frame que realmente mandó el mensaje
    // (puede ser un iframe de otro dominio). sender.tab?.url en cambio SIEMPRE
    // es la URL del frame principal de la pestaña, sin importar desde qué
    // iframe se originó -- si se prioriza eso, un secreto encontrado en un
    // iframe de terceros (SSO, widget de pagos) queda mal atribuido al
    // dominio del sitio principal en vez de al dominio real del iframe.
    const domain = extractDomain(msg.pageUrl || sender.tab?.url || "");
    if (!domain) return;
    withDomainLock(domain, async () => {
      const data = await getDomainData(domain);
      if (msg.secrets?.length) {
        const existing = new Set(data.secrets.map((s) => s.match + s.source));
        for (const s of msg.secrets) if (!existing.has(s.match + s.source)) data.secrets.push(s);
      }
      if (msg.jwtTokens?.length) {
        const existing = new Set(data.jwts.map((j) => j.token));
        for (const token of msg.jwtTokens) {
          if (existing.has(token)) continue;
          const decoded = decodeJwt(token);
          if (decoded) data.jwts.push(decoded);
        }
      }
      await saveDomainData(domain, data);
    }).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "shx:netevent") {
    handleNetEvent(msg);
    return false;
  }
});

async function handleNetEvent(msg) {
  const domain = extractDomain(msg.url || "");
  if (!domain) return;
  const scope = await getScopeConfig();

  await withDomainLock(domain, async () => {
    const data = await getDomainData(domain);
    ensureEntityGraph(data);

    const path = (msg.url || "").split("?")[0];
    const method = (msg.method || "GET").toUpperCase();
    const epKey = `${method} ${path}`;
    if (!data.endpoints[epKey]) {
      data.endpoints[epKey] = { url: msg.url, method, firstSeen: Date.now(), lastSeen: Date.now(), hits: 0, inScope: isInScope(domain, scope) };
    }
    const ep = data.endpoints[epKey];
    ep.lastSeen = Date.now();
    if (msg.status !== undefined) ep.status = msg.status;
    if (msg.contentType) ep.contentType = msg.contentType;
    if (msg.responseSize != null) ep.responseSize = msg.responseSize;
    if (msg.pageUrl) ep.sourcePage = msg.pageUrl;
    const jsSource = summarizeStack(msg.stack);
    if (jsSource) ep.jsSource = jsSource;
    if (msg.responseBody) ep.sampleResponseBody = msg.responseBody.slice(0, 400);

    // Extraer entidades del body de request/response y de la URL
    let reqEntities = [], resEntities = [];
    try {
      if (msg.requestBody) reqEntities = extractEntitiesFromObject(JSON.parse(msg.requestBody));
    } catch {}
    try {
      if (msg.responseBody) resEntities = extractEntitiesFromObject(JSON.parse(msg.responseBody));
    } catch {}
    const urlEntities = extractEntitiesFromUrl(msg.url);
    const allEntities = [...urlEntities, ...reqEntities, ...resEntities];

    if (allEntities.length >= 2) updateEntityGraph(data, allEntities, msg.url);

    for (const e of resEntities) {
      data.entitySeenInResponse[`${e.key}:${e.value}`] = true;
    }

    // Corroboración de reflexión: si el valor de un parámetro clasificado
    // como XSS/SSTI aparece literal en un cuerpo de respuesta, es una señal
    // real de reflexión (no confirma la vulnerabilidad, pero saca la
    // hipótesis de "solo por el nombre del parámetro" a "reflexión
    // observada"). Sin esto, cualquier `name=`/`title=`/`comment=` se
    // reportaría igual sin importar si el valor vuelve en la respuesta.
    if (msg.responseBody) {
      data.reflectedValues = data.reflectedValues || {};
      for (const [param, val] of Object.entries(data.params || {})) {
        const hits = val.hits || val;
        if (!hits.some((h) => h.needsReflection)) continue;
        for (const srcUrl of val.sources || []) {
          try {
            const value = new URL(srcUrl).searchParams.get(param);
            if (value && value.length >= 4 && msg.responseBody.includes(value)) {
              data.reflectedValues[`${param}=${value}`] = true;
            }
          } catch {}
        }
      }
    }

    // Re-scorear candidatos IDOR existentes con las señales nuevas (eco en response)
    if (data.idorCandidates?.length) {
      data.idorCandidates = data.idorCandidates.map((c) => scoreIdorCandidate(c, data)).sort((a, b) => b.score - a.score);
    }

    await saveDomainData(domain, data);
  });
}
