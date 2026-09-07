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
  // Un patrón "pelado" (sin *.) cubre el dominio Y todos sus subdominios --
  // igual que si se hubiera escrito con el wildcard explícito. La mayoría
  // de los programas de bug bounty listan un dominio raíz dando por hecho
  // que cubre sus subdominios; exigir el "*." a mano era una fuente real
  // de falsos "fuera de scope" (ej.: "clearstreet.io" en Permitido dejaba
  // "www.clearstreet.io" marcado fuera de scope con pruebas activas
  // bloqueadas, pese a no haber nada excluido). El "*." sigue aceptándose
  // como sinónimo explícito, por compatibilidad con scopes ya guardados.
  const bare = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
  return hostname === bare || hostname.endsWith("." + bare);
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
    payloads: ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd (encoding)", "....//....//etc/passwd (bypass de filtro simple)", "php://filter/convert.base64-encode/resource=index.php (si es PHP)"],
    // "page" es, con enorme diferencia, el nombre más común de parámetro
    // de PAGINACIÓN (page=2, page=15) -- sin este filtro, cualquier API
    // paginada generaba una alerta de LFI en cada request, ahogando el
    // resto de los hallazgos reales en ruido. Si TODOS los valores
    // observados para el parámetro son un entero simple, se omite el
    // hallazgo; basta con que UN SOLO valor observado se vea como ruta
    // (tenga "/", "\\", "..") para que se muestre igual -- no hace falta
    // ver ese valor en la primera request, se re-evalúa en cada una.
    suspiciousValue: (v) => !/^\d{1,6}$/.test(v),
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

// El objetivo que se está investigando controla libremente los nombres de
// sus propios parámetros de URL -- eso incluye, en principio, "__proto__",
// "constructor" o "prototype". Ninguna regla de PARAM_RULES matchea esos
// nombres literalmente hoy, así que no es explotable en la práctica ahora
// mismo -- pero esa protección es implícita (depende de que ninguna regla
// futura los matchee por accidente) y no una barrera real. Cualquier string
// que vaya a usarse como clave dinámica de un objeto (bracket assignment)
// debería pasar por este chequeo explícito primero, sin importar si hoy
// parece alcanzable o no.
const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function isSafeObjectKey(key) {
  return typeof key === "string" && !DANGEROUS_OBJECT_KEYS.has(key);
}

function classifyParams(paramEntries) {
  const results = {};
  for (const [p, value] of paramEntries) {
    const hits = [];
    for (const rule of PARAM_RULES) {
      if (rule.patterns.some((re) => re.test(p))) {
        // Reglas sin suspiciousValue (la mayoría) se comportan exactamente
        // igual que antes -- "suspicious" siempre true, ningún filtro
        // adicional. Solo reglas explícitamente marcadas (ver LFI/"page")
        // exigen que el valor observado se vea realmente sospechoso.
        const suspicious = rule.suspiciousValue ? rule.suspiciousValue(value) : true;
        hits.push({ name: rule.name, cwe: rule.cwe, hint: rule.hint, payloads: rule.payloads || [], needsReflection: !!rule.needsReflection, suspicious });
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

// Sin tope, updateEntityGraph podía crecer sin límite: conecta cada PAR de
// entidades distintas vistas en la misma respuesta (O(n²) por respuesta), y
// nunca dejaba de agregar nodos nuevos. Medido con una simulación de sesión
// larga realista (80 endpoints, no un caso extremo artificial): 5.5 MB solo
// en esta estructura, proyectando a ~20 MB en una sesión de varias horas
// contra un programa grande. Dos topes, atacando las dos fuentes del
// crecimiento por separado:
//  - MAX_ENTITIES_PER_RESPONSE acota el O(n²) de una sola respuesta con
//    muchísimos campos tipo-id (común en listados grandes de una API).
//  - MAX_ENTITY_NODES acota el crecimiento acumulado a lo largo de toda
//    la sesión -- una vez alcanzado, no se agregan nodos NUEVOS, pero los
//    ya existentes se siguen actualizando (count/urls) con normalidad.
const MAX_ENTITIES_PER_RESPONSE = 40;
const MAX_ENTITY_NODES = 3000;

function ensureEntityGraph(data) {
  if (!data.entityGraph) data.entityGraph = { nodes: {}, edges: {} };
  if (!data.entitySeenInResponse) data.entitySeenInResponse = {};
}

function updateEntityGraph(data, entities, sourceUrl) {
  ensureEntityGraph(data);
  if (data.domain) entityGraphDirty.add(data.domain); // ver saveDomainData: solo se reescribe la clave separada si esto está marcado
  const capped = entities.slice(0, MAX_ENTITIES_PER_RESPONSE);
  // Se trackean solo las entidades que realmente entraron al grafo (nodo ya
  // existente, o nodo nuevo que no chocó con el tope) -- así el cálculo de
  // pares más abajo nunca conecta un nodo que no llegó a registrarse.
  const tracked = [];
  for (const e of capped) {
    const nodeId = `${e.key}:${e.value}`;
    let node = data.entityGraph.nodes[nodeId];
    if (!node) {
      if (Object.keys(data.entityGraph.nodes).length >= MAX_ENTITY_NODES) continue;
      node = data.entityGraph.nodes[nodeId] = { key: e.key, value: e.value, count: 0, urls: [] };
    }
    node.count += 1;
    if (sourceUrl && !node.urls.includes(sourceUrl) && node.urls.length < 5) node.urls.push(sourceUrl);
    tracked.push({ nodeId, key: e.key });
  }
  // conectar cada par de entidades DISTINTAS (distinta key) vistas juntas en el mismo JSON
  for (let i = 0; i < tracked.length; i++) {
    for (let j = i + 1; j < tracked.length; j++) {
      const a = tracked[i].nodeId, b = tracked[j].nodeId;
      if (tracked[i].key === tracked[j].key) continue; // no conectar dos valores del mismo campo
      data.entityGraph.edges[a] = data.entityGraph.edges[a] || {};
      data.entityGraph.edges[b] = data.entityGraph.edges[b] || {};
      data.entityGraph.edges[a][b] = (data.entityGraph.edges[a][b] || 0) + 1;
      data.entityGraph.edges[b][a] = (data.entityGraph.edges[b][a] || 0) + 1;
    }
  }
}



// ---- GraphQL: detección de operación, introspection y candidatos BFLA -----
// Cualquier POST puede ser GraphQL sin importar la URL (no todos usan
// /graphql), así que la detección es por FORMA del body, no por ruta.
// Se hace en dos pasos a propósito por rendimiento: un chequeo barato de
// substring ANTES de intentar JSON.parse, para no pagar el costo de parsear
// el body de cada request JSON normal (la inmensa mayoría no es GraphQL).

const GRAPHQL_OP_RE = /^\s*(query|mutation|subscription)\s*([A-Za-z_][A-Za-z0-9_]*)?/;

function looksLikeGraphQLPayload(bodyText) {
  return typeof bodyText === "string" && bodyText.length > 0 && bodyText.length < 20000 &&
    (bodyText.includes('"query"') || bodyText.includes('"mutation"'));
}

// Soporta batching (GraphQL permite mandar un array de operaciones en un
// solo request -- es del propio checklist de reconocimiento GraphQL, no
// un caso raro).
// Hash simple y rápido (djb2) para el texto de una query anónima -- ver uso
// en recordGraphQLOperations: sin esto, TODAS las queries anónimas de un
// mismo endpoint comparten literalmente el string "(anónima)" como parte
// de la clave de deduplicación, así que queries con contenido totalmente
// distinto (una pide "users", otra "orders", otra "invoices") colapsaban
// en una sola entrada -- se perdía la visibilidad de todas menos la
// primera. Se normaliza el whitespace antes de hashear para que la MISMA
// query con formato ligeramente distinto (espacios, saltos de línea)
// siga colapsando correctamente entre sí, que es el comportamiento
// deseado para polling/refetch.
function simpleHash(str) {
  const normalized = str.replace(/\s+/g, " ").trim();
  let hash = 5381;
  for (let i = 0; i < normalized.length; i++) {
    hash = ((hash << 5) + hash + normalized.charCodeAt(i)) | 0;
  }
  return (hash >>> 0).toString(36);
}

function parseGraphQLOperations(bodyText) {
  if (!looksLikeGraphQLPayload(bodyText)) return [];
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return [];
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  const ops = [];
  for (const item of items.slice(0, 20)) {
    if (!item || typeof item.query !== "string" || !item.query.trim()) continue;
    const queryText = item.query;
    const match = queryText.match(GRAPHQL_OP_RE);
    // "{ campo }" sin la palabra "query" adelante es una query implícita
    // (shorthand válido de la spec de GraphQL), no una operación desconocida.
    const operationType = match ? match[1].toLowerCase() : "query";
    const operationName = (match && match[2]) || item.operationName || null;
    const hasIntrospectionKeyword = /__schema\b|__type\b/.test(queryText);
    ops.push({ operationType, operationName, hasIntrospectionKeyword, queryHash: operationName ? null : simpleHash(queryText) });
  }
  return ops;
}

// Confirma introspection HABILITADA (no solo intentada): exige que la
// respuesta tenga la forma real de una respuesta de introspection
// ("__schema" junto con "queryType"/"types"), no solo la palabra suelta --
// evita falsos positivos de un campo de negocio que coincidentemente se
// llame parecido.
function isIntrospectionResponseConfirmed(bodyText) {
  if (typeof bodyText !== "string" || bodyText.length > 550000 || !bodyText.includes("__schema")) return false;
  return /"queryType"/.test(bodyText) || /"types"\s*:\s*\[/.test(bodyText);
}

function ensureGraphQLData(data) {
  if (!data.graphqlOperations) data.graphqlOperations = {};
  if (!data.graphqlIntrospection) data.graphqlIntrospection = [];
}

function recordGraphQLOperations(data, url, method, ops) {
  if (!ops.length) return;
  ensureGraphQLData(data);
  const now = Date.now();
  for (const op of ops) {
    // Clave por endpoint+tipo+nombre: si la misma query se repite (polling,
    // refetch, etc.) se incrementa un contador en vez de acumular entradas
    // nuevas sin límite -- esto es lo que evita que el storage crezca sin
    // control en una sesión larga con una app que hace polling constante.
    // Para queries ANÓNIMAS (sin operationName), se usa el hash del texto
    // de la query en vez del literal "(anónima)" -- si no, dos queries
    // anónimas con contenido totalmente distinto colapsarían en la misma
    // clave, perdiendo visibilidad de una de las dos.
    const opKey = `${method} ${url.split("?")[0]}::${op.operationType}:${op.operationName || `(anónima:${op.queryHash})`}`;
    if (!data.graphqlOperations[opKey]) {
      data.graphqlOperations[opKey] = {
        endpoint: url, method,
        operationType: op.operationType,
        operationName: op.operationName,
        queryHash: op.queryHash, // solo para anonimas -- ver display en panel-core.js
        hits: 0,
        firstSeen: now,
        introspectionRequested: false,
      };
    }
    const rec = data.graphqlOperations[opKey];
    rec.hits++;
    rec.lastSeen = now;
    if (op.hasIntrospectionKeyword) rec.introspectionRequested = true;
  }
}

function recordGraphQLIntrospection(data, url, schemaJson) {
  ensureGraphQLData(data);
  const existing = data.graphqlIntrospection.find((f) => f.url === url);
  if (existing) return; // ya está registrado para este endpoint, no duplicar
  const finding = {
    url,
    confidence: 90,
    severity: "high",
    detectedAt: Date.now(),
    note: "Se observó una respuesta con la forma real de un esquema de introspection (__schema + queryType/types), no solo la palabra suelta. Esto confirma que introspection está habilitada en este endpoint -- en producción, normalmente debería estar deshabilitada."
  };
  const analysis = analyzeGraphQLSchema(schemaJson);
  if (analysis) finding.schemaAnalysis = analysis;
  data.graphqlIntrospection.push(finding);
}

// ---- Análisis del schema completo (cuando introspection está habilitada) --
// Cuando la introspection responde con el schema real, no solo confirmamos
// que está habilitada -- lo PARSEAMOS de verdad para sacar lo que un hunter
// senior mira a mano: qué mutations existen (incluso las que la UI de la
// app nunca llama -- "shadow API" clásico), qué campos están deprecados,
// qué campos suenan a datos sensibles, y el resto del sistema de tipos
// (inputs/enums/interfaces/unions) que hace falta para armar payloads
// válidos al probar cada operación.
//
// Límites de tamaño (MAX_TYPES/MAX_FIELDS_PER_TYPE/etc.) existen porque
// algunos schemas públicos reales (GitHub, Shopify) tienen miles de tipos
// -- sin tope, esto podría tardar en procesar y generar un objeto enorme
// para guardar en storage.local, que tiene cuota.

const MAX_TYPES = 500;
const MAX_FIELDS_PER_TYPE = 60;
const MAX_ENUM_VALUES = 25;
const MAX_ROOT_FIELDS = 150;

const SENSITIVE_FIELD_RE = /\b(password|passwd|secret|token|api[_-]?key|apikey|ssn|social[_-]?security|credit[_-]?card|creditcard|cvv|cvc|private[_-]?key|privatekey|access[_-]?token|refresh[_-]?token|auth[_-]?code|pin\b|otp\b|salary|bank[_-]?account)\b/i;

const PRIVILEGED_VERBS = new Set(["delete", "remove", "destroy", "ban", "suspend", "impersonate", "grant", "revoke", "setrole", "assignrole", "makeadmin", "promote", "demote", "disable", "enable", "force", "purge", "wipe", "resetall", "override"]);

// Antes esto era un regex ancladdo con ^ (solo detectaba el verbo si era
// literalmente la PRIMERA palabra del nombre) -- las convenciones de
// nombres en GraphQL varían mucho entre APIs (verbo-primero vs.
// sustantivo-primero, o con un namespace/prefijo como "adminDeleteUser"),
// así que mutations reales y peligrosas como "adminDeleteUser",
// "userDelete" (convención noun-first), o "hardDeleteUser" (modificador
// antes del verbo) nunca se marcaban como privilegiadas. Ahora se separa
// el nombre en "palabras" (camelCase/snake_case/kebab-case) y se busca el
// verbo como palabra completa en cualquier posición, no solo al inicio.
function looksLikePrivilegedMutation(name) {
  if (!name) return false;
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s_-]+/)
    .map((w) => w.toLowerCase());
  return words.some((w) => PRIVILEGED_VERBS.has(w));
}

function graphqlTypeToString(typeRef) {
  if (!typeRef) return "?";
  if (typeRef.kind === "NON_NULL") return graphqlTypeToString(typeRef.ofType) + "!";
  if (typeRef.kind === "LIST") return "[" + graphqlTypeToString(typeRef.ofType) + "]";
  return typeRef.name || "?";
}

function analyzeGraphQLSchema(schemaJson) {
  let root;
  try {
    root = JSON.parse(schemaJson);
  } catch {
    return null;
  }
  const schema = root?.data?.__schema;
  if (!schema || !Array.isArray(schema.types)) return null;

  const typeByName = {};
  for (const t of schema.types.slice(0, MAX_TYPES)) typeByName[t.name] = t;

  const queryTypeName = schema.queryType?.name;
  const mutationTypeName = schema.mutationType?.name;
  const subscriptionTypeName = schema.subscriptionType?.name;

  function extractRootFields(typeName) {
    const t = typeByName[typeName];
    if (!t || !Array.isArray(t.fields)) return [];
    return t.fields.slice(0, MAX_ROOT_FIELDS).map((f) => ({
      name: f.name,
      returnType: graphqlTypeToString(f.type),
      args: (f.args || []).map((a) => ({ name: a.name, type: graphqlTypeToString(a.type) })),
    }));
  }

  const queryFields = queryTypeName ? extractRootFields(queryTypeName) : [];
  const mutationFields = (mutationTypeName ? extractRootFields(mutationTypeName) : []).map((f) => ({
    ...f,
    looksPrivileged: looksLikePrivilegedMutation(f.name),
  }));
  const subscriptionFields = subscriptionTypeName ? extractRootFields(subscriptionTypeName) : [];

  // Argumentos interesantes: cualquier argumento (en cualquier campo, no
  // solo en la raíz) cuyo nombre suene a identificador de recurso -- son
  // los candidatos naturales a IDOR/BOLA vía GraphQL, igual que un
  // parámetro "id=" en REST.
  const ID_ARG_RE = /^(id|.*Id|.*_id|uuid|.*Uuid|.*_uuid|pk|key)$/;
  const interestingArgs = [];
  const deprecatedFields = [];
  const sensitiveFields = [];
  const enums = [];
  const inputs = [];
  const interfaces = [];
  const unions = [];

  for (const t of schema.types.slice(0, MAX_TYPES)) {
    if (!t.name || t.name.startsWith("__")) continue; // tipos internos de introspection, ruido

    if (t.kind === "ENUM" && Array.isArray(t.enumValues)) {
      enums.push({ name: t.name, values: t.enumValues.slice(0, MAX_ENUM_VALUES).map((v) => v.name) });
    }
    if (t.kind === "INPUT_OBJECT" && Array.isArray(t.inputFields)) {
      inputs.push({
        name: t.name,
        fields: t.inputFields.slice(0, MAX_FIELDS_PER_TYPE).map((f) => ({ name: f.name, type: graphqlTypeToString(f.type) })),
      });
      for (const f of t.inputFields) {
        if (SENSITIVE_FIELD_RE.test(f.name)) sensitiveFields.push({ typeName: t.name, fieldName: f.name });
      }
    }
    if (t.kind === "INTERFACE") {
      interfaces.push({ name: t.name, possibleTypesCount: (t.possibleTypes || []).length });
    }
    if (t.kind === "UNION") {
      unions.push({ name: t.name, possibleTypes: (t.possibleTypes || []).slice(0, 20).map((p) => p.name) });
    }
    if (Array.isArray(t.fields)) {
      for (const f of t.fields.slice(0, MAX_FIELDS_PER_TYPE)) {
        if (f.isDeprecated) deprecatedFields.push({ typeName: t.name, fieldName: f.name, reason: f.deprecationReason || null });
        if (SENSITIVE_FIELD_RE.test(f.name)) sensitiveFields.push({ typeName: t.name, fieldName: f.name });
        for (const a of f.args || []) {
          if (ID_ARG_RE.test(a.name)) {
            interestingArgs.push({ typeName: t.name, fieldName: f.name, argName: a.name, argType: graphqlTypeToString(a.type) });
          }
        }
      }
    }
  }

  return {
    totalTypes: schema.types.length,
    queryFields, mutationFields, subscriptionFields,
    deprecatedFields: deprecatedFields.slice(0, 100),
    sensitiveFields: sensitiveFields.slice(0, 100),
    interestingArgs: interestingArgs.slice(0, 100),
    enums: enums.slice(0, 100),
    inputs: inputs.slice(0, 100),
    interfaces: interfaces.slice(0, 100),
    unions: unions.slice(0, 100),
  };
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
    // Antes usaba indexOf (siempre el PRIMER {id} en la plantilla) -- en una
    // URL con varios segmentos tipo-ID (ej. /orgs/{id}/projects/{id}/tasks/{id}),
    // el bono de "nombre de recurso reconocible" siempre evaluaba la palabra
    // antes del primero ("orgs"), sin importar cuál de los segmentos fue el
    // que realmente demostró variación en el tráfico observado. El ÚLTIMO
    // {id} suele ser el más específico/relevante en APIs REST anidadas
    // (el recurso final que se está pidiendo, no sus ancestros en la ruta).
    const idIdx = segments.lastIndexOf("{id}");
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
    // Math.ceil, no Math.round -- con Math.round, un token de 30.4 días
    // mostraba "~30 día(s)" (redondeado hacia abajo) justo al lado de la
    // advertencia "Expiración larga (>30 días)", un mensaje que sonaba
    // contradictorio pese a que ambos datos eran ciertos por separado.
    // Con ceil, el valor mostrado nunca cruza el umbral de 30 hacia abajo.
    const days = Math.ceil((payload.exp * 1000 - Date.now()) / (1000 * 60 * 60 * 24));
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
  // Un nonce o hash presente en la CSP hace que los navegadores modernos
  // (con soporte CSP Level 2+, la inmensa mayoría hoy) IGNOREN
  // 'unsafe-inline' por completo -- es un patrón de compatibilidad
  // progresiva intencional (navegadores viejos sin soporte de nonce/hash
  // usan 'unsafe-inline', los modernos usan el nonce/hash y lo ignoran).
  // Antes se marcaba como hallazgo sin ninguna distinción, generando un
  // falso positivo real en una configuración segura e intencional.
  const HASH_OR_NONCE_RE = /'(nonce-[A-Za-z0-9+/=_-]+|sha(256|384|512)-[A-Za-z0-9+/=]+)'/i;
  if (/unsafe-inline/i.test(csp)) {
    const hasNonceOrHash = HASH_OR_NONCE_RE.test(csp);
    findings.push({
      severity: hasNonceOrHash ? "low" : "medium", type: "CSP", directive: "script-src / style-src",
      observedValue: "'unsafe-inline'", confidence: hasNonceOrHash ? "BAJA" : "BAJA / MEDIA", rawHeader: `Content-Security-Policy: ${csp}`,
      msg: hasNonceOrHash
        ? "CSP permite 'unsafe-inline', pero también incluye un nonce/hash."
        : "CSP permite 'unsafe-inline'.",
      whyItMatters: hasNonceOrHash
        ? "En navegadores con soporte CSP Level 2+ (la inmensa mayoría hoy), la presencia de un nonce/hash hace que 'unsafe-inline' se IGNORE por completo -- solo aplicaría en navegadores muy antiguos sin ese soporte. Vale la pena confirmar que el nonce/hash se genera de forma impredecible en cada request (si es estático o predecible, ahí sí sería explotable pese a esto)."
        : "'unsafe-inline' permite que se ejecuten scripts o estilos puestos directamente en el HTML, sin que la CSP los bloquee. Esto NO demuestra por sí mismo una XSS — se requiere un punto de inyección real para explotarlo."
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

// ---- Headers de seguridad básicos (HSTS, X-Frame-Options,
// X-Content-Type-Options, Permissions-Policy) -- reconocimiento estándar,
// más allá de CORS/CSP, que cualquier hunter chequea de entrada. Mismo
// principio que CSP: "ausente" solo se reporta sobre el documento HTML
// principal, no sobre cada asset/respuesta de API, para no generar ruido.
// ---- OAuth/OIDC: análisis del flujo de autorización, no solo del JWT
// resultante -- redirect_uri sin validar, state ausente (CSRF), PKCE
// ausente. Se detecta por la FORMA de los query params (client_id +
// redirect_uri + response_type juntos), no por una ruta fija, porque cada
// proveedor usa una URL distinta para su endpoint de autorización.

function analyzeOAuthRequest(url) {
  let params;
  try {
    params = new URL(url).searchParams;
  } catch {
    return null;
  }
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  const responseType = params.get("response_type");
  if (!clientId || !redirectUri || !responseType) return null; // no es un request de autorización OAuth

  const state = params.get("state");
  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method");
  const scope = params.get("scope");
  const nonce = params.get("nonce");

  const rawHeader = `client_id=${clientId}\nredirect_uri=${redirectUri}\nresponse_type=${responseType}${scope ? `\nscope=${scope}` : ""}`;
  const findings = [];

  if (!state) {
    findings.push({
      severity: "high", type: "OAuth/OIDC", directive: "state", observedValue: "(ausente)", confidence: "ALTA", rawHeader,
      msg: "Parámetro 'state' ausente en la solicitud de autorización.",
      whyItMatters: "Sin 'state', el flujo OAuth es vulnerable a CSRF: un atacante puede iniciar su propio flujo de autorización e inducir a la víctima a completarlo, vinculando la cuenta de la víctima a la sesión/cuenta del atacante en el proveedor externo. Confirmar requiere armar el flujo CSRF completo."
    });
  }
  if (!codeChallenge && responseType === "code") {
    findings.push({
      severity: "medium", type: "OAuth/OIDC", directive: "code_challenge (PKCE)", observedValue: "(ausente)", confidence: "MEDIA", rawHeader,
      msg: "PKCE ausente (sin 'code_challenge') en un flujo de tipo 'code'.",
      whyItMatters: "Sin PKCE, si el 'authorization code' es interceptado (otra app en el mismo dispositivo con el mismo redirect_uri, un log, un proxy) puede canjearse por un token sin necesitar el client_secret -- especialmente relevante en clientes públicos (SPA, apps móviles) que no pueden guardar un secreto de forma segura."
    });
  }
  if (responseType === "token" || responseType === "id_token") {
    findings.push({
      severity: "medium", type: "OAuth/OIDC", directive: "response_type", observedValue: responseType, confidence: "ALTA", rawHeader,
      msg: `Flujo implícito detectado (response_type=${responseType}).`,
      whyItMatters: "El flujo implícito devuelve el token directamente en el fragmento de la URL sin canjear un 'code' -- queda expuesto en el historial del navegador, en logs de proxies intermedios, y vía el header Referer si la página de destino carga recursos externos. OAuth 2.1 lo deprecó a favor de Authorization Code + PKCE."
    });
  }
  findings.push({
    severity: "info", type: "OAuth/OIDC", directive: "redirect_uri", observedValue: redirectUri, confidence: "BAJA", rawHeader,
    msg: `redirect_uri observado: ${redirectUri}`,
    whyItMatters: "Probá modificar este parámetro (subdominios, path traversal, '@' en la URL, doble encoding) para ver si el servidor de autorización valida estrictamente contra una whitelist exacta o acepta variantes -- un redirect_uri manipulable permite robar el code/token redirigiendo la respuesta a un dominio propio. Esto es una hipótesis a validar activamente, no un hallazgo confirmado."
  });

  return {
    flow: { clientId, redirectUri, responseType, scope: scope || null, nonceObserved: !!nonce, stateObserved: !!state, pkceObserved: !!codeChallenge, codeChallengeMethod: codeChallengeMethod || null },
    findings,
  };
}

function ensureOAuthData(data) {
  if (!data.oauthFlows) data.oauthFlows = {};
  if (!data.oauthFindings) data.oauthFindings = [];
}

function recordOAuthFlow(data, url) {
  const analysis = analyzeOAuthRequest(url);
  if (!analysis) return;
  ensureOAuthData(data);
  const key = `${analysis.flow.clientId}::${analysis.flow.redirectUri}`;
  const now = Date.now();
  if (!data.oauthFlows[key]) {
    data.oauthFlows[key] = { ...analysis.flow, firstSeen: now, lastSeen: now, hits: 1 };
  } else {
    const rec = data.oauthFlows[key];
    rec.lastSeen = now;
    rec.hits++;
    // si en algún request posterior SÍ aparece state/PKCE, no lo pisamos a "ausente" de nuevo
    rec.stateObserved = rec.stateObserved || analysis.flow.stateObserved;
    rec.pkceObserved = rec.pkceObserved || analysis.flow.pkceObserved;
  }
  for (const f of analysis.findings) {
    if (!data.oauthFindings.some((x) => x.msg === f.msg)) data.oauthFindings.push({ ...f, url });
  }
}

function analyzeSecurityHeaders(headers, contentType, url) {
  const findings = [];
  const isDocument = !contentType || /text\/html/i.test(contentType);
  if (!isDocument) return findings;

  // HSTS solo tiene sentido evaluarlo sobre HTTPS -- sobre HTTP puro
  // todavía no aplica (el navegador ni siquiera lo procesaría).
  let isHttps = false;
  try { isHttps = new URL(url).protocol === "https:"; } catch {}
  const hsts = headers["strict-transport-security"];
  if (isHttps && !hsts) {
    findings.push({
      severity: "low", type: "Security Header", directive: "Strict-Transport-Security",
      observedValue: "(ausente)", confidence: "ALTA", rawHeader: "(sin header Strict-Transport-Security)",
      msg: "Sin header Strict-Transport-Security (HSTS).",
      whyItMatters: "Sin HSTS, un usuario que escriba la URL sin https:// (o siga un link http://) puede quedar expuesto a un downgrade a HTTP antes de la redirección -- condición que habilita ataques de intermediario tipo SSL stripping en redes no confiables. No es una vulnerabilidad confirmada por sí sola, depende del escenario de red del usuario."
    });
  } else if (isHttps && hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    if (maxAge > 0 && maxAge < 15552000) { // menos de ~180 días, valor mínimo recomendado habitual
      const humanReadable = maxAge < 86400 ? `${Math.round(maxAge / 3600)} hora(s)` : `${Math.round(maxAge / 86400)} día(s)`;
      findings.push({
        severity: "info", type: "Security Header", directive: "Strict-Transport-Security",
        observedValue: hsts, confidence: "MEDIA", rawHeader: `Strict-Transport-Security: ${hsts}`,
        msg: `HSTS presente pero con max-age bajo (${maxAge}s, ${humanReadable}).`,
        whyItMatters: "Un max-age corto reduce la ventana real de protección de HSTS -- si el header deja de enviarse por un error de despliegue o una CDN mal configurada, la protección expira rápido en vez de mantenerse por meses."
      });
    }
  }

  // X-Frame-Options: la directiva frame-ancestors de CSP puede cumplir el
  // mismo rol y es más moderna -- si CSP ya la trae, no tiene sentido
  // reportar la ausencia de X-Frame-Options como si nada la cubriera.
  const csp = headers["content-security-policy"] || "";
  const hasFrameAncestors = /frame-ancestors/i.test(csp);
  const xfo = headers["x-frame-options"];
  if (!xfo && !hasFrameAncestors) {
    findings.push({
      severity: "medium", type: "Security Header", directive: "X-Frame-Options / CSP frame-ancestors",
      observedValue: "(ausente)", confidence: "MEDIA", rawHeader: "(sin X-Frame-Options ni frame-ancestors en CSP)",
      msg: "Sin X-Frame-Options ni CSP frame-ancestors.",
      whyItMatters: "Sin ninguno de los dos, la página puede embeberse en un <iframe> de un sitio de terceros -- condición necesaria (no suficiente) para clickjacking. Hace falta un flujo de UI sensible (cambio de contraseña, transferencia, autorización OAuth) para que esto sea explotable de verdad; requiere armar la prueba de concepto con un iframe real."
    });
  }

  // X-Content-Type-Options
  const xcto = headers["x-content-type-options"];
  if (!xcto || !/nosniff/i.test(xcto)) {
    findings.push({
      severity: "low", type: "Security Header", directive: "X-Content-Type-Options",
      observedValue: xcto || "(ausente)", confidence: "ALTA",
      rawHeader: xcto ? `X-Content-Type-Options: ${xcto}` : "(sin header X-Content-Type-Options)",
      msg: "Sin X-Content-Type-Options: nosniff.",
      whyItMatters: "Sin 'nosniff', el navegador puede intentar adivinar el tipo de contenido en vez de respetar el Content-Type declarado -- relevante sobre todo si el sitio sirve contenido subido por usuarios (avatares, adjuntos) desde el mismo origen, donde MIME-sniffing puede habilitar XSS almacenado en escenarios específicos."
    });
  }

  // Permissions-Policy
  if (!headers["permissions-policy"]) {
    findings.push({
      severity: "info", type: "Security Header", directive: "Permissions-Policy",
      observedValue: "(ausente)", confidence: "ALTA", rawHeader: "(sin header Permissions-Policy)",
      msg: "Sin header Permissions-Policy.",
      whyItMatters: "Sin Permissions-Policy, no hay restricción explícita sobre qué APIs del navegador (cámara, micrófono, geolocalización, USB, etc.) puede usar la página o un iframe de terceros embebido en ella. Es una capa de mitigación ausente, no una vulnerabilidad confirmada por sí sola."
    });
  }

  return findings;
}

// ---- Storage --------------------------------------------------------------

function domainKey(domain) {
  return STORAGE_PREFIX + domain;
}

// entityGraph vive en su propia clave, separada del resto -- es la
// estructura más pesada con diferencia (medida en varios MB en sesiones
// largas), y se marca "sucia" (entityGraphDirty) solo cuando updateEntityGraph
// la modifica de verdad, para no reescribirla en CADA guardado cuando lo
// que cambió fue otra cosa sin relación (un endpoint, un hallazgo CORS).
function entityGraphKey(domain) {
  return `${domainKey(domain)}::entities`;
}
const entityGraphDirty = new Set();

// ---- Cache en memoria de los datos por dominio + guardado con debounce ---
// Antes, CADA evento capturado hacía un ciclo completo de lectura+escritura
// del blob entero de storage.local para ese dominio -- en una ráfaga de
// varios requests casi simultáneos (común: varios recursos de una página
// cargando a la vez), eso significaba re-leer Y re-escribir el mismo
// objeto grande una y otra vez, aunque el lock ya serializaba
// correctamente el orden. Con el cache, solo se lee de storage.local UNA
// vez por dominio (la primera vez que se lo toca en esta sesión del
// service worker); las escrituras se agrupan con un debounce corto (200ms),
// así varios cambios seguidos terminan en un solo write real en vez de uno
// por evento.
//
// Tradeoff conocido, documentado a propósito: si el service worker de MV3
// se suspende por inactividad justo en la ventana de 200ms entre un cambio
// y su flush, ese cambio puntual podría no llegar a guardarse. Se eligió
// una ventana corta específicamente para minimizar ese riesgo (mucho menor
// al umbral típico de suspensión por inactividad de Chrome), pero no es
// una garantía absoluta -- es el mismo tipo de tradeoff que ya se acepta en
// cualquier sistema con buffering de escritura.
const domainDataCache = new Map();
const pendingSaveTimers = new Map();
const SAVE_DEBOUNCE_MS = 200;

// domainDataCache no tenía ningún tope -- chrome.webRequest captura TODO
// el tráfico global del navegador, no solo el dominio activo en el panel,
// así que una sesión de navegación normal y larga (cientos de pestañas
// distintas, no todas targets de bug bounty) acumulaba una entrada por
// cada dominio visitado, para siempre, mientras el service worker
// siguiera vivo. Medido con una simulación de 300 dominios: ~373 KB,
// proyectando a ~1.2 MB en 1000 dominios -- mismo patrón que ya se
// corrigió para entityGraph, pero en la capa de cache. LRU simple: Map
// preserva el orden de inserción, así que "tocar" una entrada (delete +
// set) la mueve al final: la más vieja sin tocar queda siempre al
// principio, lista para evictar. Nunca se evicta un dominio con una
// escritura pendiente sin flushear (perdería ese cambio en silencio).
const MAX_CACHED_DOMAINS = 200;

// Un dominio queda protegido de eviction mientras tenga una escritura
// pendiente (pendingSaveTimers) -- pero esa protección solo se activa AL
// FINAL de saveDomainData(), no durante todo el procesamiento previo
// (clasificar parámetros, actualizar el grafo de entidades, etc.) que
// pasa ENTRE getDomainData() y saveDomainData() dentro del mismo
// callback bloqueado. Confirmado con test + tracing: bajo ráfagas de
// muchos dominios DISTINTOS simultáneos, un dominio podía quedar
// evictado a mitad de su propio procesamiento (todavía sin timer
// registrado), y terminaba en un ciclo de evict/re-agregar que le
// impedía guardarse del todo -- se perdían dominios enteros en
// silencio. domainsInFlight cubre TODA la ventana de procesamiento
// activo (desde que arranca el callback bloqueado hasta que termina),
// no solo la cola del debounce.
const domainsInFlight = new Set();

function touchCacheEntry(domain, data) {
  domainDataCache.delete(domain);
  domainDataCache.set(domain, data);
}

function evictLRUIfNeeded() {
  if (domainDataCache.size <= MAX_CACHED_DOMAINS) return;
  for (const key of domainDataCache.keys()) {
    if (domainDataCache.size <= MAX_CACHED_DOMAINS) break;
    if (pendingSaveTimers.has(key) || domainsInFlight.has(key)) continue;
    domainDataCache.delete(key);
  }
}

async function getDomainData(domain) {
  if (domainDataCache.has(domain)) {
    const data = domainDataCache.get(domain);
    touchCacheEntry(domain, data);
    return data;
  }
  const key = domainKey(domain);
  const egKey = entityGraphKey(domain);
  const res = await ext.storage.local.get([key, egKey]);
  const data = res[key] || {
    domain,
    endpoints: {},
    params: {},
    secrets: [],
    jwts: [],
    corsFindings: [],
    cspFindings: [],
    idorCandidates: [],
    notes: [],
    entitySeenInResponse: {},
    reflectedValues: {},
    dismissedFindings: {},
    graphqlOperations: {},
    graphqlIntrospection: [],
    techFingerprint: {},
    sourceMaps: {},
    securityHeaderFindings: [],
    oauthFlows: {},
    oauthFindings: []
  };
  data.entityGraph = res[egKey] || { nodes: {}, edges: {} };
  domainDataCache.set(domain, data);
  evictLRUIfNeeded();
  return data;
}

function saveDomainData(domain, data) {
  // .set() en un Map sobre una clave YA existente actualiza el valor pero
  // NO cambia su posición en el orden de inserción -- para que una
  // escritura también cuente como "uso reciente" a efectos del LRU (no
  // solo las lecturas), se usa touchCacheEntry acá también.
  touchCacheEntry(domain, data);
  evictLRUIfNeeded();
  if (pendingSaveTimers.has(domain)) return; // ya hay un flush programado -- viaja igual porque es el mismo objeto en memoria
  // Importante: NO se retorna una promesa ligada al propio flush del
  // setTimeout. withDomainLock espera (`await saveDomainData(...)`) antes
  // de dejar avanzar al siguiente evento de la cola -- si esta función
  // esperara los 200ms del debounce para resolver, terminaría atando TODA
  // la cadena del lock a ese delay (cada evento se volvería más lento en
  // vez de más rápido, justo lo opuesto de lo que se busca). El cache en
  // memoria ya quedó actualizado de forma síncrona arriba, así que
  // cualquier lectura posterior dentro de esta sesión del service worker
  // ve los datos correctos sin depender de que el disco ya se haya
  // actualizado.
  const timer = setTimeout(async () => {
    pendingSaveTimers.delete(domain);
    const current = domainDataCache.get(domain);
    if (current) {
      const { entityGraph, ...rest } = current;
      const toWrite = { [domainKey(domain)]: rest };
      // entityGraph solo se reescribe si updateEntityGraph la tocó de
      // verdad desde el último flush -- si lo que cambió fue un endpoint o
      // un hallazgo CORS sin relación, no hace falta volver a serializar
      // varios MB de nodos/aristas que no cambiaron en nada.
      if (entityGraphDirty.has(domain)) {
        toWrite[entityGraphKey(domain)] = entityGraph;
        entityGraphDirty.delete(domain);
      }
      try {
        await ext.storage.local.set(toWrite);
        await ensureDomainRegistered(domain);
        await checkAndNotifySevereFindings(domain, rest);
      } catch (e) {
        console.error("surface-hound: error guardando datos de", domain, e);
      }
    }
    // Al FINAL, ya con la escritura de este dominio resuelta -- llamarlo
    // antes (justo al quitar la protección del debounce) arriesgaba
    // evictar este MISMO dominio antes de leerlo/escribirlo. Sin este
    // reintento en algún punto, si muchos dominios de una ráfaga
    // terminaban de flushear más o menos juntos, nada volvía a evaluar
    // si ya se podía achicar el cache de vuelta al tope.
    evictLRUIfNeeded();
  }, SAVE_DEBOUNCE_MS);
  pendingSaveTimers.set(domain, timer);
}

// ---- Monitoreo continuo: notificaciones cuando aparece algo de alta
// severidad, sin que el hunter tenga que estar mirando el panel activamente.
//
// El contador de "última cantidad notificada" se persiste en storage (no
// en una variable en memoria) a propósito: el service worker de una
// extensión MV3 se reinicia solo, sin aviso, cuando el navegador lo
// considera inactivo -- cualquier estado en memoria (un Map, una
// variable) se pierde en ese momento. Si el contador viviera solo en
// memoria, un reinicio del service worker haría que el próximo hallazgo
// se comparara contra 0 en vez de contra lo ya notificado, generando una
// notificación duplicada para algo que el hunter ya vio. Persistiendo el
// contador, tanto esta función (llamada en tiempo real desde
// saveDomainData) como el chequeo periódico de abajo leen y escriben el
// MISMO valor -- ninguno de los dos puede duplicar lo que el otro ya
// notificó.
const SEVERE_NOTIFY_PREFIX = "shxnotif:";

function countSevereFindings(data) {
  const isSevere = (f) => f.severity === "critical" || f.severity === "high";
  let count = 0;
  count += (data.corsFindings || []).filter(isSevere).length;
  count += (data.cspFindings || []).filter(isSevere).length;
  count += (data.securityHeaderFindings || []).filter(isSevere).length;
  count += (data.oauthFindings || []).filter(isSevere).length;
  count += (data.idorCandidates || []).filter((c) => c.level === "HIGH").length;
  // Cualquier secreto detectado ya pasó el filtro de entropía/placeholders
  // (ver v0.27.0) -- no hace falta un umbral de severidad adicional acá,
  // un secreto real siempre amerita una alerta.
  count += (data.secrets || []).length;
  return count;
}

async function checkAndNotifySevereFindings(domain, data) {
  if (!ext.notifications?.create) return; // entorno sin soporte (tests, Firefox sin el permiso concedido, etc.)
  const current = countSevereFindings(data);
  const key = SEVERE_NOTIFY_PREFIX + domain;
  let previous = 0;
  try {
    const res = await ext.storage.local.get(key);
    previous = res[key] || 0;
  } catch {
    return; // si no se puede leer el contador, no arriesgar una notificación duplicada -- mejor omitir esta vez
  }
  if (current > previous) {
    const delta = current - previous;
    try {
      ext.notifications.create(`shx-severe-${domain}-${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "Surface Hound -- nuevo hallazgo de alta severidad",
        message: `${domain}: ${delta} hallazgo${delta === 1 ? "" : "s"} nuevo${delta === 1 ? "" : "s"} de severidad alta/crítica.`,
      });
    } catch (e) {
      console.error("surface-hound: error creando notificación", e);
    }
  }
  if (current !== previous) {
    try {
      await ext.storage.local.set({ [key]: current });
    } catch (e) {
      console.error("surface-hound: error guardando contador de notificación", e);
    }
  }
}

// Chequeo periódico (además del de tiempo real de arriba): re-lee TODOS
// los dominios guardados y aplica la misma comparación contra su propio
// contador persistido. Esto no es redundante con el chequeo en tiempo
// real -- cubre el caso en que el service worker se reinició (perdiendo
// cualquier timer/debounce en curso) mientras había tráfico pasando, o en
// que el hunter dejó varias pestañas abiertas navegando sin mirar el
// panel de ningún dominio en particular.
const SEVERE_DIGEST_ALARM = "shx-severe-digest";

// ---- Registro liviano de dominios conocidos ---------------------------
// chrome.storage.local.get() solo admite "todo" (null) o una lista
// explícita de claves -- no hay forma de pedir "todo excepto las claves
// que terminan en ::entities". Sin este registro, el único modo de
// enumerar los dominios guardados era get(null), que trae TAMBIÉN los
// entity graphs (potencialmente varios MB cada uno) a memoria solo para
// descartarlos después en el filtro -- una carga innecesaria cada 30
// minutos, incluso con el navegador inactivo. Con el registro, el digest
// pide explícitamente solo las claves `shx:<dominio>` que le interesan.
const KNOWN_DOMAINS_KEY = "shxmeta:domains";
const knownDomainsCache = new Set(); // evita relecturas repetidas del registro para dominios ya vistos en esta vida del service worker

async function ensureDomainRegistered(domain) {
  if (knownDomainsCache.has(domain)) return;
  try {
    const res = await ext.storage.local.get(KNOWN_DOMAINS_KEY);
    const list = res[KNOWN_DOMAINS_KEY] || [];
    if (!list.includes(domain)) {
      list.push(domain);
      await ext.storage.local.set({ [KNOWN_DOMAINS_KEY]: list });
    }
    knownDomainsCache.add(domain);
  } catch (e) {
    console.error("surface-hound: error registrando dominio conocido", e);
  }
}

async function runSevereFindingsDigest() {
  if (!ext.notifications?.create) return;
  let domains;
  try {
    const meta = await ext.storage.local.get(KNOWN_DOMAINS_KEY);
    domains = meta[KNOWN_DOMAINS_KEY] || [];
  } catch (e) {
    console.error("surface-hound: error leyendo el registro de dominios para el digest periódico", e);
    return;
  }
  if (!domains.length) return;
  const keys = domains.map(domainKey);
  let all;
  try {
    all = await ext.storage.local.get(keys);
  } catch (e) {
    console.error("surface-hound: error leyendo storage para el digest periódico", e);
    return;
  }
  // Auto-limpieza del registro: si "Limpiar dominio"/"Limpiar TODOS" borró
  // los datos de un dominio, su entrada en el registro queda huérfana --
  // se saca acá mismo (no hace falta que el panel conozca este registro
  // interno de background.js para mantenerlo sincronizado).
  const staleDomains = [];
  for (const domain of domains) {
    const data = all[domainKey(domain)];
    if (data) {
      await checkAndNotifySevereFindings(domain, data);
    } else {
      staleDomains.push(domain);
    }
  }
  if (staleDomains.length) {
    const stillValid = domains.filter((d) => !staleDomains.includes(d));
    for (const d of staleDomains) knownDomainsCache.delete(d);
    try {
      await ext.storage.local.set({ [KNOWN_DOMAINS_KEY]: stillValid });
    } catch (e) {
      console.error("surface-hound: error limpiando registro de dominios huérfanos", e);
    }
  }
}

if (ext.alarms) {
  ext.alarms.create(SEVERE_DIGEST_ALARM, { periodInMinutes: 30 });
  ext.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === SEVERE_DIGEST_ALARM) runSevereFindingsDigest();
  });
}

// Mantiene el cache sincronizado con cambios que NO pasaron por
// saveDomainData -- "Limpiar dominio"/"Limpiar TODOS" desde el panel, la
// migración de fusión de "www.", o una escritura directa a la clave de un
// dominio que no es el activo (ver fix de contaminación cruzada de source
// maps). Sin esto, el cache podría "resucitar" datos que el usuario
// acababa de borrar si llegara un evento nuevo antes de refrescarse solo.
ext.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  const ENTITY_SUFFIX = "::entities";
  for (const [key, change] of Object.entries(changes)) {
    if (!key.startsWith(STORAGE_PREFIX) || key.startsWith(CONFIG_PREFIX)) continue;
    if (key.endsWith(ENTITY_SUFFIX)) {
      // La clave separada de entityGraph -- no es un dominio en sí misma,
      // es la sub-estructura de uno. Si ese dominio está en cache, se
      // actualiza solo esa parte sin tocar el resto.
      const domain = key.slice(STORAGE_PREFIX.length, -ENTITY_SUFFIX.length);
      const cached = domainDataCache.get(domain);
      if (cached) cached.entityGraph = change.newValue || { nodes: {}, edges: {} };
      continue;
    }
    const domain = key.slice(STORAGE_PREFIX.length);
    if (change.newValue === undefined) {
      domainDataCache.delete(domain);
    } else {
      // Esta clave nunca trae entityGraph adentro (vive aparte) -- se
      // preserva el que ya estuviera en cache para no perderlo al
      // reemplazar el resto de los datos.
      const existingGraph = domainDataCache.get(domain)?.entityGraph;
      const newData = { ...change.newValue, entityGraph: existingGraph || { nodes: {}, edges: {} } };
      touchCacheEntry(domain, newData);
    }
  }
  // El dato de este batch YA está persistido en disco antes de que este
  // listener se dispare (onChanged llega DESPUÉS de la escritura real,
  // no antes) -- así que podar acá, incluso el dominio recién tocado, es
  // seguro sin ninguna de las precauciones que hicieron falta para el
  // flush del debounce (ahí sí podar antes de tiempo podía perder una
  // escritura todavía sin persistir). Sin este llamado, cualquier
  // escritura que no pase por saveDomainData -- Importar sesión, un
  // "Limpiar dominio" disparado desde OTRA pestaña del panel, o
  // cualquier sincronización entre pestañas -- bypaseaba el tope de LRU
  // por completo. Confirmado con test: 300 escrituras por esta vía
  // dejaban el cache en 300 entradas, no en el tope de 200.
  evictLRUIfNeeded();
});

// ---- Lock por dominio para evitar condiciones de carrera --------------
// webRequest puede disparar varios eventos casi simultáneos para el mismo
// dominio (ej. varios recursos cargando en paralelo). Sin serializar el
// read-modify-write de storage.local, dos updates concurrentes pueden
// pisarse y perder datos (el último en escribir gana, el resto se pierde).

const domainLocks = new Map();

function withDomainLock(domain, fn) {
  const prev = domainLocks.get(domain) || Promise.resolve();
  const wrappedFn = async () => {
    domainsInFlight.add(domain);
    try {
      return await fn();
    } finally {
      domainsInFlight.delete(domain);
      // En una ráfaga con muchos dominios simultáneos, TODOS pueden estar
      // "en vuelo" a la vez cuando se intenta podar por primera vez --
      // evictLRUIfNeeded() solo se dispara como efecto colateral de
      // AGREGAR una entrada nueva, nunca cuando un dominio deja de estar
      // protegido. Sin este reintento acá, una vez que la ráfaga termina
      // el cache podía quedarse por encima del tope para siempre (nada
      // vuelve a intentar podar si no llegan más dominios nuevos).
      evictLRUIfNeeded();
    }
  };
  const next = prev.then(wrappedFn, wrappedFn).catch((err) => console.error("surface-hound lock error:", err));
  domainLocks.set(domain, next);
  return next;
}

// ---- Captura de tráfico ----------------------------------------------------

const urlHistoryByDomain = new Map();

// A diferencia de extractDomain() (que normaliza "www." para decidir en
// qué BUCKET de storage guardar los datos -- www.x.com y x.com comparten
// bucket), esto devuelve el hostname REAL de la URL, sin normalizar.
// Necesario para evaluar scope: un patrón como "www.dominio.com" (con
// www, tal como lo escribió el usuario) debe evaluarse contra el
// hostname real de cada request, no contra el bucket ya normalizado --
// si se usara el bucket, ese patrón CON www nunca podría matchear (el
// bucket le saca el "www." antes de llegar acá), aunque la URL real sí
// lo tuviera. Confirmado como una inconsistencia real: el mismo request
// podía guardar inScope:false acá mientras que un chequeo en vivo sobre
// la misma URL (que sí usa el hostname real) decía inScope:true.
function realHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function extractDomain(url) {
  try {
    // "www.target.com" y "target.com" son, en la inmensa mayoría de los
    // casos, el mismo target/app -- pero antes generaban dos claves de
    // storage completamente separadas ("shx:target.com" vs
    // "shx:www.target.com"), así que hallazgos detectados en una variante
    // "desaparecían" al volver a la otra sin que nada los borrara: solo
    // quedaban en un bucket distinto al que se estaba mirando. Se normaliza
    // SOLO el prefijo "www." (no otros subdominios como api./admin., que sí
    // suelen ser apps distintas y deben seguir separados).
    const hostname = new URL(url).hostname;
    return hostname.replace(/^www\./i, "");
  } catch {
    return null;
  }
}

function extractParamsFromUrl(url) {
  try {
    return Array.from(new URL(url).searchParams.entries());
  } catch {
    return [];
  }
}

function headersToObject(headerArray) {
  const obj = {};
  for (const h of headerArray || []) obj[h.name.toLowerCase()] = h.value;
  return obj;
}

// ---- Fingerprinting de tecnología (100% pasivo) ---------------------------
// Tres fuentes de señal, cada una ve algo que las otras no pueden:
//  1. Headers de respuesta + cookies (acá mismo, via webRequest -- ve
//     Set-Cookie completo, incluso cookies HttpOnly que document.cookie
//     nunca podría ver desde JS)
//  2. Firmas en el DOM (content.js, mundo aislado -- comparte el DOM con
//     la página aunque no sus variables JS)
//  3. Variables JS globales (network-interceptor.js, mundo MAIN -- ve
//     window.React/Vue/etc., que el mundo aislado de content.js NO puede
//     ver aunque comparta el mismo DOM)
// Las tres alimentan la misma tabla dedupeada por nombre de tecnología, con
// confianza que sube si se corrobora por más de una fuente.

function getAllHeaderValues(headerArray, name) {
  // headersToObject() colapsa duplicados (se queda con el último) -- para
  // Set-Cookie eso pierde información real, porque una respuesta típica
  // manda VARIOS Set-Cookie a la vez (sesión + CSRF + preferencias, etc.)
  // y cada uno es una pista de tecnología distinta.
  // El filtro "typeof h.value === 'string'" existe porque la propia
  // documentación de chrome.webRequest contempla que un header llegue con
  // binaryValue en vez de value cuando su contenido no es UTF-8 válido
  // (un servidor exótico/mal configurado puede producir esto de verdad) --
  // sin este guard, un solo header así tira todo el análisis de headers
  // de esa respuesta, aunque el resto ya se hubiera calculado.
  return (headerArray || []).filter((h) => h.name.toLowerCase() === name && typeof h.value === "string").map((h) => h.value);
}

const TECH_HEADER_RULES = [
  { header: "x-powered-by", re: /php/i, name: "PHP", category: "Lenguaje", confidence: 85 },
  { header: "x-powered-by", re: /express/i, name: "Express.js", category: "Framework", confidence: 85 },
  { header: "x-powered-by", re: /asp\.net/i, name: "ASP.NET", category: "Framework", confidence: 85 },
  { header: "x-powered-by", re: /next\.js/i, name: "Next.js", category: "Framework frontend", confidence: 90 },
  { header: "x-aspnet-version", re: /.+/, name: "ASP.NET", category: "Framework", confidence: 80 },
  { header: "x-aspnetmvc-version", re: /.+/, name: "ASP.NET MVC", category: "Framework", confidence: 85 },
  { header: "x-generator", re: /drupal/i, name: "Drupal", category: "CMS", confidence: 85 },
  { header: "x-drupal-cache", re: /.+/, name: "Drupal", category: "CMS", confidence: 80 },
  { header: "server", re: /nginx/i, name: "nginx", category: "Servidor web", confidence: 70 },
  { header: "server", re: /apache/i, name: "Apache", category: "Servidor web", confidence: 70 },
  { header: "server", re: /microsoft-iis/i, name: "IIS", category: "Servidor web", confidence: 80 },
  { header: "server", re: /cloudflare/i, name: "Cloudflare", category: "WAF/CDN", confidence: 80 },
  { header: "server", re: /gunicorn/i, name: "Gunicorn (Python)", category: "Servidor web", confidence: 80 },
  { header: "server", re: /kestrel/i, name: "Kestrel (ASP.NET Core)", category: "Servidor web", confidence: 80 },
  { header: "server", re: /litespeed/i, name: "LiteSpeed", category: "Servidor web", confidence: 75 },
  { header: "server", re: /caddy/i, name: "Caddy", category: "Servidor web", confidence: 75 },
  { header: "cf-ray", re: /.+/, name: "Cloudflare", category: "WAF/CDN", confidence: 90 },
  { header: "x-sucuri-id", re: /.+/, name: "Sucuri", category: "WAF/CDN", confidence: 90 },
  { header: "x-akamai-transformed", re: /.+/, name: "Akamai", category: "WAF/CDN", confidence: 85 },
  { header: "x-varnish", re: /.+/, name: "Varnish", category: "Cache/CDN", confidence: 75 },
  { header: "x-amz-cf-id", re: /.+/, name: "Amazon CloudFront", category: "WAF/CDN", confidence: 85 },
  { header: "x-vercel-id", re: /.+/, name: "Vercel", category: "Hosting", confidence: 85 },
];

const TECH_COOKIE_RULES = [
  { re: /^PHPSESSID$/i, name: "PHP", category: "Lenguaje", confidence: 75 },
  { re: /^laravel_session$/i, name: "Laravel", category: "Framework", confidence: 90 },
  { re: /^XSRF-TOKEN$/i, name: "Laravel / Angular", category: "Framework", confidence: 45 },
  { re: /^JSESSIONID$/i, name: "Java (Servlet/JSP)", category: "Lenguaje/Framework", confidence: 75 },
  { re: /^connect\.sid$/i, name: "Express.js", category: "Framework", confidence: 85 },
  { re: /^ASP\.NET_SessionId$/i, name: "ASP.NET", category: "Framework", confidence: 85 },
  { re: /^\.AspNetCore\./i, name: "ASP.NET Core", category: "Framework", confidence: 85 },
  { re: /^django_?sessionid$/i, name: "Django", category: "Framework", confidence: 85 },
  { re: /^csrftoken$/i, name: "Django", category: "Framework", confidence: 50 },
  { re: /^wordpress_logged_in_/i, name: "WordPress", category: "CMS", confidence: 92 },
  { re: /^wp-settings-/i, name: "WordPress", category: "CMS", confidence: 85 },
  { re: /^sails\.sid$/i, name: "Sails.js", category: "Framework", confidence: 85 },
  { re: /^ci_session$/i, name: "CodeIgniter", category: "Framework", confidence: 80 },
  { re: /^symfony$/i, name: "Symfony", category: "Framework", confidence: 80 },
  { re: /^_rails_session$/i, name: "Ruby on Rails", category: "Framework", confidence: 80 },
];

function analyzeTechFromHeaders(responseHeaderArray) {
  const findings = [];
  const headers = headersToObject(responseHeaderArray);
  for (const rule of TECH_HEADER_RULES) {
    const value = headers[rule.header];
    if (value && rule.re.test(value)) {
      findings.push({ name: rule.name, category: rule.category, confidence: rule.confidence, evidence: `Header ${rule.header}: ${value}` });
    }
  }
  for (const cookieHeader of getAllHeaderValues(responseHeaderArray, "set-cookie")) {
    const cookieName = (cookieHeader.split("=")[0] || "").trim();
    if (!cookieName) continue;
    for (const rule of TECH_COOKIE_RULES) {
      if (rule.re.test(cookieName)) {
        findings.push({ name: rule.name, category: rule.category, confidence: rule.confidence, evidence: `Cookie: ${cookieName}` });
      }
    }
  }
  return findings;
}

// ---- Source maps: referencias detectadas pasivamente (la verificación real
// -- descargar el .map y ver si de verdad expone código fuente -- es una
// acción activa que vive en el panel, gateada por Scope Guard igual que
// "Probar CORS ahora") --------------------------------------------------

function ensureSourceMapsData(data) {
  if (!data.sourceMaps) data.sourceMaps = {};
}

function recordSourceMapReferences(data, refs) {
  if (!refs || !refs.length) return;
  ensureSourceMapsData(data);
  const now = Date.now();
  for (const ref of refs) {
    if (!ref || !ref.mapUrl) continue;
    if (!data.sourceMaps[ref.mapUrl]) {
      data.sourceMaps[ref.mapUrl] = {
        scriptUrl: ref.scriptUrl,
        mapUrl: ref.mapUrl,
        firstSeen: now,
        lastSeen: now,
        // Estos campos se llenan solo cuando el usuario hace clic en
        // "Verificar exposición" en el panel -- hasta entonces, esto es
        // únicamente "se referencia un mapa", no "está confirmado expuesto".
        verified: false,
        accessible: null,
        sourcesCount: null,
        hasSourcesContent: null,
        sampleSourcePaths: [],
        endpointsFound: [],
        secretsFound: [],
      };
    } else {
      data.sourceMaps[ref.mapUrl].lastSeen = now;
    }
  }
}

function ensureTechFingerprint(data) {
  if (!data.techFingerprint) data.techFingerprint = {};
}

function recordTechFindings(data, findings) {
  if (!findings || !findings.length) return;
  ensureTechFingerprint(data);
  const now = Date.now();
  for (const f of findings) {
    const existing = data.techFingerprint[f.name];
    if (existing) {
      existing.lastSeen = now;
      // Confirmado por más de una fuente/señal -> más confianza, con tope
      existing.confidence = Math.min(99, Math.max(existing.confidence, f.confidence) + (existing.evidence.includes(f.evidence) ? 0 : 3));
      if (!existing.evidence.includes(f.evidence)) {
        existing.evidence.push(f.evidence);
        if (existing.evidence.length > 6) existing.evidence.shift();
      }
    } else {
      data.techFingerprint[f.name] = {
        name: f.name, category: f.category, confidence: f.confidence,
        evidence: [f.evidence], firstSeen: now, lastSeen: now,
      };
    }
  }
}

async function upsertEndpoint(domain, url, method) {
  const scope = await getScopeConfig();
  return withDomainLock(domain, async () => {
    const data = await getDomainData(domain);
    const key = `${method} ${url.split("?")[0]}`;
    const now = Date.now();
    const inScope = isInScope(realHostname(url) || domain, scope);
    if (!data.endpoints[key]) {
      data.endpoints[key] = { url, method, firstSeen: now, lastSeen: now, hits: 1, inScope };
    } else {
      data.endpoints[key].lastSeen = now;
      data.endpoints[key].hits += 1;
      data.endpoints[key].inScope = inScope;
    }

    const params = extractParamsFromUrl(url);
    const classified = classifyParams(params);
    recordOAuthFlow(data, url);
    for (const [param, hits] of Object.entries(classified)) {
      if (!isSafeObjectKey(param)) continue; // ver DANGEROUS_OBJECT_KEYS más arriba
      const existing = data.params[param];
      // "suspicious" es sticky: si en CUALQUIER request anterior el valor
      // observado se vio sospechoso (ver suspiciousValue de LFI), se
      // mantiene así aunque la request actual traiga un valor inocuo --
      // no queremos que una alerta real desaparezca solo porque la
      // siguiente página visitada usó un valor de ejemplo normal.
      const mergedHits = hits
        .map((h) => {
          const prevHit = existing?.hits?.find((ph) => ph.name === h.name);
          return { ...h, suspicious: h.suspicious || !!prevHit?.suspicious };
        })
        .filter((h) => h.suspicious);
      if (!mergedHits.length) continue; // todo lo visto hasta ahora para este param se ve inocuo (ej. "page" siempre numérico)
      if (!existing) data.params[param] = { hits: mergedHits, sources: [] };
      else data.params[param].hits = mergedHits;
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
        if (!data.endpoints[epKey]) {
          // Condición de carrera real con onBeforeRequest: aunque Chrome
          // dispara onBeforeRequest primero, upsertEndpoint hace un await
          // extra (getScopeConfig) antes de llegar al lock, mientras que
          // ESTE listener llega de forma inmediata y síncrona -- en
          // tráfico real, puede "adelantarse" y encontrar el endpoint
          // todavía inexistente, perdiendo hasAuth en silencio (confirmado
          // con test: sin margen entre eventos, falla; con 50ms de
          // margen, funciona -- es una carrera real, no un bug
          // determinista). Se crea acá un stub con la MISMA forma que
          // upsertEndpoint usaría (hits: 0, no 1 -- así, si upsertEndpoint
          // corre después y toma la rama de "ya existe" incrementando
          // hits, el conteo final queda en 1, no duplicado).
          const scope = await getScopeConfig();
          data.endpoints[epKey] = {
            url: details.url, method: details.method,
            firstSeen: Date.now(), lastSeen: Date.now(), hits: 0,
            inScope: isInScope(realHostname(details.url) || domain, scope),
          };
        }
        data.endpoints[epKey].hasAuth = true;
      }
      if (jwts.length) {
        // Antes: un token ya visto se descartaba entero (dedup por
        // token), perdiendo cualquier URL nueva donde volviera a
        // aparecer. Ahora se acumulan las URLs de origen (hasta 5) tanto
        // para tokens nuevos como para uno ya conocido.
        const byToken = new Map(data.jwts.map((j) => [j.token, j]));
        for (const j of jwts) {
          const existingJwt = byToken.get(j.token);
          if (existingJwt) {
            existingJwt.sources = existingJwt.sources || [];
            if (!existingJwt.sources.includes(details.url) && existingJwt.sources.length < 5) {
              existingJwt.sources.push(details.url);
            }
          } else {
            j.sources = [details.url];
            data.jwts.push(j);
            byToken.set(j.token, j);
          }
        }
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
      // Cada análisis corre en su propio try/catch -- si UNO tira una
      // excepción inesperada (headers malformados, un caso límite no
      // contemplado), los demás igual se calculan y se guardan. Antes,
      // una sola excepción en cualquiera de estos cortaba TODO el resto
      // del callback a mitad de camino, perdiendo hallazgos que ya se
      // habían calculado correctamente y nunca llegaban a guardarse.
      function safeAnalyze(label, fn) {
        try {
          return fn();
        } catch (e) {
          console.error(`surface-hound: error en ${label}:`, e);
          return [];
        }
      }
      const corsFindings = safeAnalyze("analyzeCors", () => analyzeCors(headers, contentType));
      const cspFindings = safeAnalyze("analyzeCsp", () => analyzeCsp(headers, contentType));
      const securityHeaderFindings = safeAnalyze("analyzeSecurityHeaders", () => analyzeSecurityHeaders(headers, contentType, details.url));
      const techFindings = safeAnalyze("analyzeTechFromHeaders", () => analyzeTechFromHeaders(details.responseHeaders));
      // details.statusCode está disponible acá para CUALQUIER request (no
      // solo fetch/XHR, a diferencia de handleNetEvent) -- por eso el
      // rastreo de "alguna vez vimos un 429 en este endpoint" vive acá, no
      // en el otro listener, que se pierde requests de navegación/formularios.
      const is429 = details.statusCode === 429;
      if (!corsFindings.length && !cspFindings.length && !securityHeaderFindings.length && !techFindings.length && !is429) return;
      const data = await getDomainData(domain);
      if (!data.securityHeaderFindings) data.securityHeaderFindings = [];
      for (const f of corsFindings) if (!data.corsFindings.some((x) => x.msg === f.msg)) data.corsFindings.push({ ...f, url: details.url });
      for (const f of cspFindings) if (!data.cspFindings.some((x) => x.msg === f.msg)) data.cspFindings.push({ ...f, url: details.url });
      for (const f of securityHeaderFindings) if (!data.securityHeaderFindings.some((x) => x.msg === f.msg)) data.securityHeaderFindings.push({ ...f, url: details.url });
      recordTechFindings(data, techFindings);
      if (is429) {
        const epKey = `${(details.method || "GET").toUpperCase()} ${details.url.split("?")[0]}`;
        if (!data.endpoints[epKey]) {
          // Mismo problema que hasAuth tenía antes de corregirse: onHeadersReceived
          // puede llegar al lock del dominio antes de que onBeforeRequest haya
          // terminado de crear el endpoint (éste hace un await extra a
          // getScopeConfig() antes de llegar ahí). Sin este stub, saw429 se
          // perdía en silencio -- y esa pérdida es peligrosa acá en particular,
          // porque "Posible ausencia de rate limiting" se basa exactamente en
          // NO haber visto nunca un 429: un 429 real que se pierde por esta
          // carrera generaría un falso positivo del hallazgo.
          const scope = await getScopeConfig();
          data.endpoints[epKey] = {
            url: details.url, method: (details.method || "GET").toUpperCase(),
            firstSeen: Date.now(), lastSeen: Date.now(), hits: 0,
            inScope: isInScope(realHostname(details.url) || domain, scope),
          };
        }
        data.endpoints[epKey].saw429 = true;
      }
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
        const byToken = new Map(data.jwts.map((j) => [j.token, j]));
        for (const token of msg.jwtTokens) {
          const existingJwt = byToken.get(token);
          if (existingJwt) {
            existingJwt.sources = existingJwt.sources || [];
            if (msg.pageUrl && !existingJwt.sources.includes(msg.pageUrl) && existingJwt.sources.length < 5) {
              existingJwt.sources.push(msg.pageUrl);
            }
            continue;
          }
          const decoded = decodeJwt(token);
          if (decoded) {
            decoded.sources = msg.pageUrl ? [msg.pageUrl] : [];
            data.jwts.push(decoded);
            byToken.set(token, decoded);
          }
        }
      }
      recordTechFindings(data, msg.techSignals);
      recordSourceMapReferences(data, msg.sourceMaps);
      await saveDomainData(domain, data);
    }).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "shx:netevent") {
    if (msg.source === "techfingerprint") handleTechFingerprintEvent(msg);
    else handleNetEvent(msg);
    return false;
  }
});

async function handleTechFingerprintEvent(msg) {
  const domain = extractDomain(msg.pageUrl || "");
  if (!domain) return;
  await withDomainLock(domain, async () => {
    const data = await getDomainData(domain);
    recordTechFindings(data, msg.techSignals);
    await saveDomainData(domain, data);
  });
}

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
      data.endpoints[epKey] = { url: msg.url, method, firstSeen: Date.now(), lastSeen: Date.now(), hits: 0, inScope: isInScope(realHostname(msg.url) || domain, scope) };
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

    // GraphQL: el chequeo barato de substring en looksLikeGraphQLPayload()
    // descarta la inmensa mayoría de requests JSON normales ANTES de pagar
    // el costo de un JSON.parse -- solo se parsea de verdad cuando el body
    // ya contiene el texto '"query"' o '"mutation"'.
    if (method === "POST" && msg.requestBody) {
      const gqlOps = parseGraphQLOperations(msg.requestBody);
      if (gqlOps.length) {
        recordGraphQLOperations(data, msg.url, method, gqlOps);
      }
    }
    if (msg.responseBody && isIntrospectionResponseConfirmed(msg.responseBody)) {
      recordGraphQLIntrospection(data, msg.url, msg.responseBody);
    }

    await saveDomainData(domain, data);
  });
}
