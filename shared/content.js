// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

// Se ejecuta en cada página cargada. Escanea scripts inline y externos (fetch)
// buscando secretos y JWTs expuestos en el código cliente. Pasivo, no modifica nada.

(function () {
  const ext = typeof browser !== "undefined" ? browser : chrome;

  // Cuando la extensión se recarga/actualiza (o se desinstala) mientras esta
  // pestaña ya tenía el content script cargado, ese script queda "huérfano":
  // sigue corriendo en la página, pero su conexión con el contexto de la
  // extensión murió. Cualquier llamada a chrome.runtime.* en ese estado
  // tira "Extension context invalidated" -- no es un bug real de lógica,
  // es un caso de ciclo de vida esperable (particularmente frecuente
  // mientras se está desarrollando/actualizando la extensión seguido).
  // isExtensionContextValid() detecta el caso ANTES de intentar nada, y
  // safeSendMessage() además envuelve el intento en try/catch por si el
  // contexto se invalida justo entre el chequeo y el envío.
  // Envuelve CUALQUIER llamada que pueda toparse con el contexto muerto
  // (no solo sendMessage): cuando Chrome invalida el contexto de un content
  // script en medio de su ejecución, puede destruir el "realm" de JS
  // completo de ese script -- en ese estado, hasta código que no toca
  // chrome.* en absoluto puede tirar "Extension context invalidated",
  // porque el motor del navegador está desconectando el script a la fuerza,
  // no porque el código en sí esté mal. safeSendMessage() ya cubre el envío
  // del mensaje; esto cubre la ejecución de run() entera y los callbacks
  // que la disparan.
  function isContextInvalidatedError(err) {
    return !!(err && typeof err.message === "string" && err.message.includes("Extension context invalidated"));
  }

  async function safeRun() {
    try {
      await run();
    } catch (err) {
      if (!isContextInvalidatedError(err)) throw err; // otros errores reales sí se dejan propagar
    }
  }

  function isExtensionContextValid() {
    try {
      return !!(ext && ext.runtime && ext.runtime.id);
    } catch {
      return false;
    }
  }

  function safeSendMessage(msg) {
    if (!isExtensionContextValid()) return;
    try {
      const p = ext.runtime.sendMessage(msg);
      if (p && typeof p.catch === "function") p.catch(() => {});
    } catch {
      // contexto invalidado justo al intentar enviar; se ignora en silencio
      // en vez de dejar un "Uncaught Error" en la consola de la página.
    }
  }

  const SECRET_PATTERNS = [
    { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, confidence: 96, severity: "critical",
      reason: "Prefijo AKIA + exactamente 16 caracteres alfanuméricos (formato fijo de AWS, no heurístico).",
      nextStep: "Probar con `aws sts get-caller-identity` usando esta clave -- hazlo desde tu propia terminal, fuera de la extensión, y solo si el programa lo permite." },
    { name: "AWS Secret Key (heurístico)", re: /(?:aws_secret|secret_key)["'\s:=]+[A-Za-z0-9\/+=]{40}/gi, confidence: 60, severity: "high", note: "Patrón heurístico: confirmar que el valor es realmente una clave y no un hash/placeholder.",
      reason: "Nombre de variable (aws_secret/secret_key) + valor de 40 caracteres compatible con base64 -- no confirma que sea una clave real.",
      nextStep: "Combinala con un AWS Access Key ID visto cerca (mismo request/respuesta) y probá `aws sts get-caller-identity` fuera de la extensión." },
    { name: "GitHub Token", re: /gh[pousr]_[A-Za-z0-9]{36,}/g, confidence: 95, severity: "critical",
      reason: "Prefijo reconocido de GitHub (ghp_/gho_/ghu_/ghs_/ghr_) + longitud mínima de 36 caracteres tras el prefijo.",
      nextStep: "Probar con `curl -H \"Authorization: token <valor>\" https://api.github.com/user` desde tu propia terminal." },
    { name: "Slack Token", re: /xox[baprs]-[0-9A-Za-z-]{10,48}/g, confidence: 90, severity: "high",
      reason: "Prefijo reconocido de Slack (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-).",
      nextStep: "Probar con `curl -H \"Authorization: Bearer <valor>\" https://slack.com/api/auth.test` desde tu propia terminal." },
    { name: "Stripe Secret Key", re: /sk_live_[0-9a-zA-Z]{24,}/g, confidence: 96, severity: "critical",
      reason: "Prefijo sk_live_ -- clave de producción de Stripe.",
      nextStep: "No la ejecutes contra la API de Stripe sin autorización explícita del programa -- documentá el hallazgo y repórtalo tal cual." },
    { name: "Stripe Test Secret Key", re: /sk_test_[0-9a-zA-Z]{24,}/g, confidence: 92, severity: "low", note: "Clave de entorno de pruebas — impacto limitado, pero repórtala igual si aparece en producción.",
      reason: "Prefijo sk_test_ -- clave de entorno de pruebas de Stripe, no de producción.",
      nextStep: "Confirmá si aparece en un contexto de PRODUCCIÓN (no solo staging/dev) antes de reportar -- ahí está el impacto real." },
    { name: "Stripe Publishable Key", re: /pk_(live|test)_[0-9a-zA-Z]{24,}/g, confidence: 90, severity: "info", byDesignPublic: true, note: "Diseñada para exponerse en el cliente (Stripe.js la necesita ahí). No es un secreto por sí sola.",
      reason: "Prefijo pk_ -- clave publicable, pensada para vivir en el cliente." },
    { name: "Google API Key", re: /AIza[0-9A-Za-z\-_]{35}/g, confidence: 80, severity: "info", byDesignPublic: true, note: "Las API keys de Google (Maps/Firebase) suelen estar pensadas para el cliente y restringirse por referrer, no por secreto. Confirma las restricciones antes de reportar.",
      reason: "Prefijo AIza + 35 caracteres (formato fijo de Google API Key).",
      nextStep: "Verificá las restricciones de la key (referrer/IP/API habilitadas) en vez de asumir que la sola exposición es el hallazgo." },
    { name: "Firebase Config", re: /"apiKey"\s*:\s*"AIza[0-9A-Za-z\-_]{35}"/g, confidence: 75, severity: "info", byDesignPublic: true, note: "La config de Firebase Web es pública por diseño; la protección real son las Security Rules del proyecto.",
      reason: "Bloque JSON con el campo \"apiKey\" y una clave con formato de Google/Firebase.",
      nextStep: "Si el objetivo es Firebase, el hallazgo real está en las Security Rules (Firestore/Storage) mal configuradas, no en esta key." },
    { name: "Sentry DSN", re: /https:\/\/[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io\/\d+/gi, confidence: 90, severity: "info", byDesignPublic: true, note: "El DSN de Sentry está diseñado para usarse desde el cliente.",
      reason: "URL con el formato exacto de un DSN de Sentry (host ingest.sentry.io + ID numérico de proyecto)." },
    { name: "Private Key block", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, confidence: 99, severity: "critical",
      reason: "Encabezado PEM reconocido -- prácticamente nunca es un falso positivo; lo que sigue al encabezado es la clave real.",
      nextStep: "Si podés capturar el bloque completo (no solo el encabezado), validá el formato con `openssl rsa -in archivo -check` fuera de la extensión." },
    { name: "Credencial genérica (patrón api_key/secret/token)", re: /(?:api[_-]?key|apikey|secret|token)["'\s:=]+["'][A-Za-z0-9_\-]{20,}["']/gi, confidence: 50, severity: "medium", note: "Patrón genérico con alta tasa de falsos positivos — se recomienda prueba manual para confirmar el hallazgo.",
      reason: "Coincidencia basada únicamente en nombre de variable (api_key/secret/token) + entropía del valor -- no hay un formato fijo que confirme que es real.",
      nextStep: "Revisá el contexto (¿es un ejemplo en un comentario? ¿un placeholder de documentación?) antes de asumir que es un secreto real." },
  ];

  // ---- Patrones adicionales (v0.37) -- formatos con prefijo fijo, baja tasa de FP ----
  // skipIf: descarta placeholders de documentación (user:pass@host, <token>, {{var}}).
  const PLACEHOLDER_URI_RE = /(user(name)?:pass(word)?@|<[a-z_]+>|\{\{?[a-z_]+\}?\}|example\.(com|org)|your[_-]?(user|pass|host)|changeme|localhost:\d+\/(db|test))/i;
  SECRET_PATTERNS.push(
    { name: "Google OAuth Client Secret", re: /GOCSPX-[A-Za-z0-9_-]{28}/g, confidence: 92, severity: "high",
      reason: "Prefijo GOCSPX- + 28 caracteres (formato fijo de client secret de Google OAuth).",
      nextStep: "Un client secret en el cliente permite suplantar la app OAuth -- verificá el client_id asociado y documentá sin usarlo contra Google." },
    { name: "GitLab Personal Access Token", re: /glpat-[A-Za-z0-9_-]{20}/g, confidence: 95, severity: "critical",
      reason: "Prefijo glpat- + 20 caracteres (formato fijo de GitLab PAT).",
      nextStep: "Probar con `curl -H \"PRIVATE-TOKEN: <valor>\" https://gitlab.com/api/v4/user` desde tu terminal, solo si el programa lo permite." },
    { name: "npm Access Token", re: /npm_[A-Za-z0-9]{36}/g, confidence: 92, severity: "critical",
      reason: "Prefijo npm_ + 36 caracteres (formato fijo de token npm).",
      nextStep: "Probar con `npm whoami --registry=https://registry.npmjs.org` usando el token en un .npmrc temporal (fuera de la extensión)." },
    { name: "SendGrid API Key", re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, confidence: 96, severity: "critical",
      reason: "Formato SG.<22>.<43> exacto de SendGrid.",
      nextStep: "Validar con `curl -H \"Authorization: Bearer <valor>\" https://api.sendgrid.com/v3/scopes` -- solo lista permisos, no envía correo." },
    { name: "Twilio API Key SID", re: /\bSK[0-9a-f]{32}\b/g, confidence: 65, severity: "medium", note: "SK + 32 hex puede coincidir con otros IDs; confirmá junto a un Account SID (AC...) y un secret cercano.",
      reason: "Prefijo SK + 32 caracteres hex (formato de API Key SID de Twilio).",
      nextStep: "Buscá el Account SID (AC + 32 hex) y el secret en el mismo archivo antes de reportar." },
    { name: "Mailgun API Key", re: /\bkey-[0-9a-f]{32}\b/g, confidence: 70, severity: "high", note: "Formato key-<32 hex> -- confirmar contexto (variable mailgun/api).",
      reason: "Prefijo key- + 32 hex (formato histórico de Mailgun)." },
    { name: "Slack Webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g, confidence: 97, severity: "high",
      reason: "URL completa de Incoming Webhook de Slack (permite publicar mensajes en el canal).",
      nextStep: "No publiques nada de prueba sin permiso del programa; documentá la URL y el canal si es visible." },
    { name: "Discord Webhook URL", re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[\w-]{60,}/g, confidence: 97, severity: "high",
      reason: "URL completa de webhook de Discord (permite publicar mensajes/leer metadatos del webhook).",
      nextStep: "Un GET a la URL devuelve metadatos del webhook sin enviar mensajes -- suficiente para validar." },
    { name: "Telegram Bot Token", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, confidence: 90, severity: "high",
      reason: "Formato <id>:AA<33> de bot token de Telegram.",
      nextStep: "Validar con `curl https://api.telegram.org/bot<valor>/getMe` (solo lectura)." },
    { name: "Anthropic API Key", re: /sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}/g, confidence: 97, severity: "critical",
      reason: "Prefijo sk-ant-api03/admin01 (formato fijo de claves de Anthropic).",
      nextStep: "Reportar tal cual; no la uses para generar tráfico facturable." },
    { name: "OpenAI API Key", re: /sk-(?:proj-[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{48}\b)/g, confidence: 85, severity: "critical",
      reason: "Prefijo sk-proj- o sk- + 48 alfanuméricos (formato de claves de OpenAI).",
      nextStep: "Validar con `GET /v1/models` (no consume créditos significativos) y reportar." },
    { name: "Shopify Access Token", re: /shp(?:at|ss|ca|pa)_[a-f0-9]{32}/g, confidence: 96, severity: "critical",
      reason: "Prefijo shpat_/shpss_/shpca_/shppa_ + 32 hex (tokens de Shopify Admin/Partner)." },
    { name: "DigitalOcean Token", re: /dop_v1_[a-f0-9]{64}/g, confidence: 97, severity: "critical",
      reason: "Prefijo dop_v1_ + 64 hex (formato fijo de DigitalOcean)." },
    { name: "Square Access Token", re: /\b(?:sq0atp-[0-9A-Za-z_-]{22}|EAAA[A-Za-z0-9_-]{60})\b/g, confidence: 88, severity: "critical",
      reason: "Formato sq0atp-/EAAA de tokens de acceso de Square." },
    { name: "Braintree Access Token", re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, confidence: 97, severity: "critical",
      reason: "Formato exacto de access token de producción de Braintree/PayPal." },
    { name: "Mapbox Secret Token", re: /\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, confidence: 92, severity: "high",
      reason: "Prefijo sk.eyJ... (los tokens pk. son públicos; los sk. son secretos de Mapbox)." },
    { name: "Facebook Access Token", re: /\bEAA[A-Za-z0-9]{100,}\b/g, confidence: 75, severity: "high", note: "Puede ser app token o user token; verificar con debug_token.",
      reason: "Prefijo EAA + 100+ alfanuméricos (formato de tokens de Graph API)." },
    { name: "AWS Session Key ID (ASIA)", re: /\bASIA[0-9A-Z]{16}\b/g, confidence: 90, severity: "high", note: "Credencial temporal STS -- buscar aws_secret/session_token cercanos; suelen expirar.",
      reason: "Prefijo ASIA + 16 caracteres (credenciales temporales de AWS STS)." },
    { name: "AWS Cognito Identity Pool ID", re: /\b[a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, confidence: 90, severity: "medium", byDesignPublic: true, note: "Es público por diseño, pero si el pool permite identidades no autenticadas entrega credenciales AWS temporales: el hallazgo real es el rol IAM asociado.",
      reason: "Formato región:UUID de Identity Pool de Cognito.",
      nextStep: "Con `aws cognito-identity get-id` / `get-credentials-for-identity` (solo si el programa lo permite) verificá si hay acceso no autenticado y qué permisos tiene el rol." },
    { name: "Azure Storage Connection String", re: /DefaultEndpointsProtocol=https?;AccountName=[^;"'\s]+;AccountKey=[A-Za-z0-9+\/=]{60,}/g, confidence: 98, severity: "critical",
      reason: "Cadena de conexión completa con AccountKey de Azure Storage (acceso total a la cuenta)." },
    { name: "Azure SAS Token", re: /[?&]sv=\d{4}-\d{2}-\d{2}[^"'\s<>]{0,300}?&sig=[A-Za-z0-9%]{40,}/g, confidence: 85, severity: "high", note: "Verificar permisos (sp=), expiración (se=) y recurso (sr=).",
      reason: "Query de SAS con sv= y sig= (acceso delegado a Azure Storage)." },
    { name: "Credenciales en URI de base de datos/cola", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@\/"'<>]+:[^\s:@\/"'<>]+@[^\s"'<>]+/gi, confidence: 82, severity: "critical", skipIf: PLACEHOLDER_URI_RE,
      reason: "URI con usuario:contraseña@host para un motor de datos/cola." },
    { name: "Credenciales en URL (basic auth)", re: /https?:\/\/[A-Za-z0-9._%-]{2,}:[^\s:@\/"'<>]{3,}@[a-z0-9.-]+\.[a-z]{2,}/gi, confidence: 70, severity: "high", skipIf: PLACEHOLDER_URI_RE,
      reason: "URL con usuario:contraseña embebido (HTTP basic auth)." },
    { name: "Firebase Realtime Database URL", re: /https:\/\/[a-z0-9-]+(?:-default-rtdb)?(?:\.[a-z0-9-]+)?\.firebaseio\.com/g, confidence: 85, severity: "info", byDesignPublic: true, note: "La URL es pública; el hallazgo real es una base con reglas abiertas.",
      reason: "Host de Firebase Realtime Database.",
      nextStep: "Probar lectura anónima: `curl '<url>/.json?shallow=true'` -- 200 con datos = reglas abiertas (hallazgo real)." },
    { name: "Cloudinary URL con credenciales", re: /cloudinary:\/\/\d+:[A-Za-z0-9_-]+@[a-z0-9-]+/g, confidence: 95, severity: "critical",
      reason: "Formato cloudinary://api_key:api_secret@cloud." },
    { name: "JWT secret hardcodeado", re: /(?:jwt[_-]?secret|jwtSecret|signing[_-]?key)["'\s:=]+["'][^"'\s]{8,}["']/gi, confidence: 70, severity: "high", note: "Confirmar que no sea un placeholder.",
      reason: "Variable de secreto JWT con valor literal -- permitiría forjar tokens si es el real.",
      nextStep: "Intentá verificar la firma de un JWT observado con este valor (offline, jwt_tool/hashcat)." },
    { name: "Bearer token hardcodeado", re: /["']Bearer\s+[A-Za-z0-9._\-]{20,}["']/g, confidence: 62, severity: "medium", note: "Puede ser un token de ejemplo o de sesión del propio usuario.",
      reason: "Cabecera Authorization con token literal en código cliente." }
  );

  const JWT_RE = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;

  // Detección de source maps referenciados: por convención, el comentario
  // "//# sourceMappingURL=..." (o su variante de bloque /*# ... */) siempre
  // va al FINAL del archivo -- por eso solo se busca en la cola (últimos
  // 500 caracteres), no en el texto completo del bundle, que puede pesar
  // cientos de KB. Cero costo de red extra: se reutiliza el mismo fetch que
  // ya se hace para buscar secretos, solo se lee un poco más del texto que
  // ya está en memoria.
  const SOURCEMAP_COMMENT_RE = /\/[\/*]#\s*sourceMappingURL=\s*(\S+?)\s*(?:\*\/)?\s*$/;

  function detectSourceMapReference(text, scriptUrl) {
    if (typeof text !== "string" || !text.length) return null;
    const tail = text.slice(-500);
    const match = tail.match(SOURCEMAP_COMMENT_RE);
    if (!match) return null;
    const raw = match[1];
    if (raw.startsWith("data:")) return null; // mapa inline en base64, no es un archivo "expuesto" aparte
    try {
      return new URL(raw, scriptUrl).href;
    } catch {
      return null;
    }
  }

  // Firmas en el DOM: content.js corre en el mundo AISLADO, que comparte el
  // DOM con la página (esto SÍ lo puede leer) pero no sus variables JS
  // globales (window.React, etc. -- eso lo cubre network-interceptor.js,
  // que corre en el mundo MAIN). Cada test() se ejecuta con su propio
  // try/catch individual para que un selector raro en una firma puntual no
  // tumbe la detección de las demás.
  const DOM_TECH_SIGNATURES = [
    { test: () => !!document.querySelector('meta[name="generator" i][content*="WordPress" i]'), name: "WordPress", category: "CMS", confidence: 95, evidence: "meta generator" },
    { test: () => !!document.querySelector('meta[name="generator" i][content*="Drupal" i]'), name: "Drupal", category: "CMS", confidence: 95, evidence: "meta generator" },
    { test: () => !!document.querySelector('meta[name="generator" i][content*="Joomla" i]'), name: "Joomla", category: "CMS", confidence: 95, evidence: "meta generator" },
    { test: () => !!document.querySelector('meta[name="generator" i][content*="Wix" i]'), name: "Wix", category: "CMS", confidence: 95, evidence: "meta generator" },
    { test: () => !!document.querySelector('meta[name="generator" i][content*="Squarespace" i]'), name: "Squarespace", category: "CMS", confidence: 95, evidence: "meta generator" },
    { test: () => !!document.querySelector('script[src*="wp-content" i], link[href*="wp-content" i], script[src*="wp-includes" i]'), name: "WordPress", category: "CMS", confidence: 85, evidence: "ruta wp-content/wp-includes" },
    { test: () => !!document.querySelector('[ng-version]'), name: "Angular", category: "Framework frontend", confidence: 90, evidence: "atributo ng-version" },
    { test: () => !!document.getElementById("__next"), name: "Next.js", category: "Framework frontend", confidence: 85, evidence: "id=__next" },
    { test: () => !!document.getElementById("__nuxt"), name: "Nuxt.js", category: "Framework frontend", confidence: 85, evidence: "id=__nuxt" },
    // data-reactroot/data-reactid solo existían en React 15/16 -- React 17+
    // (la inmensa mayoría de apps reales hoy) lo eliminó por completo. Se
    // deja como señal débil de respaldo (por si acaso), pero la detección
    // confiable de React moderno vive en network-interceptor.js (mundo
    // MAIN), vía las propiedades internas __reactFiber$/__reactContainer$
    // que React sigue adjuntando al DOM sin importar la versión.
    { test: () => !!document.querySelector("[data-reactroot], [data-reactid]"), name: "React", category: "Framework frontend", confidence: 50, evidence: "atributo data-reactroot/data-reactid (React ≤16, obsoleto en versiones modernas)" },
    { test: () => !!document.querySelector('script[src*="cdn.shopify.com" i]'), name: "Shopify", category: "E-commerce", confidence: 90, evidence: "script cdn.shopify.com" },
    { test: () => !!document.querySelector('script[src*="jquery" i]'), name: "jQuery", category: "Librería JS", confidence: 55, evidence: "script src jquery" },
    { test: () => !!document.querySelector('link[href*="/skin/frontend/" i], script[src*="/skin/frontend/" i]'), name: "Magento", category: "E-commerce", confidence: 85, evidence: "ruta /skin/frontend/" },
    { test: () => !!document.querySelector('meta[name="generator" i][content*="Hugo" i]'), name: "Hugo", category: "Generador estático", confidence: 90, evidence: "meta generator" },
  ];

  // Claves de ejemplo públicas y bien conocidas (documentación oficial, tutoriales)
  // que NO deben reportarse como hallazgo aunque calcen con el regex.
  const KNOWN_BENIGN_SECRETS = new Set([
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc", // clave de ejemplo de la documentación oficial de Stripe
    "AKIAIOSFODNN7EXAMPLE", // access key ID de ejemplo de la documentación oficial de AWS
  ]);

  // La entropía sola no distingue "estructura variada" de "aleatoriedad
  // real" -- placeholders comunes en documentación como "YOUR_API_KEY_HERE"
  // o "REPLACE_WITH_YOUR_TOKEN" tienen suficiente variedad de caracteres
  // para superar el umbral de entropía sin ser secretos reales. Se agrega
  // este chequeo de marcadores textuales conocidos, en paralelo al de
  // entropía (además, no en vez de) -- la entropía sigue descartando los
  // casos degenerados ("xxxxxxxx") que este chequeo de palabras no cubre.
  const PLACEHOLDER_MARKER_RE = /YOUR[_-]?(API[_-]?)?(KEY|TOKEN|SECRET)|PLACEHOLDER|REPLACE[_-]?(THIS|WITH|ME)|INSERT[_-]?YOUR|ENTER[_-]?YOUR|CHANGE[_-]?ME|DUMMY|SAMPLE[_-]?(KEY|TOKEN|SECRET)|_HERE$/i;

  function shannonEntropy(str) {
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    for (const c in freq) {
      const p = freq[c] / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  function scanText(text, source) {
    const secrets = [];
    for (const p of SECRET_PATTERNS) {
      const matches = text.match(p.re);
      if (!matches) continue;
      for (const m of new Set(matches)) {
        if (KNOWN_BENIGN_SECRETS.has(m)) continue;
        if (p.skipIf && p.skipIf.test(m)) continue;
        // El patrón genérico es el único con alto riesgo de placeholders/valores
        // de relleno (ej. "xxxxxxxxxxxxxxxx" o "YOUR_API_KEY_HERE"); se filtra
        // por entropía Y por marcador textual conocido.
        const valueMatch = m.match(/["']([A-Za-z0-9_\-]{20,})["']$/);
        const value = valueMatch ? valueMatch[1] : m;
        const entropy = shannonEntropy(value);
        if (p.confidence <= 55) {
          if (entropy < 3.0) continue;
          if (PLACEHOLDER_MARKER_RE.test(value)) continue;
        }
        // Contexto: unos caracteres antes/después del match en el texto
        // original -- suele ser la señal más rápida para descartar un
        // falso positivo a ojo (ej. ver que está dentro de un comentario
        // de ejemplo, no en código real). indexOf() sobre la primera
        // aparición alcanza -- ya se dedupea por Set arriba, así que un
        // mismo match no se procesa dos veces igual.
        const idx = text.indexOf(m);
        const CONTEXT_RADIUS = 35;
        const context = idx === -1 ? null : text.slice(Math.max(0, idx - CONTEXT_RADIUS), idx + m.length + CONTEXT_RADIUS);
        secrets.push({
          name: p.name,
          severity: p.severity,
          confidence: p.confidence,
          byDesignPublic: !!p.byDesignPublic,
          note: p.note || null,
          reason: p.reason || null,
          nextStep: p.nextStep || null,
          entropy: Math.round(entropy * 100) / 100,
          context,
          // Antes: "match: m.slice(0, 80)" -- truncaba el valor guardado
          // en storage, no solo la vista colapsada. 500 caracteres cubre
          // cómodamente cualquier secreto real (los tokens más largos
          // observados en la práctica no se acercan a eso) sin arriesgar
          // un bloque PEM completo de varios KB inflando el storage.
          match: m.slice(0, 500),
          source
        });
      }
    }
    const jwts = [...new Set(text.match(JWT_RE) || [])].map((token) => ({ token, source }));
    return { secrets, jwts };
  }


  // ==========================================================================
  // JS Recon (v0.37): extracción pasiva de inteligencia de los bundles JS.
  // Reutiliza el MISMO texto que ya se descarga para buscar secretos -- cero
  // tráfico extra por script. Encuentra lo que el tráfico observado nunca
  // muestra: endpoints/rutas que el JS conoce pero la UI no llamó, buckets y
  // hosts cloud (candidatos a takeover/permisos abiertos), IPs/hosts internos.
  // ==========================================================================
  const STATIC_ASSET_RE = /\.(?:png|jpe?g|gif|svg|webp|ico|css|scss|woff2?|ttf|eot|otf|mp[34]|webm|map|pdf|zip|html?)(?:[?#].*)?$/i;
  const API_HINT_RE = /^\/(?:api|rest|graphql|gql|v\d{1,2}|internal|admin|auth|oauth2?|sso|saml|user|users|account|accounts|billing|payments?|orders?|upload|uploads|download|export|import|webhooks?|callback|token|session|me|profile|settings|config|debug|actuator|swagger|openapi|private|backoffice|manage|management|dashboard|portal|search|files?|media|_next\/data|\.well-known)(?:\/|\?|$)/i;
  const ABS_URL_RE = /["'`](https?:\/\/[a-zA-Z0-9.-]+(?::\d{2,5})?(?:\/[^\s"'`<>\\]{0,220})?)["'`]/g;
  const REL_PATH_RE = /["'`](\/[A-Za-z0-9_\-./{}:$%?=&+~@,]{3,200})["'`]/g;
  const CLOUD_RES = [
    { kind: "S3 bucket", re: /\b([a-z0-9][a-z0-9.-]{2,62})\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b/g, hint: "Probar listado/lectura anónima del bucket (`aws s3 ls s3://<bucket> --no-sign-request`) y escritura; revisar si el bucket existe (NoSuchBucket = takeover)." },
    { kind: "S3 bucket (s3://)", re: /\bs3:\/\/([a-z0-9][a-z0-9.-]{2,62})/g, hint: "Igual que S3 bucket: validar permisos anónimos." },
    { kind: "S3 bucket (path-style)", re: /(?<![a-z0-9.-])s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\/([a-z0-9][a-z0-9.-]{2,62})/g, hint: "Validar permisos anónimos del bucket." },
    { kind: "GCS bucket", re: /\bstorage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{2,62})/g, hint: "Probar `curl https://storage.googleapis.com/<bucket>` (listado público = hallazgo)." },
    { kind: "Firebase Storage", re: /\bfirebasestorage\.googleapis\.com\/v0\/b\/([a-z0-9._-]+)/g, hint: "Revisar Security Rules del bucket (lectura/listado anónimo)." },
    { kind: "Azure Blob", re: /\b([a-z0-9]{3,24})\.blob\.core\.windows\.net\b/g, hint: "Probar listado de contenedores anónimo (`?comp=list`); NXDOMAIN = posible takeover." },
    { kind: "DigitalOcean Spaces", re: /\b([a-z0-9-]+)\.(?:[a-z0-9]+\.)?digitaloceanspaces\.com\b/g, hint: "Probar listado anónimo." },
    { kind: "Cloudflare R2 pública", re: /\b([a-z0-9-]+)\.r2\.dev\b/g, hint: "Validar si lista/escribe sin autenticación." },
    { kind: "Heroku app", re: /\b([a-z0-9-]+)\.herokuapp\.com\b/g, hint: "Candidato a subdomain takeover si la app ya no existe (página 'No such app')." },
    { kind: "Azure App Service", re: /\b([a-z0-9-]+)\.azurewebsites\.net\b/g, hint: "Candidato a takeover si el CNAME apunta a un sitio inexistente (NXDOMAIN)." },
    { kind: "AWS API Gateway", re: /\b([a-z0-9]{8,12})\.execute-api\.([a-z0-9-]+)\.amazonaws\.com\b/g, hint: "API directa sin el WAF/dominio principal: probar auth y stages (dev/test)." },
    { kind: "Elastic Beanstalk", re: /\b([a-z0-9-]+)\.[a-z0-9-]+\.elasticbeanstalk\.com\b/g, hint: "Posible takeover si el entorno fue eliminado." },
    { kind: "App Engine", re: /\b([a-z0-9-]+)\.appspot\.com\b/g, hint: "Revisar proyectos huérfanos/stages de prueba." },
    { kind: "Túnel/exposición dev (ngrok)", re: /\b([a-z0-9-]+)\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt)\b/g, hint: "URL de desarrollo olvidada en producción: revisar si sigue viva." },
  ];
  const INTERNAL_RE = /\b(?:(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?::\d{2,5})?|localhost:\d{2,5}|127\.0\.0\.1:\d{2,5})\b/g;
  const ENV_SUBDOMAIN_RE = /^(?:[a-z0-9-]+\.)*(?:internal|intranet|corp|stage|staging|stg|dev|qa|uat|test|preprod|sandbox|beta|admin|jenkins|grafana|kibana|vpn)(?:[.-][a-z0-9-]+)*\./i;

  function baseDomain(host) {
    const parts = host.split(".");
    return parts.length <= 2 ? host : parts.slice(-2).join(".");
  }

  function newIntel() {
    return { endpoints: new Map(), cloud: new Map(), internal: new Map(), hosts: new Map(), params: new Set() };
  }

  function extractJsIntel(text, source, intel) {
    if (typeof text !== "string" || text.length < 20) return;
    const pageBase = baseDomain(location.hostname);
    // Endpoints absolutos (también alimentan hosts / entornos no productivos)
    let m;
    ABS_URL_RE.lastIndex = 0;
    while ((m = ABS_URL_RE.exec(text)) !== null && intel.endpoints.size < 600) {
      const url = m[1];
      let u;
      try { u = new URL(url); } catch { continue; }
      if (STATIC_ASSET_RE.test(u.pathname)) continue;
      if (/hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks/i.test(u.host + u.pathname)) continue; // ya se reporta como secreto; no duplicar el valor en la lista de rutas
      if (/(?:w3\.org|schema\.org|googleapis\.com\/css|fonts\.g|gstatic|reactjs\.org|github\.com\/|mozilla\.org|npmjs)/i.test(u.host + u.pathname)) continue;
      const key = "abs:" + u.origin + u.pathname;
      if (!intel.endpoints.has(key)) intel.endpoints.set(key, { path: u.pathname + (u.search ? u.search.slice(0, 120) : ""), origin: u.origin, abs: true, hint: API_HINT_RE.test(u.pathname), sources: [] });
      const e = intel.endpoints.get(key);
      if (e.sources.length < 3 && !e.sources.includes(source)) e.sources.push(source);
      u.searchParams.forEach((_v, k) => { if (k.length <= 32 && /^[A-Za-z_][\w.-]*$/.test(k)) intel.params.add(k); });
      const h = u.hostname.toLowerCase();
      if (baseDomain(h) === pageBase && h !== location.hostname.toLowerCase()) {
        const rec = intel.hosts.get(h) || { host: h, envLike: ENV_SUBDOMAIN_RE.test(h + "."), sources: [] };
        if (rec.sources.length < 3 && !rec.sources.includes(source)) rec.sources.push(source);
        intel.hosts.set(h, rec);
      }
    }
    // Rutas relativas (priorizamos las que parecen API; el resto solo si tienen 2+ segmentos)
    REL_PATH_RE.lastIndex = 0;
    while ((m = REL_PATH_RE.exec(text)) !== null && intel.endpoints.size < 600) {
      const path = m[1];
      if (path.startsWith("//") || STATIC_ASSET_RE.test(path)) continue;
      const hint = API_HINT_RE.test(path);
      const segs = path.split("?")[0].split("/").filter(Boolean);
      if (!hint && segs.length < 2) continue;
      if (!hint && /[{}$]/.test(path) === false && segs.every((x) => x.length <= 2)) continue;
      const key = "rel:" + path.split("?")[0];
      if (!intel.endpoints.has(key)) intel.endpoints.set(key, { path: path.slice(0, 200), origin: location.origin, abs: false, hint, sources: [] });
      const e = intel.endpoints.get(key);
      if (e.sources.length < 3 && !e.sources.includes(source)) e.sources.push(source);
      const q = path.split("?")[1];
      if (q) q.split("&").forEach((kv) => { const k = kv.split("=")[0]; if (k && k.length <= 32 && /^[A-Za-z_][\w.-]*$/.test(k)) intel.params.add(k); });
    }
    // Activos cloud (buckets/hosts potencialmente huérfanos)
    for (const c of CLOUD_RES) {
      c.re.lastIndex = 0;
      while ((m = c.re.exec(text)) !== null && intel.cloud.size < 150) {
        const value = m[0].slice(0, 160);
        const key = c.kind + "|" + value;
        if (!intel.cloud.has(key)) intel.cloud.set(key, { kind: c.kind, value, hint: c.hint, sources: [] });
        const e = intel.cloud.get(key);
        if (e.sources.length < 3 && !e.sources.includes(source)) e.sources.push(source);
      }
    }
    // IPs / hosts internos filtrados en el cliente
    INTERNAL_RE.lastIndex = 0;
    while ((m = INTERNAL_RE.exec(text)) !== null && intel.internal.size < 60) {
      const v = m[0];
      if (!intel.internal.has(v)) intel.internal.set(v, { value: v, sources: [] });
      const e = intel.internal.get(v);
      if (e.sources.length < 3 && !e.sources.includes(source)) e.sources.push(source);
    }
  }

  function serializeIntel(intel) {
    const out = {
      endpoints: [...intel.endpoints.values()].sort((a, b) => Number(b.hint) - Number(a.hint)).slice(0, 400),
      cloud: [...intel.cloud.values()],
      internal: [...intel.internal.values()],
      hosts: [...intel.hosts.values()],
      params: [...intel.params].slice(0, 200),
    };
    const empty = !out.endpoints.length && !out.cloud.length && !out.internal.length && !out.hosts.length && !out.params.length;
    return empty ? null : out;
  }

  // Scripts cargados dinámicamente (chunks lazy, SDKs) que no están como
  // <script src> en el DOM -- performance.getEntriesByType los lista igual.
  function discoverScriptUrls() {
    const urls = new Set(Array.from(document.querySelectorAll("script[src]")).map((s) => s.src));
    try {
      for (const e of performance.getEntriesByType("resource")) {
        if (e.initiatorType === "script" || /\.m?js(?:[?#]|$)/i.test(e.name)) urls.add(e.name);
      }
    } catch {}
    return [...urls].filter((u) => /^https?:/i.test(u));
  }

  // Referencias a chunks en los propios bundles (runtime de webpack/Next/Vite):
  // nombres completos entre comillas que terminan en .js, resueltos contra el
  // directorio del script que los menciona. Solo mismo origen.
  const CHUNK_REF_RE = /["'`]((?:[\w.-]+\/)*[\w.-]+\.(?:[a-f0-9]{6,20}\.)?(?:chunk\.)?m?js)["'`]/g;
  function discoverChunkRefs(text, scriptUrl, seen) {
    const found = [];
    let m;
    CHUNK_REF_RE.lastIndex = 0;
    while ((m = CHUNK_REF_RE.exec(text)) !== null && found.length < 60) {
      const ref = m[1];
      if (!/(?:chunk|static\/|assets\/|\/[a-f0-9]{6,20}\.)/i.test(ref)) continue;
      try {
        const abs = new URL(ref, ref.includes("/") ? location.origin + "/" : scriptUrl).href;
        const abs2 = new URL(ref, scriptUrl).href;
        for (const u of [abs, abs2]) {
          if (new URL(u).origin === location.origin && !seen.has(u)) { seen.add(u); found.push(u); }
        }
      } catch {}
    }
    return found;
  }

  async function mapPool(items, limit, fn) {
    let i = 0;
    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) { const idx = i++; await fn(items[idx]); }
    });
    await Promise.all(workers);
  }

  // localStorage / sessionStorage / cookies legibles: tokens y JWTs que la app
  // guarda en el cliente (fuente muy rentable de sesiones y secretos).
  function scanBrowserStorage(allSecrets, allJwts) {
    for (const [label, store] of [["localStorage", () => window.localStorage], ["sessionStorage", () => window.sessionStorage]]) {
      try {
        const st = store();
        for (let i = 0; i < Math.min(st.length, 200); i++) {
          const k = st.key(i);
          const v = st.getItem(k);
          if (!v || v.length > 50000) continue;
          const { secrets, jwts } = scanText(v, `${label}://${location.origin}/${String(k).slice(0, 60)}`);
          allSecrets.push(...secrets);
          allJwts.push(...jwts);
        }
      } catch {}
    }
    try {
      if (document.cookie) {
        const { secrets, jwts } = scanText(document.cookie, `document.cookie://${location.origin}`);
        allSecrets.push(...secrets);
        allJwts.push(...jwts);
      }
    } catch {}
  }

  async function run() {
    if (!isExtensionContextValid()) return; // no perder tiempo escaneando si ya sabemos que está invalidado

    const allSecrets = [];
    const allJwts = [];

    for (const script of document.querySelectorAll("script:not([src])")) {
      const { secrets, jwts } = scanText(script.textContent || "", location.href);
      allSecrets.push(...secrets);
      allJwts.push(...jwts);
    }

    const intel = newIntel();
    for (const script of document.querySelectorAll("script:not([src])")) {
      extractJsIntel(script.textContent || "", location.href, intel);
    }

    const seenScripts = new Set(discoverScriptUrls());
    const queue = [...seenScripts].slice(0, 120);
    const allSourceMaps = [];
    let chunkBudget = 60; // segundo nivel: chunks referenciados por los bundles (mismo origen)

    async function scanScript(src, depth) {
      try {
        const res = await fetch(src, { credentials: "omit" });
        const text = await res.text();
        const { secrets, jwts } = scanText(text, src);
        allSecrets.push(...secrets);
        allJwts.push(...jwts);
        extractJsIntel(text, src, intel);
        const mapUrl = detectSourceMapReference(text, src);
        if (mapUrl) allSourceMaps.push({ scriptUrl: src, mapUrl });
        if (depth === 0 && chunkBudget > 0) {
          for (const u of discoverChunkRefs(text, src, seenScripts)) {
            if (chunkBudget-- <= 0) break;
            await scanScript(u, 1);
          }
        }
      } catch {
        // CORS u otro fallo de red: ignorar, es best-effort
      }
    }
    await mapPool(queue, 6, (src) => scanScript(src, 0));
    scanBrowserStorage(allSecrets, allJwts);
    const jsIntel = serializeIntel(intel);

    // Firmas de tecnología en el DOM. Cada una con su propio try/catch para
    // que un selector raro puntual no tumbe la detección de las demás.
    const techSignals = [];
    for (const sig of DOM_TECH_SIGNATURES) {
      try {
        if (sig.test()) techSignals.push({ name: sig.name, category: sig.category, confidence: sig.confidence, evidence: sig.evidence });
      } catch {}
    }

    if (allSecrets.length || allJwts.length || techSignals.length || allSourceMaps.length || jsIntel) {
      // Solo mandamos los tokens crudos: el decodificador vive en background.js
      // (una sola fuente de verdad para los niveles OBSERVED/SUSPICIOUS/CANDIDATE,
      // en vez de mantener dos implementaciones que podrían desincronizarse)
      safeSendMessage({
        type: "shx:findings",
        pageUrl: location.href,
        secrets: allSecrets,
        jwtTokens: [...new Set(allJwts.map((j) => j.token))],
        techSignals,
        sourceMaps: allSourceMaps,
        jsIntel,
      });
    }
  }

  if (document.readyState === "complete") {
    setTimeout(safeRun, 500);
  } else {
    window.addEventListener("load", () => setTimeout(safeRun, 500));
  }

  // Re-escanea en SPAs cuando cambia la URL sin recarga completa (pushState)
  let lastHref = location.href;
  new MutationObserver(() => {
    try {
      if (location.href !== lastHref) {
        lastHref = location.href;
        setTimeout(safeRun, 800);
      }
    } catch (err) {
      if (!isContextInvalidatedError(err)) throw err;
    }
  }).observe(document, { subtree: true, childList: true });

  // ---- Puente con el interceptor de red (mundo MAIN) ----
  // network-interceptor.js corre en el contexto real de la página y no
  // puede llamar directo a chrome.runtime, así que nos manda los eventos
  // por postMessage y nosotros (mundo aislado, con acceso a la API de
  // extensiones) los retransmitimos al background.
  //
  // event.source === window solo descarta mensajes de OTRAS ventanas/
  // iframes -- no protege contra otro script corriendo en esta MISMA
  // página (un ad, una librería de terceros comprometida, un XSS del
  // propio sitio) que llame a window.postMessage con la misma propiedad
  // __surfaceHoundNetEvent, inyectando hallazgos falsos (operaciones
  // GraphQL inventadas, entidades correlacionadas fabricadas, etc.).
  // Mitigación: se exige un token que network-interceptor.js escribe en un
  // atributo del DOM (no por postMessage -- ese script corre en
  // document_start y este en document_idle, un postMessage de una sola vez
  // ahí se perdería sin que nadie lo escuche todavía). Se lee UNA vez acá,
  // al arrancar, y se exige que cada netevent lo incluya. No es un secreto
  // criptográficamente perfecto (cualquier otro script de la página puede
  // leer el mismo atributo), pero eleva el ataque de "cualquier script
  // genérico que adivine la propiedad __surfaceHoundNetEvent" a "requiere
  // conocer este protocolo interno específico".
  let pageToken = null;
  try {
    pageToken = document.documentElement.getAttribute("data-shx-t");
  } catch {
    // fail-closed: si no se puede leer el token, pageToken queda null y
    // ningún netevent pasa la validación de abajo -- se pierde captura en
    // vez de aceptar datos sin poder verificarlos.
  }

  window.addEventListener("message", (event) => {
    try {
      if (event.source !== window) return;
      const data = event.data;
      if (!data || !data.__surfaceHoundNetEvent) return;
      if (pageToken === null || data.token !== pageToken) return;
      safeSendMessage({ type: "shx:netevent", ...data });
    } catch (err) {
      if (!isContextInvalidatedError(err)) throw err;
    }
  });
})();
