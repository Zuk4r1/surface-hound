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
    { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, confidence: 96, severity: "critical" },
    { name: "AWS Secret Key (heurístico)", re: /(?:aws_secret|secret_key)["'\s:=]+[A-Za-z0-9\/+=]{40}/gi, confidence: 60, severity: "high", note: "Patrón heurístico: confirmar que el valor es realmente una clave y no un hash/placeholder." },
    { name: "GitHub Token", re: /gh[pousr]_[A-Za-z0-9]{36,}/g, confidence: 95, severity: "critical" },
    { name: "Slack Token", re: /xox[baprs]-[0-9A-Za-z-]{10,48}/g, confidence: 90, severity: "high" },
    { name: "Stripe Secret Key", re: /sk_live_[0-9a-zA-Z]{24,}/g, confidence: 96, severity: "critical" },
    { name: "Stripe Test Secret Key", re: /sk_test_[0-9a-zA-Z]{24,}/g, confidence: 92, severity: "low", note: "Clave de entorno de pruebas — impacto limitado, pero repórtala igual si aparece en producción." },
    { name: "Stripe Publishable Key", re: /pk_(live|test)_[0-9a-zA-Z]{24,}/g, confidence: 90, severity: "info", byDesignPublic: true, note: "Diseñada para exponerse en el cliente (Stripe.js la necesita ahí). No es un secreto por sí sola." },
    { name: "Google API Key", re: /AIza[0-9A-Za-z\-_]{35}/g, confidence: 80, severity: "info", byDesignPublic: true, note: "Las API keys de Google (Maps/Firebase) suelen estar pensadas para el cliente y restringirse por referrer, no por secreto. Confirma las restricciones antes de reportar." },
    { name: "Firebase Config", re: /"apiKey"\s*:\s*"AIza[0-9A-Za-z\-_]{35}"/g, confidence: 75, severity: "info", byDesignPublic: true, note: "La config de Firebase Web es pública por diseño; la protección real son las Security Rules del proyecto." },
    { name: "Sentry DSN", re: /https:\/\/[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io\/\d+/gi, confidence: 90, severity: "info", byDesignPublic: true, note: "El DSN de Sentry está diseñado para usarse desde el cliente." },
    { name: "Private Key block", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, confidence: 99, severity: "critical" },
    { name: "Credencial genérica (patrón api_key/secret/token)", re: /(?:api[_-]?key|apikey|secret|token)["'\s:=]+["'][A-Za-z0-9_\-]{20,}["']/gi, confidence: 50, severity: "medium", note: "Patrón genérico con alta tasa de falsos positivos — se descartan automáticamente los valores de baja entropía (placeholders tipo 'xxxxxxxx')." },
  ];
  const JWT_RE = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;

  // Claves de ejemplo públicas y bien conocidas (documentación oficial, tutoriales)
  // que NO deben reportarse como hallazgo aunque calcen con el regex.
  const KNOWN_BENIGN_SECRETS = new Set([
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc", // clave de ejemplo de la documentación oficial de Stripe
  ]);

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
        // El patrón genérico es el único con alto riesgo de placeholders/valores
        // de relleno (ej. "xxxxxxxxxxxxxxxx"); se filtra por entropía.
        if (p.confidence <= 55) {
          const valueMatch = m.match(/["']([A-Za-z0-9_\-]{20,})["']$/);
          const value = valueMatch ? valueMatch[1] : m;
          if (shannonEntropy(value) < 3.0) continue;
        }
        secrets.push({
          name: p.name,
          severity: p.severity,
          confidence: p.confidence,
          byDesignPublic: !!p.byDesignPublic,
          note: p.note || null,
          match: m.slice(0, 80),
          source
        });
      }
    }
    const jwts = [...new Set(text.match(JWT_RE) || [])].map((token) => ({ token, source }));
    return { secrets, jwts };
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

    const srcs = Array.from(document.querySelectorAll("script[src]")).map((s) => s.src).slice(0, 40);

    await Promise.all(
      srcs.map(async (src) => {
        try {
          const res = await fetch(src, { credentials: "omit" });
          const text = await res.text();
          const { secrets, jwts } = scanText(text, src);
          allSecrets.push(...secrets);
          allJwts.push(...jwts);
        } catch {
          // CORS u otro fallo de red: ignorar, es best-effort
        }
      })
    );

    if (allSecrets.length || allJwts.length) {
      // Solo mandamos los tokens crudos: el decodificador vive en background.js
      // (una sola fuente de verdad para los niveles OBSERVED/SUSPICIOUS/CANDIDATE,
      // en vez de mantener dos implementaciones que podrían desincronizarse)
      safeSendMessage({
        type: "shx:findings",
        pageUrl: location.href,
        secrets: allSecrets,
        jwtTokens: [...new Set(allJwts.map((j) => j.token))]
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
  window.addEventListener("message", (event) => {
    try {
      if (event.source !== window) return;
      const data = event.data;
      if (!data || !data.__surfaceHoundNetEvent) return;
      safeSendMessage({ type: "shx:netevent", ...data });
    } catch (err) {
      if (!isContextInvalidatedError(err)) throw err;
    }
  });
})();
