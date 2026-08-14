// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

// Se inyecta en el mundo MAIN (el contexto real de la página, no el aislado
// de las extensiones) para poder interceptar fetch/XHR ANTES de que el JS
// de la app los use. Esto es lo que habilita: bodies de request/response
// (para el clasificador avanzado y el grafo de entidades), el script de
// origen real (via stack trace) y metadata que webRequest no puede dar
// (contenido de la respuesta).
//
// Se comunica con content.js (mundo aislado) via window.postMessage, porque
// ambos mundos comparten el mismo objeto `window`/DOM aunque no puedan
// llamarse funciones entre sí directamente.

(function () {
  const MAX_BODY_CAPTURE = 20000; // cap general de caracteres por body, evita payloads gigantes
  // Los schemas de introspection GraphQL reales pasan los 20KB con facilidad
  // (decenas o cientos de tipos) -- truncarlos con el límite general corta
  // el JSON a la mitad, y el análisis completo del schema (queries,
  // mutations, deprecated, etc.) nunca puede correr porque JSON.parse falla
  // sobre un documento incompleto. Se detecta el caso puntual (barato, por
  // substring) y se le da un límite mucho más alto SOLO a esa respuesta,
  // el límite general se mantiene bajo para todo lo demás.
  const MAX_INTROSPECTION_CAPTURE = 500000;
  const FLAG = "__surfaceHoundNetEvent";

  function truncate(s, maxLen = MAX_BODY_CAPTURE) {
    if (typeof s !== "string") return s;
    return s.length > maxLen ? s.slice(0, maxLen) + "…[truncado]" : s;
  }

  function truncateResponseBody(text) {
    if (typeof text === "string" && text.includes('"__schema"')) {
      return truncate(text, MAX_INTROSPECTION_CAPTURE);
    }
    return truncate(text);
  }

  // fetch('/api/users') con URL relativa es el caso MÁS COMÚN en SPAs reales
  // (casi nadie escribe la URL absoluta a mano). Sin resolverla, background.js
  // hace `new URL(url)` sobre un string relativo, que lanza, y el evento
  // entero se descartaba en silencio -- perdiendo metadata rica, grafo de
  // entidades y corroboración de reflexión para la mayoría de los requests
  // reales, no solo un caso raro.
  function resolveUrl(url) {
    try {
      return new URL(url, location.href).href;
    } catch {
      return url;
    }
  }

  function captureStack() {
    try {
      throw new Error();
    } catch (e) {
      // Filtra por CONTENIDO (nunca es del propio interceptor) en vez de por
      // una posición fija de línea. Esto es necesario porque el formato del
      // stack trace difiere entre motores:
      //   V8/Chrome:    "Error" + "    at fn (archivo:línea:col)"
      //   SpiderMonkey/Firefox: "fn@archivo:línea:col" (sin "Error", sin "at")
      // Contar un offset fijo de líneas solo funcionaba en Chrome, y encima
      // apuntaba al frame equivocado (el propio wrapper fetch/XHR, no el
      // código real de la página que hizo el request).
      const lines = (e.stack || "").split("\n").map((l) => l.trim()).filter(Boolean);
      const realCallerLines = lines.filter(
        (l) =>
          !/network-interceptor\.js/i.test(l) &&
          !/^Error\b/i.test(l) &&
          !/captureStack/i.test(l)
      );
      return realCallerLines.slice(0, 5).join(" | ");
    }
  }

  function post(evt) {
    try {
      window.postMessage({ [FLAG]: true, ...evt, pageUrl: location.href, capturedAt: Date.now() }, "*");
    } catch {
      // si postMessage falla por algun motivo, no rompemos la app anfitriona
    }
  }

  // ---- fetch ----
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      let url, method;
      try {
        url = resolveUrl(typeof input === "string" ? input : input?.url);
        method = (init?.method || (typeof input === "object" && input?.method) || "GET").toUpperCase();
      } catch {
        return origFetch.apply(this, arguments);
      }
      const reqBody = typeof init?.body === "string" ? init.body : null;
      const stack = captureStack();

      return origFetch.apply(this, arguments).then(
        (res) => {
          try {
            const contentType = res.headers.get("content-type") || "";
            const contentLength = res.headers.get("content-length");
            const status = res.status;
            if (/json|text/i.test(contentType)) {
              res
                .clone()
                .text()
                .then((text) => {
                  post({ source: "fetch", url, method, status, contentType, responseSize: contentLength ? Number(contentLength) : text.length, requestBody: truncate(reqBody), responseBody: truncateResponseBody(text), stack });
                })
                .catch(() => {
                  post({ source: "fetch", url, method, status, contentType, responseSize: contentLength ? Number(contentLength) : null, requestBody: truncate(reqBody), stack });
                });
            } else {
              post({ source: "fetch", url, method, status, contentType, responseSize: contentLength ? Number(contentLength) : null, requestBody: truncate(reqBody), stack });
            }
          } catch {}
          return res;
        },
        (err) => {
          post({ source: "fetch", url, method, error: String(err), requestBody: truncate(reqBody), stack });
          throw err;
        }
      );
    };
  }

  // ---- XMLHttpRequest ----
  const OrigXHR = window.XMLHttpRequest;
  if (OrigXHR) {
    function PatchedXHR() {
      const xhr = new OrigXHR();
      let _method, _url, _reqBody, _stack;

      const origOpen = xhr.open;
      xhr.open = function (method, url, ...rest) {
        _method = method;
        _url = resolveUrl(url);
        _stack = captureStack();
        return origOpen.call(xhr, method, url, ...rest);
      };

      const origSend = xhr.send;
      xhr.send = function (body) {
        _reqBody = typeof body === "string" ? body : null;
        xhr.addEventListener("loadend", () => {
          try {
            const contentType = xhr.getResponseHeader("content-type") || "";
            post({
              source: "xhr",
              url: _url,
              method: _method,
              status: xhr.status,
              contentType,
              responseSize: xhr.responseText ? xhr.responseText.length : null,
              requestBody: truncate(_reqBody),
              responseBody: /json|text/i.test(contentType) ? truncateResponseBody(xhr.responseText) : null,
              stack: _stack,
            });
          } catch {}
        });
        return origSend.call(xhr, body);
      };

      return xhr;
    }
    PatchedXHR.prototype = OrigXHR.prototype;
    window.XMLHttpRequest = PatchedXHR;
  }
  // ---- WebSocket ----
  // A diferencia de fetch/XHR, una conexión WebSocket es persistente y
  // puede mandar/recibir cientos de mensajes por segundo (trading en vivo,
  // notificaciones push, chat). Capturar CADA frame inundaría el storage y
  // degradaría el rendimiento -- por eso hay un muestreo por conexión y por
  // dirección (entrada/salida): como mucho un mensaje forwardeado cada
  // WS_SAMPLE_INTERVAL_MS, con un contador de cuántos se saltearon en el
  // medio (así background.js puede seguir sabiendo el volumen real sin
  // necesitar cada frame individual). El envío real (ws.send) NUNCA se
  // salta ni se demora -- el muestreo solo afecta qué se REPORTA, jamás el
  // comportamiento real de la app anfitriona.
  const OrigWebSocket = window.WebSocket;
  if (OrigWebSocket) {
    const WS_SAMPLE_INTERVAL_MS = 400;

    function makeSampler() {
      let last = 0;
      let skippedSinceLastSample = 0;
      return function sample() {
        const now = Date.now();
        if (now - last >= WS_SAMPLE_INTERVAL_MS) {
          last = now;
          const skipped = skippedSinceLastSample;
          skippedSinceLastSample = 0;
          return { forward: true, skipped };
        }
        skippedSinceLastSample++;
        return { forward: false, skipped: skippedSinceLastSample };
      };
    }

    // La mayoría de apps reales mandan JSON como texto sobre WebSocket
    // (chat, trading, notificaciones), pero la spec permite Blob/ArrayBuffer
    // también. Se intenta decodificar como texto en los tres casos -- si es
    // binario de verdad (audio/video/protocolo propietario), la decodificación
    // simplemente no produce texto legible y se reporta como "binario" sin
    // forzar el contenido.
    function readFrameData(data, cb) {
      if (typeof data === "string") {
        cb(data, false);
        return;
      }
      if (typeof Blob !== "undefined" && data instanceof Blob) {
        data.text().then((t) => cb(t, true)).catch(() => cb(null, true));
        return;
      }
      if (data instanceof ArrayBuffer) {
        try {
          cb(new TextDecoder("utf-8", { fatal: true }).decode(data), true);
        } catch {
          cb(null, true); // binario de verdad, no texto -- no se fuerza
        }
        return;
      }
      cb(null, true);
    }

    function PatchedWebSocket(url, protocols) {
      const resolvedUrl = resolveUrl(url);
      const stack = captureStack();
      const ws = protocols !== undefined ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);

      const sampleIn = makeSampler();
      const sampleOut = makeSampler();

      post({ source: "websocket", event: "connect", url: resolvedUrl, protocols: protocols ? [].concat(protocols) : null, stack });

      // addEventListener (no sobreescribir .onmessage/.onclose) para no
      // pisar los listeners que la app anfitriona ya tenga puestos --
      // varios listeners para el mismo evento conviven sin problema.
      ws.addEventListener("close", (ev) => {
        post({ source: "websocket", event: "close", url: resolvedUrl, code: ev.code, reason: ev.reason || null, stack });
      });
      ws.addEventListener("error", () => {
        post({ source: "websocket", event: "error", url: resolvedUrl, stack });
      });
      ws.addEventListener("message", (ev) => {
        const { forward, skipped } = sampleIn();
        if (!forward) return;
        readFrameData(ev.data, (text, isBinary) => {
          post({ source: "websocket", event: "message_in", url: resolvedUrl, data: text ? truncate(text) : null, binary: isBinary, skippedSinceLastSample: skipped, stack });
        });
      });

      // send() sí hay que envolverlo (no es un evento, es una llamada
      // directa) -- pero origSend se llama SIEMPRE, el muestreo solo decide
      // si se reporta, nunca si se envía de verdad.
      const origSend = ws.send.bind(ws);
      ws.send = function (data) {
        const { forward, skipped } = sampleOut();
        if (forward) {
          readFrameData(data, (text, isBinary) => {
            post({ source: "websocket", event: "message_out", url: resolvedUrl, data: text ? truncate(text) : null, binary: isBinary, skippedSinceLastSample: skipped, stack });
          });
        }
        return origSend(data);
      };

      return ws;
    }
    PatchedWebSocket.prototype = OrigWebSocket.prototype;
    PatchedWebSocket.CONNECTING = OrigWebSocket.CONNECTING;
    PatchedWebSocket.OPEN = OrigWebSocket.OPEN;
    PatchedWebSocket.CLOSING = OrigWebSocket.CLOSING;
    PatchedWebSocket.CLOSED = OrigWebSocket.CLOSED;
    window.WebSocket = PatchedWebSocket;
  }
  // ---- Fingerprinting de tecnología: variables JS globales (mundo MAIN) --
  // content.js (mundo aislado) comparte el DOM con la página pero NO sus
  // variables JS globales -- window.React ahí es undefined aunque React
  // esté cargado de verdad, porque el mundo aislado tiene su propio objeto
  // window separado. Esto SOLO se puede ver desde acá.
  function checkGlobalTechSignals() {
    const found = [];
    try {
      if (window.React) found.push({ name: "React", category: "Framework frontend", confidence: 88, evidence: "window.React" });
      if (window.Vue) found.push({ name: "Vue.js", category: "Framework frontend", confidence: 88, evidence: "window.Vue" });
      if (window.angular) found.push({ name: "AngularJS", category: "Framework frontend", confidence: 85, evidence: "window.angular" });
      if (window.__NEXT_DATA__) found.push({ name: "Next.js", category: "Framework frontend", confidence: 92, evidence: "window.__NEXT_DATA__" });
      if (window.__NUXT__) found.push({ name: "Nuxt.js", category: "Framework frontend", confidence: 92, evidence: "window.__NUXT__" });
      if (window.jQuery) found.push({ name: "jQuery", category: "Librería JS", confidence: 70, evidence: "window.jQuery" });
      if (window.Shopify) found.push({ name: "Shopify", category: "E-commerce", confidence: 92, evidence: "window.Shopify" });
      if (window.wp) found.push({ name: "WordPress", category: "CMS", confidence: 80, evidence: "window.wp" });
      if (window.Drupal) found.push({ name: "Drupal", category: "CMS", confidence: 90, evidence: "window.Drupal" });
    } catch {}
    if (found.length) post({ source: "techfingerprint", techSignals: found });
  }
  // React/Vue/etc. se cargan async -- un solo chequeo inmediato al inyectar
  // el script llegaría demasiado temprano (nada cargado todavía). Se
  // reintenta tras el load y de nuevo un poco después por si el framework
  // tarda en inicializar variables globales.
  setTimeout(checkGlobalTechSignals, 1500);
  window.addEventListener("load", () => setTimeout(checkGlobalTechSignals, 1000));
})();
