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
  // Token de handshake por carga de página (ver content.js para el resto de
  // la mitigación). Se escribe como atributo del DOM, NO como postMessage
  // de una sola vez -- este script corre en document_start, pero content.js
  // (que necesita leerlo) corre recién en document_idle; un postMessage
  // disparado acá se perdería sin que nadie lo escuche todavía. Un atributo
  // del DOM, en cambio, persiste: content.js lo lee cuando arranca, sin
  // depender de ninguna carrera de timing entre ambos scripts.
  //
  // Esto no es un secreto criptográficamente perfecto (cualquier otro
  // script de la página puede leer el mismo atributo tan pronto como
  // nosotros) -- pero eleva el costo de falsificar un evento de red de
  // "cualquier script genérico que adivine la propiedad
  // __surfaceHoundNetEvent" a "requiere conocer y leer este protocolo
  // interno específico".
  const PAGE_TOKEN = (crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`);
  const TOKEN_ATTR = "data-shx-t";
  try {
    document.documentElement.setAttribute(TOKEN_ATTR, PAGE_TOKEN);
  } catch {
    // document.documentElement puede no existir todavía en algún borde
    // exótico (ej. un documento XML sin elemento raíz aún) -- si falla,
    // el token queda null y content.js simplemente no relayará nada,
    // fail-closed en vez de fail-open.
  }

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
      window.postMessage({ [FLAG]: true, ...evt, pageUrl: location.href, capturedAt: Date.now(), token: PAGE_TOKEN }, "*");
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
  // ---- Fingerprinting de tecnología: variables JS globales (mundo MAIN) --
  // content.js (mundo aislado) comparte el DOM con la página pero NO sus
  // variables JS globales -- window.React ahí es undefined aunque React
  // esté cargado de verdad, porque el mundo aislado tiene su propio objeto
  // window separado. Esto SOLO se puede ver desde acá.
  // Detección por propiedades internas del DOM en vez de globales de window:
  // window.React/window.Vue casi nunca están expuestos en builds de
  // producción reales (quedan encapsulados dentro del bundle) -- pero React
  // (16+) y Vue (3+) SIGUEN adjuntando propiedades internas directo a los
  // nodos del DOM para su propio funcionamiento interno (reconciliación,
  // manejo de eventos). Esto no se puede eliminar con tree-shaking porque
  // es comportamiento en tiempo de ejecución, no una conveniencia de debug
  // -- sobrevive a cualquier build de producción, a diferencia de
  // "data-reactroot" (React 15/16 lo tenía; React 17+ lo eliminó por
  // completo) o de confiar solo en window.React.
  function detectByDomExpandoProps(prefixes, sampleSize = 12) {
    try {
      const candidates = [document.body, ...Array.from(document.body?.children || []).slice(0, sampleSize)];
      for (const el of candidates) {
        if (!el) continue;
        for (const key of Object.keys(el)) {
          if (prefixes.some((p) => key.startsWith(p))) return true;
        }
      }
    } catch {}
    return false;
  }

  function checkGlobalTechSignals() {
    const found = [];
    try {
      if (window.React) {
        found.push({ name: "React", category: "Framework frontend", confidence: 88, evidence: "window.React" });
      } else if (detectByDomExpandoProps(["__reactFiber$", "__reactContainer$", "__reactProps$"])) {
        found.push({ name: "React", category: "Framework frontend", confidence: 85, evidence: "propiedades internas __reactFiber$/__reactContainer$ en el DOM (window.React no expuesto -- típico de builds de producción)" });
      }
      if (window.Vue) {
        found.push({ name: "Vue.js", category: "Framework frontend", confidence: 88, evidence: "window.Vue" });
      } else if (detectByDomExpandoProps(["__vue_app__", "__vueParentComponent", "__vnode"])) {
        found.push({ name: "Vue.js", category: "Framework frontend", confidence: 82, evidence: "propiedades internas __vue_app__/__vueParentComponent en el DOM" });
      }
      if (window.angular) found.push({ name: "AngularJS", category: "Framework frontend", confidence: 85, evidence: "window.angular" });
      if (window.__NEXT_DATA__) found.push({ name: "Next.js", category: "Framework frontend", confidence: 92, evidence: "window.__NEXT_DATA__" });
      // Next.js con App Router (13+) no siempre expone __NEXT_DATA__, pero
      // sigue registrando sus chunks bajo este namespace de webpack.
      if (!window.__NEXT_DATA__ && window.webpackChunk_N_E) found.push({ name: "Next.js", category: "Framework frontend", confidence: 80, evidence: "window.webpackChunk_N_E (namespace de chunks de Next.js)" });
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
