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
  const MAX_BODY_CAPTURE = 20000; // cap de caracteres por body, evita payloads gigantes
  const FLAG = "__surfaceHoundNetEvent";

  function truncate(s) {
    if (typeof s !== "string") return s;
    return s.length > MAX_BODY_CAPTURE ? s.slice(0, MAX_BODY_CAPTURE) + "…[truncado]" : s;
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
                  post({ source: "fetch", url, method, status, contentType, responseSize: contentLength ? Number(contentLength) : text.length, requestBody: truncate(reqBody), responseBody: truncate(text), stack });
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
              responseBody: /json|text/i.test(contentType) ? truncate(xhr.responseText) : null,
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
})();
