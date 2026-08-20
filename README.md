# 🐺 Surface Hound

**Extensión de navegador (Chrome y Firefox) para reconocimiento pasivo en
vivo durante bug bounty**, con un puente opcional hacia tus herramientas
CLI locales (nuclei, httpx, katana, arjun, dalfox, ffuf, dnsx, gau,
subfinder).

Creada por **Zuk4r1**. Ver [LICENSE](./LICENSE) para
términos de atribución y uso.

> Uso exclusivo en programas autorizados: VDP, Bug Bounty, pentest
> contratado, CTF o laboratorios propios. Respetá siempre el scope y las
> reglas de cada programa — la extensión incluye un **Scope Guard** para
> ayudarte a no salirte de ahí por accidente (ver más abajo).

---

## 📜 Para qué sirve

Mientras navegás normalmente un objetivo dentro de scope, Surface Hound
construye en segundo plano un mapa completo de su superficie de ataque —
sin que tengas que hacer nada extra — y te da hipótesis de vulnerabilidad
ya clasificadas con nivel de confianza, en vez de una lista cruda de datos
que tenés que interpretar vos.

La idea central: la fase de reconocimiento pasivo (ver qué endpoints
existen, qué parámetros usan, si hay secretos expuestos, si CORS/CSP están
mal configurados, si hay patrones de IDOR) pasa **mientras cazás**, no como
un paso aparte con otra herramienta. Y cuando encontrás algo que vale la
pena profundizar, tenés un puente directo a tu toolkit de línea de
comandos sin salir del navegador.

## 📌 El panel, pestaña por pestaña

Todo lo que sigue vive en el mismo panel (F12 → pestaña "Superficie de
ataque", el popup, o la vista de pantalla completa) — este es el detalle
de qué hace cada una:

### 🗺️ Mapa
Árbol interactivo de todo lo descubierto, agrupado por segmentos de path
(`api` → `{id}` → `files` → `{id}` → `preview`). Los segmentos tipo ID
muestran `{id}` con un sufijo corto para distinguirlos entre sí, y
**doble clic revela y copia el valor real** al portapapeles. Cada nodo
lleva el badge del nivel de confianza IDOR calculado (HIGH/MED/LOW) y el
método HTTP — sólido si hubo una solicitud directa ahí, atenuado (`↓ GET`)
si es un agregado de las rutas anidadas debajo. Clic en cualquier nodo con
endpoint(s) despliega la ruta completa exacta (`GET https://…`).

### 📡 Endpoints
También marca **posible ausencia de rate limiting**: un endpoint sensible
(login/OTP/reset-password, por patrón de ruta) visto 5+ veces sin haber
recibido nunca un HTTP 429 aparece destacado arriba de la lista — no
confirma la ausencia, solo que no se observó throttling en el tráfico
capturado hasta ahora.

Lista completa de cada solicitud capturada: método, URL, cuántas veces se
vio, hora del último, código HTTP, y si iba autenticada. Al expandir un
endpoint: metadata (content-type, tamaño de respuesta, página que lo
originó, y el script exacto del sitio que lo disparó, extraído del stack
trace), una muestra de la respuesta capturada, los parámetros clasificados
ahí, los hallazgos CORS/CSP asociados a ese endpoint puntual, y dos
botones: **"Probar CORS ahora"** (dispara el request real y muestra los
headers al instante) y **"Analizar con CLI"** (te lleva a la sección
avanzada con el target precargado).

### 🔎 Parámetros
Cada parámetro visto, con su hipótesis de vulnerabilidad (IDOR, SSRF, Open
Redirect, LFI, SQLi, SSTI, Mass Assignment, XSS, Command Injection), CWE
correspondiente, y una lista de payloads concretos para probar a mano. Los
parámetros propensos a falsos positivos (como `name`, `title`, `comment`
para XSS/SSTI) muestran si el valor se vio **reflejado de verdad** en una
respuesta capturada — si no hay esa corroboración, queda marcado como
hipótesis por nombre solamente, no como hallazgo confirmado.

### 🎯 IDOR
Candidatos con **confidence % real** (nunca 100%, es análisis pasivo),
calculado combinando: si es numérico/UUID, si es parte del path o de la
query, si el nombre del recurso es reconocible, cuántos valores distintos
se observaron, y si el valor apareció reflejado en una respuesta JSON.
Cada tarjeta tiene:
- **"Ver validación sugerida"**: arma la especificación del test (endpoint,
  parámetro, ID sugerido para reemplazar, qué se necesita para validarlo)
- **"Enviar a Burp"**: copia un request en texto crudo listo para pegar en
  Repeater
- **"Crear hallazgo"**: pre-completa automáticamente la pestaña
  **Notas/Reporte** con título, severidad (mapeada del nivel HIGH/MED/LOW)
  y el detalle completo — sin tener que escribirlo de cero

### 🕸️ Entidades
Grafo de correlación: cuando dos IDs distintos aparecen juntos en el mismo
JSON (ej. `user_id` + `organization_id` en una misma respuesta), quedan
conectados acá. Cada entidad muestra su clave=valor, cuántas veces se vio,
con qué otras entidades está correlacionada (y cuántas veces), y en qué
URLs apareció — útil para detectar acceso horizontal entre
tenants/organizaciones sin tener que cruzar los datos a mano.

### 🔑 JWT
Cada token visto, decodificado (header + payload completos al expandir),
con hallazgos clasificados en 4 niveles: `OBSERVED` (hecho objetivo, sin
implicar vulnerabilidad), `SUSPICIOUS` (patrón que amerita revisión pero
es común y a veces benigno), `CANDIDATE` (hipótesis de explotación
concreta, no confirmada) — nunca `CONFIRMED` desde análisis pasivo. Por
ejemplo, `alg: HS256` es solo `OBSERVED`; `alg: none` sube a `CANDIDATE`
con la aclaración explícita de que falta probarlo activamente.

### 🔓 Secretos
Claves y tokens expuestos en el JS del sitio (AWS, GitHub, Slack, Stripe,
claves privadas, y un patrón genérico con alta tasa de falsos positivos
que se filtra por entropía). Cada uno con confianza % por tipo, exposición
(dónde se encontró), y una marca explícita de **"público por diseño"**
para claves que no son secretos por sí solas (Stripe publishable key,
config de Firebase, DSN de Sentry) — en vez de tratarlas como hallazgo
crítico igual que una AWS key real.

También detecta **source maps referenciados** (`//# sourceMappingURL=`),
pasivamente y sin tráfico extra. Verificar si de verdad están expuestos
(botón "Verificar exposición", requiere modo Asistido/Activo y respeta el
Scope Guard) descarga el `.map` real y, si trae el código fuente original
completo (`sourcesContent`), busca endpoints internos y secretos ahí —
código que a veces nunca aparece en el bundle minificado final.

### 🌐 CORS/CSP
También cubre headers de seguridad básicos (HSTS, X-Frame-Options,
X-Content-Type-Options, Permissions-Policy) y hallazgos de **OAuth/OIDC**
(state ausente = CSRF en OAuth, PKCE ausente, flujo implícito deprecado,
redirect_uri observado como hipótesis a probar) — no solo CORS/CSP,
reusando la misma tarjeta. Cada hallazgo se puede expandir con doble clic
a una tarjeta completa: Directiva, Valor observado, Origen, Tipo,
Severidad, Confianza, una sección "¿Por qué importa?" que explica el
riesgo sin sobre-afirmar explotabilidad, la Evidencia (header/parámetro
crudo capturado), y validación sugerida con botones **Ver respuesta**,
**Ver headers**, **Copiar evidencia**, y **Marcar como falso positivo**
(queda persistido y marcado visualmente, sin borrar el hallazgo).
X-Frame-Options ausente no se reporta si CSP ya trae `frame-ancestors`
(evita falso positivo). El flujo OAuth se detecta por la forma de los
query params (`client_id`+`redirect_uri`+`response_type` juntos), no por
una ruta fija, ya que dispara con cualquier request (incluida la
navegación completa típica del paso de autorización).

### ⬡ GraphQL
Detecta operaciones GraphQL **por la forma del body**, no por la URL (no
todos los backends usan `/graphql`). Extrae tipo de operación
(query/mutation/subscription) y nombre, soporta batching (varias
operaciones en un solo request), y distingue introspection realmente
confirmada (schema completo visto en una respuesta) de un simple intento
del lado del cliente. **Cada mutation se marca como candidata a BFLA**
automáticamente, con un botón que arma la especificación de validación
(probar con sesión de menor privilegio) — el patrón de GraphQL que casi
nadie prueba a mano porque no aparece como una ruta REST separada.

Cuando introspection está habilitada, **doble clic en esa tarjeta** expande
el análisis completo del schema: todas las queries/mutations/subscriptions
disponibles (no solo las que la app usa — incluye "shadow API"), argumentos
que parecen identificadores de recurso (candidatos IDOR/BOLA), campos
deprecados, campos con nombre de dato sensible, enums/inputs/interfaces/
uniones, y las mutations con nombre de acción destructiva marcadas como
candidatas prioritarias a revisar autorización.

### 🔌 WebSocket
Captura conexiones WebSocket completas (chat en vivo, trading,
notificaciones push) — un blind spot total antes de esta versión, ya que
solo se hookeaba `fetch`/`XHR`. Muestra conexiones, cierres (código +
razón), y mensajes entrantes/salientes con **conteo real acumulado**
(incluye los que el muestreo no guardó como ejemplo) más muestras
expandibles de texto. El muestreo (máx. 1 mensaje reportado cada 400ms por
dirección) existe para no saturar el storage con un feed de alto volumen —
pero nunca afecta el envío/recepción real, solo qué se reporta al panel.

### 🧬 Tecnología
Fingerprinting 100% pasivo de framework/CMS/servidor/WAF, antes de decidir
qué payloads probar. Combina tres fuentes que ven cosas distintas: headers
de respuesta (`Server`, `X-Powered-By`, headers de WAF/CDN) y cookies
características (`PHPSESSID`, `laravel_session`, `wordpress_logged_in_*`);
firmas en el DOM (meta generator, rutas como `wp-content`, atributos como
`ng-version`); y variables JS globales (`window.React`, `window.Vue`,
`window.__NEXT_DATA__`) — esto último solo se puede ver desde el mundo
`MAIN` de la página, ninguna otra fuente lo detecta. Si más de una fuente
corrobora la misma tecnología, la confianza sube en vez de duplicar la
entrada.

### 🔗 Cadenas
Cruza automáticamente datos que ya viste en otras pestañas — nunca
ejecuta nada nuevo, solo lee lo ya capturado — para sugerir combinaciones
que valen la pena probar juntas, no aisladas (SSRF candidato + secreto
AWS visto → probar metadata de instancia; CORS crítico + endpoint
autenticado; IDOR de alta confianza + entidad correlacionada con más
recursos; mutation GraphQL + JWT débil; source map con secretos dentro;
OAuth sin PKCE + Open Redirect candidato). Cada regla exige **dos**
señales concretas en la misma sesión, nunca una sola pista aislada — son
hipótesis para que las valides vos, no hallazgos confirmados.

### 🛡️ Scope
Definís un programa activo con patrones `allow`/`deny` (admite
`*.dominio.com`). A partir de ahí, todo lo capturado se marca dentro/fuera
de scope en el resto del panel. **Fail-closed real**: cualquier acción
activa (CORS en vivo, ejecución de herramientas CLI) requiere que el
objetivo matchee explícitamente un patrón `allow` — sin scope configurado,
con `allow` vacío, o con el host en `deny`, la acción queda bloqueada por
defecto, no permitida. La validación se repite también del lado del
agente nativo de forma independiente, como defensa en profundidad real.

### 📝 Notas / Reporte
Acá armás el reporte final de la sesión:
- **Agregar hallazgos a mano**: título, severidad (Critical/High/Medium/
  Low/Informational) y un cuerpo libre para steps to reproduce e impacto
- **Se completa solo** desde la pestaña IDOR con el botón "Crear hallazgo"
  (trae el título, severidad y detalle ya armados, incluyendo las señales
  que motivaron el candidato, y el checklist de qué falta demostrar)
- Cada hallazgo muestra la **traducción de severidad a HackerOne/Bugcrowd/
  Intigriti** (Bugcrowd usa su propia taxonomía P1-P5, no las mismas
  etiquetas que las otras dos) — tanto en la lista como en el export
- Lista de todos los hallazgos guardados en la sesión, con severidad y
  fecha, para revisar antes de exportar
- **"Exportar reporte"** (botón en el header, arriba de todo) descarga un
  archivo Markdown con todos los hallazgos guardados, formateado para
  adaptar directo a HackerOne/Bugcrowd/Intigriti — con la evidencia, el
  confidence % de cada uno, y la traducción de severidad, no solo el título

## 🔐 Controles generales (header del panel)

- **Modo Pasivo / Asistido / Activo** — qué tan lejos puede llegar la
  extensión sin pedírtelo explícitamente (ver tabla abajo)
- **Línea de estado** (`● MODO · SCOPE: ON/OFF · AGENT: ONLINE/OFFLINE`) —
  de un vistazo, si estás generando tráfico, si hay scope configurado, y
  si el puente CLI está conectado
- **Selector de dominio** (en la vista de pantalla completa) — cambiá
  entre todos los dominios que ya capturaste sin perder el historial
- **Refrescar / Exportar reporte / Limpiar dominio / Limpiar TODOS** —
  este último borra todo el storage acumulado de todos los dominios, útil
  si `chrome.storage.local` se llena en una sesión larga

### 📊 Los tres modos de operación

| Modo | Qué desbloquea |
|---|---|
| **Pasivo** (default) | Solo observa. Nunca genera tráfico propio. |
| **Asistido** | Habilita chequeos puntuales de un clic (ej. probar CORS en vivo) y arma especificaciones de test para copiar a Burp — sin ejecutar nada por su cuenta. |
| **Activo** | Habilita el envío de comandos a tus herramientas CLI a través del agente nativo. |

### 🔗 Puente a tu CLI local

Desde "Análisis avanzado" (dentro de Endpoints), ejecutá nuclei / httpx /
katana / arjun / dalfox / ffuf / dnsx / gau / subfinder directo contra
cualquier endpoint capturado. Antes de correr nada, aparece un modal
mostrando el **comando exacto** que se va a ejecutar y recomendándote
correrlo en tu propia terminal para mejores resultados (menos límites de
timeout, sin salida truncada) — con opción de copiarlo o de igual forma
ejecutarlo desde la extensión. Los jobs corren en cola (varios en
paralelo), con streaming de salida en vivo y la posibilidad de expandir
cada uno para ver su resultado completo.

## ⚙️ Instalación

### 1. Descargar

```bash
git clone https://github.com/Zuk4r1/surface-hound.git
cd surface-hound
```

Las carpetas `chrome/` y `firefox/` ya vienen generadas y listas para
cargar — no hace falta compilar nada.

### 2a. Cargar en Chrome / Chromium / Brave

1. `chrome://extensions`
2. Activá "Modo de desarrollador" (arriba a la derecha)
3. "Cargar descomprimida" → seleccioná la carpeta **`chrome/`**
4. Copiá el ID de extensión que aparece en la tarjeta (lo vas a necesitar
   si instalás el puente CLI)

### 2b. Cargar en Firefox

1. `about:debugging#/runtime/this-firefox`
2. "Cargar complemento temporal…" → seleccioná el archivo
   **`firefox/manifest.json`** directamente (el archivo, no la carpeta)
3. Se desinstala al cerrar Firefox (limitación de los complementos
   temporales) — recargala cuando reinicies

### 3. Puente CLI (opcional)

Si querés el botón "Ejecutar" para correr herramientas contra un target
capturado, necesitás tenerlas instaladas en tu PATH y registrar el agente
nativo:

```bash
cd native-host
python install.py chrome <EXTENSION_ID>   # o: python install.py firefox
```

Funciona igual en Windows, Linux y macOS — en Windows genera automáticamente
el `.bat` necesario y se registra en el Registro de Windows, sin pasos
manuales adicionales. Recargá la extensión después de instalar el agente.

## 🎛️ Uso rápido

1. Navegá el objetivo normalmente — todo se captura solo
2. Abrí el panel (F12 → pestaña "Superficie de ataque", o el popup)
3. Configurá el **Scope** antes de subir a modo Activo, si vas a usar el
   puente CLI
4. Revisá **Mapa** para la vista general, **IDOR** para candidatos con
   confianza calculada, **Entidades** para correlaciones entre recursos
5. Guardá lo que confirmes en **Notas / Reporte** (a mano, o con "Crear
   hallazgo" desde IDOR) y exportalo en Markdown al terminar la sesión

## ⚖️ Licencia y autoría

Ver [LICENSE](./LICENSE). Cualquier redistribución (modificada o no) debe
mantener la atribución a **Zuk4r1**.


## ☕ Apoya mis proyectos

Si te resultan útil el proyecto, considera dar una ⭐ en GitHub o invitarme un café. ¡Gracias!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/investigacq)  [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/yordansuarezrojas)
