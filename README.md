# 🐺 Surface Hound

**Extensión de navegador (Chrome y Firefox) para reconocimiento pasivo en
vivo durante bug bounty**, con un puente opcional hacia tus herramientas
CLI locales (nuclei, httpx, katana, arjun, dalfox, ffuf, dnsx, gau,
subfinder).

Creada por **Zuk4r1 (Yordan Suárez)**. Ver [LICENSE](./LICENSE) para
términos de atribución y uso.

> Uso exclusivo en programas autorizados: VDP, Bug Bounty, pentest
> contratado, CTF o laboratorios propios. Respetá siempre el scope y las
> reglas de cada programa — la extensión incluye un **Scope Guard** para
> ayudarte a no salirte de ahí por accidente (ver más abajo).

---

## Para qué sirve

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

## Qué hace

- **Mapea la superficie de ataque en vivo**: cada request que hace el
  navegador (fetch, XHR, recursos) se captura automáticamente — endpoint,
  método, parámetros, headers de autenticación, content-type, tamaño de
  respuesta, y hasta el script exacto del sitio que originó el request
- **Clasifica parámetros por hipótesis de vulnerabilidad** (IDOR, SSRF,
  Open Redirect, LFI, SQLi, SSTI, Mass Assignment, XSS, Command Injection),
  cada uno con su CWE y payloads sugeridos para probar
- **Detecta candidatos IDOR con scoring real**, no solo "tiene `id` en el
  nombre": combina si es un ID numérico o UUID, si es parte del path o de
  la query, si el nombre del recurso es reconocible, cuántos valores
  distintos se observaron, y si el valor se vio reflejado en una respuesta
  JSON — todo eso se traduce en un porcentaje de confianza (nunca 100%
  desde análisis pasivo) y una lista de señales concretas
- **Correlaciona entidades**: si dos IDs distintos aparecen juntos en el
  mismo JSON (ej. `user_id` + `organization_id`), quedan conectados en un
  grafo — útil para detectar acceso horizontal entre tenants/organizaciones
- **Decodifica JWTs** con un sistema de 4 niveles de confianza
  (`OBSERVED`/`SUSPICIOUS`/`CANDIDATE`, nunca `CONFIRMED` desde análisis
  pasivo) en vez de gritar "vulnerable" por cada `alg: HS256`
- **Escanea secretos expuestos** en el JS del sitio (AWS, GitHub, Slack,
  Stripe, claves privadas...) con confianza calculada por tipo, filtro de
  entropía para descartar placeholders, y distinción explícita entre
  secretos reales y claves que son públicas por diseño (Stripe
  publishable, Firebase config, Sentry DSN)
- **Detecta misconfiguraciones CORS/CSP**, con tarjetas de detalle que
  explican qué significa cada hallazgo, por qué importa, y qué validación
  activa hace falta para confirmarlo — nunca lo presenta como vulnerabilidad
  confirmada solo por observación pasiva
- **Puente a tu CLI local**: ejecutá nuclei/httpx/katana/arjun/dalfox/
  ffuf/dnsx/gau/subfinder directo desde el panel, con streaming de salida
  en vivo, cola de jobs concurrentes, y un modal de confirmación que te
  muestra el comando exacto antes de correrlo

## Cómo funciona

### Los tres modos de operación

| Modo | Qué desbloquea |
|---|---|
| **Pasivo** (default) | Solo observa. Nunca genera tráfico propio. |
| **Asistido** | Habilita chequeos puntuales de un clic (ej. probar CORS en vivo) y arma especificaciones de test para copiar a Burp — sin ejecutar nada por su cuenta. |
| **Activo** | Habilita el envío de comandos a tus herramientas CLI a través del agente nativo. |

### Scope Guard

Definís un programa activo con patrones `allow`/`deny` (admite
`*.dominio.com`). Todo lo capturado se marca dentro/fuera de scope, y
**cualquier acción activa queda bloqueada contra objetivos fuera de
scope**, sin importar el modo seleccionado — la validación se repite
también del lado del agente nativo, no solo en la interfaz.

## Instalación

### 1. Descargar

Cloná el repo (o descargalo como zip si es privado y no tenés acceso SSH
configurado):

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

## Uso rápido

1. Navegá el objetivo normalmente — todo se captura solo
2. Abrí el panel (F12 → pestaña "Superficie de ataque", o el popup)
3. Configurá el **Scope** antes de subir a modo Activo, si vas a usar el
   puente CLI
4. Revisá **Mapa** para la vista general, **IDOR** para candidatos con
   confianza calculada, **Entidades** para correlaciones entre recursos
5. Guardá lo que confirmes en **Notas / Reporte** y exportalo en Markdown
   al terminar la sesión.

## Licencia y autoría

Ver [LICENSE](./LICENSE). Cualquier redistribución (modificada o no) debe
mantener la atribución a Zuk4r1 (Yordan Suárez).
