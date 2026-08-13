#!/usr/bin/env python3
"""
Surface Hound
Creado por Zuk4r1 (Yordan Suárez)
Ver LICENSE en la raíz del proyecto.

Native messaging host de Surface Hound -- v2, con cola de jobs.

En vez de "un botón, un proceso", cada ejecución es un job con su propio
job_id: se puede tener varios corriendo a la vez (hasta MAX_CONCURRENT),
consultar su estado, cancelar uno puntual sin afectar a los demás, y la
extensión recibe la salida en streaming etiquetada por job_id.

Además valida el target contra un scope (allow/deny) ANTES de ejecutar
cualquier comando, si la extensión lo manda -- defensa en profundidad: aunque
el panel ya bloquea esto del lado de la UI, el agente no confía ciegamente
en el llamador.

Instalación: ver README.md en esta misma carpeta / native-host/install.py.
"""
import sys
import json
import struct
import subprocess
import re
import threading
import uuid
import queue
import time

ALLOWED_ACTIONS = {
    "nuclei":    ["nuclei", "-u", "{target}", "-silent", "-timeout", "8"],
    "arjun":     ["arjun", "-u", "{target}", "-oT", "/tmp/surfacehound_arjun_out.txt"],
    "dalfox":    ["dalfox", "url", "{target}", "--silence"],
    "gau":       ["gau", "{target_host}"],
    "ffuf":      ["ffuf", "-u", "{target}/FUZZ", "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt", "-s"],
    "httpx":     ["httpx", "-u", "{target}", "-silent", "-title", "-tech-detect", "-status-code"],
    "katana":    ["katana", "-u", "{target}", "-silent", "-depth", "2"],
    "dnsx":      ["dnsx", "-d", "{target_host}", "-silent", "-a", "-resp"],
    "subfinder": ["subfinder", "-d", "{target_host}", "-silent"],
}

# Timeout por herramienta: las de crawling/fuzzing (katana, ffuf) necesitan
# más margen que un chequeo puntual (httpx, dnsx). Default si no está listada.
TOOL_TIMEOUTS = {
    "nuclei": 180, "arjun": 120, "dalfox": 120, "gau": 90,
    "ffuf": 240, "httpx": 60, "katana": 240, "dnsx": 30, "subfinder": 90,
}
DEFAULT_TIMEOUT = 180

MAX_CONCURRENT = 2
MAX_OUTPUT_LINES = 5000   # corta el proceso si se desborda de output (evita flood/DoS al propio agente)
MAX_JOBS_HISTORY = 50     # jobs terminados más viejos que esto se podan de memoria

URL_RE = re.compile(r"^https?://[a-zA-Z0-9.\-]+(:\d+)?(/[^\s]*)?$")
HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")

jobs = {}            # job_id -> dict con status/proceso/metadata
jobs_lock = threading.Lock()
job_queue = queue.Queue()
running_count = 0
running_count_lock = threading.Lock()
write_lock = threading.Lock()


def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        sys.exit(0)
    message_length = struct.unpack("<I", raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)


def send_message(obj):
    encoded = json.dumps(obj).encode("utf-8")
    with write_lock:
        sys.stdout.buffer.write(struct.pack("<I", len(encoded)))
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


def validate_target(target):
    if not URL_RE.match(target):
        return None, "target inválido (se espera URL http/https)"
    host = target.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
    if not HOST_RE.match(host):
        return None, "host inválido"
    return host, None


# ---- Scope Guard (misma lógica que la extensión, en Python) ----------------

def scope_match(hostname, pattern):
    if not pattern:
        return False
    pattern = pattern.strip().lower()
    hostname = hostname.lower()
    if not pattern:
        return False
    if pattern.startswith("*."):
        bare = pattern[2:]
        return hostname == bare or hostname.endswith("." + bare)
    return hostname == pattern


def is_in_scope(hostname, scope):
    if not scope or not scope.get("allow"):
        return None  # scope no configurado: el agente no bloquea, confía en el llamador
    deny = scope.get("deny") or []
    if any(scope_match(hostname, p) for p in deny):
        return False
    allow = scope.get("allow") or []
    return any(scope_match(hostname, p) for p in allow)


# ---- Ejecución de jobs -------------------------------------------------

def worker_loop():
    while True:
        job_id = job_queue.get()
        with jobs_lock:
            job = jobs.get(job_id)
        if not job or job["status"] == "cancelled":
            job_queue.task_done()
            continue
        run_job(job_id)
        job_queue.task_done()


def run_job(job_id):
    global running_count
    with jobs_lock:
        job = jobs[job_id]
        action = job["tool"]
        target = job["target"]

    with running_count_lock:
        running_count += 1

    try:
        with jobs_lock:
            job["status"] = "running"
            job["startedAt"] = time.time()
        send_message({"job_id": job_id, "status": "running"})

        if action not in ALLOWED_ACTIONS:
            finish_job(job_id, ok=False, error=f"acción no permitida: {action}")
            return

        host, err = validate_target(target)
        if err:
            finish_job(job_id, ok=False, error=err)
            return

        scope = job.get("scope")
        if scope:
            in_scope = is_in_scope(host, scope)
            if in_scope is False:
                finish_job(job_id, ok=False, error=f"BLOQUEADO por scope guard: {host} no está permitido ({scope.get('programName', 'programa sin nombre')})", blocked=True)
                return

        cmd_template = ALLOWED_ACTIONS[action]
        cmd = [c.replace("{target}", target).replace("{target_host}", host) for c in cmd_template]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except FileNotFoundError:
            finish_job(job_id, ok=False, error=f"herramienta '{cmd[0]}' no encontrada en PATH")
            return

        with jobs_lock:
            job["process"] = proc

        timeout = TOOL_TIMEOUTS.get(action, DEFAULT_TIMEOUT)
        timer = threading.Timer(timeout, lambda: proc.poll() is None and proc.kill())
        timer.start()
        truncated = False
        line_count = 0
        try:
            for line in proc.stdout:
                line_count += 1
                if line_count > MAX_OUTPUT_LINES:
                    truncated = True
                    proc.kill()
                    break
                send_message({"job_id": job_id, "line": line.rstrip("\n")})
                with jobs_lock:
                    if job["status"] == "cancelled":
                        break
            proc.wait()
        finally:
            timer.cancel()

        if truncated:
            send_message({"job_id": job_id, "line": f"[cortado: se superaron {MAX_OUTPUT_LINES} líneas de salida]"})

        with jobs_lock:
            cancelled = job["status"] == "cancelled"
        if not cancelled:
            finish_job(job_id, ok=True, returncode=proc.returncode)
        else:
            with jobs_lock:
                job["finishedAt"] = time.time()
            send_message({"job_id": job_id, "ok": True, "done": True, "cancelled": True, "returncode": proc.returncode})

    finally:
        with running_count_lock:
            running_count -= 1
        prune_old_jobs()


def finish_job(job_id, ok, error=None, returncode=None, blocked=False):
    with jobs_lock:
        jobs[job_id]["status"] = "blocked" if blocked else ("done" if ok else "error")
        jobs[job_id]["finishedAt"] = time.time()
    send_message({"job_id": job_id, "ok": ok, "done": True, "error": error, "returncode": returncode, "blocked": blocked})
    prune_old_jobs()


def prune_old_jobs():
    """Evita que jobs viejos se acumulen indefinidamente en memoria durante
    una sesión larga de bug bounty. Solo poda jobs ya terminados, nunca uno
    en cola o corriendo."""
    with jobs_lock:
        finished = [
            (jid, j) for jid, j in jobs.items()
            if j["status"] in ("done", "error", "blocked", "cancelled") and "finishedAt" in j
        ]
        if len(finished) <= MAX_JOBS_HISTORY:
            return
        finished.sort(key=lambda item: item[1]["finishedAt"])
        for jid, _ in finished[: len(finished) - MAX_JOBS_HISTORY]:
            del jobs[jid]


def submit_job(msg):
    job_id = uuid.uuid4().hex[:10]
    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "tool": msg.get("tool"),
            "target": msg.get("target", ""),
            "scope": msg.get("scope"),
            "status": "queued",
            "createdAt": time.time(),
        }
    send_message({"job_id": job_id, "ok": True, "status": "queued"})
    job_queue.put(job_id)


def cancel_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            send_message({"job_id": job_id, "ok": False, "error": "job no encontrado"})
            return
        job["status"] = "cancelled"
        proc = job.get("process")
    if proc and proc.poll() is None:
        proc.kill()
    send_message({"job_id": job_id, "ok": True, "cancelled": True})


def list_jobs():
    with jobs_lock:
        snapshot = [
            {"job_id": j["job_id"], "tool": j["tool"], "target": j["target"], "status": j["status"]}
            for j in jobs.values()
        ]
    send_message({"ok": True, "jobs": snapshot})


def main():
    for _ in range(MAX_CONCURRENT):
        threading.Thread(target=worker_loop, daemon=True).start()

    while True:
        try:
            msg = read_message()
        except json.JSONDecodeError as e:
            # Un mensaje malformado no debería tirar abajo todo el agente
            # (eso mataría todos los jobs en curso sin aviso). Se informa el
            # error y se sigue esperando el próximo mensaje.
            send_message({"ok": False, "error": f"mensaje inválido (JSON malformado): {e}"})
            continue

        action = msg.get("action")
        try:
            if action == "ping":
                send_message({"ok": True, "pong": True})
            elif action == "submit_job":
                submit_job(msg)
            elif action == "cancel_job":
                cancel_job(msg.get("job_id"))
            elif action == "list_jobs":
                list_jobs()
            else:
                send_message({"ok": False, "error": f"acción de protocolo desconocida: {action}"})
        except Exception as e:
            # Cualquier error inesperado procesando UN mensaje no debería
            # matar el proceso entero (y con él, todos los jobs corriendo).
            send_message({"ok": False, "action": action, "error": f"error interno: {e}"})


if __name__ == "__main__":
    main()
