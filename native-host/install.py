#!/usr/bin/env python3
"""
Surface Hound
Creado por Zuk4r1 (Yordan Suárez)
Ver LICENSE en la raíz del proyecto.

Instalador multiplataforma del native host de Surface Hound.
Funciona igual en Windows, Linux y macOS -- no depende de bash.

Uso:
  python install.py chrome <EXTENSION_ID>
  python install.py firefox

El EXTENSION_ID de Chrome aparece en chrome://extensions con el Modo
desarrollador activado (es el ID largo debajo del nombre de la extensión).
Firefox no lo necesita: usa el id fijo del manifest ("surface-hound@local.dev").
"""
import sys
import os
import json
import platform

HOST_NAME = "com.surfacehound.host"
GECKO_ID = "surface-hound@local.dev"


def host_script_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "host.py"))


def make_windows_launcher():
    """
    Native messaging en Windows no puede apuntar 'path' directo a un .py:
    el sistema operativo necesita un ejecutable. Generamos un .bat que
    invoca 'python' (o 'py') con host.py, y el manifest apunta a ese .bat.
    """
    bat_path = os.path.join(os.path.dirname(__file__), "run_host.bat")
    py_launcher = sys.executable or "python"
    content = f'@echo off\r\n"{py_launcher}" "{host_script_path()}"\r\n'
    with open(bat_path, "w", newline="") as f:
        f.write(content)
    return os.path.abspath(bat_path)


def write_manifest(target_path, allowed_key, allowed_value):
    manifest = {
        "name": HOST_NAME,
        "description": "Puente nativo de Surface Hound hacia herramientas CLI locales",
        "path": target_path,
        "type": "stdio",
        allowed_key: allowed_value,
    }
    return manifest


def install_chrome(extension_id):
    if not extension_id:
        print("Falta el EXTENSION_ID. Uso: python install.py chrome <EXTENSION_ID>")
        sys.exit(1)

    allowed_origins = [f"chrome-extension://{extension_id}/"]
    system = platform.system()

    if system == "Windows":
        launcher = make_windows_launcher()
        manifest = write_manifest(launcher, "allowed_origins", allowed_origins)
        manifest_path = os.path.join(os.path.dirname(__file__), f"{HOST_NAME}.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        import winreg
        key_path = rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}"
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValue(key, "", winreg.REG_SZ, manifest_path)
        winreg.CloseKey(key)
        print(f"Registrado en el registro de Windows (HKCU):")
        print(f"  {key_path}")
        print(f"  -> {manifest_path}")
        print(f"  -> lanza: {launcher}")

    else:
        manifest = write_manifest(host_script_path(), "allowed_origins", allowed_origins)
        target_dirs = []
        home = os.path.expanduser("~")
        if system == "Darwin":
            target_dirs = [
                os.path.join(home, "Library/Application Support/Google/Chrome/NativeMessagingHosts"),
                os.path.join(home, "Library/Application Support/Chromium/NativeMessagingHosts"),
                os.path.join(home, "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            ]
        else:  # Linux
            target_dirs = [
                os.path.join(home, ".config/google-chrome/NativeMessagingHosts"),
                os.path.join(home, ".config/chromium/NativeMessagingHosts"),
                os.path.join(home, ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            ]
            os.chmod(host_script_path(), 0o755)

        for d in target_dirs:
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, f"{HOST_NAME}.json")
            with open(path, "w") as f:
                json.dump(manifest, f, indent=2)
            print(f"Instalado: {path}")

    print("\nListo. Recarga la extensión y probá el botón 'Ejecutar' en el panel.")


def install_firefox():
    system = platform.system()

    if system == "Windows":
        launcher = make_windows_launcher()
        manifest = write_manifest(launcher, "allowed_extensions", [GECKO_ID])
        manifest_path = os.path.join(os.path.dirname(__file__), f"{HOST_NAME}.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        import winreg
        key_path = rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}"
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValue(key, "", winreg.REG_SZ, manifest_path)
        winreg.CloseKey(key)
        print(f"Registrado en el registro de Windows (HKCU):")
        print(f"  {key_path}")
        print(f"  -> {manifest_path}")

    else:
        manifest = write_manifest(host_script_path(), "allowed_extensions", [GECKO_ID])
        home = os.path.expanduser("~")
        if system == "Darwin":
            target_dir = os.path.join(home, "Library/Application Support/Mozilla/NativeMessagingHosts")
        else:
            target_dir = os.path.join(home, ".mozilla/native-messaging-hosts")
            os.chmod(host_script_path(), 0o755)
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, f"{HOST_NAME}.json")
        with open(path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"Instalado: {path}")

    print("\nListo. Recarga la extensión en about:debugging y probá 'Ejecutar' en el panel.")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("chrome", "firefox"):
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "chrome":
        ext_id = sys.argv[2] if len(sys.argv) > 2 else None
        install_chrome(ext_id)
    else:
        install_firefox()
