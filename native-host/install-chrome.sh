#!/usr/bin/env bash
# Instala el native messaging host para Chrome/Chromium/Brave en Linux.
# Uso: ./install-chrome.sh <EXTENSION_ID>
set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Uso: $0 <EXTENSION_ID>"
  echo "El EXTENSION_ID aparece en chrome://extensions con el Modo desarrollador activado."
  exit 1
fi

EXT_ID="$1"
HOST_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_PY="$HOST_DIR/host.py"
chmod +x "$HOST_PY"

MANIFEST_CONTENT=$(cat <<EOF
{
  "name": "com.surfacehound.host",
  "description": "Puente nativo de Surface Hound hacia herramientas CLI locales",
  "path": "$HOST_PY",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
EOF
)

for DIR in "$HOME/.config/google-chrome/NativeMessagingHosts" \
           "$HOME/.config/chromium/NativeMessagingHosts" \
           "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"; do
  mkdir -p "$DIR"
  echo "$MANIFEST_CONTENT" > "$DIR/com.surfacehound.host.json"
  echo "Instalado: $DIR/com.surfacehound.host.json"
done

echo ""
echo "Listo. Recarga la extensión en chrome://extensions y prueba el botón 'Ejecutar' en el panel."
