#!/usr/bin/env bash
# Instala el native messaging host para Firefox en Linux.
# Uso: ./install-firefox.sh
# Firefox identifica la extensión por el "id" declarado en browser_specific_settings.gecko.id
# del manifest.json (por defecto "surface-hound@local.dev" en este proyecto), no por un ID
# generado en tiempo de carga, así que no hace falta pasarlo como argumento.
set -euo pipefail

HOST_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_PY="$HOST_DIR/host.py"
chmod +x "$HOST_PY"

GECKO_ID="surface-hound@local.dev"

MANIFEST_CONTENT=$(cat <<EOF
{
  "name": "com.surfacehound.host",
  "description": "Puente nativo de Surface Hound hacia herramientas CLI locales",
  "path": "$HOST_PY",
  "type": "stdio",
  "allowed_extensions": ["$GECKO_ID"]
}
EOF
)

TARGET_DIR="$HOME/.mozilla/native-messaging-hosts"
mkdir -p "$TARGET_DIR"
echo "$MANIFEST_CONTENT" > "$TARGET_DIR/com.surfacehound.host.json"

echo "Instalado: $TARGET_DIR/com.surfacehound.host.json"
echo ""
echo "Nota: si cargaste la extensión como 'Add-on temporal' (about:debugging),"
echo "Firefox respeta el id fijo declarado en el manifest ($GECKO_ID), así que"
echo "no necesitas reinstalar el host cada vez que recargues la extensión."
