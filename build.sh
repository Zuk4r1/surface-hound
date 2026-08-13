#!/usr/bin/env bash
# Regenera chrome/ y firefox/ a partir de shared/ + el manifest específico.
# Solo hace falta correrlo si editas algo dentro de shared/. Las carpetas
# chrome/ y firefox/ que vienen en este proyecto YA están generadas y listas
# para cargar tal cual en el navegador -- no necesitas correr esto para usarlas.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf chrome firefox
mkdir -p chrome firefox

cp -r shared/* chrome/
cp manifests/chrome.json chrome/manifest.json
cp LICENSE chrome/LICENSE

cp -r shared/* firefox/
cp manifests/firefox.json firefox/manifest.json
cp LICENSE firefox/LICENSE

echo "Regenerado:"
echo "  chrome/   -> cargar en chrome://extensions (Modo desarrollador > Cargar descomprimida)"
echo "  firefox/  -> cargar en about:debugging#/runtime/this-firefox (Cargar complemento temporal > manifest.json)"
