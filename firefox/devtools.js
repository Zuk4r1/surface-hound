// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

const ext = typeof browser !== "undefined" ? browser : chrome;
ext.devtools.panels.create("Superficie de ataque", "icons/icon48.png", "panel/panel.html");
