// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

const extPanel = typeof browser !== "undefined" ? browser : chrome;

window.PanelCore.init(() => {
  return new Promise((resolve) => {
    extPanel.devtools.inspectedWindow.eval("location.hostname", (result, exc) => {
      resolve(exc ? null : result);
    });
  });
});
