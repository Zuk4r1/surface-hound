// ============================================================================
// Surface Hound
// Creado por Zuk4r1 (Yordan Suárez)
// Repositorio/autoría original de este proyecto — ver LICENSE en la raíz.
// ============================================================================

const extFull = typeof browser !== "undefined" ? browser : chrome;

function domainFromUrl() {
  return new URLSearchParams(location.search).get("domain");
}

async function listCapturedDomains() {
  const all = await extFull.storage.local.get(null);
  // STORAGE_PREFIX viene de panel-core.js, cargado antes que este script.
  // Se usa la constante en vez de repetir "shx:" a mano para que si ese
  // prefijo cambia algún día, esto no quede desincronizado en silencio.
  return Object.keys(all)
    .filter((k) => k.startsWith(STORAGE_PREFIX))
    .map((k) => k.slice(STORAGE_PREFIX.length));
}

async function buildDomainSwitcher() {
  const domains = await listCapturedDomains();
  if (domains.length <= 1) return;

  const current = domainFromUrl();
  const select = document.createElement("select");
  select.style.cssText = "margin-left:10px;background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:4px 8px;font-size:12px";
  for (const d of domains) {
    const opt = document.createElement("option");
    opt.value = d;
    opt.textContent = d;
    if (d === current) opt.selected = true;
    select.appendChild(opt);
  }
  select.addEventListener("change", () => {
    const url = new URL(location.href);
    url.searchParams.set("domain", select.value);
    location.href = url.toString();
  });
  document.getElementById("domain-title").after(select);
}

buildDomainSwitcher();

window.PanelCore.init(async () => domainFromUrl());
