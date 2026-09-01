"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;

  async function currentCfg() {
    if (!AV.state.config) AV.state.config = await Aegis.invoke("config:get");
    return AV.state.config;
  }

  function bindToggle(id, key) {
    const el = $(id);
    el.addEventListener("change", async () => {
      AV.state.config = await Aegis.invoke("config:set", { [key]: el.checked });
      AV.toast("Ajuste guardado", "ok");
    });
  }

  function renderLists() {
    renderExclusions();
    renderWatched();
    renderExts();
    renderAdmin();
  }

  function renderExclusions() {
    const box = $("#exclusionList");
    const list = (AV.state.config.exclusions || []).filter(Boolean);
    if (!list.length) {
      box.innerHTML = '<div class="muted">Sin exclusiones.</div>';
      return;
    }
    box.innerHTML = list.map((p) => `<div class="list-item">
      <div class="li-title">${p}</div>
      <button class="btn small danger" data-ex="${p}">Quitar</button>
    </div>`).join("");
    AV.$$("[data-ex]", box).forEach((b) =>
      b.addEventListener("click", async () => {
        AV.state.config = await Aegis.invoke("config:set", { exclusions: (AV.state.config.exclusions || []).filter((x) => x !== b.dataset.ex) });
        renderExclusions();
      })
    );
  }

  function renderWatched() {
    const box = $("#watchedList");
    const list = AV.state.config.watchedFolders || [];
    const html = list.length
      ? list.map((p) => `<div class="list-item"><div class="li-title">${p}</div><button class="btn small danger" data-w="${p}">Quitar</button></div>`).join("")
      : '<div class="muted">Solo se vigila la carpeta Descargas. Añade más carpetas.</div>';
    box.innerHTML = html;
    AV.$$("[data-w]", box).forEach((b) =>
      b.addEventListener("click", async () => {
        AV.state.config = await Aegis.invoke("config:set", { watchedFolders: (AV.state.config.watchedFolders || []).filter((x) => x !== b.dataset.w) });
        renderWatched();
      })
    );
  }

  function renderExts() {
    const box = $("#extList");
    box.innerHTML = (AV.state.config.scanExtensions || []).map((e) => `<span>.${e}</span>`).join("");
  }

  async function renderAdmin() {
    const info = AV.state.appInfo || (AV.state.appInfo = await Aegis.invoke("app:info"));
    const box = $("#adminSection");
    if (info.isAdmin) {
      box.innerHTML = '<div class="ok-text">La app se ejecuta como administrador. Firewall y puertos disponibles.</div>';
    } else {
      box.innerHTML = `<div class="warn-text">Sin permisos de administrador. Algunas funciones (firewall, apertura/cierre de puertos, bloqueo) no funcionarán.</div>
        <button class="btn primary" id="btnElevate" style="margin-top:10px">Reiniciar como administrador</button>`;
      $("#btnElevate").addEventListener("click", async () => {
        await Aegis.invoke("app:elevate");
        AV.toast("Reiniciando con permisos de administrador...", "ok");
      });
    }
  }

  AV.views.settings = {
    async init() {
      const cfg = await currentCfg();
      $("#cfgRealtime").checked = !!cfg.realtime;
      $("#cfgAutoQ").checked = !!cfg.autoQuarantine;
      $("#cfgAutoBlock").checked = !!cfg.autoBlockConnections;
      $("#cfgEmailScan").checked = !!cfg.emailScan;
      $("#cfgNotify").checked = !!cfg.notifications;
      $("#cfgAiEnabled").checked = !!cfg.aiEnabled;
      $("#cfgVtKey").value = cfg.virustotalKey || "";

      bindToggle("#cfgRealtime", "realtime");
      bindToggle("#cfgAutoQ", "autoQuarantine");
      bindToggle("#cfgAutoBlock", "autoBlockConnections");
      bindToggle("#cfgEmailScan", "emailScan");
      bindToggle("#cfgNotify", "notifications");
      bindToggle("#cfgAiEnabled", "aiEnabled");

      $("#cfgVtKey").addEventListener("change", async (e) => {
        AV.state.config = await Aegis.invoke("config:set", { virustotalKey: e.target.value });
        AV.toast("Clave VirusTotal guardada", "ok");
      });

      $("#btnAddExclusion").addEventListener("click", async () => {
        const dir = await Aegis.invoke("dialog:pickFolder");
        if (!dir) return;
        AV.state.config = await Aegis.invoke("config:set", { exclusions: [...new Set([...(AV.state.config.exclusions || []), dir])] });
        renderExclusions();
      });

      $("#btnAddWatched").addEventListener("click", async () => {
        const dir = await Aegis.invoke("dialog:pickFolder");
        if (!dir) return;
        AV.state.config = await Aegis.invoke("config:set", { watchedFolders: [...new Set([...(AV.state.config.watchedFolders || []), dir])] });
        renderWatched();
      });

      renderLists();
    },

    async show() {
      AV.state.config = await Aegis.invoke("config:get");
      const cfg = AV.state.config;
      $("#cfgRealtime").checked = !!cfg.realtime;
      $("#cfgAutoQ").checked = !!cfg.autoQuarantine;
      $("#cfgAutoBlock").checked = !!cfg.autoBlockConnections;
      $("#cfgEmailScan").checked = !!cfg.emailScan;
      $("#cfgNotify").checked = !!cfg.notifications;
      $("#cfgAiEnabled").checked = !!cfg.aiEnabled;
      if ($("#cfgVtKey").value !== (cfg.virustotalKey || "")) $("#cfgVtKey").value = cfg.virustotalKey || "";
      renderLists();
    }
  };
})();