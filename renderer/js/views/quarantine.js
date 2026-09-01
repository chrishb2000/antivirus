"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;

  AV.views.quarantine = {
    async init() {
      $("#btnQuarRefresh").addEventListener("click", () => this.show());
    },

    async show() {
      const items = await Aegis.invoke("quarantine:list");
      const box = $("#quarantineList");
      if (!items.length) {
        box.innerHTML = '<div class="muted">La cuarentena está vacía.</div>';
        return;
      }
      box.innerHTML = items.map((it) => {
        const threat = it.threat || {};
        const sev = threat.severity || "unknown";
        const cls = AV.riskClass(sev);
        return `<div class="list-item">
          <div class="li-main">
            <div class="li-title">${(threat.name || it.originalPath).split(/[\\/]/).pop()}</div>
            <div class="li-sub">${it.originalPath} · ${AV.fmtDate(it.time)}</div>
            ${threat.name ? `<div class="li-sub">${threat.name} ${threat.sha256 ? ("· SHA256 " + threat.sha256.slice(0, 16) + "…") : ""}</div>` : ""}
          </div>
          <span class="risk-tag ${cls}">${AV.riskLabel(sev)}</span>
          <div class="li-actions">
            <button class="btn small" data-act="restore" data-id="${it.id}">Restaurar</button>
            <button class="btn small danger" data-act="remove" data-id="${it.id}">Eliminar</button>
          </div>
        </div>`;
      }).join("");

      AV.$$("[data-act]", box).forEach((b) =>
        b.addEventListener("click", async () => {
          const act = b.dataset.act;
          const id = b.dataset.id;
          if (act === "restore") {
            const r = await Aegis.invoke("quarantine:restore", id);
            AV.toast(r.ok ? "Archivo restaurado a su ubicación original" : "Error: " + r.error, r.ok ? "ok" : "danger");
          } else {
            const r = await Aegis.invoke("quarantine:remove", id);
            AV.toast(r.ok ? "Archivo eliminado permanentemente" : "Error: " + r.error, r.ok ? "ok" : "danger");
          }
          this.show();
        })
      );
    }
  };
})();