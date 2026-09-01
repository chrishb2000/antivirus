"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;

  async function renderList() {
    const rules = await Aegis.invoke("firewall:list");
    const box = $("#ruleList");
    if (!rules.length) {
      box.innerHTML = '<div class="muted">Sin reglas creadas por Aegis.</div>';
      return;
    }
    box.innerHTML = rules.map((r) => {
      const detail = [r.direction, r.action, r.protocol, r.ports ? "puerto " + r.ports : "", r.program].filter(Boolean).join(" · ");
      return `<div class="list-item">
        <div class="li-main">
          <div class="li-title">${r.name}</div>
          <div class="li-sub">${detail}</div>
        </div>
        <span class="risk-tag ${r.enabled ? "risk-medium" : "risk-none"}">${r.enabled ? "Activa" : "Inactiva"}</span>
        <div class="li-actions">
          <button class="btn small danger" data-name="${r.name}">Eliminar</button>
        </div>
      </div>`;
    }).join("");

    AV.$$("[data-name]", box).forEach((b) =>
      b.addEventListener("click", async () => {
        const r = await Aegis.invoke("firewall:remove", b.dataset.name);
        AV.toast(r.ok ? "Regla eliminada" : "Error: " + (r.error || ""), r.ok ? "ok" : "danger");
        renderList();
      })
    );
  }

  AV.views.firewall = {
    async init() {
      $("#btnFwOn").addEventListener("click", () => this.setFirewall(true));
      $("#btnFwOff").addEventListener("click", () => this.setFirewall(false));
      $("#btnRulesRefresh").addEventListener("click", renderList);
      $("#btnRuleAdd").addEventListener("click", () => this.addRule());
    },

    async show() {
      const st = await Aegis.invoke("firewall:status");
      const el = $("#fwStatus");
      if (st && st.ok) {
        el.textContent = st.enabled === null ? "Mixto" : st.enabled ? "ON" : "OFF";
        el.className = "badge " + (st.enabled ? "" : "danger");
      } else {
        el.textContent = "Sin permiso admin";
        el.className = "badge warn";
      }
      const adminNote = $("#fwAdminNote");
      const info = AV.state.appInfo || (AV.state.appInfo = await Aegis.invoke("app:info"));
      adminNote.textContent = info.isAdmin
        ? "Administrador: gestión completa de reglas."
        : "Ejecuta la app como administrador para gestionar reglas (pestaña Ajustes).";
      renderList();
    },

    async setFirewall(on) {
      const r = await Aegis.invoke("firewall:set", on);
      AV.toast(r.ok ? "Firewall " + (on ? "activado" : "desactivado") : "Error: " + r.error, r.ok ? "ok" : "danger");
      this.show();
    },

    async addRule() {
      const data = {
        name: $("#ruleName").value,
        dir: $("#ruleDir").value,
        action: $("#ruleAction").value,
        protocol: $("#ruleProtocol").value === "any" ? "any" : $("#ruleProtocol").value,
        localport: $("#rulePort").value || undefined,
        remoteip: $("#ruleIp").value || undefined,
        program: $("#ruleProgram").value || undefined
      };
      if (!data.name) return AV.toast("Pon un nombre para la regla", "warn");
      const r = await Aegis.invoke("firewall:add", data);
      if (r.ok) {
        AV.toast("Regla creada correctamente (como administrador)", "ok");
        $("#ruleName").value = ""; $("#rulePort").value = ""; $("#ruleIp").value = ""; $("#ruleProgram").value = "";
        renderList();
      } else {
        AV.toast("Error al crear regla: " + (r.error || ""), "danger");
      }
    }
  };
})();