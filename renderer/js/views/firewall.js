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
        const info = AV.state.appInfo || (AV.state.appInfo = await Aegis.invoke("app:info"));
        if (!info.isAdmin) {
          AV.toast("Reiniciando la aplicación con permisos de administrador...", "ok");
          await Aegis.invoke("app:elevate");
          return;
        }
        const r = await Aegis.invoke("firewall:remove", b.dataset.name);
        AV.toast(r.ok ? "Regla eliminada" : (r.error || "Error al eliminar"), r.ok ? "ok" : "danger");
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
      const info = AV.state.appInfo = await Aegis.invoke("app:info");
      const st = await Aegis.invoke("firewall:status");
      const el = $("#fwStatus");
      if (st && st.ok) {
        el.textContent = st.enabled === null ? "Mixto" : st.enabled ? "ON" : "OFF";
        el.className = "badge " + (st.enabled ? "" : "danger");
      } else {
        el.textContent = "Sin admin";
        el.className = "badge warn";
      }

      const adminNote = $("#fwAdminNote");
      if (info.isAdmin) {
        adminNote.innerHTML = '<span style="color:#22c55e; font-weight:500">✓ Modo Administrador: Gestión completa de reglas activa.</span>';
      } else {
        adminNote.innerHTML = `<div style="margin-top:10px; background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.3); padding:12px; border-radius:8px">
          <div style="color:#ef4444; font-weight:bold; margin-bottom:4px">⚠️ Sin permisos de administrador</div>
          <div style="font-size:12px; color:#cbd5e1; margin-bottom:8px">Windows requiere elevación de administrador para activar/desactivar el Firewall o crear reglas.</div>
          <button class="btn primary small" id="btnFwElevate">🛡️ Reiniciar como administrador</button>
        </div>`;
        const btnElevate = $("#btnFwElevate");
        if (btnElevate) {
          btnElevate.addEventListener("click", async () => {
            AV.toast("Reiniciando con permisos de administrador...", "ok");
            await Aegis.invoke("app:elevate");
          });
        }
      }
      renderList();
    },

    async setFirewall(on) {
      const info = AV.state.appInfo || (AV.state.appInfo = await Aegis.invoke("app:info"));
      if (!info.isAdmin) {
        AV.toast("Reiniciando aplicación como administrador para gestionar el Firewall...", "ok");
        await Aegis.invoke("app:elevate");
        return;
      }
      const r = await Aegis.invoke("firewall:set", on);
      if (r.ok) {
        AV.toast("Firewall " + (on ? "activado" : "desactivado"), "ok");
      } else {
        AV.toast(r.error || "Error al cambiar el estado del Firewall", "danger");
      }
      this.show();
    },

    async addRule() {
      const info = AV.state.appInfo || (AV.state.appInfo = await Aegis.invoke("app:info"));
      if (!info.isAdmin) {
        AV.toast("Reiniciando aplicación como administrador para crear reglas...", "ok");
        await Aegis.invoke("app:elevate");
        return;
      }
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
        AV.toast("Regla creada correctamente", "ok");
        $("#ruleName").value = ""; $("#rulePort").value = ""; $("#ruleIp").value = ""; $("#ruleProgram").value = "";
        renderList();
      } else {
        AV.toast(r.error || "Error al crear regla de Firewall", "danger");
      }
    }
  };
})();