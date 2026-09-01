"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;
  const fn = AV.fmtBytes;

  AV.views.dashboard = {
    dirty: true,

    async init() {
      this.renderThreats();
      this.renderFirewallStatus();
      const metrics = await Aegis.invoke("system:metrics");
      if (metrics) this.renderMetrics(metrics);
    },

    async show() {
      this.dirty = true;
      this.renderThreats();
      this.renderFirewallStatus();
      const metrics = await Aegis.invoke("system:metrics");
      if (metrics) this.renderMetrics(metrics);
    },

    renderThreats() {
      const box = $("#recentThreats");
      const counts = $("#threatCount");
      Aegis.invoke("threats:list", 8).then((threats) => {
        AV.state.threats = threats;
        counts.textContent = threats.length;
        if (!threats.length) {
          box.innerHTML = '<div class="muted">Sin alertas recientes</div>';
          return;
        }
        box.innerHTML = threats
          .slice(0, 6)
          .map((t) => {
            const cls = t.severity === "critical" || t.severity === "high" ? "risk-high" : t.severity === "medium" ? "risk-medium" : "risk-none";
            return `<div class="list-item">
              <div class="li-main">
                <div class="li-title">${t.name || t.description}</div>
                <div class="li-sub">${AV.fmtDate(t.time)} - ${t.action || "flagged"}</div>
              </div>
              <span class="risk-tag ${cls}">${AV.riskLabel(t.severity)}</span>
            </div>`;
          })
          .join("");
      });
    },

    async renderFirewallStatus() {
      const rt = await Aegis.invoke("runtime:status");
      const rtRow = $("#rtRow");
      rtRow.textContent = rt.realtime ? "ON" : "OFF";
      rtRow.className = rt.realtime ? "ok-text" : "bad-text";

      const watched = $("#watchedCount");
      watched.textContent = rt.watchedFolders ? rt.watchedFolders.length : 0;

      const cfg = AV.state.config || (await Aegis.invoke("config:get"));
      const aiRow = $("#aiRowStatus");
      if (cfg.aiEnabled && cfg.aiKeys[cfg.aiProvider]) {
        aiRow.textContent = "Conectada (" + cfg.aiProvider + ")";
        aiRow.className = "ok-text";
      } else {
        aiRow.textContent = "No configurada";
        aiRow.className = "warn-text";
      }

      const fw = await Aegis.invoke("firewall:status");
      const fwRow = $("#fwRowStatus");
      if (fw && fw.ok) {
        fwRow.textContent = fw.enabled ? "ON" : "OFF";
        fwRow.className = fw.enabled ? "ok-text" : "bad-text";
      } else {
        fwRow.textContent = "N/A";
        fwRow.className = "warn-text";
      }
    },

    renderMetrics(m) {
const rt = AV.state.metrics || {};
    const memPct = m.memPercent != null ? m.memPercent : (m.mem ? m.mem.percent : (rt.memPercent || 0));
    const procs = m.processCount != null ? m.processCount : (rt.processCount != null ? rt.processCount : "--");
    const conns = m.connectionCount != null ? m.connectionCount : (rt.connectionCount != null ? rt.connectionCount : "--");

    $("#statCpu").textContent = (m.cpu == null ? 0 : m.cpu) + "%";
    $("#statMem").textContent = memPct + "%";
    $("#statProcs").textContent = procs;
    $("#statConns").textContent = conns;

    if (memPct > 85) $("#statMem").style.color = "var(--danger)";
    else $("#statMem").style.color = "";
    if (m.cpu > 90) $("#statCpu").style.color = "var(--danger)";
    else $("#statCpu").style.color = "";

      const disks = m.disks || [];
      $("#diskCount").textContent = disks.length;
      const dl = $("#diskList");
      dl.innerHTML = disks
        .map((d) => {
          const color = d.percent > 90 ? "var(--danger)" : "var(--accent)";
          return `<div class="disk-item">
            <div class="disk-head"><span>${d.drive} ${d.label ? "(" + d.label + ")" : ""}</span>
            <span>${d.percent}% - ${fn(d.free)} libres de ${fn(d.size)}</span></div>
            <div class="disk-bar"><div class="disk-bar-fill" style="width:${d.percent}%;background:${color}"></div></div>
          </div>`;
        })
        .join("") || '<div class="muted">No hay discos</div>';
      this.dirty = false;
    }
  };
})();