"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;

  const BAD_NAMES = ["xmrig.exe", "minerd.exe", "crypto.exe", "nc.exe", "psexecsvc.exe", "meterpreter.exe", "netbus.exe", "njrat.exe", "loopback.exe", "keylogger.exe", "proxy.exe"];
  const RISK_PORTS = { 23: 1, 4444: 1, 1337: 1, 31337: 1, 5555: 1, 6667: 1, 9050: 1, 6666: 1, 12345: 1, 54321: 1, 2745: 1, 65000: 1 };

  function procRisk(p) {
    if (BAD_NAMES.includes((p.name || "").toLowerCase())) return { level: "critical", label: "Malicioso" };
    const cmd = (p.cmdline || "").toLowerCase();
    const pth = (p.path || "").toLowerCase();
    let risk = 0;
    let detail = "Normal";
    if (cmd.includes("powershell") && (cmd.includes("-enc") || cmd.includes("frombase64"))) { risk = Math.max(risk, 3); detail = "PS ofuscado"; }
    if (cmd.includes("downloadstring") || (cmd.includes("iwr ") && cmd.includes("http"))) { risk = Math.max(risk, 3); detail = "Descarga remota"; }
    if (pth.includes("\\temp\\") && !pth.includes("node_modules")) { risk = Math.max(risk, 2); detail = "Temp"; }
    if (pth.includes("\\startup\\")) { risk = Math.max(risk, 2); detail = "Startup"; }
    if (cmd.includes("net user") && cmd.includes("admin")) { risk = Math.max(risk, 3); detail = "Add user admin"; }
    if (risk === 0) return { level: "none", label: "Normal" };
    return { level: risk >= 3 ? "high" : "medium", label: detail };
  }

  AV.views.realtime = {
    async init() {
      $("#btnProcsRefresh").addEventListener("click", () => this.render());
      $("#btnConnsRefresh").addEventListener("click", () => this.render());
    },

    async show() {
      await this.render();
    },

    async render() {
      const [procs, conns] = await Promise.all([
        Aegis.invoke("processes:list"),
        Aegis.invoke("network:connections")
      ]);
      this.renderProcs(procs || []);
      this.renderConns(conns || []);
    },

    renderProcs(procs) {
      const tb = $("#procTable");
      const sorted = procs
        .map((p) => ({ ...p, risk: procRisk(p) }))
        .sort((a, b) => {
          const order = { critical: 3, high: 2, medium: 1, none: 0 };
          return order[b.risk.level] - order[a.risk.level];
        });
      tb.innerHTML = sorted
        .slice(0, 400)
        .map((p) => {
          const cls = AV.riskClass(p.risk.level);
          return `<tr>
            <td>${p.pid}</td>
            <td title="${(p.path || "").replace(/"/g, "")}">${p.name}</td>
            <td>${AV.fmtBytes(p.mem)}</td>
            <td><span class="risk-tag ${cls}">${p.risk.label}</span></td>
            <td>
              <button class="btn small danger" data-pact="kill" data-pid="${p.pid}" data-name="${p.name}">Detener (Kill)</button>
              ${p.path ? `<button class="btn small primary" data-pact="ai" data-path="${p.path}">Analizar IA</button>` : ""}
            </td>
          </tr>`;
        })
        .join("");

      AV.$$("[data-pact]", tb).forEach((b) =>
        b.addEventListener("click", async () => {
          const act = b.dataset.pact;
          if (act === "kill") {
            const pid = parseInt(b.dataset.pid, 10);
            const name = b.dataset.name || "proceso";
            const r = await Aegis.invoke("processes:kill", pid);
            if (r.ok) {
              AV.toast(`Proceso ${name} (PID ${pid}) terminado correctamente`, "ok");
            } else {
              AV.toast(r.error || "No se pudo terminar el proceso", "danger");
            }
            this.render();
          } else if (act === "ai") {
            const pth = b.dataset.path;
            if (!pth) return AV.toast("Sin ruta de archivo disponible", "warn");
            AV.toast("Enviando ejecutable a análisis IA...", "ok");
            const res = await Aegis.invoke("ai:analyzeFile", pth);
            if (res && res.ai) {
              AV.toast(`Veredicto IA: ${res.ai.raw ? res.ai.raw.verdict : "Analizado"}`, "ok");
            }
          }
        })
      );

      const empty = AV.$("#procTable").innerHTML;
      if (!empty) AV.$("#procTable").innerHTML = '<tr><td colspan="5" class="muted">Sin datos</td></tr>';
    },

    renderConns(conns) {
      const tb = $("#connTable");
      if (!conns.length) {
        tb.innerHTML = '<tr><td colspan="6" class="muted">Sin conexiones activas</td></tr>';
        return;
      }
      tb.innerHTML = conns.map((c) => {
        const risky = c.risky || RISK_PORTS[c.remotePort];
        const cls = risky ? "risk-high" : "risk-none";
        const label = risky ? (c.riskReason || "Puerto riesgo") : "Normal";
        const ip = c.remoteAddress === "0.0.0.0" || c.remoteAddress === "::" ? "local" : c.remoteAddress;
        return `<tr>
          <td>${c.localAddress}:${c.localPort}</td>
          <td>${ip}</td>
          <td>${c.remotePort}</td>
          <td>${c.pid}</td>
          <td><span class="risk-tag ${cls}">${label}</span></td>
          <td>
            <button class="btn small" data-act="proc" data-pid="${c.pid}">Bloquear app</button>
            <button class="btn small" data-act="ip" data-ip="${c.remoteAddress}">Bloquear IP</button>
          </td>
        </tr>`;
      }).join("");

      AV.$$("[data-act]", tb).forEach((b) =>
        b.addEventListener("click", async () => {
          const act = b.dataset.act;
          if (act === "proc") {
            const conn = conns.find((c) => String(c.pid) === b.dataset.pid);
            if (!conn) return AV.toast("Proceso no encontrado", "warn");
            const procs = await Aegis.invoke("processes:list");
            const proc = procs.find((p) => String(p.pid) === b.dataset.pid);
            if (!proc || !proc.path) return AV.toast("No hay ruta del ejecutable para bloquear", "warn");
            const r = await Aegis.invoke("firewall:blockProgram", proc.path);
            AV.toast(r.ok ? "Programa bloqueado en firewall" : "Fallo: " + (r.error || ""), r.ok ? "ok" : "danger");
          } else if (act === "ip") {
            const r = await Aegis.invoke("firewall:blockIp", b.dataset.ip);
            AV.toast(r.ok ? "IP bloqueada" : "Fallo: " + (r.error || ""), r.ok ? "ok" : "danger");
          }
          this.render();
        })
      );
    }
  };
})();