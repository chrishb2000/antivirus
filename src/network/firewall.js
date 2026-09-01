"use strict";
const { runNetsh, runPowerShell } = require("../utils/ps");

const PREFIX = "AEGIS";

function sanitize(name) {
  return String(name || "Regla").replace(/[^a-zA-Z0-9 _\-]/g, "").trim().slice(0, 60);
}

class Firewall {
  async status() {
    // Devuelve estado de perfiles
    const out = await runNetsh(["advfirewall", "show", "allprofiles", "state"]);
    if (!out.ok) return { ok: false, error: out.error };
    const active = /ON/i.test(out.output) !== /OFF/i.test(out.output) ? /ON/i.test(out.output) : null;
    const publicProf = /Estado del perfil p[uú]blica?: *\s*(ON|OFF)/i.exec(out.output);
    const domainProf = /Estado del perfil de dominio?: *\s*(ON|OFF)/i.exec(out.output);
    const privProf = /Estado del perfil privad[oa]?: *\s*(ON|OFF)/i.exec(out.output);
    return {
      ok: true,
      enabled: active,
      profiles: {
        domain: domainProf ? domainProf[1] : null,
        public: publicProf ? publicProf[1] : null,
        private: privProf ? privProf[1] : null
      }
    };
  }

  async setEnabled(on) {
    const state = on ? "on" : "off";
    const r = await runNetsh(["advfirewall", "set", "allprofiles", "state", state]);
    return r;
  }

  async add({ name, dir = "in", action = "allow", protocol = "TCP", localport, remoteip, program }) {
    const args = ["advfirewall", "firewall", "add", "rule", `name=${PREFIX}-${sanitize(name)}`, `dir=${dir}`, `action=${action}`, `protocol=${protocol}`];
    if (localport) args.push(`localport=${localport}`);
    if (remoteip) args.push(`remoteip=${remoteip}`);
    if (program) args.push(`program=${program}`);
    return runNetsh(args);
  }

  async remove(name) {
    return runNetsh(["advfirewall", "firewall", "delete", "rule", `name=${PREFIX}-${sanitize(name)}`]);
  }

  async removeExact(fullName) {
    return runNetsh(["advfirewall", "firewall", "delete", "rule", `name=${fullName}`]);
  }

  async list() {
    // Lista reglas creadas por Aegis (idioma independiente)
    const script =
      "Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'AEGIS*' } | Select-Object DisplayName,Enabled,Direction,Action,@{N='Program';E={($_.Program | Where-Object {$_.Enabled}).Program}},@{N='Ports';E={($_.PortFilter | Where-Object {$_.Enabled}).LocalPort}},@{N='Protocol';E={($_.PortFilter | Where-Object {$_.Enabled}).Protocol}} | ConvertTo-Json -Compress";
    const out = await runPowerShell(script, 20000);
    if (!out) return [];
    try {
      const arr = JSON.parse(out);
      const list = Array.isArray(arr) ? arr : [arr];
      return list.filter(x => x && x.DisplayName).map(r => ({
        name: r.DisplayName,
        enabled: !!r.Enabled,
        direction: r.Direction,
        action: r.Action,
        program: r.Program ? String(r.Program).split("|")[0] : "",
        ports: r.Ports,
        protocol: r.Protocol
      }));
    } catch (e) {
      return [];
    }
  }

  async blockProgram(filePath) {
    const name = sanitize("BLK-" + decodeURIComponent(filePath.split(/[\\/]/).pop() || "app") + "-" + Date.now().toString(36));
    return this.add({ name, dir: "out", action: "block", program: filePath });
  }

  async blockIp(ip) {
    const name = sanitize("BLKIP-" + ip + "-" + Date.now().toString(36));
    return this.add({ name, dir: "out", action: "block", remoteip: ip });
  }
}

module.exports = new Firewall();