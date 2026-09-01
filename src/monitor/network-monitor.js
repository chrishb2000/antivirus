"use strict";
const { runPowerShell } = require("../utils/ps");

const RISK_PORTS = {
  23: "Telnet (sin cifrado)",
  4444: "Backdoor / Metasploit",
  1337: "Backdoor comun",
  31337: "Backdoor ",
  5555: "ADB / Backdoor",
  6667: "IRC (botnets)",
  9050: "Tor",
  3389: "Escritorio remoto expuesto",
  6666: "IRC (botnets)",
  12345: "NetBus (troyano)",
  54321: "Backdoor",
  2745: "Beast (troyano)",
  65000: "Backdoor"
};

function classifyConn(conn) {
  const risk = RISK_PORTS[conn.remotePort];
  return risk ? { risky: true, reason: risk } : { risky: false, reason: null };
}

class NetworkMonitor {
  async list() {
    const out = await runPowerShell(
      'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | ConvertTo-Json -Compress',
      15000
    );
    if (!out) return [];
    try {
      const arr = JSON.parse(out);
      const list = Array.isArray(arr) ? arr : [arr];
      return list
        .filter(x => x && x.RemotePort)
        .map(c => {
          const cls = classifyConn(c);
          return {
            localAddress: String(c.LocalAddress || ""),
            localPort: c.LocalPort,
            remoteAddress: String(c.RemoteAddress || ""),
            remotePort: c.RemotePort,
            pid: c.OwningProcess,
            state: c.State || "",
            risky: cls.risky,
            riskReason: cls.reason
          };
        });
    } catch (e) {
      return [];
    }
  }
}

module.exports = new NetworkMonitor();