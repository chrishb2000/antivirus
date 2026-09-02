"use strict";
const { execFile } = require("child_process");

const RISK_PORTS = {
  23: "Telnet (sin cifrado)",
  4444: "Backdoor / Metasploit",
  1337: "Backdoor común",
  31337: "Backdoor",
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
  list() {
    return new Promise((resolve) => {
      execFile("netstat.exe", ["-ano", "-p", "tcp"], { maxBuffer: 10 * 1024 * 1024, windowsHide: true }, (err, stdout) => {
        if (err || !stdout) return resolve([]);
        try {
          const lines = stdout.split(/\r?\n/);
          const connections = [];

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed.startsWith("TCP")) continue;

            const parts = trimmed.split(/\s+/);
            if (parts.length < 5) continue;

            const local = parts[1] || "";
            const remote = parts[2] || "";
            const state = parts[3] || "";
            const pid = parseInt(parts[4], 10);

            const lastColonLocal = local.lastIndexOf(":");
            const lastColonRemote = remote.lastIndexOf(":");

            if (lastColonLocal === -1 || lastColonRemote === -1) continue;

            const localAddress = local.slice(0, lastColonLocal);
            const localPort = parseInt(local.slice(lastColonLocal + 1), 10);
            const remoteAddress = remote.slice(0, lastColonRemote);
            const remotePort = parseInt(remote.slice(lastColonRemote + 1), 10);

            if (isNaN(remotePort) || remotePort === 0) continue;

            const conn = {
              localAddress,
              localPort,
              remoteAddress,
              remotePort,
              pid: isNaN(pid) ? 0 : pid,
              state
            };

            const cls = classifyConn(conn);
            conn.risky = cls.risky;
            conn.riskReason = cls.reason;

            connections.push(conn);
          }
          resolve(connections);
        } catch (e) {
          resolve([]);
        }
      });
    });
  }
}

module.exports = new NetworkMonitor();