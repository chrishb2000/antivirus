"use strict";
const path = require("path");
const os = require("os");
const sig = require("./signatures");

const SUSPICIOUS_CMD_TOKENS = [
  "-enc", "frombase64string", "downloadstring", "iwr http", "invoke-webrequest http",
  "wget http", "curl http", "powershell -nop", "-hidden",
  "reg add", "sc create", "net user", "netsh firewall add"
];

const KNOWN_BAD = {
  "xmrig.exe": "Minero de criptomonedas",
  "minerd.exe": "Minero de criptomonedas",
  "crypto.exe": "Minero de criptomonedas",
  "nc.exe": "Netcat (shell remota abierta)",
  "psexecsvc.exe": "Servicio PsExec (ejecucion remota)",
  "meterpreter.exe": "Payload Meterpreter",
  "netbus.exe": "Troyano NetBus",
  "njrat.exe": "Troyano njRAT",
  "loopback.exe": "Herramienta de loopback potencialmente peligrosa",
  "winlogon-mimikatz.exe": "Mimikatz",
  "keylogger.exe": "Keylogger",
  "proxy.exe": "Posible tool de exfiltracion"
};

function getFlags(proc) {
  const flags = [];
  const name = (proc.name || "").toLowerCase();
  const cmd = (proc.cmdline || "").toLowerCase();
  const p = (proc.path || "").toLowerCase();

  if (KNOWN_BAD[name]) {
    flags.push({ risk: "critical", label: "Proceso conocido malicioso", detail: KNOWN_BAD[name] });
  }

  const tmp = path.join(os.tmpdir(), "").toLowerCase();
  if (p && p.startsWith(tmp)) {
    flags.push({ risk: "medium", label: "Ejecutable en carpeta temporal", detail: p });
  }

  if (p && (p.includes("\\temp\\") || p.includes("\\tmp\\") && !p.includes("node_modules"))) {
    flags.push({ risk: "medium", label: "Ejecutable desde carpeta Temp/Tmp", detail: p });
  }

  if (p && (p.includes("\\startup\\") || (p.includes("\\start menu") && p.includes("\\programs")))) {
    flags.push({ risk: "high", label: "Ejecutable en arranque automático (Startup)", detail: p });
  }

  if (cmd) {
    if (cmd.includes("powershell") && (cmd.includes("-enc") || cmd.includes("frombase64"))) {
      flags.push({ risk: "high", label: "PowerShell ofuscado", detail: "Comando oculto en Base64 detectado" });
    }
    for (const t of SUSPICIOUS_CMD_TOKENS) {
      if (cmd.includes(t)) {
        flags.push({ risk: "medium", label: "Línea de comando sospechosa", detail: t });
      }
    }
    if (cmd.includes("admin") && cmd.includes("net user")) {
      flags.push({ risk: "high", label: "Modificación de usuarios del sistema", detail: cmd.slice(0, 160) });
    }
  }

  const b64Pattern = /([A-Za-z0-9+/]{40,}={0,2})/g;
  const m = cmd.match(b64Pattern);
  if (m && cmd.includes("powershell")) {
    flags.push({ risk: "high", label: "Bloque Base64 largo en PowerShell", detail: "Posible payload oculto" });
  }

  return flags;
}

function score(flags) {
  const weights = { low: 1, medium: 2, high: 4, critical: 8 };
  return flags.reduce((s, f) => s + (weights[f.risk] || 0), 0);
}

function analyzeProcess(proc) {
  const flags = getFlags(proc);
  const sc = score(flags);
  let level = "none";
  if (sc >= 8) level = "critical";
  else if (sc >= 4) level = "high";
  else if (sc >= 2) level = "medium";
  else if (sc >= 1) level = "low";
  return { flags, score: sc, level };
}

module.exports = { getFlags, score, analyzeProcess, KNOWN_BAD, SUSPICIOUS_CMD_TOKENS };