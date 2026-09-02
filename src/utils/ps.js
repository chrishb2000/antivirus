"use strict";
const { execFile } = require("child_process");

/** Ejecuta un comando PowerShell y devuelve la salida (string), o null si falla. */
function runPowerShell(script, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const args = [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
      script
    ];
    execFile("powershell.exe", args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return resolve(null);
      resolve(String(stdout || "").trim());
    });
  });
}

/** Ejecuta netsh (para reglas de firewall). */
function runNetsh(args, timeoutMs = 12000) {
  return new Promise((resolve) => {
    execFile("netsh.exe", args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 2 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const rawErr = String(stderr || err.message || "");
        if (/elevation|admin|permis|denied|privilege|solicitada requiere|elevaci/i.test(rawErr)) {
          return resolve({ ok: false, error: "Se requieren permisos de Administrador para modificar el Firewall de Windows.", needsAdmin: true });
        }
        return resolve({ ok: false, error: rawErr });
      }
      resolve({ ok: true, output: String(stdout || "").trim() });
    });
  });
}

/** Ejecuta un comando del sistema y devuelve salida. */
function runExe(exe, args, timeoutMs = 15000) {
  return new Promise((resolve) => {
    execFile(exe, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return resolve({ ok: false, error: err.message });
      resolve({ ok: true, output: String(stdout || "").trim() });
    });
  });
}

module.exports = { runPowerShell, runNetsh, runExe };