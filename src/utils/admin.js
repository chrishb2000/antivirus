"use strict";
const { execFile } = require("child_process");

function isAdmin() {
  return new Promise((resolve) => {
    const script = `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`;
    execFile("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { timeout: 10000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve(false);
      resolve(String(stdout || "").trim().toLowerCase() === "true");
    });
  });
}

/** Re-lanza la app elevada a administrador. */
function elevate() {
  return new Promise((resolve) => {
    const execPath = process.execPath;
    const isDev = process.argv.includes("--dev") || process.defaultApp;
    let command = "";
    if (isDev) {
      command = `Start-Process -FilePath "${execPath}" -ArgumentList ". --dev" -Verb RunAs`;
    } else {
      command = `Start-Process -FilePath "${execPath}" -Verb RunAs`;
    }
    execFile("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", command], { timeout: 10000, windowsHide: true }, (err) => {
      resolve(!err);
    });
  });
}

module.exports = { isAdmin, elevate };