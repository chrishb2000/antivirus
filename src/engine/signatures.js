"use strict";
const fs = require("fs");
const path = require("path");
const { hashFile, readHead } = require("../utils/hashing");

/** Base de firmas: patrones de texto/binario y hashes conocidos (deteccion local offline). */
const PATTERNS = [
  // ---- Mimikatz / robo de credenciales ----
  { id: "MIMIKATZ", family: "Credential-Theft", name: "Mimikatz (robo de credenciales)", severity: "critical", needle: "sekurlsa::logonpasswords" },
  { id: "MIMIKATZ2", family: "Credential-Theft", name: "Herramienta Mimikatz", severity: "critical", needle: "privilege::debug" },
  // ---- Ransomware ----
  { id: "WANNACRY", family: "Ransomware", name: "Ransomware WannaCry (nota de rescate)", severity: "critical", needle: "wannacry" },
  { id: "RANSOM_NOTE", family: "Ransomware", name: "Nota de rescate de ransomware", severity: "critical", needle: "how to decrypt your files" },
  { id: "RANSOM_NOTE2", family: "Ransomware", name: "Nota de pago de rescate", severity: "critical", needle: "your files have been encrypted" },
  // ---- Mineria de criptomonedas ----
  { id: "XMRIG", family: "Cryptominer", name: "Minero XMRig", severity: "high", needle: "xmrig" },
  { id: "STRATUM", family: "Cryptominer", name: "Protocolo de mineria (stratum)", severity: "high", needle: "stratum+tcp" },
  // ---- Keyloggers / spyware ----
  { id: "KEYLOG_GETKEY", family: "Keylogger", name: "Captura de teclas (GetAsyncKeyState)", severity: "high", needle: "getasynckeystate" },
  { id: "KEYLOG_HOOK", family: "Keylogger", name: "Hook de teclado (SetWindowsHookEx)", severity: "high", needle: "setwindowshookexa" },
  { id: "KEYLOG_HOOKW", family: "Keylogger", name: "Hook de teclado (SetWindowsHookExW)", severity: "high", needle: "setwindowshookexw" },
  { id: "SPY_CLIP", family: "Spyware", name: "Monitorizacion de clipboard", severity: "high", needle: "getclipboarddata" },
  // ---- Troyanos / RAT ----
  { id: "NETBUS", family: "Trojan", name: "Troyano NetBus", severity: "high", needle: "netbus" },
  { id: "METERPRETER", family: "RAT", name: "Meterpreter (shell remota)", severity: "critical", needle: "meterpreter" },
  { id: "BACKDOOR_SHELL", family: "Backdoor", name: "Shell reversa (powershell)", severity: "critical", needle: "invoke-powershell" },
  { id: "REV_SHELL_NC", family: "Backdoor", name: "Netcat shell reversa", severity: "high", needle: "-e cmd.exe" },
  { id: "REV_SHELL", family: "Backdoor", name: "Shell reversa bash", severity: "high", needle: "bash -i >& /dev/tcp" },
  // ---- Stealers ----
  { id: "STEALER_AUTOFILL", family: "Stealer", name: "Robo de autocompletado del navegador", severity: "critical", needle: "autofill" },
  { id: "STEALER_CRED", family: "Stealer", name: "Acceso a credenciales de navegadores", severity: "critical", needle: "browser\\password" },
  { id: "STEALER_LOGIN", family: "Stealer", name: "Extraccion de datos de login", severity: "critical", needle: "\\login data" },
  // ---- Persistencia maliciosa ----
  { id: "PERSIST_RUN", family: "Persistence", name: "Persistencia en clave Run del registro", severity: "high", needle: "currentversion\\run" },
  { id: "PERSIST_SVC", family: "Persistence", name: "Creacion de servicio persistente", severity: "high", needle: "sc create" },
  // ---- Ofuscacion de PowerShell ----
  { id: "PS_ENCODED", family: "Obfuscated-Script", name: "PowerShell ofuscado (-enc)", severity: "high", needle: "-enc " },
  { id: "PS_B64", family: "Obfuscated-Script", name: "PowerShell con Base64", severity: "high", needle: "frombase64string" },
  // ---- Descargas sin autorizacion ----
  { id: "PS_DOWNLOAD", family: "Downloader", name: "PowerShell descargando ejecutable", severity: "high", needle: "downloadstring" },
  { id: "PS_WEB", family: "Downloader", name: "Descarga web en script", severity: "medium", needle: "invoke-webrequest" },
  // ---- Scripts destructivos ----
  { id: "SELF_DEL", family: "Destructive", name: "Script de autodestruccion", severity: "high", needle: "del /s /q" },
  { id: "DISK_WIPE", family: "Destructive", name: "Borro de disco (format)", severity: "critical", needle: "format c:" },
  { id: "DISK_WIPE2", family: "Destructive", name: "Eliminacion masiva de archivos", severity: "critical", needle: "rd /s /q c:\\" },
  // ---- Acceso remoto no autorizado ----
  { id: "RDPTOOL", family: "RAT", name: "Herramienta de acceso remoto", severity: "medium", needle: "teamviewer" },
  // ---- Emails maliciosos ----
  { id: "EMAIL_ATTACH", family: "Malicious-Email", name: "Adjunto ejecutable en correo", severity: "high", needle: "filename=\".exe\"" },
  { id: "EMAIL_ATTACH2", family: "Malicious-Email", name: "Adjunto peligroso en correo", severity: "high", needle: "content-type: application/octet-stream" },
  { id: "EMAIL_HTMLMACRO", family: "Macro", name: "Macro VBA sospechosa", severity: "medium", needle: "auto_open" }
];

const HASH_HITS = {
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": { name: "EICAR-ARMA-TEST (archivo de prueba de antivirus)", family: "Test-Only", severity: "low" },
  "44d88612fea8a8f36de82e1278abb02f": { name: "EICAR-ARMA-TEST (MD5)", family: "Test-Only", severity: "low" }
};

function bgBlacklist() {
  // Nombres de procesos conocidos por ser maliciosos
  return [
    "xmrig.exe", "minerd.exe", "loopback.exe", "crypto.exe", "loader.exe",
    "winlogon-mimikatz.exe", "psexecsvc.exe", "nc.exe", "meterpreter.exe",
    "keylogger.exe", "njRAT.exe", "netbus.exe", "proxy.exe"
  ];
}

function checkPatterns(lowerContent) {
  for (const p of PATTERNS) {
    if (lowerContent.includes(p.needle)) return p;
  }
  return null;
}

/** Analiza un archivo contra firmas locales. Devuelve deteccion o null. */
async function checkFile(filePath) {
  try {
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) return null;

    const hashes = await hashFile(filePath);
    if (hashes) {
      const hit = HASH_HITS[hashes.sha256] || HASH_HITS[hashes.md5];
      if (hit) {
        return {
          found: true,
          source: "hash",
          id: hit.name,
          family: hit.family,
          severity: hit.severity,
          name: hit.name,
          sha256: hashes.sha256,
          md5: hashes.md5,
          size: stats.size
        };
      }
    }

    const head = await readHead(filePath, 2 * 1024 * 1024);
    if (!head) return null;
    const content = head.buf.toString("latin1").toLowerCase();
    const hit = checkPatterns(content);
    if (hit) {
      return {
        found: true,
        source: "signature",
        id: hit.id,
        family: hit.family,
        severity: hit.severity,
        name: hit.name,
        sha256: hashes ? hashes.sha256 : "",
        md5: hashes ? hashes.md5 : "",
        size: stats.size
      };
    }
    return { found: false, sha256: hashes ? hashes.sha256 : "", md5: hashes ? hashes.md5 : "", size: stats.size };
  } catch (e) {
    return null;
  }
}

module.exports = {
  PATTERNS,
  HASH_HITS,
  bgBlacklist,
  checkPatterns,
  checkFile
};