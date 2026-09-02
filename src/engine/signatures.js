"use strict";
const fs = require("fs");
const path = require("path");
const { hashFile, readHead } = require("../utils/hashing");

/** Base de firmas optimizada: sin falsos positivos sobre software legítimo y con soporte UTF-16. */
const PATTERNS = [
  // ---- Mimikatz / robo de credenciales ----
  { id: "MIMIKATZ", family: "Credential-Theft", name: "Mimikatz (robo de credenciales)", severity: "critical", needle: "sekurlsa::logonpasswords" },
  { id: "MIMIKATZ2", family: "Credential-Theft", name: "Herramienta Mimikatz", severity: "critical", needle: "privilege::debug" },
  // ---- Ransomware ----
  { id: "WANNACRY", family: "Ransomware", name: "Ransomware WannaCry (nota de rescate)", severity: "critical", needle: "wannacry" },
  { id: "RANSOM_NOTE", family: "Ransomware", name: "Nota de rescate de ransomware", severity: "critical", needle: "how to decrypt your files" },
  { id: "RANSOM_NOTE2", family: "Ransomware", name: "Nota de pago de rescate", severity: "critical", needle: "your files have been encrypted" },
  // ---- Minería de criptomonedas ----
  { id: "XMRIG", family: "Cryptominer", name: "Minero XMRig", severity: "high", needle: "xmrig" },
  { id: "STRATUM", family: "Cryptominer", name: "Protocolo de minería (stratum)", severity: "high", needle: "stratum+tcp" },
  // ---- Keyloggers / spyware ----
  { id: "KEYLOG_GETKEY", family: "Keylogger", name: "Captura de teclas (GetAsyncKeyState)", severity: "high", needle: "getasynckeystate" },
  { id: "KEYLOG_HOOK", family: "Keylogger", name: "Hook de teclado (SetWindowsHookEx)", severity: "high", needle: "setwindowshookexa" },
  { id: "KEYLOG_HOOKW", family: "Keylogger", name: "Hook de teclado (SetWindowsHookExW)", severity: "high", needle: "setwindowshookexw" },
  // ---- Troyanos / RAT ----
  { id: "NETBUS", family: "Trojan", name: "Troyano NetBus", severity: "high", needle: "netbus" },
  { id: "METERPRETER", family: "RAT", name: "Meterpreter (shell remota)", severity: "critical", needle: "meterpreter" },
  { id: "BACKDOOR_SHELL", family: "Backdoor", name: "Shell reversa (powershell)", severity: "critical", needle: "invoke-powershell" },
  { id: "REV_SHELL_NC", family: "Backdoor", name: "Netcat shell reversa", severity: "high", needle: "-e cmd.exe" },
  { id: "REV_SHELL", family: "Backdoor", name: "Shell reversa bash", severity: "high", needle: "bash -i >& /dev/tcp" },
  // ---- Stealers ----
  { id: "STEALER_LOGIN", family: "Stealer", name: "Extracción de datos de login de navegador", severity: "critical", needle: "\\login data" },
  // ---- Scripts destructivos ----
  { id: "DISK_WIPE", family: "Destructive", name: "Borrado de disco (format c:)", severity: "critical", needle: "format c:" },
  { id: "DISK_WIPE2", family: "Destructive", name: "Eliminación masiva de archivos del sistema", severity: "critical", needle: "rd /s /q c:\\" }
];

const HASH_HITS = {
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": { name: "EICAR-ARMA-TEST (archivo de prueba de antivirus)", family: "Test-Only", severity: "low" },
  "44d88612fea8a8f36de82e1278abb02f": { name: "EICAR-ARMA-TEST (MD5)", family: "Test-Only", severity: "low" }
};

function bgBlacklist() {
  return [
    "xmrig.exe", "minerd.exe", "loopback.exe", "crypto.exe", "loader.exe",
    "winlogon-mimikatz.exe", "psexecsvc.exe", "nc.exe", "meterpreter.exe",
    "keylogger.exe", "njRAT.exe", "netbus.exe", "proxy.exe"
  ];
}

function checkPatterns(latin1Content) {
  for (const p of PATTERNS) {
    if (latin1Content.includes(p.needle)) return p;
    // Soporte binario para cadenas UTF-16LE en ejecutables PE de Windows
    const wideNeedle = Buffer.from(p.needle, "utf16le").toString("latin1");
    if (latin1Content.includes(wideNeedle)) return p;
  }
  return null;
}

/** Analiza un archivo contra firmas locales. Devuelve detección o null. */
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