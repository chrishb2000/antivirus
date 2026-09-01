"use strict";
const crypto = require("crypto");
const fs = require("fs");

/** Hash SHA-256 y MD5 de un archivo. */
function hashFile(filePath) {
  return new Promise((resolve) => {
    try {
      const sha = crypto.createHash("sha256");
      const md5 = crypto.createHash("md5");
      const stream = fs.createReadStream(filePath);
      stream.on("data", (chunk) => { sha.update(chunk); md5.update(chunk); });
      stream.on("error", () => resolve(null));
      stream.on("end", () => resolve({
        sha256: sha.digest("hex"),
        md5: md5.digest("hex")
      }));
    } catch (e) {
      resolve(null);
    }
  });
}

function hashBuffer(buf) {
  const sha = crypto.createHash("sha256");
  sha.update(buf);
  return sha.digest("hex");
}

/** Entropia de Shannon del contenido (0..8). Alta entropia = contenido comprimido/empaquetado. */
function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
  let ent = 0;
  const len = buf.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    ent -= p * Math.log2(p);
  }
  return Math.round(ent * 1000) / 1000;
}

/** Primeros bytes de un archivo (para analisis de contenedor/firma). */
function readHead(filePath, maxBytes = 512 * 1024) {
  return new Promise((resolve) => {
    try {
      const size = fs.statSync(filePath).size;
      const fd = fs.openSync(filePath, "r");
      const len = Math.min(size, maxBytes);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, 0);
      fs.closeSync(fd);
      resolve({ buf, size });
    } catch (e) {
      resolve(null);
    }
  });
}

/** Tipos de archivo por magic bytes. */
function detectFileType(buf) {
  if (!buf || buf.length < 4) return "desconocido";
  if (buf[0] === 0x4D && buf[1] === 0x5A) return "PE (portable executable)";
  if (buf[0] === 0x50 && buf[1] === 0x4B) return "Archivo ZIP/Office";
  if (buf[0] === 0xD0 && buf[1] === 0xCF && buf[2] === 0x11 && buf[3] === 0xE0) return "Documento OLE (Office)";
  if (buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46) return "ELF (ejecutable Linux)";
  if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) return "PDF";
  if (buf[0] === 0x41 && buf[1] === 0x49 && buf[2] === 0x44 && buf[3] === 0x53) return "Secuencia de archivos ZIP autoextraible";
  if (buf[0] === 0x53 && buf[1] === 0x48 && buf[2] === 0x45 && buf[3] === 0x4c) return "Instalador NSIS";
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "Imagen PNG";
  if (buf[0] === 0xFF && buf[1] === 0xD8) return "Imagen JPEG";
  return "otros";
}

/** Extensiones de alto riesgo (ejecutables / scripts / macros). */
const RISKY_EXTENSIONS = [
  ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1",
  ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi", ".msp", ".mst",
  ".jar", ".lnk", ".docm", ".xlsm", ".pptm", ".eml", ".reg", ".apk", ".sh", ".elf"
];

function hasRiskyExt(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return RISKY_EXTENSIONS.includes("." + ext) || ext.length > 0 && RISKY_EXTENSIONS.includes(name.toLowerCase().slice(-5));
}

module.exports = { hashFile, hashBuffer, shannonEntropy, readHead, detectFileType, hasRiskyExt, RISKY_EXTENSIONS };