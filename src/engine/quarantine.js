"use strict";
const fs = require("fs");
const path = require("path");

const XOR_KEY = 0x5A;

function xorBuffer(buffer) {
  const result = Buffer.alloc(buffer.length);
  for (let i = 0; i < buffer.length; i++) {
    result[i] = buffer[i] ^ XOR_KEY;
  }
  return result;
}

class Quarantine {
  constructor(dataDir) {
    this.qDir = path.join(dataDir, "quarantine");
    this.indexFile = path.join(this.qDir, "index.json");
    this.items = [];
    try {
      if (!fs.existsSync(this.qDir)) fs.mkdirSync(this.qDir, { recursive: true });
    } catch (e) { /* error de directorio */ }
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.indexFile)) {
        this.items = JSON.parse(fs.readFileSync(this.indexFile, "utf8"));
      }
    } catch (e) {
      this.items = [];
    }
  }

  save() {
    try {
      fs.writeFileSync(this.indexFile, JSON.stringify(this.items, null, 2), "utf8");
    } catch (e) { /* ignorar */ }
  }

  async add(filePath, threat) {
    try {
      if (!fs.existsSync(filePath)) return null;
      const id = "q_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);
      const destDir = path.join(this.qDir, id);
      fs.mkdirSync(destDir, { recursive: true });
      const rawFileName = path.basename(filePath) || "archivo";
      const destFile = path.join(destDir, `${rawFileName}.qbin`);

      let moved = false;
      try {
        const fileData = fs.readFileSync(filePath);
        const encrypted = xorBuffer(fileData);
        fs.writeFileSync(destFile, encrypted);
        fs.unlinkSync(filePath);
        moved = true;
      } catch (e) {
        // En caso de fallo de lectura/escritura (archivo en uso)
      }

      const item = {
        id,
        originalPath: filePath,
        storedPath: destFile,
        threat: threat || {},
        time: new Date().toISOString(),
        encrypted: true,
        moved
      };
      this.items.unshift(item);
      this.save();
      return item;
    } catch (e) {
      return null;
    }
  }

  list() {
    return this.items;
  }

  async restore(id) {
    try {
      const item = this.items.find(i => i.id === id);
      if (!item) return { ok: false, error: "No encontrado" };
      if (!fs.existsSync(item.storedPath)) return { ok: false, error: "Archivo aislado no existe" };

      const dir = path.dirname(item.originalPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      const storedData = fs.readFileSync(item.storedPath);
      const restoredData = item.encrypted ? xorBuffer(storedData) : storedData;
      fs.writeFileSync(item.originalPath, restoredData);

      try { fs.rmSync(path.dirname(item.storedPath), { recursive: true, force: true }); } catch (e) { /* ignorar */ }

      this.items = this.items.filter(i => i.id !== id);
      this.save();
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  async remove(id) {
    try {
      const item = this.items.find(i => i.id === id);
      if (!item) return { ok: false, error: "No encontrado" };
      try { fs.rmSync(path.dirname(item.storedPath), { recursive: true, force: true }); } catch (e) { /* ignorar */ }
      this.items = this.items.filter(i => i.id !== id);
      this.save();
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }
}

module.exports = Quarantine;