"use strict";
const fs = require("fs");
const path = require("path");

class ThreatStore {
  constructor(dataDir) {
    this.file = path.join(dataDir, "threats.json");
    this.items = [];
    try { this.load(); } catch (e) { this.items = []; }
  }

  load() {
    if (fs.existsSync(this.file)) {
      this.items = JSON.parse(fs.readFileSync(this.file, "utf8"));
    }
  }

  save() {
    try {
      fs.writeFileSync(this.file, JSON.stringify(this.items, null, 2), "utf8");
    } catch (e) { /* ignorar */ }
  }

  add(threat) {
    const item = {
      id: "th_" + Date.now() + "_" + Math.random().toString(36).slice(2, 7),
      time: new Date().toISOString(),
      ...threat
    };
    this.items.unshift(item);
    if (this.items.length > 800) this.items.length = 800;
    this.save();
    return item;
  }

  list(limit = 500) {
    return this.items.slice(0, limit);
  }

  resolve(id, status) {
    const it = this.items.find(i => i.id === id);
    if (it) {
      it.resolved = status || "handled";
      it.resolvedAt = new Date().toISOString();
      this.save();
    }
    return it;
  }

  clear() {
    this.items = [];
    this.save();
  }
}

module.exports = ThreatStore;