"use strict";
const fs = require("fs");
const path = require("path");
const { hashFile, readHead, detectFileType, RISKY_EXTENSIONS, hasRiskyExt } = require("../utils/hashing");
const sig = require("./signatures");
const { runExe } = require("../utils/ps");
const https = require("https");

class Scanner {
  constructor(engine) {
    this.engine = engine; // { config, quarantine, ai, logger, emitThreat }
    this.cancelled = false;
    this.vtCooldownUntil = 0;
  }

  cancel() { this.cancelled = true; }

  isExcluded(p) {
    const exclusions = this.engine.config.get().exclusions || [];
    const pNorm = p.toLowerCase();
    for (const ex of exclusions) {
      const e = new String(ex).toLowerCase();
      if (e === "*") return false;
      if (pNorm === e || pNorm.startsWith(e)) return true;
    }
    return false;
  }

  async collectFiles(root, mode) {
    const files = [];
    const stack = [root];
    const maxDepth = mode === "quick" ? 5 : null;
    const skippedRoots = ["node_modules", ".git", "$recycle.bin", "windows\\installer", "\\program files\\microsoft", "\\programdata\\package cache", "\\appdata\\local\\temp"].map(s => s.toLowerCase());

    while (stack.length) {
      const dir = stack.pop();
      if (this.cancelled) break;
      if (this.isExcluded(dir)) continue;
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (e) {
        continue;
      }
      for (const ent of entries) {
        if (this.cancelled) break;
        const full = path.join(dir, ent.name);
        try {
          if (ent.isDirectory()) {
            const low = full.toLowerCase();
            if (skippedRoots.some(s => low.includes(s))) continue;
            if (this.isExcluded(full)) continue;
            stack.push(full);
          } else if (ent.isFile() && this.shouldScan(full)) {
            files.push(full);
          }
        } catch (e) { /* ignorar */ }
      }
    }
    return files;
  }

  shouldScan(filePath) {
    if (this.isExcluded(filePath)) return false;
    const cfgExts = (this.engine.config.get().scanExtensions || RISKY_EXTENSIONS.map(e => e.replace(".", "")));
    const ext = path.extname(filePath).toLowerCase().replace(".", "");
    return cfgExts.includes(ext);
  }

  async checkFile(filePath) {
    const local = await sig.checkFile(filePath);
    if (local && local.found) {
      return {
        danger: true,
        source: "signature",
        low: local.severity,
        name: local.name,
        family: local.family,
        detail: "Coincidencia con base de firmas locales",
        sha256: local.sha256,
        hashHit: true
      };
    }
    return { danger: false };
  }

  async scanFile(filePath, onThreat) {
    const res = await this.checkFile(filePath);
    if (res.danger) {
      const threat = {
        type: "file",
        path: filePath,
        name: path.basename(filePath),
        source: res.source,
        severity: res.low,
        family: res.family,
        description: res.name,
        detail: res.detail,
        sha256: res.sha256,
        size: (fs.existsSync(filePath) ? fs.statSync(filePath).size : 0),
        time: new Date().toISOString()
      };
      let action = "flagged";
      const cfg = this.engine.config.get();
      if (cfg.autoQuarantine && (res.low === "high" || res.low === "critical") && fs.existsSync(filePath)) {
        const q = await this.engine.quarantine.add(filePath, threat);
        if (q) action = q.moved ? "quarantined" : "quarantined-copy";
      }
      threat.action = action;
      onThreat(threat);
    }
  }

  async scanRoot(root, opts = {}) {
    this.cancelled = false;
    const mode = opts.mode || "custom";
    const start = Date.now();
    let scanned = 0;
    let threats = 0;

    const report = (fn, ...args) => { if (typeof opts.onProgress === "function") opts.onProgress(...args); };

    try {
      const stats = fs.statSync(root);
      if (stats.isFile()) {
        report(null, 0, 1, root);
        await this.scanFile(root, (t) => { threats++; opts.onThreat && opts.onThreat(t); });
        scanned = 1;
      } else {
        const files = await this.collectFiles(root, mode);
        const total = files.length;
        for (let i = 0; i < files.length; i++) {
          if (this.cancelled) break;
          const f = files[i];
          scanned = i;
          if (i % 3 === 0) report(f, i, total);
          await this.scanFile(f, (t) => {
            threats++;
            opts.onThreat && opts.onThreat(t);
          });
        }
        scanned = files.length;
      }
    } catch (e) {
      // ignorar
    }

    return {
      mode,
      root,
      scanned,
      threats,
      cancelled: this.cancelled,
      durationMs: Date.now() - start
    };
  }
}

module.exports = Scanner;