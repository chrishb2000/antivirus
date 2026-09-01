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

  async vtLookup(sha256) {
    const key = this.engine.config.get().virustotalKey;
    if (!key || !sha256) return null;
    const now = Date.now();
    if (now < this.vtCooldownUntil) return null;
    this.vtCooldownUntil = now + 16000; // limite de API gratuita
    return new Promise((resolve) => {
      const url = `https://www.virustotal.com/api/v3/files/${sha256}`;
      const req = https.get(url, {
        headers: {
          "x-apikey": key,
          "User-Agent": "aegis-ai-antivirus/1.0",
          "Accept": "application/json"
        },
        timeout: 15000
      }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            const stats = (data.data && data.data.attributes && data.data.attributes.last_analysis_stats) || null;
            if (stats) {
              const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
              const total = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.timeout || 0);
              resolve({
                found: true,
                malicious,
                total: total || 0,
                harmless: stats.harmless || 0,
                link: data.data.links ? data.data.links.self : ""
              });
            } else {
              resolve(null); // hash no en la base VT
            }
          } catch (e) {
            resolve(null);
          }
        });
      });
      req.on("error", () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    });
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

    // Comprobacion reputacional en la nube (VirusTotal)
    if (this.engine.config.get().virustotalKey) {
      const hashes = local || (await hashFile(filePath));
      if (hashes && hashes.sha256) {
        const vt = await this.vtLookup(hashes.sha256);
        if (vt && vt.found && vt.malicious > 0) {
          return {
            danger: true,
            source: "cloud",
            low: vt.malicious >= 10 ? "critical" : vt.malicious >= 3 ? "high" : "medium",
            name: `Detectado por ${vt.malicious} motores de VirusTotal`,
            family: "Cloud-Reputation",
            detail: `${vt.malicious} de ${vt.total} motores lo marcan como malicioso`,
            sha256: hashes.sha256,
            vt
          };
        }
      }
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