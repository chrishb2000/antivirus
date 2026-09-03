"use strict";
const fs = require("fs");
const path = require("path");

const DEFAULTS = {
  autoStart: true,
  realtime: true,
  autoQuarantine: false,
  autoBlockConnections: false,
  webProtection: true,
  emailScan: true,
  aiEnabled: false,
  aiProvider: "openai",
  aiKeys: { openai: "", gemini: "", claude: "", perplexity: "" },
  aiModel: "",
  virustotalKey: "",
  notifications: true,
  theme: "dark",
  watchedFolders: [],
  exclusions: [],
  scanExtensions: ["exe", "dll", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "msi", "msp", "jar", "lnk", "docm", "xlsm", "pptm", "eml", "reg", "apk"]
};

class Config {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, "config.json");
    this.data = { ...DEFAULTS, watchedFolders: [...DEFAULTS.watchedFolders], exclusions: [...DEFAULTS.exclusions] };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.file)) {
        const parsed = JSON.parse(fs.readFileSync(this.file, "utf8"));
        this.data = { ...DEFAULTS, ...parsed, aiKeys: { ...DEFAULTS.aiKeys, ...(parsed.aiKeys || {}) } };
      }
    } catch (e) {
      // config corrupta -> defaults
    }
  }

  save() {
    try {
      if (!fs.existsSync(this.dataDir)) fs.mkdirSync(this.dataDir, { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2), "utf8");
    } catch (e) { /* ignorar */ }
  }

  get() {
    this.load();
    return this.data;
  }

  set(patch) {
    for (const key of Object.keys(patch)) {
      if (key === "aiKeys") {
        this.data.aiKeys = { ...this.data.aiKeys, ...patch.aiKeys };
      } else {
        this.data[key] = patch[key];
      }
    }
    this.save();
    this.load();
    return this.data;
  }

  resolveWatched() {
    const list = [];
    const os = require("os");
    const home = os.homedir();
    const downloads = path.join(home, "Downloads");
    list.push(downloads);
    for (const f of this.data.watchedFolders || []) {
      if (f && f !== downloads) list.push(f);
    }
    return list;
  }
}

module.exports = Config;