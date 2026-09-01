"use strict";
const fs = require("fs");
const path = require("path");

class Logger {
  constructor(dataDir, eventSink) {
    this.dataDir = dataDir;
    this.eventSink = eventSink || null;
    this.events = [];
    this.load();
  }

  load() {
    try {
      const f = path.join(this.dataDir, "events.json");
      if (fs.existsSync(f)) this.events = JSON.parse(fs.readFileSync(f, "utf8"));
    } catch (e) {
      this.events = [];
    }
  }

  log(event) {
    const item = {
      id: event.id || ("ev_" + Date.now() + "_" + Math.random().toString(36).slice(2, 7)),
      time: event.time || new Date().toISOString(),
      type: event.type || "info",
      level: event.level || "info",
      message: event.message || "",
      detail: event.detail || null
    };
    this.events.unshift(item);
    if (this.events.length > 1200) this.events.length = 1200;
    try {
      fs.writeFileSync(path.join(this.dataDir, "events.json"), JSON.stringify(this.events), "utf8");
    } catch (e) { /* ignorar */ }
    if (this.eventSink && typeof this.eventSink === "function") {
      try { this.eventSink(item); } catch (e) { /* ignorar */ }
    }
    return item;
  }

  list(limit = 200) {
    return this.events.slice(0, limit);
  }
}

module.exports = Logger;