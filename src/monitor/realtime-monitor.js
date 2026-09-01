"use strict";
const os = require("os");
const path = require("path");
const ProcessMonitor = require("../monitor/process-monitor");
const NetworkMonitor = require("../monitor/network-monitor");
const SystemMonitor = require("../monitor/system-monitor");
const behavior = require("../engine/behavior");

class RealtimeMonitor {
  constructor(engine) {
    this.engine = engine;
    this.timer = null;
    this.watcher = engine.watcher;
    this.prevProcs = new Map();   // pid -> ruta
    this.prevConns = new Map();   // "pid|ip:port" -> 1
    this.seenThreats = new Map(); // clave -> timestamp
    this.warmed = false;          // la primera pasada solo construye la linea base
    this.runtime = {
      lastSnapshot: null,
      processCount: 0,
      connectionCount: 0,
      threatsDetected: 0,
      startedAt: null
    };
  }

  start() {
    if (this.timer) return;
    this.runtime.startedAt = new Date();
    this.engine.logger.log({ type: "realtime", level: "info", message: "Proteccion en tiempo real iniciada" });
    this.tick();
    this.timer = setInterval(() => this.tick(), 3500);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.engine.logger.log({ type: "realtime", level: "info", message: "Proteccion en tiempo real detenida" });
  }

  isRunning() {
    return !!this.timer;
  }

  async tick() {
    try {
      const [snap, procs, conns] = await Promise.all([
        SystemMonitor.snapshot(),
        ProcessMonitor.list(),
        NetworkMonitor.list()
      ]);
      this.runtime.lastSnapshot = snap;
      this.runtime.processCount = procs.length;
      this.runtime.connectionCount = conns.length;
      this.runtime.cpu = snap.cpu;
      this.runtime.memPercent = snap.mem ? snap.mem.percent : 0;

      this.engine.emit("rt:metrics", {
        cpu: snap.cpu,
        memPercent: snap.mem ? snap.mem.percent : 0,
        memFreeGb: snap.mem ? Math.round((snap.mem.freeKb / 1024 / 1024) * 10) / 10 : 0,
        memTotalGb: snap.mem ? Math.round((snap.mem.totalKb / 1024 / 1024) * 10) / 10 : 0,
        disks: snap.disks,
        processCount: procs.length,
        connectionCount: conns.length
      });

      this.diffProcesses(procs);
      this.diffNetwork(conns);
    } catch (e) {
      /* silencioso */
    }
  }

  diffProcesses(procs) {
    const seen = new Set();
    for (const p of procs) {
      seen.add(p.pid);
      if (!this.warmed) {
        this.prevProcs.set(p.pid, p.path || "");
        continue;
      }
      const prev = this.prevProcs.get(p.pid);
      if (prev === undefined) {
        // Proceso nuevo
        this.evaluateProcess(p);
      } else if (prev !== p.path && p.path) {
        this.evaluateProcess(p);
      }
    }
    this.warmed = true;
    // limpiar pids que ya no existen
    for (const pid of this.prevProcs.keys()) {
      if (!seen.has(pid)) this.prevProcs.delete(pid);
    }
    for (const p of procs) {
      this.prevProcs.set(p.pid, p.path || "");
    }
  }

  evaluateProcess(proc) {
    const lowPath = (proc.path || "").toLowerCase();
    // Ignorar electron/node propios de la app para evitar falsos positivos
    if (lowPath.includes("node_modules") && lowPath.includes("electron")) return;
    const notUs = this.engine.appPath ? this.engine.appPath.toLowerCase() : "";
    if (notUs && lowPath && lowPath.startsWith(notUs)) return;

    if (proc.name === "electron.exe" && (!proc.path || lowPath.includes("aegis") || lowPath.includes("antivirus"))) return;

    const cfg = this.engine.config.get();
    const analysis = behavior.analyzeProcess(proc);
    if (!analysis.flags.length) return;
    const level = analysis.level;
    // Sólo alertamos desde "medium" hacia arriba
    if (level !== "medium" && level !== "high" && level !== "critical") return;

    const key = `proc|${proc.pid}|${proc.path || proc.name}`;
    const now = Date.now();
    const last = this.seenThreats.get(key) || 0;
    if (now - last < 60000) return;
    this.seenThreats.set(key, now);

    const flagsShown = analysis.flags.slice(0, 6);
    const threat = {
      type: "process",
      name: proc.name,
      pid: proc.pid,
      path: proc.path,
      cmdline: proc.cmdline,
      flags: flagsShown,
      severity: level,
      source: "behavior",
      family: "Behavioral",
      description: analysis.flags[0].label,
      detail: analysis.flags[0].detail,
      time: new Date().toISOString(),
      justDetected: true
    };
    this.engine.handleThreat(threat, { realtime: true });
  }

  diffNetwork(conns) {
    const seen = new Set();
    for (const c of conns) {
      const k = `${c.pid}|${c.remoteAddress}:${c.remotePort}`;
      seen.add(k);
      if (c.risky && !this.prevConns.has(k)) {
        this.engine.processMonitor.byPid(c.pid).then((proc) => {
          const threat = {
            type: "network",
            name: proc ? proc.name : "Proceso desconocido",
            pid: c.pid,
            path: proc ? proc.path : "",
            cmdline: proc ? proc.cmdline : "",
            processName: proc ? proc.name : null,
            localAddress: c.localAddress,
            localPort: c.localPort,
            remoteAddress: c.remoteAddress,
            remotePort: c.remotePort,
            riskReason: c.riskReason,
            severity: "high",
            source: "network",
            family: "Network",
            description: `Conexión a puerto de alto riesgo (${c.remotePort})`,
            detail: c.riskReason,
            time: new Date().toISOString(),
            justDetected: true
          };
          const key = `net|${c.remoteAddress}:${c.remotePort}|${c.pid}`;
          const now = Date.now();
          const last = this.seenThreats.get(key) || 0;
          if (now - last < 120000) return;
          this.seenThreats.set(key, now);
          this.engine.handleThreat(threat, { realtime: true });
        });
      }
    }
    for (const k of this.prevConns.keys()) {
      if (!seen.has(k)) this.prevConns.delete(k);
    }
    for (const c of conns) {
      this.prevConns.set(`${c.pid}|${c.remoteAddress}:${c.remotePort}`, 1);
    }
  }

  onNewFile(filePath) {
    this.engine.quickFileCheck(filePath);
  }
}

module.exports = RealtimeMonitor;