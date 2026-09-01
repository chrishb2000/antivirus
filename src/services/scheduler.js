"use strict";
const fs = require("fs");
const path = require("path");
const os = require("os");
const { runPowerShell } = require("../utils/ps");

// ---------------------------------------------------------------------------
// Motor de cron simple (verifica cada 60s si la expresion matchea)
// ---------------------------------------------------------------------------
function matchCronField(pattern, value) {
  if (pattern === "*") return true;
  if (pattern.includes(",")) return pattern.split(",").some((p) => matchCronField(p.trim(), value));
  if (pattern.includes("-")) {
    const [a, b] = pattern.split("-").map(Number);
    return value >= a && value <= b;
  }
  if (pattern.startsWith("*/")) {
    const step = Number(pattern.slice(2));
    return value % step === 0;
  }
  return Number(pattern) === value;
}

function shouldRunCron(expr, date) {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const fields = [date.getMinutes(), date.getHours(), date.getDate(), date.getMonth() + 1, date.getDay()];
  return parts.every((p, i) => matchCronField(p, fields[i]));
}

function shouldRunInterval(task, now) {
  const ms = (task.intervalHours || 1) * 3600000;
  if (!task.lastRun) return true;
  return now.getTime() - new Date(task.lastRun).getTime() >= ms;
}

function shouldRun(task, now) {
  if (task.scheduleType === "cron") return shouldRunCron(task.scheduleExpr, now);
  if (task.scheduleType === "interval") return shouldRunInterval(task, now);
  return false;
}

// ---------------------------------------------------------------------------
// Funciones predefinidas que las tareas pueden ejecutar
// ---------------------------------------------------------------------------
const FUNCTIONS = {
  "quick-scan": {
    name: "Ejecutar escaneo rápido",
    description: "Escanea Downloads, Desktop y archivos temporales en busca de amenazas.",
    exec: async (engine) => {
      const home = os.homedir();
      const targets = [path.join(home, "Downloads"), path.join(home, "Desktop"), os.tmpdir()];
      let threats = 0;
      for (const t of targets) {
        const r = await engine.scanner.scanRoot(t, {
          mode: "quick",
          onProgress: () => {},
          onThreat: (th) => { threats++; engine.threats.add(th); }
        });
      }
      return { message: `Escaneo rápido completado. ${threats} amenaza(s) detectada(s).`, threats };
    }
  },
  "full-scan": {
    name: "Ejecutar escaneo completo",
    description: "Escanea todo el disco del sistema (C:\\) en busca de amenazas.",
    exec: async (engine) => {
      const drive = process.env.SystemDrive + "\\";
      const r = await engine.scanner.scanRoot(drive, {
        mode: "full",
        onProgress: () => {},
        onThreat: (th) => { engine.threats.add(th); }
      });
      return { message: `Escaneo completo finalizado. ${r.threats} amenaza(s), ${r.scanned} archivos.`, threats: r.threats };
    }
  },
  "clean-temp": {
    name: "Limpiar archivos temporales",
    description: "Elimina archivos temporales del usuario con más de 3 días de antigüedad.",
    exec: async (engine) => {
      const tmpDir = os.tmpdir();
      const home = os.homedir();
      const userTmp = path.join(home, "AppData", "Local", "Temp");
      let cleaned = 0;
      let freed = 0;
      const cleanDir = (dir) => {
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          const now = Date.now();
          for (const e of entries) {
            if (e.name.startsWith(".") || e.name === "opencode") continue;
            const fp = path.join(dir, e.name);
            try {
              const stat = fs.statSync(fp);
              const age = now - stat.mtimeMs;
              if (age > 3 * 24 * 3600000 && stat.isFile()) {
                freed += stat.size;
                fs.unlinkSync(fp);
                cleaned++;
              }
            } catch (err) { /* skip locked files */ }
          }
        } catch (err) { /* skip inaccessible dirs */ }
      };
      cleanDir(tmpDir);
      if (userTmp !== tmpDir) cleanDir(userTmp);
      const freedMB = Math.round(freed / 1024 / 1024);
      return { message: `${cleaned} archivo(s) temporales eliminado(s). ${freedMB} MB recuperados.`, cleaned, freedMB };
    }
  },
  "audit-network": {
    name: "Auditoría de conexiones de red",
    description: "Revisa conexiones TCP activas en busca de puertos de alto riesgo o IPs sospechosas.",
    exec: async (engine) => {
      const NetworkMonitor = require("../monitor/network-monitor");
      const conns = await NetworkMonitor.list();
      const risky = conns.filter((c) => c.risky);
      if (risky.length > 0) {
        for (const c of risky) {
          engine.threats.add({
            type: "network",
            name: `Puerto de riesgo abierto: ${c.remotePort}`,
            severity: "high",
            source: "scheduler-audit",
            family: "Network-Audit",
            description: `Conexión detectada a puerto ${c.remotePort} (${c.riskReason})`,
            remoteAddress: c.remoteAddress,
            remotePort: c.remotePort,
            pid: c.pid,
            time: new Date().toISOString()
          });
        }
      }
      return { message: `${conns.length} conexión(es) activa(s), ${risky.length} de riesgo.`, total: conns.length, risky: risky.length };
    }
  },
  "audit-startup": {
    name: "Auditoría de programas en arranque",
    description: "Comprueba si hay nuevos programas ejecutándose al inicio del sistema.",
    exec: async (engine) => {
      const script = "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json -Compress";
      const out = await runPowerShell(script, 20000);
      let items = [];
      if (out) {
        try {
          const data = JSON.parse(out);
          items = Array.isArray(data) ? data : [data];
        } catch (e) { /* parse error */ }
      }
      // Guardar baseline
      const baselineFile = path.join(engine.dataDir || "", "scheduler", "startup-baseline.json");
      const baselineDir = path.dirname(baselineFile);
      if (!fs.existsSync(baselineDir)) fs.mkdirSync(baselineDir, { recursive: true });
      let baseline = [];
      if (fs.existsSync(baselineFile)) {
        try { baseline = JSON.parse(fs.readFileSync(baselineFile, "utf8")); } catch (e) { baseline = []; }
      }
      const currentNames = items.map((i) => i.Name || "").sort();
      const baselineNames = baseline.map((i) => i.Name || "").sort();
      const newEntries = items.filter((i) => !baselineNames.includes(i.Name || ""));
      fs.writeFileSync(baselineFile, JSON.stringify(items, null, 2), "utf8");
      if (newEntries.length > 0) {
        for (const n of newEntries) {
          engine.threats.add({
            type: "behavior",
            name: `Nuevo programa en arranque: ${n.Name}`,
            severity: "medium",
            source: "scheduler-audit",
            family: "Startup-Audit",
            description: `Nuevo programa detectado en el arranque: ${n.Command}`,
            detail: n.Location,
            time: new Date().toISOString()
          });
        }
      }
      return { message: `${items.length} programa(s) en arranque, ${newEntries.length} nuevo(s).`, total: items.length, newItems: newEntries.length };
    }
  },
  "audit-firewall": {
    name: "Auditoría del firewall",
    description: "Comprueba que el firewall de Windows sigue activo y no ha sido deshabilitado.",
    exec: async (engine) => {
      const Firewall = require("../network/firewall");
      const status = await Firewall.status();
      const rules = await Firewall.list();
      if (!status.enabled) {
        engine.threats.add({
          type: "behavior",
          name: "¡FIREWALL DESACTIVADO!",
          severity: "critical",
          source: "scheduler-audit",
          family: "Firewall-Audit",
          description: "El firewall de Windows ha sido desactivado o no está funcionando.",
          time: new Date().toISOString()
        });
      }
      return { message: `Firewall: ${status.enabled ? "ACTIVO" : "DESACTIVADO"}. ${rules.length} regla(s) AEGIS.`, enabled: status.enabled, rules: rules.length };
    }
  },
  "clean-quarantine": {
    name: "Limpiar cuarentena antigua",
    description: "Elimina de cuarentena los archivos que llevan más de 30 días sin ser revisados.",
    exec: async (engine) => {
      const items = engine.quarantine.list();
      const now = Date.now();
      let removed = 0;
      for (const item of items) {
        const age = now - new Date(item.time).getTime();
        if (age > 30 * 24 * 3600000) {
          await engine.quarantine.remove(item.id);
          removed++;
        }
      }
      return { message: `${removed} archivo(s) antiguo(s) eliminado(s) de cuarentena.`, removed };
    }
  },
  "backup-config": {
    name: "Backup de configuración",
    description: "Crea una copia de seguridad de la configuración actual en data/backups/.",
    exec: async (engine) => {
      const src = path.join(engine.dataDir || "", "config.json");
      const backupDir = path.join(engine.dataDir || "", "backups");
      if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
      if (!fs.existsSync(src)) return { message: "No hay configuración para respaldar." };
      const date = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const dest = path.join(backupDir, `config-${date}.json`);
      fs.copyFileSync(src, dest);
      // Limpiar backups viejos (>7)
      const backups = fs.readdirSync(backupDir).sort().reverse();
      for (const b of backups.slice(7)) {
        try { fs.unlinkSync(path.join(backupDir, b)); } catch (e) { /* ignore */ }
      }
      return { message: `Configuración respaldada: ${dest}`, file: dest };
    }
  },
  "audit-system32": {
    name: "Verificar integridad del sistema",
    description: "Escanea archivos ejecutables en Windows\\System32 en busca de firmas conocidas maliciosas.",
    exec: async (engine) => {
      const sysDir = path.join(process.env.SystemRoot || "C:\\Windows", "System32");
      let scanned = 0;
      let threats = 0;
      const r = await engine.scanner.scanRoot(sysDir, {
        mode: "quick",
        onProgress: () => {},
        onThreat: (th) => { threats++; engine.threats.add(th); }
      });
      return { message: `System32 verificado: ${r.scanned} archivo(s), ${r.threats} amenaza(s).`, scanned: r.scanned, threats: r.threats };
    }
  },
  "security-report": {
    name: "Generar reporte de seguridad",
    description: "Genera un resumen semanal: amenazas, conexiones, procesos y estado del sistema.",
    exec: async (engine) => {
      const threats = engine.threats.list(100);
      const weekAgo = Date.now() - 7 * 24 * 3600000;
      const recent = threats.filter((t) => new Date(t.time).getTime() > weekAgo);
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const t of recent) { bySeverity[t.severity] = (bySeverity[t.severity] || 0) + 1; }
      const report = {
        period: `Semana al ${new Date().toLocaleDateString("es-ES")}`,
        totalThreats: recent.length,
        bySeverity,
        topFamilies: [...new Set(recent.map((t) => t.family).filter(Boolean))],
        actions: { quarantined: recent.filter((t) => t.action === "quarantined").length, blocked: recent.filter((t) => t.action === "blocked").length }
      };
      const reportDir = path.join(engine.dataDir || "", "scheduler");
      if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
      const reportFile = path.join(reportDir, "last-report.json");
      fs.writeFileSync(reportFile, JSON.stringify(report, null, 2), "utf8");
      return { message: `Reporte generado: ${report.totalThreats} amenaza(s) esta semana.`, report };
    }
  }
};

// ---------------------------------------------------------------------------
// Tareas por defecto
// ---------------------------------------------------------------------------
function defaultTasks() {
  return [
    { id: "ts-daily-quick", name: "Escaneo rápido programado", description: "Escanea Downloads, Desktop y temporales cada día a las 02:00.", function: "quick-scan", scheduleType: "cron", scheduleExpr: "0 2 * * *", enabled: true, lastRun: null, history: [] },
    { id: "ts-weekly-full", name: "Escaneo completo semanal", description: "Escaneo completo del sistema cada domingo a las 03:00.", function: "full-scan", scheduleType: "cron", scheduleExpr: "0 3 * * 0", enabled: true, lastRun: null, history: [] },
    { id: "ts-daily-temp", name: "Limpieza de temporales", description: "Elimina archivos temporales >3 días cada día a las 03:30.", function: "clean-temp", scheduleType: "cron", scheduleExpr: "30 3 * * *", enabled: true, lastRun: null, history: [] },
    { id: "ts-hourly-network", name: "Auditoría de red (horaria)", description: "Revisa conexiones TCP activas y puertos de riesgo cada hora.", function: "audit-network", scheduleType: "interval", intervalHours: 1, enabled: true, lastRun: null, history: [] },
    { id: "ts-daily-startup", name: "Auditoría de arranque", description: "Detecta nuevos programas en el arranque cada día a las 09:00.", function: "audit-startup", scheduleType: "cron", scheduleExpr: "0 9 * * *", enabled: true, lastRun: null, history: [] },
    { id: "ts-weekly-firewall", name: "Auditoría del firewall", description: "Comprueba que el firewall sigue activo cada lunes a las 08:00.", function: "audit-firewall", scheduleType: "cron", scheduleExpr: "0 8 * * 1", enabled: true, lastRun: null, history: [] },
    { id: "ts-monthly-quarantine", name: "Limpiar cuarentena antigua", description: "Elimina archivos en cuarentena >30 días sin revisar, cada mes.", function: "clean-quarantine", scheduleType: "cron", scheduleExpr: "0 4 1 * *", enabled: true, lastRun: null, history: [] },
    { id: "ts-every-3d-backup", name: "Backup de configuración", description: "Crea copia de seguridad de config.json cada 3 días.", function: "backup-config", scheduleType: "interval", intervalHours: 72, enabled: true, lastRun: null, history: [] },
    { id: "ts-weekly-system32", name: "Integridad del sistema", description: "Escanea Windows\\System32 en busca de firmas maliciosas (miércoles).", function: "audit-system32", scheduleType: "cron", scheduleExpr: "0 3 * * 3", enabled: false, lastRun: null, history: [] },
    { id: "ts-weekly-report", name: "Reporte de seguridad semanal", description: "Genera resumen de amenazas, conexiones y estado del sistema (viernes).", function: "security-report", scheduleType: "cron", scheduleExpr: "0 8 * * 5", enabled: true, lastRun: null, history: [] }
  ];
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------
class Scheduler {
  constructor(dataDir, engine) {
    this.dataDir = dataDir;
    this.engine = engine;
    this.tasks = [];
    this.running = false;
    this.tickTimer = null;
    this.load();
  }

  load() {
    const file = path.join(this.dataDir, "scheduler.json");
    try {
      if (fs.existsSync(file)) {
        this.tasks = JSON.parse(fs.readFileSync(file, "utf8"));
        // Merge new defaults if user removed them
        const defaults = defaultTasks();
        const existingIds = this.tasks.map((t) => t.id);
        for (const d of defaults) {
          if (!existingIds.includes(d.id)) this.tasks.push({ ...d, history: [] });
        }
      } else {
        this.tasks = defaultTasks();
      }
    } catch (e) {
      this.tasks = defaultTasks();
    }
    this.save();
  }

  save() {
    try {
      const dir = path.join(this.dataDir, "scheduler");
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(this.dataDir, "scheduler.json"), JSON.stringify(this.tasks, null, 2), "utf8");
    } catch (e) { /* ignore */ }
  }

  start() {
    if (this.running) return;
    this.running = true;
    this.engine.logger.log({ type: "scheduler", level: "info", message: "Motor de automatización iniciado" });
    this.tick();
    this.tickTimer = setInterval(() => this.tick(), 60000);
  }

  stop() {
    if (this.tickTimer) { clearInterval(this.tickTimer); this.tickTimer = null; }
    this.running = false;
    this.engine.logger.log({ type: "scheduler", level: "info", message: "Motor de automatización detenido" });
  }

  tick() {
    const now = new Date();
    for (const task of this.tasks) {
      if (!task.enabled) continue;
      if (!FUNCTIONS[task.function]) continue;
      try {
        if (shouldRun(task, now)) {
          this.executeTask(task);
        }
      } catch (e) { /* ignore */ }
    }
  }

  async executeTask(task) {
    const fn = FUNCTIONS[task.function];
    if (!fn) return;
    const start = Date.now();
    task.lastRun = new Date().toISOString();
    this.save();
    this.engine.logger.log({ type: "scheduler", level: "info", message: `Ejecutando tarea: ${task.name}` });
    try {
      const result = await fn.exec(this.engine);
      const entry = { time: new Date().toISOString(), success: true, message: result.message || "Completada", durationMs: Date.now() - start };
      task.history = task.history || [];
      task.history.unshift(entry);
      if (task.history.length > 20) task.history.length = 20;
      this.engine.logger.log({ type: "scheduler", level: "info", message: `Tarea completada: ${task.name} - ${result.message}` });
    } catch (e) {
      const entry = { time: new Date().toISOString(), success: false, message: e.message, durationMs: Date.now() - start };
      task.history = task.history || [];
      task.history.unshift(entry);
      if (task.history.length > 20) task.history.length = 20;
      this.engine.logger.log({ type: "scheduler", level: "warn", message: `Tarea fallida: ${task.name} - ${e.message}` });
    }
    this.save();
  }

  list() { return this.tasks.map((t) => ({ ...t })); }

  toggle(taskId, enabled) {
    const task = this.tasks.find((t) => t.id === taskId);
    if (task) { task.enabled = enabled; this.save(); }
    return task;
  }

  async runNow(taskId) {
    const task = this.tasks.find((t) => t.id === taskId);
    if (!task) return { ok: false, error: "Tarea no encontrada" };
    await this.executeTask(task);
    return { ok: true };
  }

  add({ name, description, function: fn, scheduleType, scheduleExpr, intervalHours }) {
    if (!FUNCTIONS[fn]) return { ok: false, error: "Función no disponible" };
    if (scheduleType === "cron" && !shouldRunCron(scheduleExpr, new Date())) {
      // Validate cron expression by checking it parses to 5 fields
      if (!scheduleExpr || scheduleExpr.trim().split(/\s+/).length !== 5) {
        return { ok: false, error: "Expresión cron inválida (requiere 5 campos: min hora dia mes dia-semana)" };
      }
    }
    const task = {
      id: "ts-custom-" + Date.now().toString(36),
      name: name || "Tarea personalizada",
      description: description || "",
      function: fn,
      scheduleType: scheduleType || "cron",
      scheduleExpr: scheduleExpr || "0 12 * * *",
      intervalHours: intervalHours || 24,
      enabled: true,
      lastRun: null,
      history: [],
      custom: true
    };
    this.tasks.push(task);
    this.save();
    return { ok: true, task };
  }

  remove(taskId) {
    const task = this.tasks.find((t) => t.id === taskId);
    if (!task) return { ok: false };
    this.tasks = this.tasks.filter((t) => t.id !== taskId);
    this.save();
    return { ok: true };
  }

  getFunctions() {
    return Object.entries(FUNCTIONS).map(([id, fn]) => ({
      id,
      name: fn.name,
      description: fn.description
    }));
  }

  getHistory(taskId, limit = 20) {
    const task = this.tasks.find((t) => t.id === taskId);
    return task ? (task.history || []).slice(0, limit) : [];
  }
}

module.exports = Scheduler;