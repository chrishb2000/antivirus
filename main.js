"use strict";
const { app, BrowserWindow, ipcMain, Notification, dialog, Tray, Menu } = require("electron");
const path = require("path");
const fs = require("fs");
const os = require("os");

const Config = require("./src/services/config");
const Logger = require("./src/services/logger");
const ThreatStore = require("./src/services/threats");
const Quarantine = require("./src/engine/quarantine");
const Scanner = require("./src/engine/scanner");
const AI = require("./src/ai/ai-manager");
const Firewall = require("./src/network/firewall");
const FileWatcher = require("./src/monitor/file-watcher");
const RealtimeMonitor = require("./src/monitor/realtime-monitor");
const ProcessMonitor = require("./src/monitor/process-monitor");
const NetworkMonitor = require("./src/monitor/network-monitor");
const SystemMonitor = require("./src/monitor/system-monitor");
const Scheduler = require("./src/services/scheduler");
const { isAdmin, elevate } = require("./src/utils/admin");
const { runPowerShell } = require("./src/utils/ps");

// Datos (config, cuarentena, historial) SIEMPRE fuera del .asar:
// - portable: junto al .exe (carpeta data/)
// - instalado: %APPDATA%\Aegis AI Antivirus\data
const DATA_DIR = process.env.PORTABLE_EXECUTABLE_DIR
  ? path.join(process.env.PORTABLE_EXECUTABLE_DIR, "data")
  : path.join(app.getPath("userData"), "data");

let win = null;
let engine = null;
let tray = null;
let currentScan = null;
let isQuitting = false;

// ---------------------------------------------------------------------------
// Bandeja del sistema (icono junto a volumen/wifi)
// ---------------------------------------------------------------------------
function showMainWindow() {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

function rebuildTrayMenu() {
  if (!tray) return;
  const running = engine ? engine.realtime.isRunning() : false;
  const threatCount = engine ? engine.threats.list(500).length : 0;
  const menu = Menu.buildFromTemplate([
    { label: "Mostrar Aegis AI Antivirus", click: () => showMainWindow() },
    { type: "separator" },
    { label: "Escaneo rápido", click: () => { showMainWindow(); startScan("quick", null); } },
    { label: "Abrir cuarentena", click: () => { showMainWindow(); push("nav:go", "quarantine"); } },
    {
      label: "Protección en tiempo real",
      type: "checkbox",
      checked: running,
      click: (item) => {
        engine.config.set({ realtime: item.checked });
        if (item.checked && !engine.realtime.isRunning()) engine.realtime.start();
        if (!item.checked && engine.realtime.isRunning()) engine.realtime.stop();
        rebuildTrayMenu();
      }
    },
    { label: `Amenazas registradas: ${threatCount}`, enabled: false },
    { type: "separator" },
    { label: "Configurar IA de análisis", click: () => { showMainWindow(); push("nav:go", "ai"); } },
    { label: "Salir", click: () => { isQuitting = true; app.quit(); } }
  ]);
  tray.setContextMenu(menu);
  tray.setToolTip(running ? "Aegis AI Antivirus - Protección activa" : "Aegis AI Antivirus - Protección en pausa");
}

function createTray() {
  const { trayImage } = require("./src/utils/tray-icon");
  tray = new Tray(trayImage());
  tray.on("click", () => showMainWindow());
  rebuildTrayMenu();
}

// ---------------------------------------------------------------------------
// Escaneo reutilizable (IPC + bandeja)
// ---------------------------------------------------------------------------
async function startScan(mode, root) {
  if (currentScan && currentScan.running) return { error: "YA_HayUnEscaneo" };
  engine.config.save();
  currentScan = { running: true, cancelled: false };
  const scanner = engine.scanner;
  let targets = [];
  if (mode === "quick") {
    const home = os.homedir();
    targets = [path.join(home, "Downloads"), path.join(home, "Desktop"), os.tmpdir()];
  } else if (mode === "full") {
    targets = [process.env.SystemDrive + "\\"];
  } else if (mode === "custom" && root) {
    targets = [root];
  }

  push("scan:started", { mode, targets });

  let threatsFound = 0;
  for (const t of targets) {
    if (currentScan.cancelled) break;
    const report = await scanner.scanRoot(t, {
      mode,
      onProgress: (file, i, total) => push("scan:progress", { root: t, file: file || null, i, total }),
      onThreat: (threat) => {
        threatsFound++;
        push("scan:threat", threat);
        engine.threats.add(threat);
        engine.logger.log({ type: "scan", level: "warn", message: `Escaneo: ${threat.name} (${threat.severity}) en ${threat.path}` });
      }
    });
    if (report.scanned > 0 || targets.length === 1) {
      push("scan:progress", { root: t, file: null, i: 0, total: report.scanned, done: true, threats: report.threats });
    }
  }

  currentScan.running = false;
  const summary = {
    done: true,
    cancelled: currentScan.cancelled,
    threats: threatsFound,
    at: new Date().toISOString()
  };
  push("scan:finished", summary);
  rebuildTrayMenu();
  return summary;
}

// ---------------------------------------------------------------------------
// Inicializacion del "motor" antivirus (servicios compartidos)
// ---------------------------------------------------------------------------
function buildEngine() {
  const config = new Config(DATA_DIR);
  const logger = new Logger(DATA_DIR, (ev) => push("log:event", ev));
  const threats = new ThreatStore(DATA_DIR);
  const quarantine = new Quarantine(DATA_DIR);

  const engine = {
    config,
    logger,
    threats,
    quarantine,
    ai: AI,
    firewall: Firewall,
    systemMonitor: SystemMonitor,
    processMonitor: ProcessMonitor,
    networkMonitor: NetworkMonitor,
    emit: push
  };

  const watcher = new FileWatcher((event) => {
    if (event.type === "new-file") {
      realtime.onNewFile(event.filePath);
    }
  });
  watcher.start(config.resolveWatched(), (folders) => {
    logger.log({ type: "watcher", level: "info", message: `Vigilando ${folders.length} carpeta(s) de descargas y correo` });
  });

  engine.watcher = watcher;
  engine.scanner = new Scanner(engine);
  engine.quarantine = quarantine;

  // Decision automatica sobre una amenaza
  engine.handleThreat = async (threat, opts = {}) => {
    const cfg = config.get();
    let action = "flagged";
    let aiResult = null;

    // 1) Analisis de IA si esta habilitado
    if (cfg.aiEnabled && cfg.aiKeys[cfg.aiProvider]) {
      try {
        aiResult = await AI.analyze(cfg, threat, null);
        threat.ai = {
          provider: aiResult.provider,
          verdict: aiResult.raw ? aiResult.raw.verdict : null,
          confidence: aiResult.raw ? aiResult.raw.confidence : null,
          summary: aiResult.raw ? aiResult.raw.summary : null,
          recommendation: aiResult.raw ? aiResult.raw.recommendation : null,
          reasons: aiResult.raw ? aiResult.raw.reasons : []
        };
        // Accion recomendada por la IA
        if (aiResult.raw) {
          const rec = String(aiResult.raw.recommendation || "").toLowerCase();
          if ((rec === "quarantine" || rec === "delete") && cfg.autoQuarantine) {
            if (threat.path && fs.existsSync(threat.path)) {
              const q = await quarantine.add(threat.path, threat);
              if (q) action = q.moved ? "quarantined" : "quarantined-copy";
            }
          } else if (rec === "block" && threat.type === "network" && cfg.autoBlockConnections) {
            if (threat.path) {
              const r = await Firewall.blockProgram(threat.path);
              if (r.ok) action = "blocked";
            } else if (threat.remoteAddress) {
              const r = await Firewall.blockIp(threat.remoteAddress);
              if (r.ok) action = "blocked";
            }
          }
        }
      } catch (e) {
        logger.log({ type: "ai", level: "warn", message: "Error analizando con IA: " + e.message });
      }
    }

    // 2) Cuarentena automatica por firma (sin IA)
    if (action === "flagged" && cfg.autoQuarantine && threat.source === "signature" &&
        (threat.severity === "high" || threat.severity === "critical") && threat.path && fs.existsSync(threat.path)) {
      const q = await quarantine.add(threat.path, threat);
      if (q) action = q.moved ? "quarantined" : "quarantined-copy";
    }

    threat.action = action;
    const stored = threats.add(threat);
    engine.runtime.threatsDetected = (engine.runtime.threatsDetected || 0) + 1;
    logger.log({
      type: "threat",
      level: threat.severity === "critical" ? "error" : "warn",
      message: `Amenaza ${threat.severity.toUpperCase()}: ${threat.name || threat.description} - ${action}`,
      detail: threat
    });
    push("rt:threat", stored);

    // Aviso en bandeja
    if (tray) {
      tray.setToolTip(`Amenaza (${threat.severity}): ${threat.name || threat.description} (${action})`);
      if (!tray._resetTimer) {
        tray._resetTimer = setTimeout(() => {
          const running = engine.realtime.isRunning();
          tray.setToolTip(running ? "Aegis AI Antivirus - Protección activa" : "Aegis AI Antivirus - Protección en pausa");
        }, 12000);
      }
    }

    // Notificacion del sistema
    if (cfg.notifications && typeof Notification !== "undefined" && Notification.isSupported()) {
      try {
        new Notification({
          title: "Aegis AI - Amenaza detectada",
          body: `${threat.name || threat.description} (${threat.severity}) -> ${action}`
        }).show();
      } catch (e) { /* ignorar */ }
    }
    return stored;
  };

  // Control rapido de archivos nuevos (descargas / correo)
  engine.quickFileCheck = async (filePath) => {
    const cfg = config.get();
    if (!cfg.realtime) return;
    try {
      const ext = path.extname(filePath).toLowerCase();
      const riskyExts = cfg.scanExtensions || [];
      if (!riskyExts.includes(ext.replace(".", ""))) return;
      if ((engine.config.get().exclusions || []).some(e => filePath.toLowerCase().startsWith(e.toLowerCase()))) return;

      const res = await engine.scanner.checkFile(filePath);
      if (res && res.danger) {
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
          size: fs.existsSync(filePath) ? fs.statSync(filePath).size : 0,
          time: new Date().toISOString(),
          justDetected: true
        };
        await engine.handleThreat(threat, { realtime: true });
        logger.log({ type: "download", level: "info", message: `Archivo nuevo analizado: ${filePath}` });
      } else {
        logger.log({ type: "download", level: "info", message: `Archivo nuevo verificado OK: ${filePath}` });
      }
    } catch (e) {
      // ignorar
    }
  };

  engine.appPath = __dirname;
  engine.runtime = { threatsDetected: 0 };
  const realtime = new RealtimeMonitor(engine);
  engine.realtime = realtime;
  engine.runtime.threatsDetected = 0;

  engine.scheduler = new Scheduler(DATA_DIR, engine);

  return { engine, realtime };
}

function push(channel, payload) {
  if (win && !win.isDestroyed()) {
    try { win.webContents.send(channel, payload); } catch (e) { /* ignorar */ }
  }
}

// ---------------------------------------------------------------------------
// Ventana
// ---------------------------------------------------------------------------
function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 760,
    minWidth: 960,
    minHeight: 640,
    center: true,
    autoHideMenuBar: true,
    backgroundColor: "#0b1220",
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  win.setMenuBarVisibility(false);
  win.once("ready-to-show", () => win.show());
  if (process.argv.includes("--smoke-test")) {
    win.webContents.on("console-message", (e, level, message, line, sourceId) => {
      console.log(`[renderer:${level}] ${message} (${sourceId}:${line})`);
    });
    win.webContents.on("did-fail-load", (e, code, desc) => console.log(`[did-fail-load] ${code} ${desc}`));
    win.webContents.once("did-finish-load", async () => {
      try {
        const info = await win.webContents.executeJavaScript(`(async function(){
          const r = {};
          r.views = Object.keys(window.AV.views);
          r.viewState = window.AV.state.view;
          r.navItems = document.querySelectorAll('.nav-item').length;
          r.active = document.querySelector('.view.active') ? document.querySelector('.view.active').id : 'none';
          r.cpu = document.querySelector('#statCpu') ? document.querySelector('#statCpu').textContent : 'missing';
          r.procs = document.querySelector('#statProcs') ? document.querySelector('#statProcs').textContent : 'missing';
          r.diskCount = document.querySelector('#diskCount') ? document.querySelector('#diskCount').textContent : 'missing';
          r.aiConnected = document.querySelector('#aiConnected') ? document.querySelector('#aiConnected').textContent : 'missing';
          return r;
        })()`);
        console.log("RENDER_OK " + JSON.stringify(info));
        setTimeout(async () => {
          try {
            const late = await win.webContents.executeJavaScript(`({
              cpu: document.querySelector('#statCpu').textContent,
              mem: document.querySelector('#statMem').textContent,
              procs: document.querySelector('#statProcs').textContent,
              conns: document.querySelector('#statConns').textContent,
              disks: document.querySelector('#diskList').innerText.slice(0, 60)
            })`);
            console.log("RENDER_LATE " + JSON.stringify(late));
          } catch (e) { console.log("RENDER_LATE_FAIL " + e.message); }
        }, 4600);
      } catch (e) {
        console.log("RENDER_FAIL " + e.message);
      }
    });
  }
  win.loadFile(path.join(__dirname, "renderer", "index.html"));
  // Minimizar a la bandeja (no se cierra al pulsar X)
  win.on("close", (e) => {
    if (!isQuitting) {
      e.preventDefault();
      win.hide();
    }
  });
  win.on("closed", () => { win = null; });
}

// ---------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------
function registerIpc() {
  ipcMain.handle("app:info", async () => ({
    version: app.getVersion(),
    isAdmin: await isAdmin(),
    platform: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    users: os.userInfo().username
  }));

  ipcMain.handle("app:elevate", async () => {
    const ok = await elevate();
    if (ok) {
      setTimeout(() => {
        isQuitting = true;
        app.quit();
      }, 800);
    }
    return { ok };
  });

  ipcMain.handle("dialog:pickFolder", async () => {
    const r = await dialog.showOpenDialog(win, { properties: ["openDirectory", "createDirectory"], title: "Selecciona una carpeta" });
    return r.canceled ? null : r.filePaths[0];
  });

  ipcMain.handle("dialog:pickFile", async () => {
    const r = await dialog.showOpenDialog(win, { properties: ["openFile"], title: "Selecciona un archivo" });
    return r.canceled ? null : r.filePaths[0];
  });

  ipcMain.handle("config:get", () => engine.config.get());
  ipcMain.handle("config:set", (e, patch) => {
    const before = engine.config.get();
    const after = engine.config.set(patch || {});
    // Reconfiguracion dinamica
    if (patch && "realtime" in patch) {
      if (patch.realtime && !engine.realtime.isRunning()) engine.realtime.start();
      if (!patch.realtime && engine.realtime.isRunning()) engine.realtime.stop();
      rebuildTrayMenu();
    }
    if (patch && "watchedFolders" in patch) {
      engine.watcher.start(engine.config.resolveWatched());
    }
    if (before.aiKeys && patch && patch.aiKeys) {
      engine.config.save();
    }
    return engine.config.get();
  });

  ipcMain.handle("system:metrics", () => SystemMonitor.snapshot());
  ipcMain.handle("processes:list", () => ProcessMonitor.list());
  ipcMain.handle("processes:kill", async (e, pid) => {
    try {
      if (!pid) return { ok: false, error: "PID inválido" };
      const { runExe } = require("./src/utils/ps");
      const res = await runExe("taskkill.exe", ["/F", "/PID", String(pid)]);
      return res.ok ? { ok: true } : { ok: false, error: res.error || "No se pudo terminar el proceso" };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });
  ipcMain.handle("file:delete", async (e, filePath) => {
    try {
      if (!filePath || !fs.existsSync(filePath)) return { ok: false, error: "Archivo no encontrado" };
      fs.unlinkSync(filePath);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });
  ipcMain.handle("file:quarantine", async (e, filePath) => {
    try {
      if (!filePath || !fs.existsSync(filePath)) return { ok: false, error: "Archivo no encontrado" };
      const threat = {
        type: "file",
        path: filePath,
        name: path.basename(filePath),
        severity: "high",
        source: "user-action",
        description: "Aislamiento manual por el usuario",
        time: new Date().toISOString()
      };
      const q = await engine.quarantine.add(filePath, threat);
      return q ? { ok: true } : { ok: false, error: "No se pudo aislar en cuarentena" };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });
  ipcMain.handle("network:connections", () => NetworkMonitor.list());

  ipcMain.handle("scan:start", (e, { mode, root }) => startScan(mode, root));

  ipcMain.handle("scan:status", () => currentScan ? { running: currentScan.running, cancelled: currentScan.cancelled } : { running: false });
  ipcMain.handle("scan:stop", () => {
    if (currentScan) { currentScan.cancelled = true; engine.scanner.cancel(); }
    return { ok: true };
  });

  ipcMain.handle("quarantine:list", () => engine.quarantine.list());
  ipcMain.handle("quarantine:restore", (e, id) => engine.quarantine.restore(id));
  ipcMain.handle("quarantine:remove", (e, id) => engine.quarantine.remove(id));

  ipcMain.handle("firewall:status", () => Firewall.status());
  ipcMain.handle("firewall:set", (e, on) => Firewall.setEnabled(on));
  ipcMain.handle("firewall:list", () => Firewall.list());
  ipcMain.handle("firewall:add", (e, data) => Firewall.add(data));
  ipcMain.handle("firewall:remove", (e, name) => Firewall.remove(name));
  ipcMain.handle("firewall:blockProgram", (e, filePath) => Firewall.blockProgram(filePath));
  ipcMain.handle("firewall:blockIp", (e, ip) => Firewall.blockIp(ip));

  ipcMain.handle("ai:providers", () => AI.providers());
  ipcMain.handle("ai:test", (e, cfg) => AI.testConnection(cfg));
  ipcMain.handle("ai:analyzeFile", async (e, filePath) => {
    const cfg = engine.config.get();
    const sigHit = await engine.scanner.checkFile(filePath);
    const stats = fs.existsSync(filePath) ? fs.statSync(filePath) : { size: 0 };
    const threat = {
      type: "file",
      path: filePath,
      name: path.basename(filePath),
      source: sigHit && sigHit.danger ? sigHit.source : "manual",
      severity: sigHit && sigHit.danger ? sigHit.low : "unknown",
      family: sigHit && sigHit.danger ? sigHit.family : "Analisis Manual",
      description: sigHit && sigHit.danger ? sigHit.name : "Analisis manual con IA",
      detail: "Archivo analizado manualmente",
      sha256: (sigHit && sigHit.sha256) || "",
      size: stats.size,
      time: new Date().toISOString()
    };
    const result = await AI.analyze(cfg, threat, null);
    return { threat, ai: result };
  });

  ipcMain.handle("threats:list", () => engine.threats.list());
  ipcMain.handle("threats:resolve", (e, id, status) => engine.threats.resolve(id, status));
  ipcMain.handle("threats:clear", () => { engine.threats.clear(); return { ok: true }; });
  ipcMain.handle("threats:quarantineThreat", async (e, id) => {
    const list = engine.threats.list();
    const t = list.find(x => x.id === id);
    if (!t) return { ok: false, error: "No encontrado" };
    if (t.path && fs.existsSync(t.path)) {
      const q = await engine.quarantine.add(t.path, t);
      if (q) {
        const fresh = engine.threats.resolve(id, "quarantined");
        return { ok: true, action: "quarantined" };
      }
      return { ok: false, error: "No se pudo aislar" };
    }
    // si ya no existe, marcar como manejado
    engine.threats.resolve(id, "quarantined");
    return { ok: true, action: "already-gone" };
  });

  // --- Scheduler / Automatizacion ---
  ipcMain.handle("scheduler:list", () => engine.scheduler.list());
  ipcMain.handle("scheduler:functions", () => engine.scheduler.getFunctions());
  ipcMain.handle("scheduler:toggle", (e, taskId, enabled) => engine.scheduler.toggle(taskId, enabled));
  ipcMain.handle("scheduler:runNow", async (e, taskId) => {
    const r = await engine.scheduler.runNow(taskId);
    rebuildTrayMenu();
    return r;
  });
  ipcMain.handle("scheduler:add", (e, data) => engine.scheduler.add(data));
  ipcMain.handle("scheduler:remove", (e, taskId) => engine.scheduler.remove(taskId));
  ipcMain.handle("scheduler:history", (e, taskId) => engine.scheduler.getHistory(taskId));

  ipcMain.handle("logs:list", (e, limit) => engine.logger.list(limit || 200));
  ipcMain.handle("runtime:status", () => ({
    realtime: engine.realtime.isRunning(),
    threats: engine.threats.list(1).length,
    started: engine.realtime.runtime.startedAt,
    watchedFolders: engine.config.resolveWatched(),
    engine: engine.runtime
  }));
}

// ---------------------------------------------------------------------------
// Ciclo de vida
// ---------------------------------------------------------------------------
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on("second-instance", () => { showMainWindow(); });

app.whenReady().then(() => {
  app.setAppUserModelId("com.chrishb2000.aegisantivirus");
  const built = buildEngine();
  engine = built.engine;
  // engine.runtime.threatsDetected definido en buildEngine
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  if (engine.config.get().realtime) {
    engine.realtime.start();
  }
  engine.scheduler.start();
  registerIpc();
  createWindow();
  createTray();

  // Modo prueba: arranca, espera y cierra para validar el proceso principal
  if (process.argv.includes("--smoke-test")) {
    setTimeout(() => {
      isQuitting = true;
      console.log("SMOKE_TEST_OK");
      app.quit();
    }, 6000);
  }

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", () => {
  isQuitting = true;
  if (engine && engine.scheduler) engine.scheduler.stop();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
}

