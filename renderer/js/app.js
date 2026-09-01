"use strict";

window.AV = window.AV || {};

(function () {
  "use strict";
  const AV = window.AV;
  AV.state = { config: null, appInfo: null, threats: [], view: "dashboard" };
  AV.views = {};

  AV.$ = (s, ctx) => (ctx || document).querySelector(s);
  AV.$$ = (s, ctx) => Array.from((ctx || document).querySelectorAll(s));

  AV.fmtBytes = (b) => {
    if (b == null || isNaN(b)) return "--";
    if (b === 0) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0; let v = b;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 10 || i === 0 ? 0 : 1) + " " + u[i];
  };

  AV.fmtDate = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleString("es-ES", { dateStyle: "short", timeStyle: "medium" });
  };

  AV.timeAgo = (iso) => {
    const s = Math.floor((Date.now() - new Date(iso)) / 1000);
    if (s < 5) return "ahora";
    if (s < 60) return `hace ${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `hace ${m}min`;
    const h = Math.floor(m / 60);
    if (h < 24) return `hace ${h}h`;
    return `hace ${Math.floor(h / 24)}d`;
  };

  AV.riskClass = (level) => {
    return level === "critical" ? "risk-critical" : level === "high" || level === "medium" ? "risk-" + level : "risk-none";
  };

  AV.riskLabel = (level) => {
    if (level === "critical" || level === "high") return "ALTO";
    if (level === "medium") return "MEDIO";
    return "LOW";
  };

  /* ---------- Toast ---------- */
  let toastWrap = null;
  AV.toast = (msg, kind) => {
    if (!toastWrap) {
      toastWrap = document.createElement("div");
      toastWrap.style.cssText = "position:fixed;top:62px;right:18px;z-index:999;display:flex;flex-direction:column;gap:8px;";
      document.body.appendChild(toastWrap);
    }
    const t = document.createElement("div");
    t.style.cssText =
      "background:var(--card);border:1px solid var(--border);border-left:4px solid var(--accent);" +
      "padding:11px 16px;border-radius:9px;font-size:13px;box-shadow:var(--shadow);max-width:340px;";
    if (kind === "ok") t.style.borderLeftColor = "var(--ok)";
    if (kind === "warn") t.style.borderLeftColor = "var(--warn)";
    if (kind === "danger") t.style.borderLeftColor = "var(--danger)";
    t.textContent = msg;
    toastWrap.appendChild(t);
    setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .4s"; }, 3800);
    setTimeout(() => t.remove(), 4300);
  };

  /* ---------- Tema ---------- */
  AV.applyTheme = (theme) => {
    document.documentElement.setAttribute("data-theme", theme);
    const toggle = AV.$("#themeToggle");
    if (toggle) toggle.checked = theme !== "dark";
  };

  /* ---------- Navegacion ---------- */
  function switchView(name) {
    AV.state.view = name;
    AV.$$(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
    AV.$$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === name));
    const view = AV.views[name];
    if (view && view.show) view.show();
  }

  /* ---------- Estado global de protección ---------- */
  AV.setStatus = (text, kind) => {
    const pill = AV.$("#statusPill");
    const txt = AV.$("#statusText");
    if (!pill || !txt) return;
    txt.textContent = text;
    pill.className = "status-pill" + (kind ? " " + kind : "");
    if (kind === "warn" && window.__statusTimer) clearTimeout(window.__statusTimer);
    if (kind === "warn") {
      window.__statusTimer = setTimeout(() => {
        AV.$("#statusText").textContent = "Protección activa";
        AV.$("#statusPill").className = "status-pill";
      }, 8000);
    }
  };

  /* ---------- Eventos push ---------- */
  function registerPush() {
    Aegis.on("rt:threat", (t) => {
      AV.toast(`Amenaza (${t.severity}): ${t.name || t.description} - ${t.action}`, "danger");
      AV.setStatus("Alerta: " + (t.name || t.description), "warn");
      if (!AV.state.threats) AV.state.threats = [];
      AV.state.threats.unshift(t);
      if (AV.state.view === "dashboard" && AV.views.dashboard) AV.views.dashboard.renderThreats();
      if (AV.state.view === "quarantine" && AV.views.quarantine) AV.views.quarantine.show();
    });
    Aegis.on("rt:metrics", (m) => {
      AV.state.metrics = m;
      if (AV.state.view === "dashboard" && AV.views.dashboard.dirty) AV.views.dashboard.renderMetrics(m);
    });
    Aegis.on("log:event", () => {
      if (AV.state.view === "dashboard" && AV.views.dashboard) AV.views.dashboard.renderThreats();
    });
    Aegis.on("nav:go", (view) => switchView(view));
  }

  /* ---------- App info / admin ---------- */
  async function loadAppInfo() {
    AV.state.appInfo = await Aegis.invoke("app:info");
    const badge = AV.$("#adminBadge");
    if (AV.state.appInfo.isAdmin) {
      badge.textContent = "Administrador (privilegios completos)";
      badge.classList.add("ok");
    } else {
      badge.textContent = "Sin permisos admin - Firewall limitado";
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    AV.applyTheme((AV.state.config && AV.state.config.theme) || "dark");
    const t = AV.$("#themeToggle");
    if (t) t.addEventListener("change", async () => {
      const next = t.checked ? "light" : "dark";
      AV.applyTheme(next);
      await Aegis.invoke("config:set", { theme: next });
    });

    AV.$$(".nav-item").forEach((n) => n.addEventListener("click", () => switchView(n.dataset.view)));

    AV.$("#btnQuickScan").addEventListener("click", () => { switchView("scanner"); AV.views.scanner.start("quick"); });
    AV.$("#btnFullScan").addEventListener("click", () => { switchView("scanner"); AV.views.scanner.start("full"); });

    registerPush();
    await loadAppInfo();

    const cfg = await Aegis.invoke("config:get");
    AV.state.config = cfg;
    AV.applyTheme(cfg.theme || "dark");

    for (const key of Object.keys(AV.views)) {
      if (AV.views[key].init) await AV.views[key].init();
    }

    AV.$$(".view").forEach((v) => v.classList.remove("active"));
    AV.$$(".nav-item").forEach((n) => n.classList.remove("active"));
    window.history.replaceState(null, "", "#dashboard");
    switchView("dashboard");
  });

  window.switchView = switchView;
})();