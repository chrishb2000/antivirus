"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;
  let results = [];

  function setScanState(label, kind) {
    const el = $("#scanState");
    el.textContent = label;
    el.className = "badge" + (kind ? " " + kind : " muted-b");
  }

  AV.views.scanner = {
    async init() {
      $("#scanQuick").addEventListener("click", () => this.start("quick"));
      $("#scanFull").addEventListener("click", () => this.start("full"));
      $("#scanCustom").addEventListener("click", async () => {
        const dir = await this.pickFolder();
        if (dir) this.start("custom", dir);
      });
      $("#scanStop").addEventListener("click", () => Aegis.invoke("scan:stop"));

      Aegis.on("scan:started", (s) => {
        $("#scanThreatsFound").textContent = "0";
        $("#scanFiles").textContent = "0";
        $("#scanProgressBar").style.width = "0%";
        $("#scanResults").innerHTML = '<div class="muted">Escaneando...</div>';
        $("#scanStop").disabled = false;
        setScanState("En curso (" + s.mode + ")", "warn");
        results = [];
      });
      Aegis.on("scan:progress", (p) => {
        $("#scanFiles").textContent = (p.i || 0) + (p.total ? " / " + p.total : "");
        $("#scanProgressInfo").textContent = (p.file || "Procesando...") + (p.done ? " [fin carpeta]" : "");
        if (!p.done && p.total) {
          const pct = Math.min(100, Math.round((p.i / p.total) * 100));
          $("#scanProgressBar").style.width = pct + "%";
        }
      });
      Aegis.on("scan:threat", (threat) => {
        const n = parseInt($("#scanThreatsFound").textContent || "0", 10) + 1;
        $("#scanThreatsFound").textContent = n;
        results.push(threat);
      });
      Aegis.on("scan:finished", (s) => {
        $("#scanStop").disabled = true;
        setScanState(s.cancelled ? "Cancelado" : "Completado");
        $("#scanProgressInfo").textContent = "Escaneo finalizado " + AV.fmtDate(s.at);
        $("#scanProgressBar").style.width = "100%";
        this.renderResults(s);
      });
    },

    async pickFolder() {
      try {
        return await Aegis.invoke("dialog:pickFolder");
      } catch (e) {
        AV.toast("No se pudo abrir el selector", "warn");
        return null;
      }
    },

    async start(mode, root) {
      const st = await Aegis.invoke("scan:status");
      if (st.running) return AV.toast("Ya hay un escaneo en curso", "warn");
      results = [];
      if (mode === "custom" && !root) return;
      const started = await Aegis.invoke("scan:start", { mode, root });
      if (started && started.error === "YA_HayUnEscaneo") AV.toast("Ya hay un escaneo en curso", "warn");
    },

    renderResults(s) {
      const box = $("#scanResults");
      if (!results.length) {
        box.innerHTML = '<div class="muted">Sin amenazas detectadas en este escaneo.</div>';
        return;
      }
      box.innerHTML = results.map((t, index) => {
        const cls = t.severity === "critical" || t.severity === "high" ? "risk-high" : "risk-medium";
        const handled = t._handled ? `<span class="muted small">(${t._handled})</span>` : "";
        return `<div class="list-item" style="flex-wrap:wrap; gap:8px">
          <div class="li-main" style="min-width:240px">
            <div class="li-title">${t.name} ${handled}</div>
            <div class="li-sub">${t.path || "Ruta no disponible"} - ${t.detail || ""}</div>
          </div>
          <span class="risk-tag ${cls}">${AV.riskLabel(t.severity)}</span>
          <div class="li-actions" style="display:flex; gap:6px; flex-wrap:wrap">
            <button class="btn small danger" data-act="quarantine" data-idx="${index}">Cuarentena</button>
            <button class="btn small danger" data-act="delete" data-idx="${index}">Eliminar</button>
            <button class="btn small primary" data-act="ai" data-idx="${index}">Analizar con IA</button>
          </div>
        </div>`;
      }).join("");

      AV.$$("[data-act]", box).forEach((btn) => {
        btn.addEventListener("click", async () => {
          const act = btn.dataset.act;
          const idx = parseInt(btn.dataset.idx, 10);
          const t = results[idx];
          if (!t || !t.path) return AV.toast("Ruta de archivo no disponible", "warn");

          if (act === "quarantine") {
            const r = await Aegis.invoke("file:quarantine", t.path);
            if (r.ok) {
              t._handled = "Aislado en cuarentena";
              AV.toast(`Archivo ${t.name} movido a cuarentena`, "ok");
            } else {
              AV.toast(r.error || "No se pudo mover a cuarentena", "danger");
            }
            this.renderResults(s);
          } else if (act === "delete") {
            const r = await Aegis.invoke("file:delete", t.path);
            if (r.ok) {
              results.splice(idx, 1);
              AV.toast(`Archivo ${t.name} eliminado`, "ok");
            } else {
              AV.toast(r.error || "No se pudo eliminar el archivo", "danger");
            }
            this.renderResults(s);
          } else if (act === "ai") {
            AV.toast(`Enviando ${t.name} a análisis de IA...`, "ok");
            const res = await Aegis.invoke("ai:analyzeFile", t.path);
            if (res && res.ai) {
              AV.toast(`Veredicto IA: ${res.ai.raw ? res.ai.raw.verdict : "Analizado"}`, "ok");
            }
          }
        });
      });
    }
  };
})();