"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;

  async function currentCfg() {
    if (!AV.state.config) AV.state.config = await Aegis.invoke("config:get");
    return AV.state.config;
  }

  function uiCfg() {
    const base = AV.state.config || {};
    const keys = { ...(base.aiKeys || {}) };
    keys[base.aiProvider || AV.state.config.aiProvider || "openai"] = $("#aiKey").value || keys[base.aiProvider] || "";
    return {
      aiProvider: $("#aiProvider").value,
      aiModel: $("#aiModel").value || "",
      aiKeys: keys
    };
  }

  AV.views.ai = {
    async init() {
      const providers = await Aegis.invoke("ai:providers");
      const sel = $("#aiProvider");
      sel.innerHTML = providers.map((p) => `<option value="${p.id}" data-model="${p.defaultModel}">${p.name} (${p.defaultModel})</option>`).join("");

      const cfg = await currentCfg();
      sel.value = cfg.aiProvider || "openai";
      $("#aiModel").value = cfg.aiModel || "";
      $("#aiKey").value = cfg.aiKeys[sel.value] || "";
      this.showModelHint();
      if (cfg.aiEnabled && cfg.aiKeys[sel.value]) {
        const p = AV.$("#aiConnected");
        p.textContent = "Conectada";
        p.className = "badge";
      }

      sel.addEventListener("change", () => {
        const keys = AV.state.config.aiKeys || {};
        $("#aiKey").value = keys[sel.value] || "";
        $("#aiModel").value = (AV.state.config.aiModel && AV.state.config.aiProvider === sel.value) ? AV.state.config.aiModel : "";
        this.showModelHint();
      });

      $("#btnAiSave").addEventListener("click", async () => {
        const c = uiCfg();
        await Aegis.invoke("config:set", { aiProvider: c.aiProvider, aiModel: c.aiModel, aiKeys: c.aiKeys });
        AV.state.config = await Aegis.invoke("config:get");
        AV.toast("Configuración de IA guardada", "ok");
        this.show();
      });

      $("#btnAiTest").addEventListener("click", async () => {
        const c = uiCfg();
        if (!c.aiKeys[c.aiProvider]) return AV.toast("Pega tu API key antes de probar", "warn");
        const box = $("#aiTestResult");
        box.className = "ai-result show";
        box.style.borderLeft = "4px solid var(--accent)";
        box.style.color = "";
        box.innerHTML = "Conectando y validando la clave con <b>" + c.aiProvider + "</b>...";
        $("#btnAiTest").disabled = true;
        try {
          const r = await Aegis.invoke("ai:test", c);
          // Guardar y activar la IA si la clave es correcta
          await Aegis.invoke("config:set", { aiProvider: c.aiProvider, aiModel: c.aiModel, aiKeys: c.aiKeys, aiEnabled: true });
          AV.state.config = await Aegis.invoke("config:get");
          box.innerHTML = `<div style="color:var(--ok);font-size:15px;font-weight:700">&#10004; API CORRECTA y CONECTADA</div>
            <div style="margin-top:6px">El proveedor <b>${r.provider}</b> respondió correctamente. La IA ya analizará archivos y amenazas automáticamente.</div>`;
          AV.toast("API correcta: IA conectada y activada", "ok");
          this.show();
          if (AV.views.dashboard) AV.views.dashboard.renderFirewallStatus();
        } catch (e) {
          box.innerHTML = `<div style="color:var(--danger);font-size:15px;font-weight:700">&#10008; API INCORRECTA o error</div>
            <div style="margin-top:6px">${e.message.replace(/</g, "&lt;")}</div>`;
          box.style.borderLeft = "4px solid var(--danger)";
          AV.toast("No se pudo conectar: revisa la clave", "danger");
        } finally {
          $("#btnAiTest").disabled = false;
        }
      });

      $("#btnAiAnalyzeFile").addEventListener("click", async () => {
        const cfg = await currentCfg();
        if (!cfg.aiEnabled) {
          AV.toast("Activa 'Conectar con IA' en Ajustes", "warn");
          return;
        }
        if (!cfg.aiKeys[cfg.aiProvider]) return AV.toast("Configura tu API key primera", "warn");
        const file = await Aegis.invoke("dialog:pickFile");
        if (!file) return;
        const box = $("#aiAnalysisResult");
        box.className = "ai-result show";
        box.style.borderLeft = "4px solid var(--accent)";
        box.textContent = "Enviando " + file + " a la IA para análisis forense...";
        try {
          const res = await Aegis.invoke("ai:analyzeFile", file);
          const ai = res.ai;
          const raw = ai.raw || {};
          const verdictColor = raw.verdict === "malware" ? "var(--danger)" : raw.verdict === "suspicious" ? "var(--warn)" : raw.verdict === "benign" ? "var(--ok)" : "var(--muted)";
          box.innerHTML = `<div style="font-size:15px;font-weight:700;margin-bottom:8px">
            Veredicto: <span style="color:${verdictColor}">${String(raw.verdict || "unknown").toUpperCase()}</span>
            <span style="color:var(--text-dim)"> (confianza ${Math.round((raw.confidence || 0) * 100)}%)</span></div>
            <div>${raw.summary || ""}</div>
            <div style="margin:8px 0"><b>Recomendación:</b> ${String(raw.recommendation || "monitor").toUpperCase()}</div>
            ${raw.reasons && raw.reasons.length ? `<div style="color:var(--text-dim)"><ul style="margin-left:18px">${raw.reasons.map(r => `<li>${r}</li>`).join("")}</ul></div>` : ""}
            <div class="muted" style="margin-top:8px">Motor: ${ai.provider} · Analizado a las ${AV.fmtDate(new Date().toISOString())}</div>`;
        } catch (e) {
          box.textContent = "Error: " + e.message;
          box.style.borderLeft = "4px solid var(--danger)";
        }
      });
    },

    showModelHint() {
      const opt = $("#aiProvider").selectedOptions[0];
      const hint = $("#aiModelHint");
      if (hint && opt) hint.textContent = "Modelo recomendado: " + opt.dataset.model + " (deja vacío para usarlo)";
    },

    async show() {
      const cfg = await currentCfg();
      const providers = await Aegis.invoke("ai:providers");
      const sel = $("#aiProvider");
      if (!sel.value) sel.value = cfg.aiProvider || "openai";
      const el = $("#aiConnected");
      if (cfg.aiEnabled && cfg.aiKeys[cfg.aiProvider]) {
        el.textContent = "Conectada (" + (providers.find(p => p.id === cfg.aiProvider) || {}).name + ")";
        el.className = "badge";
      } else {
        el.textContent = "No configurada";
        el.className = "badge warn";
      }
    }
  };
})();