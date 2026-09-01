"use strict";

window.AV = window.AV || {};
(function () {
  const AV = window.AV;
  const $ = AV.$;

  const SCHED_LABEL = {
    "min": "min", "hour": "hora", "day": "día", "month": "mes", "dow": "dow"
  };

  function describeCron(expr) {
    if (!expr) return "";
    const parts = expr.trim().split(/\s+/);
    if (parts.length !== 5) return expr;
    const [min, hour, dom, mon, dow] = parts;
    if (min === "0" && hour === "2" && dom === "*" && mon === "*" && dow === "*") return "Cada día a las 02:00";
    if (min === "0" && hour === "3" && dom === "*" && mon === "*" && dow === "0") return "Cada domingo a las 03:00";
    if (min === "30" && hour === "3" && dom === "*" && mon === "*" && dow === "*") return "Cada día a las 03:30";
    if (min === "0" && hour === "9" && dom === "*" && mon === "*" && dow === "*") return "Cada día a las 09:00";
    if (min === "0" && hour === "8" && dom === "*" && mon === "*" && dow === "1") return "Cada lunes a las 08:00";
    if (min === "0" && hour === "4" && dom === "1" && mon === "*" && dow === "*") return "Cada día 1 del mes a las 04:00";
    if (min === "0" && hour === "3" && dom === "*" && mon === "*" && dow === "3") return "Cada miércoles a las 03:00";
    if (min === "0" && hour === "8" && dom === "*" && mon === "*" && dow === "5") return "Cada viernes a las 08:00";
    if (min === "*" && hour === "*" && dom === "*" && mon === "*" && dow === "*") return "Cada minuto";
    return `Cron \`${expr}\``;
  }

  function describeInterval(h) {
    if (!h) return "Cada hora";
    if (h === 72) return "Cada 3 días";
    if (h === 24) return "Cada día";
    return `Cada ${h} hora(s)`;
  }

  function scheduleText(t) {
    if (t.scheduleType === "interval") return describeInterval(t.intervalHours);
    return describeCron(t.scheduleExpr);
  }

  function esc(v) {
    return String(v == null ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function severityFromText() { return ""; }

  function renderHistory(history) {
    if (!history || history.length === 0) return "<div class='muted small'>Sin ejecuciones todavía.</div>";
    return history.slice(0, 6).map((h) => {
      const icon = h.success ? "&#x2705;" : "&#x274C;";
      return `<div class="sched-hist-item ${h.success ? "ok" : "err"}">
        <span class="hist-ico">${icon}</span>
        <div>
          <div>${esc(h.message)}</div>
          <div class="muted small">${AV.fmtDate(h.time)} &middot; ${h.durationMs ? (h.durationMs / 1000).toFixed(1) + "s" : ""}</div>
        </div>
      </div>`;
    }).join("");
  }

  function renderTasks(tasks, functions) {
    const list = $("#schedTaskList");
    if (!tasks.length) {
      list.innerHTML = "<div class='muted'>No hay tareas.</div>";
      return;
    }
    const enabledCount = tasks.filter((t) => t.enabled).length;
    const badge = $("#schedEnabledCount");
    if (badge) badge.textContent = `${enabledCount} de ${tasks.length} activas`;

    list.innerHTML = tasks.map((t) => {
      const fn = (functions || []).find((f) => f.id === t.function);
      const fnName = fn ? fn.name : t.function;
      const last = t.lastRun ? `Última: ${AV.timeAgo(t.lastRun)}` : "Nunca ejecutada";
      const customTag = t.custom ? "<span class='tag'>personalizada</span>" : "";
      return `<div class="sched-card ${t.enabled ? "" : "off"}">
        <div class="sched-main">
          <label class="sw sched-sw">
            <input type="checkbox" class="sched-toggle" data-id="${esc(t.id)}" ${t.enabled ? "checked" : ""} />
            <span class="sw-slider"></span>
          </label>
          <div class="sched-info">
            <div class="sched-name">${esc(t.name)} ${customTag}</div>
            <div class="sched-desc">${esc(t.description)}</div>
            <div class="sched-meta">
              <span class="badge sched-fn">${esc(fnName)}</span>
              <span class="muted small">${esc(scheduleText(t))} &middot; ${last}</span>
            </div>
            <div class="sched-history">${renderHistory(t.history)}</div>
          </div>
          <div class="sched-actions">
            <button class="btn small primary sched-run" data-id="${esc(t.id)}" ${t.enabled ? "" : "disabled"}>&#x25B6; Ejecutar ahora</button>
            ${t.custom ? `<button class="btn small danger sched-del" data-id="${esc(t.id)}">Eliminar</button>` : ""}
          </div>
        </div>
      </div>`;
    }).join("");
  }

  async function load() {
    const [tasks, functions] = await Promise.all([
      Aegis.invoke("scheduler:list"),
      Aegis.invoke("scheduler:functions")
    ]);
    AV.state.schedulerTasks = tasks;
    AV.state.schedulerFunctions = functions;
    renderTasks(tasks, functions);
  }

  AV.views.scheduler = {
    async init() {
      const functions = await Aegis.invoke("scheduler:functions");
      const sel = $("#schedFunction");
      sel.innerHTML = functions.map((f) => `<option value="${esc(f.id)}">${esc(f.name)}</option>`).join("");
      const hint = $("#schedFuncHint");
      if (functions[0]) hint.textContent = functions[0].description;
      sel.addEventListener("change", () => {
        const f = functions.find((x) => x.id === sel.value);
        hint.textContent = f ? f.description : "";
      });

      const typeSel = $("#schedType");
      typeSel.addEventListener("change", () => {
        const isInterval = typeSel.value === "interval";
        $("#rowCronExpr").style.display = isInterval ? "none" : "";
        $("#rowInterval").style.display = isInterval ? "" : "none";
      });

      $("#btnSchedAdd").addEventListener("click", async () => {
        const type = typeSel.value;
        const data = {
          name: $("#schedName").value.trim(),
          function: sel.value,
          scheduleType: type,
          scheduleExpr: type === "cron" ? $("#schedCron").value.trim() || "0 12 * * *" : null,
          intervalHours: type === "interval" ? Number($("#schedInterval").value) || 24 : null
        };
        if (!data.name) { AV.toast("Escribe un nombre para la tarea", "warn"); return; }
        const r = await Aegis.invoke("scheduler:add", data);
        if (r.ok) {
          AV.toast("Tarea creada correctamente", "ok");
          $("#schedName").value = "";
          $("#schedCron").value = "";
          $("#schedInterval").value = "";
          await load();
        } else {
          AV.toast(r.error || "Error al crear tarea", "danger");
        }
      });

      $("#schedTaskList").addEventListener("click", async (ev) => {
        const runBtn = ev.target.closest(".sched-run");
        const delBtn = ev.target.closest(".sched-del");
        if (runBtn) {
          runBtn.disabled = true;
          runBtn.textContent = "Ejecutando...";
          await Aegis.invoke("scheduler:runNow", runBtn.dataset.id);
          AV.toast("Tarea ejecutada y registrada en el historial", "ok");
          await load();
        } else if (delBtn) {
          if (confirm("¿Eliminar esta tarea personalizada?")) {
            await Aegis.invoke("scheduler:remove", delBtn.dataset.id);
            AV.toast("Tarea eliminada", "ok");
            await load();
          }
        }
      });

      $("#schedTaskList").addEventListener("change", async (ev) => {
        const toggle = ev.target.closest(".sched-toggle");
        if (!toggle) return;
        await Aegis.invoke("scheduler:toggle", toggle.dataset.id, toggle.checked);
        const on = toggle.checked ? "activada" : "desactivada";
        AV.toast(`Tarea ${on}`, on === "activada" ? "ok" : "warn");
        await load();
      });
    },
    async show() {
      await load();
    }
  };
})();