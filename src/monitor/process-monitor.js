"use strict";
const { runPowerShell } = require("../utils/ps");

class ProcessMonitor {
  async list() {
    const out = await runPowerShell(
      "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine,WorkingSetSize,SessionId | ConvertTo-Json -Compress",
      20000
    );
    if (!out) return [];
    try {
      const arr = JSON.parse(out);
      const list = Array.isArray(arr) ? arr : [arr];
      return list
        .filter(x => x && x.ProcessId)
        .map(p => ({
          pid: p.ProcessId,
          name: p.Name || "",
          path: p.ExecutablePath || "",
          cmdline: p.CommandLine || "",
          mem: p.WorkingSetSize || 0,
          session: p.SessionId
        }));
    } catch (e) {
      return [];
    }
  }

  async byPid(pid) {
    const list = await this.list();
    return list.find(p => p.pid === pid) || null;
  }
}

module.exports = new ProcessMonitor();