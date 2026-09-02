"use strict";
const { execFile } = require("child_process");

class ProcessMonitor {
  list() {
    return new Promise((resolve) => {
      execFile("tasklist.exe", ["/V", "/FO", "CSV"], { maxBuffer: 10 * 1024 * 1024, windowsHide: true }, (err, stdout) => {
        if (err || !stdout) return resolve([]);
        try {
          const lines = stdout.split(/\r?\n/).filter(line => line.trim().length > 0);
          if (lines.length < 2) return resolve([]);

          const processes = [];
          for (let i = 1; i < lines.length; i++) {
            const line = lines[i];
            const parts = line.match(/(?:^|,)(?:"([^"]*)"|([^,]*))/g);
            if (!parts || parts.length < 5) continue;

            const clean = parts.map(p => p.replace(/^,?"?|"$/g, "").trim());
            const name = clean[0] || "";
            const pid = parseInt(clean[1], 10);
            if (isNaN(pid)) continue;

            const memStr = clean[4] || "0";
            const memKb = parseInt(memStr.replace(/[^\d]/g, ""), 10) || 0;
            const session = clean[2] || "";

            processes.push({
              pid,
              name,
              path: "",
              cmdline: name,
              mem: memKb * 1024,
              session
            });
          }
          resolve(processes);
        } catch (e) {
          resolve([]);
        }
      });
    });
  }

  async byPid(pid) {
    const list = await this.list();
    return list.find(p => p.pid === pid) || null;
  }
}

module.exports = new ProcessMonitor();