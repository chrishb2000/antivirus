"use strict";
const os = require("os");
const { runPowerShell } = require("../utils/ps");

class SystemMonitor {
  async snapshot() {
    let cpu = null;
    let mem = null;
    let disks = [];

    const c = await runPowerShell("Get-CimInstance Win32_Processor | Select-Object LoadPercentage | ConvertTo-Json -Compress");
    if (c) {
      try {
        const data = JSON.parse(c);
        cpu = Array.isArray(data) ? data.reduce((s, x) => s + (x.LoadPercentage || 0), 0) / data.length : (data.LoadPercentage || 0);
      } catch (e) { cpu = null; }
    }

    const m = await runPowerShell("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress");
    if (m) {
      try {
        const d = JSON.parse(m);
        const total = (d.TotalVisibleMemorySize || os.totalmem() / 1024);
        const free = (d.FreePhysicalMemory || os.freemem() / 1024);
        mem = { totalKb: total, freeKb: free, usedKb: total - free, percent: total > 0 ? Math.round(((total - free) / total) * 100) : 0 };
      } catch (e) { mem = null; }
    }

    const ds = await runPowerShell("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,Size,FreeSpace,VolumeName | ConvertTo-Json -Compress");
    if (ds) {
      try {
        const arr = JSON.parse(ds);
        const list = Array.isArray(arr) ? arr : [arr];
        disks = list.filter(x => x && x.Size).map(x => ({
          drive: x.DeviceID,
          label: x.VolumeName || "",
          size: x.Size,
          free: x.FreeSpace,
          percent: x.Size > 0 ? Math.round(((x.Size - x.FreeSpace) / x.Size) * 100) : 0
        }));
      } catch (e) { disks = []; }
    }

    return {
      cpu: cpu == null ? 0 : Math.round(cpu),
      mem,
      disks,
      uptime: os.uptime(),
      hostname: os.hostname(),
      platform: `${os.type()} ${os.release()}`,
      arch: os.arch()
    };
  }
}

module.exports = new SystemMonitor();