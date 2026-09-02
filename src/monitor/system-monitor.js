"use strict";
const os = require("os");
const fs = require("fs");

class SystemMonitor {
  constructor() {
    this.prevCpuTimes = this.getSystemCpuTimes();
  }

  getSystemCpuTimes() {
    const cpus = os.cpus();
    let user = 0, nice = 0, sys = 0, idle = 0, irq = 0;
    if (!cpus || !cpus.length) return { idle: 0, total: 0 };

    for (const cpu of cpus) {
      user += cpu.times.user;
      nice += cpu.times.nice || 0;
      sys += cpu.times.sys;
      idle += cpu.times.idle;
      irq += cpu.times.irq || 0;
    }
    const total = user + nice + sys + idle + irq;
    return { idle, total };
  }

  getCpuUsagePercent() {
    const curr = this.getSystemCpuTimes();
    const prev = this.prevCpuTimes;
    this.prevCpuTimes = curr;

    const idleDelta = curr.idle - prev.idle;
    const totalDelta = curr.total - prev.total;

    if (totalDelta <= 0) return 0;
    const usedPercent = Math.max(0, Math.min(100, Math.round(((totalDelta - idleDelta) / totalDelta) * 100)));
    return usedPercent;
  }

  getDisks() {
    const disks = [];
    const drives = ["C", "D", "E", "F", "G", "H", "Z"];
    for (const driveLetter of drives) {
      const rootPath = `${driveLetter}:\\`;
      try {
        if (fs.existsSync(rootPath)) {
          const stats = fs.statfsSync(rootPath);
          const size = stats.blocks * stats.bsize;
          const free = stats.bfree * stats.bsize;
          if (size > 0) {
            const percent = Math.round(((size - free) / size) * 100);
            disks.push({
              drive: `${driveLetter}:`,
              label: driveLetter === "C" ? "Disco local" : `Unidad ${driveLetter}`,
              size,
              free,
              percent
            });
          }
        }
      } catch (e) {
        // Drive missing or restricted
      }
    }
    return disks;
  }

  async snapshot() {
    const cpu = this.getCpuUsagePercent();

    const totalMemBytes = os.totalmem();
    const freeMemBytes = os.freemem();
    const totalKb = Math.round(totalMemBytes / 1024);
    const freeKb = Math.round(freeMemBytes / 1024);
    const usedKb = totalKb - freeKb;
    const memPercent = totalKb > 0 ? Math.round((usedKb / totalKb) * 100) : 0;

    const mem = {
      totalKb,
      freeKb,
      usedKb,
      percent: memPercent
    };

    const disks = this.getDisks();

    return {
      cpu,
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