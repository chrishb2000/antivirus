"use strict";
const { contextBridge, ipcRenderer } = require("electron");

const ALLOWED_CHANNELS = new Set([
  "app:info", "app:elevate", "dialog:pickFolder", "dialog:pickFile",
  "config:get", "config:set", "system:metrics", "processes:list",
  "network:connections", "scan:start", "scan:status", "scan:stop",
  "quarantine:list", "quarantine:restore", "quarantine:remove",
  "firewall:status", "firewall:set", "firewall:list", "firewall:add",
  "firewall:remove", "firewall:blockProgram", "firewall:blockIp",
  "ai:providers", "ai:test", "ai:analyzeFile", "threats:list",
  "threats:resolve", "threats:clear", "threats:quarantineThreat",
  "scheduler:list", "scheduler:functions", "scheduler:toggle",
  "scheduler:runNow", "scheduler:add", "scheduler:remove",
  "scheduler:history", "logs:list", "runtime:status"
]);

contextBridge.exposeInMainWorld("Aegis", {
  invoke: (channel, ...args) => {
    if (!ALLOWED_CHANNELS.has(channel)) {
      return Promise.reject(new Error(`Canal IPC no permitido: ${channel}`));
    }
    return ipcRenderer.invoke(channel, ...args);
  },
  on: (channel, callback) => {
    const listener = (event, payload) => callback(payload);
    ipcRenderer.on(channel, listener);
    return () => ipcRenderer.removeListener(channel, listener);
  },
  getVersion: () => process.versions.electron || "",
  platform: process.platform
});