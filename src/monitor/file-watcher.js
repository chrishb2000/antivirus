"use strict";
const path = require("path");
const chokidar = require("chokidar");

class FileWatcher {
  constructor(onEvent) {
    this.watcher = null;
    this.onEvent = onEvent;
    this.folders = [];
  }

  start(folders, onReady) {
    this.stop();
    if (!folders || folders.length === 0) return;
    this.folders = folders.slice();
    this.watcher = chokidar.watch(this.folders, {
      ignoreInitial: true,
      persistent: true,
      depth: 4,
      awaitWriteFinish: { stabilityThreshold: 1200, pollInterval: 300 },
      ignored: /node_modules|\.git[\\/]|data[\\/]quarantine/i
    });

    this.watcher.on("add", (filePath) => {
      this.onEvent({ type: "new-file", filePath: path.resolve(filePath) });
    });
    this.watcher.on("error", () => {});
    if (onReady) this.watcher.on("ready", () => onReady(this.folders));
  }

  stop() {
    if (this.watcher) {
      try { this.watcher.close(); } catch (e) { /* ignorar */ }
      this.watcher = null;
    }
  }
}

module.exports = FileWatcher;