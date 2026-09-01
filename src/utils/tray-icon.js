"use strict";
/**
 * Icono de bandeja del sistema (shield Aegis) embebido como base64.
 * No depende de archivos de imagen externos, funciona en modo dev y empaquetado.
 */
const { nativeImage } = require("electron");

const TRAY_B64 = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAA/ElEQVR42u3O7YcCURTH8f7yiEREREQiIiIisUTEsmTpT2g3Pe+u3Z72wW7rl2LGPfc2TWfuaeZNH75v5hxzbix2c4n+PwJn5XEHsdh6fxCP5eEX4rHc/0A8lu43xGPpfEE8lvYnxGO528ImB/nO0togaCoyY2muESQdmbM0VuBmHNd3WOpLcDKOn9pjqX1Ajfz8zMxr5xhL9R1OJw+cmaszElvlDU7GEZ/vRoGVX+HkR90lWSm9QM3zuLZHslZcQM04rs1JYgpzqJEHaDM3cfkZLu5qclP4dnXZCTwLTWYMo1ClRzAKXWoIt0gkn+EWmcRThMcP4oOIH2BpD+tiykov9VHDAAAAAElFTkSuQmCC";

let cached = null;

function trayImage() {
  if (!cached) {
    cached = nativeImage.createFromDataURL("data:image/png;base64," + TRAY_B64);
  }
  return cached;
}

module.exports = { trayImage };