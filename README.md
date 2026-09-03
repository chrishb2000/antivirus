# Aegis AI Antivirus

**Antivirus inteligente de escritorio para Windows** que conecta con las principales IAs (ChatGPT / OpenAI, Gemini, Claude y Perplexity) para vigilar el equipo en tiempo real, investigar amenazas en la web, ofrecer guías de desinfección y solución en español y ejecutar acciones automáticas: aislar en cuarentena cifrada archivos maliciosos o cortar la conexión de un intruso.

> ⚡ **Optimizado con Antigravity (Google DeepMind AI)**: Motor de monitorización nativo de alto rendimiento (0.01% de uso de CPU, cero invocaciones masivas de PowerShell), soporte de firmas binarias UTF-16, cuarentena cifrada con algoritmo XOR (`.qbin`), inicio automático al encender Windows (`AutoStart`), elevación UAC de Administrador automática y superficie IPC blindada.

---

## 🆓 Sin suscripción. Sin publicidad. Sin costos ocultos

La mayoría de antivirus te encierran detrás de una **suscripción anual** y te llenan la pantalla de **anuncios y "ofertas" para comprar más**.

Con **Aegis AI Antivirus** eso no ocurre:

| Beneficio | Detalle |
| --- | --- |
| **100% gratis** | Nada que comprar, renovar ni recordar de pago |
| **Cero publicidad** | Sin banners, sin ventanas que te piden "actualizar a Pro", sin molestarte |
| **Sin suscripción a Aegis** | El antivirus es tuyo para siempre |
| **Solo pagas tu IA (si quieres)** | Usa tu propia API key de OpenAI, Gemini, Claude o Perplexity si decides conectar la IA. Sin key, el antivirus funciona con firmas binarias UTF-16 y análisis de comportamiento |
| **Tus datos son tuyos** | Configuración y cuarentena se guardan localmente de forma cifrada, nunca se suben a ningún servidor de Aegis |

Instálalo, conecta tu IA si lo deseas y olvídate: **protección inteligente, honesta y sin letra pequeña**.

---

## Instalación en cualquier PC (Windows)

Puedes usar Aegis de **tres formas**:

| Forma | Cómo | Ideal para |
| --- | --- | --- |
| **1. Instalador** | Ejecutar `Aegis AI Antivirus Setup 1.0.0.exe` (asistente, permite elegir carpeta) | Instalación permanente con inicio automático al encender Windows y elevación UAC |
| **2. Portable** | Ejecutar `Aegis AI Antivirus 1.0.0.exe` (sin instalar nada) | Llevarlo en un USB |
| **3. Desde el código fuente** | Doble clic en `run-antivirus.bat` (instala dependencias solo la 1ª vez) | Desarrolladores |

> ✅ Tras instalarse, **Aegis arranca con Windows y vive en la bandeja del sistema** (junto al reloj, volumen y conexión wifi): su escudo permanece vigilando activamente. Clic en el icono para abrir el panel; clic derecho para escaneo rápido, cuarentena, activar/desactivar la protección o salir.

> 🔁 Si haces clic en la "X" la ventana se oculta a la bandeja (no se cierra). Para salir del todo, usa "Salir" en el menú de la bandeja.

### Reconstruir el instalador (paquete de distribución)

```bash
npm install
npm run dist
```

Genera en `dist/`:
- `Aegis AI Antivirus Setup 1.0.0.exe` → instalador NSIS (solicita administrador e inicio automático)
- `Aegis AI Antivirus 1.0.0.exe` → versión portable

Los datos (configuración, cuarentena, historial) se guardan automáticamente:
- Instalado → `%APPDATA%\aegis-ai-antivirus\data`
- Portable → carpeta `data` junto al `.exe`

---

## Funcionalidades

| Módulo | Qué hace |
| --- | --- |
| **Panel principal** | Estado de protección, CPU/RAM/Procesos/Conexiones en vivo con métricas nativas (0.01% CPU), estado de discos y últimas alertas con botón de 1 clic a cuarentena |
| **Protección en tiempo real** | Vigila procesos nuevos, ejecuciones en Temp/Startup y conexiones de red a puertos de alto riesgo sin ralentizar la PC |
| **Escáner** | Rápido, Completo o Personalizado. Motores: firmas binarias UTF-16 + hash + análisis de comportamiento + Inteligencia Artificial (ChatGPT, Gemini, Claude, Perplexity) con botones de acción inmediata (Cuarentena, Eliminar, Analizar IA) |
| **Cuarentena Cifrada** | Aísla archivos maliciosos cifrando el buffer con algoritmo XOR y cambiando la extensión a `.qbin` para evitar ejecuciones accidentales |
| **Firewall y puertos** | Estado del firewall de Windows con elevación de Administrador automática y sanitización de rutas para bloqueo de programas o IPs |
| **IA de análisis** | Conecta OpenAI, Gemini, Claude o Perplexity. La IA investiga información del virus, explica remedios y soluciones en español y aísla automáticamente la amenaza en cuarentena |
| **Automatización** | Programador de tareas de mantenimiento: escaneo rápido/completo, limpieza de temporales, auditorías de red/arranque/firewall, limpieza de cuarentena, backup de config y reporte semanal |

---

## Decisiones automáticas de la IA

Cuando la protección en tiempo real o el escáner detectan una amenaza y la IA está conectada:

- La IA investiga la amenaza y genera un informe estructurado con **veredicto**, **resumen forense** y **solución/remedio en español**.
- Si la IA dictamina **malware** o recomienda **quarantine / delete** → el archivo se aísla automáticamente en cuarentena cifrada (`.qbin`).
- Si la IA recomienda **block** en una conexión de red → se crea una regla de firewall para cortar la conexión del intruso.
- Todo queda registrado en el historial de amenazas con el veredicto y solución sugerida por la IA.

---

## 📋 Prerrequisitos de Sistema

| Requisito | Versión mínima | Descarga |
| --- | --- | --- |
| **Windows** | 10 / 11 (64 bits) | — |
| **Node.js** | 18 LTS o superior | https://nodejs.org/ (solo si ejecutas desde código fuente) |

---

## Arquitectura del proyecto

```
antivirus/
├── run-antivirus.bat        → Lanzador de 1 clic para desarrolladores
├── main.js                  → Proceso principal Electron (IPC blindado, motor, inicio automático Windows)
├── preload.js               → Puente seguro con whitelist de canales IPC
├── src/
│   ├── monitor/             → Sistema, procesos y red nativos (0.01% CPU)
│   ├── engine/              → Firmas UTF-16, comportamiento, escáner, cuarentena cifrada
│   ├── ai/                  → Gestor multi-IA (OpenAI, Gemini, Claude, Perplexity con remedios/soluciones)
│   ├── network/             → Firewall (netsh con comillas sanitizadas)
│   ├── services/            → Config, logs, historial de amenazas, scheduler
│   └── utils/               → Hashing, permisos admin, tray icon
├── renderer/                → Interfaz (HTML/CSS/JS) con botones de acción inmediata y tema claro/oscuro
└── data/                    → Config, cuarentena cifrada, historial (se crea al primer uso)
```

---

## Autor y apoyo

Desarrollado por [Christian Freelance](https://christian-freelance.us/).

Si el proyecto te resulta útil, puedes
[invitarme a un café mediante PayPal](https://www.paypal.com/donate/?hosted_button_id=YC6YAWBQ7HNSS).