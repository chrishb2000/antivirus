# Aegis AI Antivirus

**Antivirus inteligente de escritorio para Windows** que conecta con las principales IAs de pago (ChatGPT / OpenAI, Gemini, Claude y Perplexity) para vigilar el equipo en tiempo real, detectar descargas, intrusos, correos y documentos maliciosos, consultar inteligencia de amenazas en Internet y ejecutar acciones automáticas: poner en cuarentena archivos maliciosos o bloquear la conexión de un intruso.

> Conexión con IA: cuando detecta algo sospechoso, **Aegis envía el informe forense completo a tu IA de pago** (con tu propia API key), que devuelve un veredicto estructurado (malware / sospechoso / benigno) con recomendación de acción (cuarentena, bloqueo, eliminación o monitorización). En la pestaña **IA de análisis** hay un botón **"Probar conexión con la IA"** que valida tu API key antes de activarse.

---

## 🆓 Sin suscripción. Sin publicidad. Sin costos ocultos

La mayoría de antivirus te encierran detrás de una **suscripción anual** y te llenan la pantalla de **anuncios y "ofertas" para comprar más**.

Con **Aegis AI Antivirus** eso no ocurre:

| Beneficio | Detalle |
| --- | --- |
| **100% gratis** | Nada que comprar, renovar ni recordar de pago |
| **Cero publicidad** | Sin banners, sin ventanas que te piden "actualizar a Pro", sin molestarte |
| **Sin suscripción a Aegis** | El antivirus es tuyo para siempre |
| **Solo pagas tu IA (si quieres)** | Usa tu propia API key de OpenAI, Gemini, Claude o Perplexity solo si decides conectar la IA. Sin key, el antivirus funciona igual con firmas, comportamiento y VirusTotal |
| **Tus datos son tuyos** | Configuración y cuarentena se guardan localmente, nunca se suben a ningún servidor de Aegis |

Instálalo, conecta tu IA si lo deseas y olvídate: **protección inteligente, honesta y sin letra pequeña**.

---

## Instalación en cualquier PC (Windows)

Puedes usar Aegis de **tres formas**:

| Forma | Cómo | Ideal para |
| --- | --- | --- |
| **1. Instalador** | Ejecutar `Aegis AI Antivirus Setup 1.0.0.exe` (asistente, permite elegir carpeta) | Instalación permanente con acceso directo |
| **2. Portable** | Ejecutar `Aegis AI Antivirus 1.0.0.exe` (sin instalar nada) | Llevarlo en un USB |
| **3. Desde el código fuente** | Doble clic en `run-antivirus.bat` (instala dependencias solo la 1ª vez) | Desarrolladores |

> ✅ Tras instalarse, **Aegis vive en la bandeja del sistema** (junto al reloj, volumen y conexión wifi): su escudo permanece vigilando aunque cierres la ventana. Clic en el icono para abrir el panel; clic derecho para escaneo rápido, cuarentena, activar/desactivar la protección o salir.

> 🔁 Si haces clic en la "X" la ventana se oculta a la bandeja (no se cierra). Para salir del todo, usa "Salir" en el menú de la bandeja.

### Reconstruir el instalador (paquete de distribución)

```bash
npm install
npm run dist
```

Genera en `dist/`:
- `Aegis AI Antivirus Setup 1.0.0.exe` → instalador NSIS
- `Aegis AI Antivirus 1.0.0.exe` → versión portable

Los datos (configuración, cuarentena, historial) se guardan automáticamente:
- Instalado → `%APPDATA%\aegis-ai-antivirus\data`
- Portable → carpeta `data` junto al `.exe`

### Requisitos del equipo destino

- Windows 10 / 11 (64 bits).
- **No necesita** que el ordenador tenga Node.js instalado: el instalador incluye todo.

---

## Funcionalidades

| Módulo | Qué hace |
| --- | --- |
| **Panel principal** | Estado de protección, CPU/RAM/Procesos/Conexiones en vivo, estado de discos, últimas alertas |
| **Protección en tiempo real** | Vigila procesos nuevos, ejecutables en Temp/Startup, PowerShell ofuscado, mineros, keyloggers, RATs y conexiones de red a puertos de alto riesgo (4444, 1337, 31337, 6667...) |
| **Escáner** | Rápido (Descargas, Escritorio, Temp), Completo (todo el disco C:) o por carpeta personalizada. Motores: firmas locales + hash + análisis de comportamiento + **VirusTotal** (más de 70 motores) + IA |
| **Análisis de descargas y correo** | Vigila automáticamente la carpeta de Descargas. Detecta adjuntos ejecutables en correos (`.eml`, `.msg`) y macros de Office |
| **Cuarentena** | Aísla archivos maliciosos, restáuralos o elimínalos |
| **Firewall y puertos** | Estado del firewall de Windows, activar/desactivar, **abrir o bloquear puertos**, bloquear programas o IPs concretas por reglas propias `AEGIS` |
| **IA de análisis** | Conecta OpenAI, Gemini, Claude o Perplexity. Analiza cualquier archivo sospechoso y muestra veredicto, confianza, motivos y recomendación |
| **Automatización** | Programador de tareas de mantenimiento: escaneo rápido/completo, limpieza de temporales, auditorías de red/arranque/firewall, limpieza de cuarentena, backup de config, integridad del sistema y reporte semanal. Activa/desactiva cada tarea, "Ejecutar ahora" o crea tareas personalizadas con expresión cron o intervalo |
| **Ajustes** | **Excepciones** (carpetas excluidas), carpetas vigiladas, cuarentena/bloqueo automático, notificaciones, clave VirusTotal, permisos de administrador |
| **Bandeja del sistema** | Icono de escudo junto al volumen/wifi: menú con escaneo rápido, cuarentena, protección on/off, configurar IA y salir. Se oculta a la bandeja al pulsar "X" |
| **Estética** | **Tema claro y tema oscuro** (interruptor ☾/☀ en la barra superior), ventana maximizada, sin menús nativos |

## Decisiones automáticas de la IA

Cuando la protección en tiempo real detecta una amenaza y la IA está conectada:

- Si la IA responde **malware** y la cuarentena automática está activada → el archivo se aísla en cuarentena.
- Si la IA responde **block** en una conexión de red → se crea una regla de firewall para cortar la conexión del intruso (bloqueo del programa o de la IP).
- Todo queda registrado en el historial de amenazas con el veredicto de la IA.

---

## 📋 Prerrequisitos de Sistema

| Requisito | Versión mínima | Descarga |
| --- | --- | --- |
| **Windows** | 10 / 11 (32 o 64 bits) | — |
| **Node.js** | 18 LTS o superior | https://nodejs.org/ (descargar LTS e instalar opciones por defecto) |

No necesita Python. Todo se ejecuta con Node.js + Electron.

### Claves API (opcionales pero recomendadas para el análisis con IA)

Son **tus propias claves de pago/free** (cada servicio tiene su panel de claves):

| IA | Dónde obtener la clave |
| --- | --- |
| **ChatGPT (OpenAI)** | https://platform.openai.com/api-keys |
| **Gemini (Google)** | https://aistudio.google.com/apikey |
| **Claude (Anthropic)** | https://console.anthropic.com/ |
| **Perplexity** | https://www.perplexity.ai/settings/api |
| **VirusTotal** (opcional, gratis) | https://www.virustotal.com/gui/join-us |

> ⚠️ Las claves se guardan localmente en `data\config.json`. Nunca compartas tu API key.

---

## Cómo usar (1 clic)

1. Descarga o clona el proyecto en tu PC.
2. Doble clic en **`run-antivirus.bat`**.
3. La primera vez instalará las dependencias automáticamente (necesita Internet).
4. **Para usar Firewall, abrir/bloquear puertos y bloquear conexiones**: pulsa clic derecho sobre `run-antivirus.bat` → **"Ejecutar como administrador"**.
5. En la barra superior tienes el **interruptor ☾/☀** para alternar entre **tema claro y tema oscuro**.

### Ejecución manual (desarrolladores)

```bash
npm install
npm start
```

---

## Arquitectura del proyecto

```
antivirus/
├── run-antivirus.bat        → Instalador + lanzador de 1 clic (ASCII plano)
├── main.js                  → Proceso principal Electron (IPC, motor, acciones)
├── preload.js               → Puente seguro (contextBridge)
├── src/
│   ├── monitor/             → Sistema, procesos, red, archivos, tiempo real
│   ├── engine/              → Firmas, comportamiento, escáner, cuarentena
│   ├── ai/                  → Gestor multi-IA (OpenAI, Gemini, Claude, Perplexity)
│   ├── network/             → Firewall (netsh) y bloqueo de IPs/programas
│   ├── services/            → Config, logs, historial de amenazas, scheduler (automatización)
│   └── utils/               → PowerShell, hashing, permisos admin
├── renderer/                → Interfaz (HTML/CSS/JS) con tema claro y oscuro
└── data/                    → Config, cuarentena, historial (se crea al primer uso)
```

## Notas de seguridad

- Aegis funciona como capa **complementaria** a Windows Defender (no reemplaza el antivirus nativo de Microsoft).
- Su "truco" diferencial es la **interpretación de IA**: no solo firma conocida, sino análisis del comportamiento y reputación en Internet.
- Para acceso completo al firewall, ejecuta el `.bat` **como administrador**.
- Si un archivo está en uso por Windows no podrá aislarse en ese momento; se registrará la alerta igualmente.

---

## Autor y apoyo

Desarrollado por [Christian Freelance](https://christian-freelance.us/).

Si el proyecto te resulta útil, puedes
[invitarme a un café mediante PayPal](https://www.paypal.com/donate/?hosted_button_id=YC6YAWBQ7HNSS).