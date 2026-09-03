"use strict";

const PROVIDERS = {
  openai: {
    id: "openai",
    name: "ChatGPT (OpenAI)",
    family: "paid",
    defaultModel: "gpt-4o-mini",
    endpoint: "https://api.openai.com/v1/chat/completions",
    buildUrl: () => "https://api.openai.com/v1/chat/completions",
    headers: (key) => ({ "Content-Type": "application/json", "Authorization": `Bearer ${key}` }),
    body: (model, messages) => ({
      model: model || "gpt-4o-mini",
      messages,
      temperature: 0.1,
      max_tokens: 900,
      response_format: { type: "json_object" }
    }),
    parse: (data) => data && data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : null
  },
  gemini: {
    id: "gemini",
    name: "Gemini (Google AI)",
    family: "paid",
    defaultModel: "gemini-2.0-flash",
    buildUrl: (key, model) => `https://generativelanguage.googleapis.com/v1beta/models/${model || "gemini-2.0-flash"}:generateContent?key=${key}`,
    headers: () => ({ "Content-Type": "application/json" }),
    body: (model, messages) => {
      const system = messages.find(m => m.role === "system");
      const user = messages.filter(m => m.role !== "system").map(m => m.content).join("\n\n");
      return {
        contents: [{ role: "user", parts: [{ text: (system ? system.content + "\n\n" : "") + user }] }],
        generationConfig: { responseMimeType: "application/json", temperature: 0.1, maxOutputTokens: 900 }
      };
    },
    parse: (data) => data && data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts ? data.candidates[0].content.parts[0].text : null
  },
  claude: {
    id: "claude",
    name: "Claude (Anthropic)",
    family: "paid",
    defaultModel: "claude-3-5-sonnet-20241022",
    buildUrl: () => "https://api.anthropic.com/v1/messages",
    headers: (key) => ({ "Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" }),
    body: (model, messages) => {
      const system = messages.find(m => m.role === "system");
      return {
        model: model || "claude-3-5-sonnet-20241022",
        max_tokens: 900,
        temperature: 0.1,
        system: system ? system.content : "",
        messages: messages.filter(m => m.role !== "system").map(m => ({ role: m.role, content: m.content }))
      };
    },
    parse: (data) => data && data.content && data.content[0] ? data.content[0].text : null
  },
  perplexity: {
    id: "perplexity",
    name: "Perplexity (Sonar)",
    family: "paid",
    defaultModel: "sonar",
    buildUrl: () => "https://api.perplexity.ai/chat/completions",
    headers: (key) => ({ "Content-Type": "application/json", "Authorization": `Bearer ${key}` }),
    body: (model, messages) => {
      const system = messages.find(m => m.role === "system");
      return {
        model: model || "sonar",
        max_tokens: 900,
        temperature: 0.2,
        messages: [
          { role: "system", content: system ? system.content : SYSTEM_PROMPT },
          ...messages.filter(m => m.role !== "system")
        ]
      };
    },
    parse: (data) => data && data.choices && data.choices[0] ? data.choices[0].message.content : null
  }
};

const SYSTEM_PROMPT = `You are an elite cybersecurity forensics analyst integrated into a Windows antivirus called Aegis AI.
You receive a THREAT REPORT describing a suspicious file, process, or network connection observed on the machine.
Your task: decide whether it is malicious, search your knowledge for information about this malware/virus family, and provide step-by-step remediation/solution guidance.
Respond ONLY with a strict JSON object (no markdown, no extra text) with EXACTLY this structure:
{
  "verdict": "malware" | "suspicious" | "benign" | "unknown",
  "confidence": <number 0..1>,
  "summary": "<explicacion detallada en espanol del tipo de virus o amenaza>",
  "solution": "<pasos concretos en espanol para desinfectar, aislar o solucionar la amenaza>",
  "recommendation": "quarantine" | "block" | "delete" | "allow" | "monitor",
  "reasons": ["<razon 1>", "<razon 2>", "<razon 3>"]
}
Rules:
- If multiple strong indicators of malware (obfuscation, known malicious hashes, credential theft, remote shell, crypto mining, persistence keys, real-time self-protection tools used maliciously), verdict must be "malware".
- If only weak/isolated signals, use "suspicious" and recommend "monitor".
- If legitimate well-known software (browsers, IDEs, Node.js, Python, Office), use "benign".
- The recommendation drives automatic actions (e.g. quarantine), so be conservative but assertive when evidence is clear.`;

function extractJson(text) {
  if (!text) return null;
  const cleaned = text.replace(/```json/gi, "").replace(/```/g, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1));
  } catch (e) {
    return null;
  }
}

function buildReport(threat, systemNote) {
  const lines = [];
  lines.push("THREAT REPORT AEGIS AI");
  lines.push("======================");
  if (threat.type === "file") {
    lines.push(`Tipo:      Archivo sospechoso`);
    lines.push(`Archivo:   ${threat.path || threat.name}`);
    lines.push(`Nombre:    ${threat.name}`);
    lines.push(`Tamano:    ${threat.size ? Math.round(threat.size / 1024) + " KB" : "desconocido"}`);
    if (threat.sha256) lines.push(`SHA256:    ${threat.sha256}`);
    if (threat.family) lines.push(`Familia:   ${threat.family}`);
    lines.push(`Sev.:      ${threat.severity}`);
    lines.push(`Motivo:    ${threat.description || threat.detail || "sin detalle"}`);
  } else if (threat.type === "process") {
    lines.push(`Tipo:      Proceso sospechoso`);
    lines.push(`Proceso:   ${threat.name} (PID ${threat.pid || "?"})`);
    if (threat.path) lines.push(`Ruta:      ${threat.path}`);
    if (threat.cmdline) lines.push(`CmdLine:   ${String(threat.cmdline).slice(0, 300)}`);
    if (threat.flags) {
      lines.push(`Indicadores:`);
      for (const f of (threat.flags || [])) lines.push(`  - [${f.risk}] ${f.label}: ${f.detail}`);
    }
  } else if (threat.type === "network") {
    lines.push(`Tipo:      Conexion de red sospechosa`);
    lines.push(`Proceso:   ${threat.processName || "?"} (PID ${threat.pid || "?"})`);
    lines.push(`Local:     ${threat.localAddress}:${threat.localPort}`);
    lines.push(`Remoto:    ${threat.remoteAddress}:${threat.remotePort}`);
    if (threat.riskReason) lines.push(`Motivo:    ${threat.riskReason}`);
  } else if (threat.type === "email") {
    lines.push(`Tipo:      Correo/adjunto sospechoso`);
    lines.push(`Archivo:   ${threat.name}`);
    lines.push(`Motivo:    ${threat.description}`);
  } else {
    lines.push(`Tipo:      ${threat.type}`);
    lines.push(`Desc.:     ${threat.description || threat.detail || ""}`);
  }
  lines.push("");
  if (threat.justDetected) lines.push(`Estado:    Detectado en tiempo real, el sistema de la maquina sigue Windows normal.`);
  lines.push(`Hora:      ${threat.time || new Date().toISOString()}`);
  return lines.join("\n");
}

class AIManager {
  providers() {
    return Object.values(PROVIDERS).map(p => ({ id: p.id, name: p.name, family: p.family, defaultModel: p.defaultModel }));
  }

  async url(cfg, provider) {
    return provider.buildUrl(cfg.aiKeys[provider.id], cfg.aiModel);
  }

  async call(provider, cfg, messages) {
    const key = (cfg.aiKeys || {})[provider.id];
    if (!key) throw new Error(`No hay API key configurada para ${provider.name}`);
    const url = provider.buildUrl(key, cfg.aiModel);
    const headers = provider.headers(key);
    const body = JSON.stringify(provider.body(cfg.aiModel, messages));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 45000);
    let res;
    try {
      res = await fetch(url, { method: "POST", headers, body, signal: controller.signal });
    } catch (e) {
      clearTimeout(timer);
      throw new Error(`Error de conexion con ${provider.name}: ${e.message}`);
    }
    clearTimeout(timer);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`API ${provider.name} respondio ${res.status}: ${text.slice(0, 300)}`);
    }
    const data = await res.json();
    return provider.parse(data);
  }

  async testConnection(cfg) {
    const provider = PROVIDERS[cfg.aiProvider];
    if (!provider) throw new Error("Proveedor de IA desconocido");
    const replies = await this.call(provider, cfg, [{ role: "user", content: "Responde unicamente con: {\"verdict\":\"benign\",\"confidence\":1,\"summary\":\"OK\",\"recommendation\":\"allow\",\"reasons\":[\"test\"]}" }]);
    return { ok: true, provider: provider.name, response: replies };
  }

  async analyze(cfg, threat, systemNote) {
    const provider = PROVIDERS[cfg.aiProvider];
    if (!provider) throw new Error("Proveedor de IA desconocido");
    const report = buildReport(threat, systemNote);
    let parsed = null;
    try {
      if (provider.id === "gemini") {
        parsed = extractJson(await this.call(provider, cfg, [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: report }]));
      } else {
        parsed = extractJson(await this.call(provider, cfg, [{ role: "system", content: SYSTEM_PROMPT }, { role: "user", content: report }]));
      }
    } catch (e) {
      throw e;
    }
    return { provider: provider.name, raw: parsed, report };
  }
}

module.exports = new AIManager();