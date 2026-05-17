// ════════════════════════════════════════════════════════
//  app.js — NetAI v2.1
//  Nuevas funciones:
//    • Historial de chats (crear, cargar, borrar)
//    • Adjuntos en chat (imagen, PDF, texto, vídeo, audio, CSV, JSON)
//    • Contexto completo de la BD de dispositivos en el chat
//    • IA local con Ollama (llama3.2:1b) — 100% offline
// ════════════════════════════════════════════════════════

const OLLAMA_URL   = "http://localhost:11434";
const OLLAMA_MODEL = "llama3.2:1b";

// ── REGLAS CIS ──────────────────────────────────────────
const RULES = [
  { id:"R001", severity:"HIGH",   title:"Contraseña en texto plano (enable password)", pattern:/\benable password\b/i, description:"Se detectó 'enable password' en lugar de 'enable secret'. Las contraseñas en texto plano son legibles directamente en el archivo de configuración.", recommendation:"Reemplazar con 'enable secret <password>' que usa hash MD5/SHA." },
  { id:"R002", severity:"HIGH",   title:"Cifrado de contraseñas deshabilitado", pattern:/no service password-encryption/i, description:"El comando 'no service password-encryption' expone todas las contraseñas locales en texto claro.", recommendation:"Ejecutar 'service password-encryption' para cifrar contraseñas con tipo 7." },
  { id:"R003", severity:"HIGH",   title:"Telnet habilitado en líneas VTY", pattern:/transport input telnet/i, description:"Telnet transmite datos sin cifrado. Vector de ataque man-in-the-middle activo.", recommendation:"Cambiar a 'transport input ssh' y configurar SSH versión 2." },
  { id:"R004", severity:"HIGH",   title:"Líneas VTY sin contraseña", pattern:/line vty[\s\S]{0,200}?no password/i, description:"Acceso remoto sin autenticación. Cualquiera en la red puede conectarse al dispositivo.", recommendation:"Configurar 'password' y 'login' en todas las líneas VTY, o usar AAA." },
  { id:"R005", severity:"HIGH",   title:"SNMP con comunidades por defecto", pattern:/snmp-server community (public|private)/i, description:"Comunidades SNMP 'public' y 'private' permiten lectura/escritura remota no autorizada.", recommendation:"Eliminar con 'no snmp-server community public' y usar SNMPv3." },
  { id:"R006", severity:"MEDIUM", title:"SSH versión 2 no configurado", pattern:null, description:"La ausencia de SSH v2 obliga a usar protocolos inseguros.", recommendation:"Configurar 'ip ssh version 2' y 'crypto key generate rsa modulus 2048'." },
  { id:"R007", severity:"MEDIUM", title:"Dirección IP con octeto fuera de rango", pattern:null, description:"Se detectó una IP con octetos fuera del rango válido (0-255).", recommendation:"Verificar y corregir la dirección IP del interfaz afectado." },
  { id:"R008", severity:"MEDIUM", title:"VLAN 1 como VLAN de acceso (riesgo hopping)", pattern:/switchport access vlan 1\b/i, description:"Usar VLAN 1 facilita ataques de VLAN hopping.", recommendation:"Crear VLANs dedicadas y mover puertos fuera de VLAN 1." },
  { id:"R009", severity:"LOW",    title:"Usuario con contraseña tipo 0 (texto plano)", pattern:/username\s+\S+\s+password\s+0\s+/i, description:"Contraseña visible directamente en 'show running-config'.", recommendation:"Usar 'username <user> secret <pass>' para hash SHA-256." },
  { id:"R010", severity:"LOW",    title:"Trunk permite todas las VLANs", pattern:/switchport trunk allowed vlan all/i, description:"Aumenta la superficie de ataque innecesariamente.", recommendation:"Restringir con 'switchport trunk allowed vlan <lista>'." }
];

function analyzeDevice(device) {
  const config = device.config;
  const findings = [];
  for (const rule of RULES) {
    let triggered = false;
    if (rule.id === "R006") triggered = !/ip ssh version 2/i.test(config);
    else if (rule.id === "R007") {
      const matches = [...config.matchAll(/ip address ((?:\d{1,3}\.){3}\d{1,3})/gi)];
      triggered = matches.some(m => m[1].split('.').some(o => parseInt(o) > 255));
    } else triggered = rule.pattern.test(config);
    if (triggered) findings.push({ ...rule });
  }
  const highCount   = findings.filter(f => f.severity === "HIGH").length;
  const mediumCount = findings.filter(f => f.severity === "MEDIUM").length;
  const lowCount    = findings.filter(f => f.severity === "LOW").length;
  let riskLevel = "LOW";
  if (highCount >= 1) riskLevel = "HIGH";
  else if (mediumCount >= 2) riskLevel = "MEDIUM";
  return { findings, riskLevel, highCount, mediumCount, lowCount };
}

// ── ESTADO GLOBAL ─────────────────────────────────────────────────────────
let devices        = [];
let activeDeviceId = null;
let ollamaReady    = false;

// ── HISTORIAL DE CHATS ────────────────────────────────────────────────────
// Estructura: [{ id, title, messages:[{role,content,attachments?:[]}], createdAt }]
let chatSessions    = [];
let activeChatId    = null;
let pendingAttachments = [];  // archivos listos para enviar

// ── SYSTEM PROMPT (se actualiza con contexto BD) ──────────────────────────
let systemPrompt = buildSystemPrompt(null);

function buildSystemPrompt(activeDevice) {
  let base = `Eres NetAI, asistente experto en redes Cisco, seguridad de infraestructura y tecnologías de red.
También puedes responder preguntas generales: viajes, ciencia, programación, etc.
Responde siempre en español, de forma concisa y técnicamente precisa.
Cuando el usuario adjunte imágenes o documentos, analízalos en detalle.`;

  // Incluir inventario completo de dispositivos si existe
  if (devices.length > 0) {
    const dbContext = devices.map(d => {
      const { findings, riskLevel } = d.analysis;
      const findingsList = findings.length === 0
        ? "  Sin vulnerabilidades detectadas."
        : findings.map(f => `  - [${f.severity}] ${f.id}: ${f.title}`).join("\n");
      return `Dispositivo: ${d.name}
  Tipo: ${d.type}
  IP: ${d.ip}
  Ubicación: ${d.location}
  Riesgo: ${riskLevel}
  Hallazgos:
${findingsList}`;
    }).join("\n\n");

    base += `\n\nBASE DE DATOS DE RED CARGADA (${devices.length} dispositivos):\n${dbContext}`;
    base += `\n\nEl usuario puede preguntarte sobre cualquier dispositivo de esta base de datos. Usa esta información para responder con precisión.`;
  }

  if (activeDevice) {
    const { findings, riskLevel } = activeDevice.analysis;
    const findingsSummary = findings.length === 0
      ? "Sin vulnerabilidades."
      : findings.map(f => `- [${f.severity}] ${f.title}: ${f.recommendation}`).join("\n");
    base += `\n\nDISPOSITIVO ACTIVO EN PANTALLA: ${activeDevice.name} (${activeDevice.type}) — IP: ${activeDevice.ip} — Riesgo: ${riskLevel}\nHallazgos:\n${findingsSummary}`;
  }

  return base;
}

// ── RELOJ ─────────────────────────────────────────────────────────────────
setInterval(() => {
  const el = document.getElementById("clock");
  if (el) el.textContent = new Date().toLocaleTimeString("es-MX", { hour12: false });
}, 1000);

// ── TERMINAL LOG ──────────────────────────────────────────────────────────
function log(msg, type = "info") {
  const terminal = document.getElementById("terminal");
  const now = new Date().toLocaleTimeString("es-MX", { hour12: false });
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = `<span class="ts">[${now}]</span><span class="msg-${type}">${msg}</span>`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// ── CARGAR INVENTARIO ─────────────────────────────────────────────────────
function loadDevices(db) {
  devices = db.devices.map(d => ({ ...d, analysis: analyzeDevice(d) }));
  document.getElementById("deviceCount").textContent = devices.length;
  renderDeviceList();
  // Actualizar system prompt con la BD completa
  systemPrompt = buildSystemPrompt(null);
  log(`Inventario cargado: ${devices.length} dispositivos. IA puede responder preguntas sobre la BD.`, "ok");
  devices.forEach(d => {
    const { riskLevel, findings } = d.analysis;
    log(`  ${d.name} → Riesgo: ${riskLevel} | ${findings.length} hallazgo(s)`,
      riskLevel === "HIGH" ? "err" : riskLevel === "MEDIUM" ? "warn" : "ok");
  });
}

// ── RENDER LISTA DE DISPOSITIVOS ──────────────────────────────────────────
function getSeverityClass(level) {
  return { HIGH: "danger", MEDIUM: "warn", LOW: "safe" }[level] || "idle";
}

function renderDeviceList() {
  const list = document.getElementById("deviceList");
  list.innerHTML = "";
  devices.forEach((device, i) => {
    const { riskLevel, findings } = device.analysis;
    const cls = getSeverityClass(riskLevel);
    const item = document.createElement("div");
    item.className = `device-item${activeDeviceId === device.id ? " active" : ""}`;
    item.style.animationDelay = `${i * 60}ms`;
    item.innerHTML = `
      <div class="device-badge badge-${cls}"></div>
      <div class="device-info">
        <div class="device-name">${device.name}</div>
        <div class="device-type">${device.type}</div>
      </div>
      <div class="device-score score-${cls}">${findings.length}</div>
    `;
    item.addEventListener("click", () => selectDevice(device.id));
    list.appendChild(item);
  });
}

function selectDevice(id) {
  activeDeviceId = id;
  renderDeviceList();
  const device = devices.find(d => d.id === id);
  if (!device) return;
  const { findings, riskLevel, highCount, mediumCount, lowCount } = device.analysis;
  const riskColors = { HIGH: "var(--danger)", MEDIUM: "var(--warn)", LOW: "var(--safe)" };
  const riskLabels = { HIGH: "🔴 RIESGO ALTO", MEDIUM: "🟡 ADVERTENCIA", LOW: "🟢 SEGURO" };

  document.getElementById("emptyState").style.display = "none";
  const panel = document.getElementById("reportPanel");
  panel.style.display = "block";

  let configHtml = device.config
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/(enable password[^\n]*)/g,         '<span class="highlight-danger">$1</span>')
    .replace(/(no service password-encryption)/g, '<span class="highlight-danger">$1</span>')
    .replace(/(transport input telnet)/g,         '<span class="highlight-danger">$1</span>')
    .replace(/(snmp-server community (?:public|private)[^\n]*)/gi,'<span class="highlight-danger">$1</span>')
    .replace(/(no password)/g,                   '<span class="highlight-danger">$1</span>')
    .replace(/(enable secret[^\n]*)/g,           '<span class="highlight-safe">$1</span>')
    .replace(/(service password-encryption)/g,   '<span class="highlight-safe">$1</span>')
    .replace(/(ip ssh version 2)/g,              '<span class="highlight-safe">$1</span>')
    .replace(/(transport input ssh)/g,           '<span class="highlight-safe">$1</span>')
    .replace(/(no snmp-server\b)/g,              '<span class="highlight-safe">$1</span>');

  const findingsHtml = findings.length === 0
    ? `<div class="no-findings"><div class="icon">✅</div>No se detectaron vulnerabilidades.</div>`
    : findings.map((f, i) => `
        <div class="finding sev-${f.severity}" style="animation-delay:${i*80}ms">
          <div class="finding-top">
            <span class="sev-tag sev-${f.severity}">${f.severity}</span>
            <span class="finding-title">[${f.id}] ${f.title}</span>
          </div>
          <div class="finding-desc">${f.description}</div>
          <div class="finding-rec">${f.recommendation}</div>
        </div>`).join("");

  panel.innerHTML = `
    <div class="report-header">
      <div>
        <div class="report-device-name" style="color:${riskColors[riskLevel]}">${device.name}</div>
        <div class="report-device-meta">${device.type} &nbsp;·&nbsp; ${device.ip} &nbsp;·&nbsp; ${device.location}</div>
      </div>
      <div class="risk-badge risk-${riskLevel}">${riskLabels[riskLevel]}</div>
    </div>
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-label">Críticos</div>
        <div class="stat-value" style="color:var(--danger)">${highCount}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Advertencias</div>
        <div class="stat-value" style="color:var(--warn)">${mediumCount}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Informativos</div>
        <div class="stat-value" style="color:var(--safe)">${lowCount}</div>
      </div>
    </div>
    <div class="findings-title">Hallazgos de Seguridad (${findings.length})</div>
    ${findingsHtml}
    <div class="config-section">
      <div class="findings-title">Running-Config (análisis)</div>
      <div class="config-block">${configHtml}</div>
    </div>
  `;

  // Actualizar contexto en system prompt
  systemPrompt = buildSystemPrompt(device);
  log(`Analizando ${device.name}... ${findings.length} hallazgo(s). Contexto IA actualizado.`,
    riskLevel === "HIGH" ? "err" : riskLevel === "MEDIUM" ? "warn" : "ok");
  appendChatMsg("system-note", `📡 Dispositivo activo: ${device.name}`);
}

// ════════════════════════════════════════════════════════
//  HISTORIAL DE CHATS
// ════════════════════════════════════════════════════════

function createNewChat() {
  const id    = "chat_" + Date.now();
  const title = "Chat " + new Date().toLocaleTimeString("es-MX", { hour12:false, hour:"2-digit", minute:"2-digit" });
  const session = { id, title, messages: [], createdAt: Date.now() };
  chatSessions.unshift(session);
  activeChatId = id;
  renderChatHistory();
  clearChatUI();
  document.getElementById("chatTitleDisplay").textContent = title;
  log(`Nuevo chat creado: ${title}`, "info");
  return session;
}

function getActiveSession() {
  return chatSessions.find(s => s.id === activeChatId);
}

function switchToChat(id) {
  activeChatId = id;
  renderChatHistory();
  const session = getActiveSession();
  if (!session) return;
  document.getElementById("chatTitleDisplay").textContent = session.title;
  clearChatUI();
  // Reproducir mensajes guardados
  session.messages.forEach(m => {
    if (m.role === "system-note") {
      appendChatMsgUI("system-note", m.content);
    } else {
      appendChatMsgUI(m.role, m.content, m.attachments || []);
    }
  });
}

function deleteChat(id) {
  chatSessions = chatSessions.filter(s => s.id !== id);
  if (activeChatId === id) {
    if (chatSessions.length > 0) {
      switchToChat(chatSessions[0].id);
    } else {
      activeChatId = null;
      clearChatUI();
      document.getElementById("chatTitleDisplay").textContent = "NetAI Chat";
    }
  }
  renderChatHistory();
  log("Chat eliminado.", "warn");
}

function updateChatTitle(session, firstMessage) {
  // Genera título a partir del primer mensaje del usuario
  const words = firstMessage.replace(/[<>]/g,"").trim().split(/\s+/).slice(0,5);
  session.title = words.join(" ") + (firstMessage.split(/\s+/).length > 5 ? "…" : "");
  renderChatHistory();
  document.getElementById("chatTitleDisplay").textContent = session.title;
}

function renderChatHistory() {
  const list = document.getElementById("chatHistoryList");
  if (chatSessions.length === 0) {
    list.innerHTML = '<div class="ch-empty">No hay chats aún.<br>Inicia una conversación.</div>';
    return;
  }
  list.innerHTML = "";
  chatSessions.forEach((s, i) => {
    const item = document.createElement("div");
    item.className = `ch-item${s.id === activeChatId ? " ch-active" : ""}`;
    item.style.animationDelay = `${i * 40}ms`;
    const msgCount = s.messages.filter(m => m.role === "user").length;
    item.innerHTML = `
      <div class="ch-item-title">${escHtml(s.title)}</div>
      <div class="ch-item-meta">
        <span>${new Date(s.createdAt).toLocaleTimeString("es-MX",{hour:"2-digit",minute:"2-digit",hour12:false})}</span>
        <span class="ch-item-count">${msgCount} msgs</span>
      </div>
      <button class="ch-del" title="Eliminar chat">✕</button>
    `;
    item.querySelector(".ch-del").addEventListener("click", e => { e.stopPropagation(); deleteChat(s.id); });
    item.addEventListener("click", () => switchToChat(s.id));
    list.appendChild(item);
  });
}

function clearChatUI() {
  const box = document.getElementById("chatMessages");
  box.innerHTML = `<div class="chat-msg chat-assistant">
    <span class="chat-bubble">Chat iniciado. ${ollamaReady ? "Modelo listo, escribe tu pregunta." : "Recuerda cargar el modelo con 🤖 Cargar IA."}</span>
  </div>`;
}

// ════════════════════════════════════════════════════════
//  ADJUNTOS EN CHAT
// ════════════════════════════════════════════════════════

// Estructura de adjunto: { name, type, dataURL?, textContent?, mimeType }
async function readFileAsAttachment(file) {
  return new Promise((resolve) => {
    const mimeType = file.type || "application/octet-stream";
    const name     = file.name;

    if (mimeType.startsWith("image/")) {
      const reader = new FileReader();
      reader.onload = e => resolve({ name, mimeType, dataURL: e.target.result, kind:"image" });
      reader.readAsDataURL(file);
    } else if (mimeType.startsWith("video/") || mimeType.startsWith("audio/")) {
      // Video/audio: solo mencionamos metadatos, no enviamos binario al modelo
      resolve({ name, mimeType, kind:"media", size: file.size });
    } else {
      // PDF, txt, cfg, json, csv, md → leer como texto
      const reader = new FileReader();
      reader.onload = e => resolve({ name, mimeType, textContent: e.target.result, kind:"text" });
      reader.onerror = () => resolve({ name, mimeType, kind:"text", textContent:"[No se pudo leer el archivo]" });
      reader.readAsText(file);
    }
  });
}

function renderAttachmentsPreview() {
  const bar = document.getElementById("attachmentsPreview");
  if (pendingAttachments.length === 0) { bar.style.display="none"; return; }
  bar.style.display = "flex";
  bar.innerHTML = "";
  pendingAttachments.forEach((att, i) => {
    const chip = document.createElement("div");
    chip.className = "att-chip";
    const icon = att.kind === "image" ? `<img src="${att.dataURL}" alt="">` : (att.kind === "media" ? "🎬" : "📄");
    chip.innerHTML = `${typeof icon === "string" && icon.startsWith("<img") ? icon : `<span>${icon}</span>`}
      <span class="att-chip-name">${escHtml(att.name)}</span>
      <button class="att-chip-del" data-i="${i}">✕</button>`;
    chip.querySelector(".att-chip-del").addEventListener("click", () => {
      pendingAttachments.splice(i, 1);
      renderAttachmentsPreview();
    });
    bar.appendChild(chip);
  });
}

// Construye el contexto de adjuntos para incluir en el mensaje al modelo
function buildAttachmentContext(attachments) {
  if (!attachments || attachments.length === 0) return "";
  let ctx = "\n\n[ADJUNTOS ENVIADOS POR EL USUARIO]\n";
  attachments.forEach(att => {
    if (att.kind === "image") {
      ctx += `• Imagen: "${att.name}" — analiza su contenido visual.\n`;
    } else if (att.kind === "media") {
      const sizeMB = (att.size / 1048576).toFixed(1);
      ctx += `• Archivo de medios: "${att.name}" (${att.mimeType}, ${sizeMB} MB) — solo metadatos disponibles.\n`;
    } else {
      const preview = att.textContent
        ? att.textContent.slice(0, 3000) + (att.textContent.length > 3000 ? "\n...[truncado]" : "")
        : "";
      ctx += `• Documento: "${att.name}" (${att.mimeType})\nContenido:\n${preview}\n`;
    }
  });
  return ctx;
}

// ════════════════════════════════════════════════════════
//  CHAT CON OLLAMA — IA LOCAL
// ════════════════════════════════════════════════════════

async function loadAI() {
  const statusEl = document.getElementById("aiStatus");
  const loadBtn  = document.getElementById("loadAiBtn");
  loadBtn.disabled = true;
  statusEl.textContent = "⏳ Conectando con Ollama...";
  statusEl.className = "ai-status loading";
  log("Verificando Ollama en localhost:11434...", "info");

  try {
    const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const models = (data.models || []).map(m => m.name);
    const modelFound = models.some(m => m.startsWith("llama3.2:1b") || m === OLLAMA_MODEL);

    if (!modelFound) {
      const available = models.length ? models.join(", ") : "ninguno";
      log(`⚠ Modelo '${OLLAMA_MODEL}' no encontrado. Disponibles: ${available}`, "warn");
      statusEl.textContent = `⚠ Modelo no descargado`;
      statusEl.className = "ai-status loading";
      appendChatMsg("assistant", `⚠️ Ollama está corriendo pero el modelo <b>${OLLAMA_MODEL}</b> no está descargado.<br>Ejecuta:<br><code>ollama pull ${OLLAMA_MODEL}</code>`);
      loadBtn.disabled = false;
      loadBtn.textContent = "🔄 Reintentar";
      return;
    }

    ollamaReady = true;
    statusEl.textContent = `✅ ${OLLAMA_MODEL} listo`;
    statusEl.className = "ai-status ready";
    loadBtn.textContent = "✅ Conectado";
    log(`Ollama OK — modelo ${OLLAMA_MODEL} disponible. Inferencia 100% local.`, "ok");
    appendChatMsg("assistant", `¡Hola! Soy NetAI con <b>${OLLAMA_MODEL}</b> corriendo localmente. ${devices.length > 0 ? `Tengo acceso a la BD con <b>${devices.length} dispositivos</b>. Puedes preguntarme cualquier cosa sobre ellos.` : "Carga un inventario para que pueda analizar tu red."} También puedo leer imágenes, documentos y archivos adjuntos. ¿En qué te ayudo?`);

  } catch (err) {
    statusEl.textContent = "❌ Ollama no responde";
    statusEl.className = "ai-status error";
    loadBtn.disabled = false;
    loadBtn.textContent = "🔄 Reintentar";
    log(`Ollama no accesible: ${err.message}`, "err");
    appendChatMsg("assistant", `❌ No pude conectar con Ollama en <code>${OLLAMA_URL}</code>.<br><br>Asegúrate de ejecutar:<br><code>OLLAMA_ORIGINS="*" ollama serve</code>`);
  }
}

// ── Append mensaje al DOM y lo guarda en la sesión ────────────────────────
function appendChatMsg(role, html, attachments = []) {
  const session = getActiveSession();
  if (!session) {
    // Crear sesión automáticamente si no existe
    createNewChat();
  }
  const s = getActiveSession();
  if (s) {
    s.messages.push({ role, content: html, attachments });
    renderChatHistory();
  }
  return appendChatMsgUI(role, html, attachments);
}

// Render al DOM sin guardar (para switchToChat)
function appendChatMsgUI(role, html, attachments = []) {
  const box = document.getElementById("chatMessages");
  const msg = document.createElement("div");
  msg.className = `chat-msg chat-${role}`;

  if (role === "system-note") {
    msg.innerHTML = `<span class="chat-system">${html}</span>`;
  } else {
    // Construir contenido del bubble
    let bubbleContent = "";

    // Renderizar adjuntos visuales dentro del bubble
    if (attachments && attachments.length > 0) {
      attachments.forEach(att => {
        if (att.kind === "image") {
          bubbleContent += `<img class="chat-img-attach" src="${att.dataURL}" alt="${escHtml(att.name)}">`;
        } else if (att.kind === "media") {
          bubbleContent += `<span class="attach-tag">🎬 ${escHtml(att.name)}</span><br>`;
        } else {
          bubbleContent += `<span class="attach-tag">📄 ${escHtml(att.name)}</span><br>`;
        }
      });
    }

    bubbleContent += html;
    msg.innerHTML = `<span class="chat-bubble">${bubbleContent}</span>`;
  }

  box.appendChild(msg);
  box.scrollTop = box.scrollHeight;
  return msg;
}

// ── Enviar mensaje al modelo ──────────────────────────────────────────────
async function sendChat() {
  const input    = document.getElementById("chatInput");
  const userText = input.value.trim();
  if (!userText && pendingAttachments.length === 0) return;
  input.value = "";

  // Si no hay sesión activa, crear una
  if (!activeChatId || !getActiveSession()) createNewChat();

  const attachmentsSnapshot = [...pendingAttachments];
  pendingAttachments = [];
  renderAttachmentsPreview();

  // Mostrar mensaje del usuario con adjuntos
  const displayText = userText || "(adjunto)";
  appendChatMsg("user", escHtml(displayText), attachmentsSnapshot);

  // Actualizar título si es el primer mensaje
  const session = getActiveSession();
  if (session && session.messages.filter(m => m.role === "user").length === 1) {
    updateChatTitle(session, displayText);
  }

  if (!ollamaReady) {
    appendChatMsg("assistant", "⚠️ Primero conecta el modelo con el botón <b>🤖 Cargar IA</b>.");
    return;
  }

  // Burbuja de "pensando"
  const thinkingMsg = appendChatMsgUI("assistant", '<span class="thinking">▋</span>');
  const bubble = thinkingMsg.querySelector(".chat-bubble");

  try {
    // Construir historial excluyendo mensajes de sistema y el "pensando"
    const historyMessages = (session?.messages || [])
      .filter(m => m.role === "user" || m.role === "assistant")
      .slice(-12)
      .map(m => ({
        role: m.role,
        content: m.content.replace(/<[^>]+>/g, "") + buildAttachmentContext(m.attachments)
      }));

    // Añadir contexto de adjuntos al último mensaje del usuario
    if (attachmentsSnapshot.length > 0) {
      const lastUser = historyMessages[historyMessages.length - 1];
      if (lastUser && lastUser.role === "user") {
        lastUser.content += buildAttachmentContext(attachmentsSnapshot);
      }
    }

    const messages = [
      { role: "system", content: systemPrompt },
      ...historyMessages
    ];

    const res = await fetch(`${OLLAMA_URL}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        messages,
        stream: true,
        options: { temperature: 0.7, num_predict: 512, repeat_penalty: 1.1 }
      })
    });

    if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);

    const reader  = res.body.getReader();
    const decoder = new TextDecoder();
    let fullReply = "";
    bubble.innerHTML = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      for (const line of chunk.split("\n")) {
        if (!line.trim()) continue;
        try {
          const json = JSON.parse(line);
          if (json.message?.content) {
            fullReply += json.message.content;
            bubble.textContent = fullReply;
            document.getElementById("chatMessages").scrollTop =
              document.getElementById("chatMessages").scrollHeight;
          }
          if (json.done) break;
        } catch { /* línea incompleta */ }
      }
    }

    // Guardar respuesta en sesión
    if (session) {
      session.messages.push({ role:"assistant", content: escHtml(fullReply) });
      renderChatHistory();
    }

  } catch (err) {
    bubble.textContent = `Error al comunicarse con Ollama: ${err.message}`;
    log("Error Ollama: " + err.message, "err");
  }
}

// ── Utilidad escapeHtml ───────────────────────────────────────────────────
function escHtml(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── EVENTOS ───────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Enviar con Enter
  document.getElementById("chatInput").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
  document.getElementById("sendBtn").addEventListener("click", sendChat);
  document.getElementById("loadAiBtn").addEventListener("click", loadAI);

  // Nuevo chat
  document.getElementById("newChatBtn").addEventListener("click", createNewChat);

  // Adjuntar archivos al chat
  document.getElementById("chatFileInput").addEventListener("change", async (e) => {
    const files = Array.from(e.target.files);
    if (!files.length) return;
    log(`Procesando ${files.length} adjunto(s)...`, "info");
    for (const file of files) {
      const att = await readFileAsAttachment(file);
      pendingAttachments.push(att);
      log(`  Adjunto listo: ${file.name} (${att.kind})`, "ok");
    }
    renderAttachmentsPreview();
    e.target.value = ""; // reset input
  });

  // Crear sesión inicial
  createNewChat();
});

// ── BOTONES INVENTARIO ────────────────────────────────────────────────────
document.getElementById("loadBtn").addEventListener("click", () => {
  log("Cargando inventario demo...", "info");
  fetch("network.json")
    .then(r => r.json())
    .then(db => loadDevices(db))
    .catch(() => { log("Usando datos embebidos.", "warn"); loadDevices(FALLBACK_DB); });
});

document.getElementById("fileInput").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  log(`Leyendo: ${file.name}`, "info");
  const reader = new FileReader();
  reader.onload = (ev) => {
    const content = ev.target.result;
    if (file.name.endsWith(".json")) {
      try {
        const db = JSON.parse(content);
        if (db.devices) loadDevices(db);
        else log("JSON sin estructura 'devices'.", "err");
      } catch { log("Error al parsear JSON.", "err"); }
    } else {
      loadDevices({ devices: [{
        id: "uploaded", name: file.name.replace(/\.[^.]+$/, "").toUpperCase(),
        type: "Cisco IOS", ip: "—", location: "Archivo local", config: content
      }]});
    }
  };
  reader.readAsText(file);
});

const zone = document.getElementById("uploadZone");
zone.addEventListener("dragover",  e => { e.preventDefault(); zone.classList.add("dragover"); });
zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
zone.addEventListener("drop", e => {
  e.preventDefault(); zone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) {
    const dt = new DataTransfer(); dt.items.add(file);
    document.getElementById("fileInput").files = dt.files;
    document.getElementById("fileInput").dispatchEvent(new Event("change"));
  }
});

// ── FALLBACK DB ───────────────────────────────────────────────────────────
const FALLBACK_DB = {
  devices: [
    { id:"sw-core-01", name:"SW-CORE-01", type:"Cisco Catalyst 3750", ip:"192.168.1.1", location:"Rack A - Piso 2", config:"version 15.0\nno service password-encryption\n!\nhostname SW-CORE-01\n!\nenable password cisco123\nusername admin password 0 admin123\n!\ninterface Vlan1\n ip address 192.168.1.1 255.255.255.0\n!\ninterface GigabitEthernet0/1\n switchport trunk allowed vlan all\n!\ninterface GigabitEthernet0/2\n switchport access vlan 1\n!\nno ip ssh version 2\nline vty 0 4\n transport input telnet\n password cisco\n!\nsnmp-server community public RO\nsnmp-server community private RW\n!\nend" },
    { id:"rtr-edge-02", name:"RTR-EDGE-02", type:"Cisco ISR 4331", ip:"10.0.0.254", location:"Rack B - Datacenter", config:"version 16.9\nservice password-encryption\n!\nhostname RTR-EDGE-02\n!\nenable secret 5 $1$mERr$9cTjUIkjHVrzdV5pzqMpX1\nusername netadmin privilege 15 secret 5 $1$hash\n!\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\nno snmp-server\n!\nend" },
    { id:"sw-access-03", name:"SW-ACCESS-03", type:"Cisco Catalyst 2960", ip:"172.16.300.5", location:"Piso 3 - Oficinas", config:"version 12.2\nno service password-encryption\n!\nhostname SW-ACCESS-03\n!\nenable password letmein\n!\ninterface Vlan1\n ip address 172.16.300.5 255.255.255.0\n!\ninterface FastEthernet0/1\n switchport access vlan 1\n!\nline vty 0 4\n transport input telnet\n no password\n!\nend" }
  ]
};
