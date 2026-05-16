// ════════════════════════════════════════════════════════
//  app.js — NetAI
//  Ticket 3: Motor de lectura de datos
//  Ticket 4: Motor de IA local (reglas CIS Benchmarks)
//  Ticket 5: Lógica del dashboard de alertas
//  Ticket 6: Validación offline / E2E
// ════════════════════════════════════════════════════════

// ── TICKET 4: REGLAS DE AUDITORÍA (CIS Cisco Benchmarks) ──────────────────
const RULES = [
  {
    id: "R001",
    severity: "HIGH",
    title: "Contraseña en texto plano (enable password)",
    pattern: /\benable password\b/i,
    description: "Se detectó 'enable password' en lugar de 'enable secret'. Las contraseñas en texto plano son legibles directamente en el archivo de configuración.",
    recommendation: "Reemplazar con 'enable secret <password>' que usa hash MD5/SHA."
  },
  {
    id: "R002",
    severity: "HIGH",
    title: "Cifrado de contraseñas deshabilitado",
    pattern: /no service password-encryption/i,
    description: "El comando 'no service password-encryption' expone todas las contraseñas locales en texto claro.",
    recommendation: "Ejecutar 'service password-encryption' para cifrar contraseñas con tipo 7."
  },
  {
    id: "R003",
    severity: "HIGH",
    title: "Telnet habilitado en líneas VTY",
    pattern: /transport input telnet/i,
    description: "Telnet transmite datos sin cifrado, incluyendo credenciales. Vector de ataque man-in-the-middle activo.",
    recommendation: "Cambiar a 'transport input ssh' y configurar SSH versión 2."
  },
  {
    id: "R004",
    severity: "HIGH",
    title: "Líneas VTY sin contraseña",
    pattern: /line vty[\s\S]{0,200}?no password/i,
    description: "Acceso remoto sin autenticación. Cualquiera en la red puede conectarse al dispositivo.",
    recommendation: "Configurar 'password' y 'login' en todas las líneas VTY, o implementar AAA."
  },
  {
    id: "R005",
    severity: "HIGH",
    title: "SNMP con comunidades por defecto (public/private)",
    pattern: /snmp-server community (public|private)/i,
    description: "Comunidades SNMP 'public' y 'private' son las predeterminadas y conocidas globalmente. Permiten lectura/escritura remota no autorizada.",
    recommendation: "Eliminar con 'no snmp-server community public' y migrar a SNMPv3 con autenticación."
  },
  {
    id: "R006",
    severity: "MEDIUM",
    title: "SSH versión 2 no configurado",
    // customCheck override: se activa si NO encuentra 'ip ssh version 2'
    pattern: null,
    description: "SSH v1 tiene vulnerabilidades conocidas. La ausencia de SSH v2 obliga a usar protocolos inseguros como Telnet.",
    recommendation: "Configurar 'ip ssh version 2' y 'crypto key generate rsa modulus 2048'."
  },
  {
    id: "R007",
    severity: "MEDIUM",
    title: "Dirección IP con octeto fuera de rango (0-255)",
    // customCheck override: valida cada IP encontrada en el config
    pattern: null,
    description: "Se detectó una dirección IP con octetos fuera del rango válido (0-255). Genera errores de enrutamiento.",
    recommendation: "Verificar y corregir la dirección IP del interfaz afectado en Packet Tracer."
  },
  {
    id: "R008",
    severity: "MEDIUM",
    title: "VLAN 1 como VLAN de acceso (riesgo VLAN hopping)",
    pattern: /switchport access vlan 1\b/i,
    description: "Usar VLAN 1 como VLAN de datos facilita ataques de VLAN hopping ya que es la VLAN nativa por defecto en Cisco.",
    recommendation: "Crear VLANs dedicadas y mover todos los puertos de acceso fuera de VLAN 1."
  },
  {
    id: "R009",
    severity: "LOW",
    title: "Usuario con contraseña tipo 0 (texto plano)",
    pattern: /username\s+\S+\s+password\s+0\s+/i,
    description: "Usuario configurado con contraseña tipo 0 (texto plano). Es visible directamente al hacer 'show running-config'.",
    recommendation: "Reemplazar con 'username <user> secret <pass>' para usar hash SHA-256."
  },
  {
    id: "R010",
    severity: "LOW",
    title: "Trunk permite todas las VLANs",
    pattern: /switchport trunk allowed vlan all/i,
    description: "Permitir todas las VLANs en un enlace trunk aumenta la superficie de ataque innecesariamente.",
    recommendation: "Restringir con 'switchport trunk allowed vlan <lista>' solo a las VLANs necesarias."
  }
];

/**
 * TICKET 4 — analyzeDevice()
 * Recibe un objeto device con su .config como string
 * Devuelve: { findings[], riskLevel, highCount, mediumCount, lowCount }
 */
function analyzeDevice(device) {
  const config = device.config;
  const findings = [];

  for (const rule of RULES) {
    let triggered = false;

    // Checks personalizados para reglas sin pattern simple
    if (rule.id === "R006") {
      // Activo si NO hay 'ip ssh version 2'
      triggered = !/ip ssh version 2/i.test(config);

    } else if (rule.id === "R007") {
      // Valida cada IP encontrada en el config
      const ipMatches = [...config.matchAll(/ip address ((?:\d{1,3}\.){3}\d{1,3})/gi)];
      triggered = ipMatches.some(m =>
        m[1].split('.').some(octet => parseInt(octet) > 255)
      );

    } else {
      triggered = rule.pattern.test(config);
    }

    if (triggered) {
      findings.push({ ...rule });
    }
  }

  const highCount   = findings.filter(f => f.severity === "HIGH").length;
  const mediumCount = findings.filter(f => f.severity === "MEDIUM").length;
  const lowCount    = findings.filter(f => f.severity === "LOW").length;

  // Nivel de riesgo general del dispositivo
  let riskLevel = "LOW";
  if (highCount >= 1)   riskLevel = "HIGH";
  else if (mediumCount >= 2) riskLevel = "MEDIUM";

  return { findings, riskLevel, highCount, mediumCount, lowCount };
}

// ── ESTADO GLOBAL ─────────────────────────────────────────────────────────
let devices = [];
let activeDeviceId = null;

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

// ── TICKET 3: CARGAR INVENTARIO ───────────────────────────────────────────
/**
 * loadDevices(db)
 * Lee el JSON de red, analiza cada device y puebla la lista lateral.
 * Imprime los nombres en consola (criterio de aceptación T-03).
 */
function loadDevices(db) {
  devices = db.devices.map(d => ({
    ...d,
    analysis: analyzeDevice(d)
  }));

  // Criterio de aceptación T-03: imprimir nombres en consola
  console.log("=== NetAI — Inventario cargado ===");
  devices.forEach(d => console.log(`  › ${d.name} (${d.type}) — ${d.ip}`));

  document.getElementById("deviceCount").textContent = devices.length;
  renderDeviceList();

  log(`Inventario cargado: ${devices.length} dispositivos detectados.`, "ok");
  devices.forEach(d => {
    const { riskLevel, findings } = d.analysis;
    log(
      `  ${d.name} → Riesgo: ${riskLevel} | ${findings.length} hallazgo(s)`,
      riskLevel === "HIGH" ? "err" : riskLevel === "MEDIUM" ? "warn" : "ok"
    );
  });
}

// ── TICKET 5: RENDER LISTA DE DISPOSITIVOS ────────────────────────────────
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

// ── TICKET 5: REPORTE POR DISPOSITIVO ─────────────────────────────────────
/**
 * selectDevice(id)
 * Al seleccionar un device muestra su badge de riesgo y lista de hallazgos.
 * Colores: rojo (HIGH) / amarillo (MEDIUM) / verde (LOW/seguro).
 */
function selectDevice(id) {
  activeDeviceId = id;
  renderDeviceList();

  const device = devices.find(d => d.id === id);
  if (!device) return;

  const { findings, riskLevel, highCount, mediumCount, lowCount } = device.analysis;
  const riskColors = { HIGH: "var(--danger)", MEDIUM: "var(--warn)", LOW: "var(--safe)" };
  const riskLabels = { HIGH: "🔴 RIESGO ALTO", MEDIUM: "🟡 ADVERTENCIA", LOW: "🟢 SEGURO" };

  // Ocultar empty state, mostrar panel
  document.getElementById("emptyState").style.display = "none";
  const panel = document.getElementById("reportPanel");
  panel.style.display = "block";

  // Resaltar líneas peligrosas/seguras en el config
  let configHtml = device.config
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/(enable password[^\n]*)/g,        '<span class="highlight-danger">$1</span>')
    .replace(/(no service password-encryption)/g,'<span class="highlight-danger">$1</span>')
    .replace(/(transport input telnet)/g,        '<span class="highlight-danger">$1</span>')
    .replace(/(snmp-server community (?:public|private)[^\n]*)/gi,'<span class="highlight-danger">$1</span>')
    .replace(/(no password)/g,                  '<span class="highlight-danger">$1</span>')
    .replace(/(enable secret[^\n]*)/g,          '<span class="highlight-safe">$1</span>')
    .replace(/(service password-encryption)/g,  '<span class="highlight-safe">$1</span>')
    .replace(/(ip ssh version 2)/g,             '<span class="highlight-safe">$1</span>')
    .replace(/(transport input ssh)/g,          '<span class="highlight-safe">$1</span>')
    .replace(/(no snmp-server\b)/g,             '<span class="highlight-safe">$1</span>');

  // Renderizar hallazgos
  const findingsHtml = findings.length === 0
    ? `<div class="no-findings"><div class="icon">✅</div>No se detectaron vulnerabilidades. Configuración cumple baseline CIS.</div>`
    : findings.map((f, i) => `
        <div class="finding sev-${f.severity}" style="animation-delay:${i * 80}ms">
          <div class="finding-top">
            <span class="sev-tag sev-${f.severity}">${f.severity}</span>
            <span class="finding-title">[${f.id}] ${f.title}</span>
          </div>
          <div class="finding-desc">${f.description}</div>
          <div class="finding-rec">${f.recommendation}</div>
        </div>
      `).join("");

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

  log(
    `Analizando ${device.name}... ${findings.length} hallazgo(s) encontrado(s).`,
    riskLevel === "HIGH" ? "err" : riskLevel === "MEDIUM" ? "warn" : "ok"
  );
}

// ── TICKET 3: BOTÓN DEMO ──────────────────────────────────────────────────
document.getElementById("loadBtn").addEventListener("click", () => {
  log("Cargando inventario demo (network_db.json)...", "info");

  // Fetch local del JSON — funciona offline si los archivos están en la misma carpeta
  fetch("network_db.json")
    .then(r => r.json())
    .then(db => loadDevices(db))
    .catch(() => {
      // Fallback: datos embebidos si fetch falla (ej. file://)
      log("fetch() bloqueado en file://. Usando datos embebidos.", "warn");
      loadDevices(FALLBACK_DB);
    });
});

// ── TICKET 3: LECTURA DE ARCHIVO REAL ────────────────────────────────────
document.getElementById("fileInput").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;

  log(`Leyendo archivo: ${file.name}`, "info");
  const reader = new FileReader();

  reader.onload = (ev) => {
    const content = ev.target.result;

    if (file.name.endsWith(".json")) {
      try {
        const db = JSON.parse(content);
        if (db.devices) {
          loadDevices(db);
        } else {
          log("JSON no tiene estructura 'devices'. Verifica el formato.", "err");
        }
      } catch {
        log("Error al parsear JSON. Verifica la sintaxis del archivo.", "err");
      }
    } else {
      // Running-config de un solo dispositivo (.txt / .cfg)
      const syntheticDb = {
        devices: [{
          id: "uploaded-device",
          name: file.name.replace(/\.[^.]+$/, "").toUpperCase(),
          type: "Cisco IOS Device",
          ip: "—",
          location: "Archivo local",
          config: content
        }]
      };
      loadDevices(syntheticDb);
    }
  };

  reader.readAsText(file);
});

// ── DRAG & DROP ───────────────────────────────────────────────────────────
const zone = document.getElementById("uploadZone");
zone.addEventListener("dragover",  e => { e.preventDefault(); zone.classList.add("dragover"); });
zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
zone.addEventListener("drop", e => {
  e.preventDefault();
  zone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) {
    // Reusar el handler de fileInput
    const dt = new DataTransfer();
    dt.items.add(file);
    document.getElementById("fileInput").files = dt.files;
    document.getElementById("fileInput").dispatchEvent(new Event("change"));
  }
});

// ── TICKET 6: FALLBACK DB (para validación offline sin servidor) ──────────
// Si el fetch de network_db.json falla (protocolo file://),
// estos datos permiten que el sistema funcione igual.
const FALLBACK_DB = {
  devices: [
    {
      id: "sw-core-01",
      name: "SW-CORE-01",
      type: "Cisco Catalyst 3750",
      ip: "192.168.1.1",
      location: "Rack A - Piso 2",
      config: "version 15.0\nno service password-encryption\n!\nhostname SW-CORE-01\n!\nenable password cisco123\nusername admin password 0 admin123\n!\ninterface Vlan1\n ip address 192.168.1.1 255.255.255.0\n!\ninterface GigabitEthernet0/1\n switchport trunk allowed vlan all\n!\ninterface GigabitEthernet0/2\n switchport access vlan 1\n!\nno ip ssh version 2\nline vty 0 4\n transport input telnet\n password cisco\n!\nsnmp-server community public RO\nsnmp-server community private RW\n!\nend"
    },
    {
      id: "rtr-edge-02",
      name: "RTR-EDGE-02",
      type: "Cisco ISR 4331",
      ip: "10.0.0.254",
      location: "Rack B - Datacenter",
      config: "version 16.9\nservice password-encryption\n!\nhostname RTR-EDGE-02\n!\nenable secret 5 $1$mERr$9cTjUIkjHVrzdV5pzqMpX1\nusername netadmin privilege 15 secret 5 $1$mERr$hash\n!\ninterface GigabitEthernet0/0/0\n ip address 203.0.113.10 255.255.255.252\n!\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\nno snmp-server\n!\nend"
    },
    {
      id: "sw-access-03",
      name: "SW-ACCESS-03",
      type: "Cisco Catalyst 2960",
      ip: "172.16.300.5",
      location: "Piso 3 - Oficinas",
      config: "version 12.2\nno service password-encryption\n!\nhostname SW-ACCESS-03\n!\nenable password letmein\n!\ninterface Vlan1\n ip address 172.16.300.5 255.255.255.0\n!\ninterface FastEthernet0/1\n switchport access vlan 1\n!\nline vty 0 4\n transport input telnet\n no password\n!\nend"
    }
  ]
};