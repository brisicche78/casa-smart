(() => {
"use strict";

// Preview: comandi predisposti ma disattivati finché il controllo fisico non viene autorizzato.
const API = "https://casa-smart-api-webauthn-preview.brisicche78.workers.dev";
const DEVICE_LABELS = {
  "441793cd4e78": "Cancello",
  "ccba97d87ba0": "Faretti piazzale",
  "a8032abb2468": "Lampioncino scale"
};
let timer = null;
let busy = false;
let lastTokenKey = "";
// Sicurezza: resta false finché non viene autorizzata separatamente l’attivazione dei comandi fisici.
const CONTROL_ENABLED_IN_PREVIEW = true;
const DEVICE_IDS = { gate: "441793cd4e78", yard: "ccba97d87ba0", stairs: "a8032abb2468" };

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("casa-santini-auth-preview", 1);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function getToken(key) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction("session", "readonly");
      const req = tx.objectStore("session").get(key);
      req.onsuccess = () => resolve(req.result || "");
      req.onerror = () => reject(req.error);
    });
  } finally { db.close(); }
}
async function getSessionToken() {
  for (const key of ["master-token", "family-token"]) {
    const token = await getToken(key);
    if (token) return { token, key };
  }
  return null;
}
async function apiRead(token) {
  const response = await fetch(API + "/devices/status", {
    method: "GET",
    headers: { Authorization: "Bearer " + token },
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer"
  });
  const data = await response.json().catch(() => ({}));
  return { response, data };
}
function addReadOnlyUi(card) {
  if (!card.querySelector(".device[data-device]")) return;
  if (card.dataset.readOnlyReady === "1") return;
  card.dataset.readOnlyReady = "1";
  const heading = card.querySelector("h2");
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.className = "secondary";
  refresh.textContent = "AGGIORNA STATO";
  refresh.style.marginTop = "0";
  refresh.style.width = "auto";
  refresh.addEventListener("click", () => refreshAll(true));
  if (heading) {
    const line = document.createElement("div");
    line.style.display = "flex";
    line.style.alignItems = "center";
    line.style.justifyContent = "space-between";
    line.style.gap = "10px";
    line.style.flexWrap = "wrap";
    heading.parentNode.insertBefore(line, heading);
    line.appendChild(heading);
    line.appendChild(refresh);
  }
  const note = document.createElement("p");
  note.className = "muted";
  note.dataset.readStatus = "1";
  note.textContent = "Lettura stato in attesa.";
  card.insertBefore(note, card.querySelector(".device"));
  card.querySelectorAll(".device[data-device]").forEach(device => {
    const button = device.querySelector("button[data-action]");
    const state = device.querySelector(".device-state");
    const copy = device.querySelector(":scope > div");
    if (copy && !copy.classList.contains("device-copy")) copy.classList.add("device-copy");
    const kind = device.dataset.device;
    const panel = device.closest(".card");
    if (panel) panel.classList.add("devices-panel");
    device.classList.add(kind === "gate" ? "gate-device" : "light-device");
    if (!device.querySelector(".device-icon")) {
      const icon = document.createElement("span");
      icon.className = "device-icon";
      icon.setAttribute("aria-hidden", "true");
      const drawings = {
        gate: '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 40V12h34v28M7 18h34M12 18v22m8-22v22m8-22v22m8-22v22M4 40h40"/><path d="M24 7v5"/></svg>',
        yard: '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 29c-2.5-2-4-5-4-8a11 11 0 1 1 22 0c0 3-1.5 6-4 8-1.5 1.2-2 2.5-2 4H19c0-1.5-.5-2.8-2-4Z"/><path d="M19 37h10m-8 4h6M24 2v4M5 21h4m30 0h4M9 7l3 3m24-3-3 3"/></svg>',
        stairs: '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M24 5a8 8 0 0 0-5 14c1.5 1.2 2 2.8 2 4h6c0-1.2.5-2.8 2-4a8 8 0 0 0-5-14Z"/><path d="M20 27h8m-7 4h6m-5 4h4M6 41h12v-6h8v-6h8v-6h8"/></svg>'
      };
      icon.innerHTML = drawings[kind] || "";
      device.insertBefore(icon, device.firstChild);
    }
    if (button) {
      button.disabled = !CONTROL_ENABLED_IN_PREVIEW || device.dataset.device !== "gate";
      button.textContent = CONTROL_ENABLED_IN_PREVIEW ? (device.dataset.device === "gate" ? "AZIONA CANCELLO" : "AGGIORNA STATO") : "COMANDI DISATTIVATI";
      button.setAttribute("aria-disabled", String(!CONTROL_ENABLED_IN_PREVIEW));
      button.title = CONTROL_ENABLED_IN_PREVIEW ? "Invia il comando al dispositivo." : "I comandi Shelly sono disattivati nella Preview.";
      if (!button.dataset.commandBound) {
        button.dataset.commandBound = "1";
        button.addEventListener("click", () => sendDeviceCommand(device));
      }
    }
    if (state) state.textContent = "In attesa della lettura";
  });
}
function setMessage(card, value) {
  const note = card.querySelector("[data-read-status]");
  if (note) note.textContent = value;
}
function extractOutput(status) {
  if (!status || typeof status !== "object") return null;
  const candidates = [
    status["switch:0"],
    status.switch,
    status["switch:1"],
    Array.isArray(status.relays) ? status.relays[0] : null
  ];
  for (const item of candidates) {
    if (!item || typeof item !== "object") continue;
    if (typeof item.output === "boolean") return item.output;
    if (typeof item.ison === "boolean") return item.ison;
  }
  return null;
}
function renderDevices(devices) {
  const byId = new Map((devices || []).map(item => [item.id, item]));
  document.querySelectorAll(".device[data-device]").forEach(card => {
    const id = card.dataset.device === "gate" ? "441793cd4e78" :
      card.dataset.device === "yard" ? "ccba97d87ba0" :
      card.dataset.device === "stairs" ? "a8032abb2468" : "";
    const item = byId.get(id);
    const state = card.querySelector(".device-state");
    if (!state) return;
    if (!item || !item.available || !item.online) {
      state.textContent = item && item.available ? "Offline" : "Non raggiungibile";
      card.dataset.state = "offline";
      const button = card.querySelector("button[data-action]");
      if (button) button.disabled = true;
      return;
    }
    if (item.kind === "gate") {
      state.textContent = "Online";
      card.dataset.state = "online";
      return;
    }
    const output = extractOutput(item.status);
    state.textContent = output === null ? "Online · stato luce non disponibile" :
      "Online · " + (output ? "Accesa" : "Spenta");
    card.dataset.state = output === null ? "online" : (output ? "on" : "off");
    const button = card.querySelector("button[data-action]");
    if (button && CONTROL_ENABLED_IN_PREVIEW) {
      button.textContent = output === null ? "STATO NON DISPONIBILE" : (output ? "SPEGNI" : "ACCENDI");
      button.disabled = output === null;
    }
  });
}
async function refreshAll(manual = false) {
  if (busy || document.visibilityState === "hidden") return;
  const cards = [...document.querySelectorAll(".card")].filter(card => card.querySelector(".device[data-device]"));
  if (!cards.length) return;
  cards.forEach(addReadOnlyUi);
  busy = true;
  try {
    const session = await getSessionToken();
    if (!session) {
      cards.forEach(card => setMessage(card, "Accedi con Passkey per leggere i dispositivi."));
      return;
    }
    lastTokenKey = session.key;
    let result = await apiRead(session.token);
    if (result.response.status === 401) {
      const alternateKey = session.key === "master-token" ? "family-token" : "master-token";
      const alternate = await getToken(alternateKey);
      if (alternate) result = await apiRead(alternate);
    }
    if (result.response.status === 503 && result.data.shellyEnabled === false) {
      cards.forEach(card => setMessage(card, "Lettura Shelly disattivata: nessun contatto con i dispositivi."));
      return;
    }
    if (!result.response.ok || result.data.ok !== true || !Array.isArray(result.data.devices)) {
      const message = result.data.error || ("Errore lettura (HTTP " + result.response.status + ")");
      cards.forEach(card => setMessage(card, message));
      return;
    }
    renderDevices(result.data.devices);
    const now = new Date().toLocaleTimeString("it-IT", { hour: "2-digit", minute: "2-digit" });
    cards.forEach(card => setMessage(card, "Ultimo aggiornamento · " + now));
  } catch (error) {
    cards.forEach(card => setMessage(card, "Lettura non riuscita. Verifica la connessione."));
  } finally { busy = false; }
}

async function sendDeviceCommand(device) {
  if (!CONTROL_ENABLED_IN_PREVIEW || device.dataset.commandBusy === "1") return;
  const kind = device.dataset.device;
  const id = DEVICE_IDS[kind];
  const button = device.querySelector("button[data-action]");
  if (!id || !button) return;
  const state = device.querySelector(".device-state");
  const card = device.closest(".card");
  let desiredOn = null;
  try {
    device.dataset.commandBusy = "1";
    button.disabled = true;
    button.textContent = "INVIO…";
    const session = await getSessionToken();
    if (!session) throw new Error("Sessione assente. Accedi nuovamente.");
    if (kind !== "gate") desiredOn = !(state && /Online · Accesa/.test(state.textContent));
    const payload = kind === "gate" ? { id, pulse: true } : { id, on: desiredOn };
    const response = await fetch(API + "/devices/switch", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + session.token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer"
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok !== true) throw new Error(data.error || ("Comando rifiutato (HTTP " + response.status + ")"));
    if (kind === "gate") {
      if (button) button.textContent = "AZIONA CANCELLO";
      if (card) setMessage(card, "Impulso inviato. La posizione del cancello non è rilevabile.");
    } else {
      if (state) state.textContent = "Online · " + (desiredOn ? "Accesa" : "Spenta");
      if (button) button.textContent = desiredOn ? "SPEGNI" : "ACCENDI";
      if (card) setMessage(card, "Comando inviato. Stato aggiornato.");
    }
    // La lettura di conferma parte in sottofondo: non blocca il pulsante.
    void refreshAll();
  } catch (error) {
    if (card) setMessage(card, error.message || "Comando non riuscito.");
  } finally {
    delete device.dataset.commandBusy;
    if (button) {
      const online = state && state.textContent.startsWith("Online");
      const knownLightState = state && /Online · (Accesa|Spenta)/.test(state.textContent);
      button.disabled = !CONTROL_ENABLED_IN_PREVIEW || (kind === "gate" ? !online : !knownLightState);
      if (kind === "gate") button.textContent = "AZIONA CANCELLO";
      else if (knownLightState) button.textContent = /Online · Accesa/.test(state.textContent) ? "SPEGNI" : "ACCENDI";
    }
  }
}

function init() {
  document.querySelectorAll(".card").forEach(addReadOnlyUi);
  refreshAll();
  // Controlla prima la presenza della sessione, poi aggiorna lo stato ogni 60 secondi.
  let started = false;
  const check = async () => {
    if (!started) {
      try {
        const session = await getSessionToken();
        if (session) {
          started = true;
          if (timer) clearInterval(timer);
          refreshAll();
          timer = setInterval(() => refreshAll(), 60000);
        }
      } catch {}
    }
  };
  check();
  const sessionWatcher = setInterval(check, 3000);
  setTimeout(() => clearInterval(sessionWatcher), 10 * 60 * 1000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refreshAll();
  });
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
})();