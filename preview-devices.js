(() => {
"use strict";

// Preview: sola lettura. Nessun comando viene inviato agli Shelly.
const API = "https://b1ecd5c6-casa-smart-api-webauthn-preview.brisicche78.workers.dev";
const DEVICE_LABELS = {
  "441793cd4e78": "Cancello",
  "ccba97d87ba0": "Faretti piazzale",
  "a8032abb2468": "Lampioncino scale"
};
let timer = null;
let busy = false;
let lastTokenKey = "";

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
    if (button) {
      button.disabled = true;
      button.textContent = "COMANDI DISATTIVATI";
      button.setAttribute("aria-disabled", "true");
      button.title = "I comandi Shelly sono disattivati nella Preview.";
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
      return;
    }
    if (item.kind === "gate") {
      state.textContent = "Online · stato apertura non disponibile";
      return;
    }
    const output = extractOutput(item.status);
    state.textContent = output === null ? "Online · stato luce non disponibile" :
      "Online · " + (output ? "Accesa" : "Spenta");
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
    cards.forEach(card => setMessage(card, "Stato aggiornato alle " + now + ". Sola lettura · comandi disattivati."));
  } catch (error) {
    cards.forEach(card => setMessage(card, "Lettura non riuscita. Verifica la connessione."));
  } finally { busy = false; }
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