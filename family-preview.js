(() => {
"use strict";
const API = "https://casa-smart-api-webauthn-preview.brisicche78.workers.dev";
const $ = id => document.getElementById(id);
const decode = value => {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};
const encode = value => {
  const bytes = new Uint8Array(value); let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
function credentialBody(credential) {
  const a = credential.response;
  const result = {
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment || null
  };
  if (a.attestationObject) {
    result.response = {
      attestationObject: encode(a.attestationObject),
      clientDataJSON: encode(a.clientDataJSON),
      transports: a.getTransports ? a.getTransports() : []
    };
  } else {
    result.response = {
      authenticatorData: encode(a.authenticatorData),
      clientDataJSON: encode(a.clientDataJSON),
      signature: encode(a.signature),
      userHandle: a.userHandle ? encode(a.userHandle) : null
    };
  }
  return result;
}
async function api(path, options = {}) {
  const headers = {};
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.token) headers.Authorization = "Bearer " + options.token;
  const response = await fetch(API + path, {
    method: options.method || "POST", headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer"
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || ("Errore HTTP " + response.status));
  return data;
}
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("casa-santini-auth-preview", 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains("session")) req.result.createObjectStore("session");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function getToken(key) {
  const db = await openDb();
  const value = await new Promise((resolve, reject) => {
    const tx = db.transaction("session", "readonly");
    const req = tx.objectStore("session").get(key);
    req.onsuccess = () => resolve(req.result || "");
    req.onerror = () => reject(req.error);
  });
  db.close(); return value;
}
async function putToken(key, value) {
  const db = await openDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction("session", "readwrite");
    tx.objectStore("session").put(value, key);
    tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
  });
  db.close();
}
async function removeToken(key) {
  const db = await openDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction("session", "readwrite");
    tx.objectStore("session").delete(key);
    tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
  });
  db.close();
}
async function registerFamily() {
  const name = $("familyName").value.trim(), btn = $("familyRegisterBtn");
  if (name.length < 2) { $("familyStatus").textContent = "Inserisci nome e cognome."; return; }
  btn.disabled = true;
  try {
    if (!window.isSecureContext || !navigator.credentials?.create) throw new Error("Passkey non supportata da questo browser.");
    $("familyStatus").textContent = "Preparo la registrazione…";
    const prepared = await api("/webauthn/family/register/options", { body: { name } });
    const options = prepared.options;
    options.challenge = decode(options.challenge);
    options.user.id = decode(options.user.id);
    $("familyStatus").textContent = "Conferma la Passkey con impronta, volto o PIN…";
    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) throw new Error("Registrazione annullata.");
    $("familyStatus").textContent = "Verifica della Passkey…";
    const result = await api("/webauthn/family/register/verify", {
      body: { userId: prepared.userId, challengeId: prepared.challengeId, response: credentialBody(credential) }
    });
    $("familyStatus").textContent = result.message || "Richiesta inviata al MASTER.";
  } catch (error) {
    $("familyStatus").textContent = "Non completato: " + (error.message || "errore");
  } finally { btn.disabled = false; }
}
async function loginFamily() {
  const name = $("familyName").value.trim(), btn = $("familyLoginBtn");
  if (!name) { $("familyStatus").textContent = "Inserisci il nome usato per la richiesta."; return; }
  btn.disabled = true;
  try {
    if (!window.isSecureContext || !navigator.credentials?.get) throw new Error("Passkey non supportata da questo browser.");
    $("familyStatus").textContent = "Cerco l'account familiare…";
    const prepared = await api("/webauthn/family/authenticate/options", { body: { name } });
    const options = prepared.options;
    options.challenge = decode(options.challenge);
    if (Array.isArray(options.allowCredentials)) {
      options.allowCredentials = options.allowCredentials.map(item => ({ ...item, id: decode(item.id) }));
    }
    $("familyStatus").textContent = "Conferma l'accesso con impronta, volto o PIN…";
    const credential = await navigator.credentials.get({ publicKey: options });
    if (!credential) throw new Error("Accesso annullato.");
    const verified = await api("/webauthn/family/authenticate/verify", {
      body: { userId: prepared.userId, challengeId: prepared.challengeId, response: credentialBody(credential) }
    });
    if (!verified.verified || verified.role !== "family" || !verified.sessionToken) throw new Error("Accesso non confermato dal server.");
    await putToken("family-token", verified.sessionToken);
    $("login").classList.add("hidden");
    $("dashboard").classList.add("hidden");
    $("familyHome").classList.remove("hidden");
    $("familyWelcome").textContent = "Benvenuto, " + verified.user + ". Accesso autorizzato dal MASTER.";
  } catch (error) {
    $("familyStatus").textContent = "Accesso non completato: " + (error.message || "errore");
  } finally { btn.disabled = false; }
}
async function logoutFamily() {
  const token = await getToken("family-token");
  try { await api("/webauthn/family/logout", { token }); } catch {}
  await removeToken("family-token");
  $("familyHome").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("familyStatus").textContent = "Sessione familiare chiusa.";
}
function renderRows(target, users, pending) {
  target.replaceChildren();
  if (!users.length) {
    target.textContent = pending ? "Nessuna richiesta in attesa." : "Nessun familiare autorizzato.";
    return;
  }
  users.forEach(user => {
    const row = document.createElement("div"); row.className = "family-row";
    const title = document.createElement("strong"); title.textContent = user.name; row.appendChild(title);
    const note = document.createElement("small");
    note.textContent = pending ? "In attesa · Passkey registrata" : "Autorizzato · Passkey attiva";
    row.appendChild(note);
    const actions = document.createElement("div"); actions.className = "family-actions";
    const action = (label, path, ask) => {
      const button = document.createElement("button"); button.type = "button";
      button.className = "secondary"; button.textContent = label;
      button.addEventListener("click", async () => {
        if (ask && !confirm(ask)) return;
        button.disabled = true;
        try {
          const token = await getToken("master-token");
          await api(path, { token, body: { userId: user.id } });
          await loadAdmin();
          $("familyAdminStatus").textContent = "Operazione completata.";
        } catch (error) {
          $("familyAdminStatus").textContent = error.message; button.disabled = false;
        }
      });
      actions.appendChild(button);
    };
    if (pending) {
      action("APPROVA", "/admin/family/approve");
      action("RIFIUTA", "/admin/family/reject", "Rifiutare questa richiesta?");
    } else {
      action("REVOCA", "/admin/family/revoke", "Revocare l'accesso a " + user.name + "?");
    }
    row.appendChild(actions); target.appendChild(row);
  });
}
async function loadAdmin() {
  const token = await getToken("master-token");
  if (!token) return;
  const [pending, active] = await Promise.all([
    api("/admin/family/requests", { method: "GET", token }),
    api("/admin/family/users", { method: "GET", token })
  ]);
  const requests = pending.users || [], users = active.users || [];
  $("requestCount").textContent = requests.length + " richieste";
  $("userCount").textContent = users.length + " autorizzati";
  renderRows($("familyRequests"), requests, true);
  renderRows($("familyUsers"), users, false);
}
async function restoreFamily() {
  const token = await getToken("family-token");
  if (!token) return;
  try {
    const status = await api("/webauthn/family/session", { method: "GET", token });
    if (!status.authenticated || status.role !== "family") throw new Error("Sessione non valida");
    $("login").classList.add("hidden");
    $("dashboard").classList.add("hidden");
    $("familyHome").classList.remove("hidden");
    $("familyWelcome").textContent = "Benvenuto, " + status.user + ". Sessione verificata.";
  } catch { await removeToken("family-token"); }
}
function init() {
  $("familyRegisterBtn").addEventListener("click", registerFamily);
  $("familyLoginBtn").addEventListener("click", loginFamily);
  $("familyLogoutBtn").addEventListener("click", logoutFamily);
  $("refreshFamilyBtn").addEventListener("click", () => loadAdmin().catch(e => $("familyAdminStatus").textContent = e.message));
  restoreFamily();
  loadAdmin().catch(() => {});
  const dashboard = $("dashboard");
  new MutationObserver(() => {
    if (!dashboard.classList.contains("hidden")) loadAdmin().catch(e => $("familyAdminStatus").textContent = e.message);
  }).observe(dashboard, { attributes: true, attributeFilter: ["class"] });
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
})();