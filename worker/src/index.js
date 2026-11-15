// CASA SMART API — isolated WebAuthn preparation preview.
// This is deliberately NOT the production API.
// The production Shelly endpoints and credentials are not connected here.

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";

const MASTER_ID = "master";
const CHALLENGE_TTL_SECONDS = 300;
const RATE_WINDOW_SECONDS = 900;
const RATE_LIMIT = 8;

function json(data, status, origin, allowedOrigin) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });

  if (origin && origin === allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    headers.set("Access-Control-Max-Age", "600");
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(left || "");
  const b = new TextEncoder().encode(right || "");
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i += 1) {
    diff |= (a[i] || 0) ^ (b[i] || 0);
  }

  return diff === 0;
}

function hasEnrollmentSecret(request, env) {
  const expected = env.MASTER_ENROLLMENT_SECRET;
  const authorization = request.headers.get("Authorization") || "";
  const supplied = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  return Boolean(expected) && constantTimeEqual(supplied, expected);
}

async function readJson(request) {
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > 50000) {
    throw new Error("Payload troppo grande");
  }

  const raw = await request.text();
  if (!raw || raw.length > 50000) {
    throw new Error("Payload non valido");
  }

  return JSON.parse(raw);
}

async function checkRateLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(ip)
  );
  const ipHash = Array.from(new Uint8Array(digest))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");

  const attemptId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, NULL, ?, 'master-enroll-attempt', unixepoch() + ?)"
  ).bind(attemptId, ipHash, RATE_WINDOW_SECONDS).run();

  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM webauthn_challenges WHERE purpose = 'master-enroll-attempt' AND challenge = ? AND created_at >= unixepoch() - ?"
  ).bind(ipHash, RATE_WINDOW_SECONDS).first();

  await env.DB.prepare(
    "DELETE FROM webauthn_challenges WHERE purpose = 'master-enroll-attempt' AND expires_at <= unixepoch()"
  ).run();

  return Number(count?.total || 0) <= RATE_LIMIT;
}

function allowedRequestOrigin(request, env) {
  return Boolean(env.WEBAUTHN_ORIGIN) &&
    request.headers.get("Origin") === env.WEBAUTHN_ORIGIN;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function masterRegistrationOptions(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }

  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }

  // Il segreto è accettato soltanto per avviare la cerimonia.
  // Non viene mai richiesto né restituito dal client statico della PWA.
  if (!hasEnrollmentSecret(request, env)) {
    return json({ error: "Autorizzazione non valida" }, 401, origin, env.WEBAUTHN_ORIGIN);
  }

  if (!env.WEBAUTHN_RP_ID || !env.WEBAUTHN_RP_NAME) {
    return json({ error: "Configurazione WebAuthn incompleta" }, 500, origin, env.WEBAUTHN_ORIGIN);
  }

  const existing = await env.DB.prepare(
    "SELECT id, role, status FROM app_users WHERE id = ?"
  ).bind(MASTER_ID).first();

  if (existing && (existing.role !== "master" || existing.status !== "active")) {
    return json({ error: "Account MASTER in stato non valido" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  const existingCredential = await env.DB.prepare(
    "SELECT id FROM webauthn_credentials WHERE user_id = ? LIMIT 1"
  ).bind(MASTER_ID).first();

  if (existingCredential) {
    return json({ error: "La Passkey MASTER è già stata inizializzata" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  const consumedSecret = await env.DB.prepare(
    "SELECT id FROM webauthn_challenges WHERE id = 'master-enrollment-secret-consumed' AND purpose = 'master-enrollment-secret-consumed' LIMIT 1"
  ).first();

  if (consumedSecret) {
    return json({ error: "Il segreto di inizializzazione è già stato utilizzato" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  const activeRegistration = await env.DB.prepare(
    "SELECT id FROM webauthn_challenges WHERE purpose = 'master-registration' AND expires_at > unixepoch() LIMIT 1"
  ).first();

  if (activeRegistration) {
    return json({ error: "Esiste già una registrazione in corso. Attendi la scadenza e riprova." }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  const options = await generateRegistrationOptions({
    rpName: env.WEBAUTHN_RP_NAME,
    rpID: env.WEBAUTHN_RP_ID,
    userID: new TextEncoder().encode(MASTER_ID),
    userName: "Alessandro",
    userDisplayName: "Alessandro - MASTER",
    attestationType: "none",
    timeout: 60000,
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required"
    },
    supportedAlgorithmIDs: [-7, -257]
  });

  const challengeId = crypto.randomUUID();
  const grantId = crypto.randomUUID();
  const grantToken = randomToken();
  const grantHash = await sha256Hex(grantToken);

  // Il segreto resta riutilizzabile finché la Passkey non viene verificata
  // e salvata. Challenge e grant scadono automaticamente dopo cinque minuti.
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO app_users (id, name, role, status) VALUES (?, 'Alessandro', 'master', 'active') ON CONFLICT(id) DO NOTHING"
    ).bind(MASTER_ID),
    env.DB.prepare(
      "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-registration', unixepoch() + ?)"
    ).bind(challengeId, MASTER_ID, options.challenge, CHALLENGE_TTL_SECONDS),
    env.DB.prepare(
      "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-enrollment-grant', unixepoch() + ?)"
    ).bind(grantId, MASTER_ID, grantHash, CHALLENGE_TTL_SECONDS)
  ]);

  return json({
    ok: true,
    challengeId,
    grantId,
    grantToken,
    options
  }, 200, origin, env.WEBAUTHN_ORIGIN);
}

async function verifyMasterRegistration(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }

  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }

  let body;
  try {
    body = await readJson(request);
  } catch {
    return json({ error: "Richiesta JSON non valida" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  if (
    typeof body.challengeId !== "string" ||
    typeof body.grantId !== "string" ||
    !body.response ||
    typeof body.response !== "object" ||
    typeof body.response.id !== "string"
  ) {
    return json({ error: "Dati di registrazione incompleti" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  // La verifica usa un grant casuale, monouso e con scadenza.
  // Il MASTER_ENROLLMENT_SECRET non viene inviato nella seconda richiesta.
  const authorization = request.headers.get("Authorization") || "";
  const grantToken = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!grantToken || grantToken.length > 256) {
    return json({ error: "Autorizzazione di registrazione mancante" }, 401, origin, env.WEBAUTHN_ORIGIN);
  }

  const grantHash = await sha256Hex(grantToken);
  const grant = await env.DB.prepare(
    "SELECT id FROM webauthn_challenges WHERE id = ? AND user_id = ? AND challenge = ? AND purpose = 'master-enrollment-grant' AND expires_at > unixepoch()"
  ).bind(body.grantId, MASTER_ID, grantHash).first();

  if (!grant) {
    return json({ error: "Autorizzazione scaduta o già utilizzata. Avvia una nuova registrazione." }, 401, origin, env.WEBAUTHN_ORIGIN);
  }

  const storedChallenge = await env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-registration' AND expires_at > unixepoch()"
  ).bind(body.challengeId, MASTER_ID).first();

  if (!storedChallenge) {
    return json({ error: "Challenge scaduta o già utilizzata. Avvia una nuova registrazione." }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  const existingCredential = await env.DB.prepare(
    "SELECT id FROM webauthn_credentials WHERE user_id = ? LIMIT 1"
  ).bind(MASTER_ID).first();

  if (existingCredential) {
    return json({ error: "La Passkey MASTER è già stata inizializzata" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: env.WEBAUTHN_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      requireUserVerification: true
    });
  } catch {
    return json({ error: "Verifica WebAuthn non riuscita" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  if (!verification.verified || !verification.registrationInfo) {
    return json({ error: "Registrazione Passkey non verificata" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  const credential = verification.registrationInfo.credential;
  const transports = Array.isArray(credential.transports)
    ? JSON.stringify(credential.transports)
    : null;

  // L'inserimento è condizionato alla presenza contemporanea di challenge
  // e grant validi. Il grant viene eliminato soltanto se la credential è stata
  // effettivamente salvata; una verifica fallita lascia scadere il grant.
  const results = await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, device_name) SELECT ?, ?, ?, ?, ?, ?, 'MASTER' WHERE EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-registration' AND challenge = ? AND expires_at > unixepoch()) AND EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = ? AND user_id = ? AND challenge = ? AND purpose = 'master-enrollment-grant' AND expires_at > unixepoch()) AND NOT EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ?) AND NOT EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = 'master-enrollment-secret-consumed' AND purpose = 'master-enrollment-secret-consumed')"
    ).bind(
      crypto.randomUUID(),
      MASTER_ID,
      credential.id,
      credential.publicKey,
      credential.counter,
      transports,
      body.challengeId,
      MASTER_ID,
      storedChallenge.challenge,
      body.grantId,
      MASTER_ID,
      grantHash,
      MASTER_ID
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) SELECT 'master-enrollment-secret-consumed', ?, 'consumed', 'master-enrollment-secret-consumed', 2147483647 WHERE EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?)"
    ).bind(MASTER_ID, MASTER_ID, credential.id),
    env.DB.prepare(
      "DELETE FROM webauthn_challenges WHERE ((id = ? AND user_id = ? AND purpose = 'master-registration') OR (id = ? AND user_id = ? AND purpose = 'master-enrollment-grant')) AND EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?)"
    ).bind(body.challengeId, MASTER_ID, body.grantId, MASTER_ID, MASTER_ID, credential.id)
  ]);

  const inserted = Number(results?.[0]?.meta?.changes || 0);
  if (inserted !== 1) {
    return json({ error: "Registrazione già completata o autorizzazione non più valida" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  return json({
    ok: true,
    verified: true,
    user: "Alessandro",
    role: "master",
    credentialSaved: true,
    grantConsumed: true,
    nextStep: "master-passkey-created"
  }, 200, origin, env.WEBAUTHN_ORIGIN);
}


async function ensureSessionTable(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS webauthn_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, challenge_id TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_used_at INTEGER, revoked_at INTEGER, FOREIGN KEY (user_id) REFERENCES app_users(id))"
  ).run();
}

async function masterAuthenticationOptions(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!env.WEBAUTHN_RP_ID || !env.WEBAUTHN_ORIGIN) {
    return json({ error: "Configurazione WebAuthn incompleta" }, 500, origin, env.WEBAUTHN_ORIGIN);
  }

  const master = await env.DB.prepare(
    "SELECT id, name, role, status FROM app_users WHERE id = ?"
  ).bind(MASTER_ID).first();
  if (!master || master.role !== "master" || master.status !== "active") {
    return json({ error: "Account MASTER non disponibile" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }

  const credentials = await env.DB.prepare(
    "SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ? AND revoked_at IS NULL"
  ).bind(MASTER_ID).all();
  const rows = credentials.results || [];
  if (!rows.length) {
    return json({ error: "Nessuna Passkey MASTER attiva" }, 404, origin, env.WEBAUTHN_ORIGIN);
  }

  await ensureSessionTable(env);
  const options = await generateAuthenticationOptions({
    rpID: env.WEBAUTHN_RP_ID,
    timeout: 60000,
    userVerification: "required",
    allowCredentials: rows.map((row) => ({
      id: row.credential_id,
      transports: row.transports ? JSON.parse(row.transports) : undefined
    }))
  });

  const challengeId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-authentication', unixepoch() + ?)"
  ).bind(challengeId, MASTER_ID, options.challenge, CHALLENGE_TTL_SECONDS).run();

  return json({ ok: true, challengeId, options }, 200, origin, env.WEBAUTHN_ORIGIN);
}

async function verifyMasterAuthentication(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }

  let body;
  try {
    body = await readJson(request);
  } catch {
    return json({ error: "Richiesta JSON non valida" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }
  if (
    typeof body.challengeId !== "string" ||
    !body.response ||
    typeof body.response !== "object" ||
    typeof body.response.id !== "string"
  ) {
    return json({ error: "Dati di autenticazione incompleti" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  const challenge = await env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-authentication' AND expires_at > unixepoch()"
  ).bind(body.challengeId, MASTER_ID).first();
  if (!challenge) {
    return json({ error: "Richiesta di accesso scaduta o già utilizzata. Riprova." }, 401, origin, env.WEBAUTHN_ORIGIN);
  }

  const master = await env.DB.prepare(
    "SELECT id, name, role, status FROM app_users WHERE id = ?"
  ).bind(MASTER_ID).first();
  if (!master || master.role !== "master" || master.status !== "active") {
    return json({ error: "Account MASTER non disponibile" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }

  const storedCredential = await env.DB.prepare(
    "SELECT id, credential_id, public_key, sign_count, transports FROM webauthn_credentials WHERE credential_id = ? AND user_id = ? AND revoked_at IS NULL"
  ).bind(body.response.id, MASTER_ID).first();
  if (!storedCredential) {
    return json({ error: "Passkey non riconosciuta" }, 401, origin, env.WEBAUTHN_ORIGIN);
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: env.WEBAUTHN_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      credential: {
        id: storedCredential.credential_id,
        publicKey: new Uint8Array(storedCredential.public_key),
        counter: Number(storedCredential.sign_count || 0),
        transports: storedCredential.transports ? JSON.parse(storedCredential.transports) : undefined
      },
      requireUserVerification: true
    });
  } catch {
    return json({ error: "Verifica della Passkey non riuscita" }, 401, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!verification.verified) {
    return json({ error: "Autenticazione Passkey non verificata" }, 401, origin, env.WEBAUTHN_ORIGIN);
  }

  await ensureSessionTable(env);
  const sessionToken = randomToken();
  const tokenHash = await sha256Hex(sessionToken);
  const sessionId = crypto.randomUUID();
  const newCounter = Number(verification.authenticationInfo.newCounter || 0);

  try {
    const results = await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO webauthn_sessions (id, user_id, token_hash, challenge_id, expires_at) SELECT ?, ?, ?, ?, unixepoch() + 2592000 WHERE EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = ? AND user_id = ? AND challenge = ? AND purpose = 'master-authentication' AND expires_at > unixepoch())"
      ).bind(sessionId, MASTER_ID, tokenHash, body.challengeId, body.challengeId, MASTER_ID, challenge.challenge),
      env.DB.prepare(
        "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = unixepoch() WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
      ).bind(newCounter, storedCredential.id, MASTER_ID),
      env.DB.prepare(
        "DELETE FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-authentication'"
      ).bind(body.challengeId, MASTER_ID)
    ]);
    if (Number(results?.[0]?.meta?.changes || 0) !== 1) {
      return json({ error: "Richiesta di accesso già utilizzata. Riprova." }, 401, origin, env.WEBAUTHN_ORIGIN);
    }
  } catch {
    return json({ error: "Impossibile creare la sessione. Riprova ad accedere." }, 500, origin, env.WEBAUTHN_ORIGIN);
  }

  return json({
    ok: true,
    verified: true,
    user: master.name,
    role: "master",
    sessionToken,
    expiresIn: 2592000
  }, 200, origin, env.WEBAUTHN_ORIGIN);
}


async function getActiveMasterSession(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!token || token.length > 256) return null;
  await ensureSessionTable(env);
  const tokenHash = await sha256Hex(token);
  const session = await env.DB.prepare(
    "SELECT s.id, u.name, u.role FROM webauthn_sessions s JOIN app_users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.user_id = ? AND s.expires_at > unixepoch() AND s.revoked_at IS NULL AND u.status = 'active' AND u.role = 'master'"
  ).bind(tokenHash, MASTER_ID).first();
  if (!session) return null;
  await env.DB.prepare(
    "UPDATE webauthn_sessions SET last_used_at = unixepoch(), expires_at = unixepoch() + 2592000 WHERE id = ? AND revoked_at IS NULL"
  ).bind(session.id).run();
  return session;
}

function randomPairCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function masterPasskeyPairOptions(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }
  const session = await getActiveMasterSession(request, env);
  if (!session) return json({ error: "Sessione MASTER non valida. Accedi nuovamente." }, 401, origin, env.WEBAUTHN_ORIGIN);

  const credentials = await env.DB.prepare(
    "SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ? AND revoked_at IS NULL"
  ).bind(MASTER_ID).all();
  const rows = credentials.results || [];
  if (!rows.length) return json({ error: "Nessuna Passkey MASTER attiva" }, 404, origin, env.WEBAUTHN_ORIGIN);

  const options = await generateAuthenticationOptions({
    rpID: env.WEBAUTHN_RP_ID,
    timeout: 60000,
    userVerification: "required",
    allowCredentials: rows.map(row => ({
      id: row.credential_id,
      transports: row.transports ? JSON.parse(row.transports) : undefined
    }))
  });
  const challengeId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-passkey-pair-auth', unixepoch() + ?)"
  ).bind(challengeId, MASTER_ID, options.challenge, CHALLENGE_TTL_SECONDS).run();

  return json({ ok: true, challengeId, options }, 200, origin, env.WEBAUTHN_ORIGIN);
}

async function masterPasskeyPairVerify(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }
  const session = await getActiveMasterSession(request, env);
  if (!session) return json({ error: "Sessione MASTER non valida. Accedi nuovamente." }, 401, origin, env.WEBAUTHN_ORIGIN);

  let body;
  try { body = await readJson(request); }
  catch { return json({ error: "Richiesta JSON non valida" }, 400, origin, env.WEBAUTHN_ORIGIN); }
  if (typeof body.challengeId !== "string" || !body.response || typeof body.response.id !== "string") {
    return json({ error: "Dati di conferma incompleti" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  const challenge = await env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-passkey-pair-auth' AND expires_at > unixepoch()"
  ).bind(body.challengeId, MASTER_ID).first();
  if (!challenge) return json({ error: "Richiesta scaduta. Riprova." }, 401, origin, env.WEBAUTHN_ORIGIN);

  const storedCredential = await env.DB.prepare(
    "SELECT id, credential_id, public_key, sign_count, transports FROM webauthn_credentials WHERE credential_id = ? AND user_id = ? AND revoked_at IS NULL"
  ).bind(body.response.id, MASTER_ID).first();
  if (!storedCredential) return json({ error: "Passkey MASTER non riconosciuta" }, 401, origin, env.WEBAUTHN_ORIGIN);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: env.WEBAUTHN_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      credential: {
        id: storedCredential.credential_id,
        publicKey: new Uint8Array(storedCredential.public_key),
        counter: Number(storedCredential.sign_count || 0),
        transports: storedCredential.transports ? JSON.parse(storedCredential.transports) : undefined
      },
      requireUserVerification: true
    });
  } catch {
    return json({ error: "Conferma Windows Hello non riuscita" }, 401, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!verification.verified) return json({ error: "Conferma MASTER non verificata" }, 401, origin, env.WEBAUTHN_ORIGIN);

  const pairingCode = randomPairCode();
  const pairingHash = await sha256Hex(pairingCode);
  const grantId = crypto.randomUUID();
  const newCounter = Number(verification.authenticationInfo.newCounter || 0);
  const results = await env.DB.batch([
    env.DB.prepare(
      "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = unixepoch() WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
    ).bind(newCounter, storedCredential.id, MASTER_ID),
    env.DB.prepare(
      "DELETE FROM webauthn_challenges WHERE user_id = ? AND purpose IN ('master-passkey-add-grant', 'master-passkey-pair-auth')"
    ).bind(MASTER_ID),
    env.DB.prepare(
      "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-passkey-add-grant', unixepoch() + ?)"
    ).bind(grantId, MASTER_ID, pairingHash, CHALLENGE_TTL_SECONDS)
  ]);
  if (Number(results?.[2]?.meta?.changes || 0) !== 1) {
    return json({ error: "Impossibile generare il codice di abbinamento" }, 500, origin, env.WEBAUTHN_ORIGIN);
  }

  return json({ ok: true, pairingCode, expiresIn: CHALLENGE_TTL_SECONDS }, 200, origin, env.WEBAUTHN_ORIGIN);
}

async function masterPasskeyAddOptions(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }
  let body;
  try { body = await readJson(request); }
  catch { return json({ error: "Richiesta JSON non valida" }, 400, origin, env.WEBAUTHN_ORIGIN); }
  const pairingCode = typeof body.pairingCode === "string" ? body.pairingCode.replace(/\s/g, "").toUpperCase() : "";
  if (!/^[A-F0-9]{16}$/.test(pairingCode)) {
    return json({ error: "Codice di abbinamento non valido" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }
  const pairingHash = await sha256Hex(pairingCode);
  const grant = await env.DB.prepare(
    "SELECT id FROM webauthn_challenges WHERE user_id = ? AND challenge = ? AND purpose = 'master-passkey-add-grant' AND expires_at > unixepoch()"
  ).bind(MASTER_ID, pairingHash).first();
  if (!grant) return json({ error: "Codice scaduto, errato o già utilizzato. Generane uno nuovo dal PC." }, 401, origin, env.WEBAUTHN_ORIGIN);

  const existing = await env.DB.prepare(
    "SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ? AND revoked_at IS NULL"
  ).bind(MASTER_ID).all();
  const options = await generateRegistrationOptions({
    rpName: env.WEBAUTHN_RP_NAME,
    rpID: env.WEBAUTHN_RP_ID,
    userID: new TextEncoder().encode(MASTER_ID),
    userName: "Alessandro",
    userDisplayName: "Alessandro - MASTER",
    attestationType: "none",
    timeout: 60000,
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required"
    },
    excludeCredentials: (existing.results || []).map(row => ({
      id: row.credential_id,
      transports: row.transports ? JSON.parse(row.transports) : undefined
    })),
    supportedAlgorithmIDs: [-7, -257]
  });
  const challengeId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-passkey-add-registration', unixepoch() + ?)"
  ).bind(challengeId, MASTER_ID, options.challenge, CHALLENGE_TTL_SECONDS).run();

  return json({ ok: true, challengeId, options }, 200, origin, env.WEBAUTHN_ORIGIN);
}

async function masterPasskeyAddVerify(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }
  let body;
  try { body = await readJson(request); }
  catch { return json({ error: "Richiesta JSON non valida" }, 400, origin, env.WEBAUTHN_ORIGIN); }
  const pairingCode = typeof body.pairingCode === "string" ? body.pairingCode.replace(/\s/g, "").toUpperCase() : "";
  if (
    !/^[A-F0-9]{16}$/.test(pairingCode) ||
    typeof body.challengeId !== "string" ||
    !body.response ||
    typeof body.response.id !== "string"
  ) {
    return json({ error: "Dati di registrazione incompleti" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  const pairingHash = await sha256Hex(pairingCode);
  const grant = await env.DB.prepare(
    "SELECT id FROM webauthn_challenges WHERE user_id = ? AND challenge = ? AND purpose = 'master-passkey-add-grant' AND expires_at > unixepoch()"
  ).bind(MASTER_ID, pairingHash).first();
  if (!grant) return json({ error: "Codice scaduto, errato o già utilizzato. Generane uno nuovo dal PC." }, 401, origin, env.WEBAUTHN_ORIGIN);

  const challenge = await env.DB.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-passkey-add-registration' AND expires_at > unixepoch()"
  ).bind(body.challengeId, MASTER_ID).first();
  if (!challenge) return json({ error: "Richiesta di registrazione scaduta. Inserisci nuovamente il codice." }, 401, origin, env.WEBAUTHN_ORIGIN);

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: env.WEBAUTHN_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      requireUserVerification: true
    });
  } catch {
    return json({ error: "Verifica della nuova Passkey non riuscita" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }
  if (!verification.verified || !verification.registrationInfo) {
    return json({ error: "Nuova Passkey non verificata" }, 400, origin, env.WEBAUTHN_ORIGIN);
  }

  const credential = verification.registrationInfo.credential;
  const transports = Array.isArray(credential.transports) ? JSON.stringify(credential.transports) : null;
  const results = await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, device_name) SELECT ?, ?, ?, ?, ?, ?, 'MASTER dispositivo aggiuntivo' WHERE EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-passkey-add-registration' AND challenge = ? AND expires_at > unixepoch()) AND EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = ? AND user_id = ? AND challenge = ? AND purpose = 'master-passkey-add-grant' AND expires_at > unixepoch()) AND NOT EXISTS (SELECT 1 FROM webauthn_credentials WHERE credential_id = ?)"
    ).bind(
      crypto.randomUUID(), MASTER_ID, credential.id, credential.publicKey, credential.counter, transports,
      body.challengeId, MASTER_ID, challenge.challenge, grant.id, MASTER_ID, pairingHash, credential.id
    ),
    env.DB.prepare(
      "DELETE FROM webauthn_challenges WHERE user_id = ? AND ((id = ? AND purpose = 'master-passkey-add-registration') OR (id = ? AND purpose = 'master-passkey-add-grant')) AND EXISTS (SELECT 1 FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?)"
    ).bind(MASTER_ID, body.challengeId, grant.id, credential.id, MASTER_ID)
  ]);
  if (Number(results?.[0]?.meta?.changes || 0) !== 1) {
    return json({ error: "Codice già utilizzato, scaduto o Passkey già registrata" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  return json({
    ok: true,
    verified: true,
    user: "Alessandro",
    role: "master",
    credentialSaved: true,
    pairingGrantConsumed: true
  }, 200, origin, env.WEBAUTHN_ORIGIN);
}


async function checkFamilyRateLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
  const ipHash = Array.from(new Uint8Array(digest)).map(v => v.toString(16).padStart(2, "0")).join("");
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, NULL, ?, 'family-access-attempt', unixepoch() + ?)"
  ).bind(crypto.randomUUID(), ipHash, RATE_WINDOW_SECONDS).run();
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM webauthn_challenges WHERE purpose = 'family-access-attempt' AND challenge = ? AND created_at >= unixepoch() - ?"
  ).bind(ipHash, RATE_WINDOW_SECONDS).first();
  await env.DB.prepare(
    "DELETE FROM webauthn_challenges WHERE purpose = 'family-access-attempt' AND expires_at <= unixepoch()"
  ).run();
  return Number(count?.total || 0) <= RATE_LIMIT;
}

async function familyRegistrationOptions(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  if (!(await checkFamilyRateLimit(request,env))) return json({error:"Troppi tentativi. Riprova più tardi."},429,origin,env.WEBAUTHN_ORIGIN);
  let body;
  try { body = await readJson(request); } catch { return json({error:"Richiesta non valida"},400,origin,env.WEBAUTHN_ORIGIN); }
  const name = typeof body.name === "string" ? body.name.trim().replace(/\s+/g," ").slice(0,50) : "";
  if (name.length < 2) return json({error:"Inserisci il nome del familiare (almeno 2 caratteri)."},400,origin,env.WEBAUTHN_ORIGIN);
  const existing = await env.DB.prepare(
    "SELECT id, status FROM app_users WHERE role = 'family' AND lower(name) = lower(?) AND status IN ('pending','active') LIMIT 1"
  ).bind(name).first();
  if (existing) return json({error: existing.status === "pending" ? "Esiste già una richiesta con questo nome." : "Questo familiare risulta già autorizzato."},409,origin,env.WEBAUTHN_ORIGIN);
  const userId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO app_users (id,name,role,status) VALUES (?,?,'family','pending')"
  ).bind(userId,name).run();
  const options = await generateRegistrationOptions({
    rpName: env.WEBAUTHN_RP_NAME || "Casa Santini",
    rpID: env.WEBAUTHN_RP_ID,
    userID: new TextEncoder().encode(userId),
    userName: userId,
    userDisplayName: name,
    attestationType: "none",
    timeout: 60000,
    authenticatorSelection: { residentKey:"required", userVerification:"required" },
    supportedAlgorithmIDs: [-7,-257]
  });
  const challengeId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO webauthn_challenges (id,user_id,challenge,purpose,expires_at) VALUES (?,?,?,'family-registration',unixepoch()+?)"
  ).bind(challengeId,userId,options.challenge,CHALLENGE_TTL_SECONDS).run();
  return json({ok:true,userId,challengeId,options},200,origin,env.WEBAUTHN_ORIGIN);
}

async function familyRegistrationVerify(request, env, origin) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  if (!(await checkFamilyRateLimit(request,env))) return json({error:"Troppi tentativi. Riprova più tardi."},429,origin,env.WEBAUTHN_ORIGIN);
  let body;
  try { body=await readJson(request); } catch { return json({error:"Richiesta non valida"},400,origin,env.WEBAUTHN_ORIGIN); }
  if (typeof body.userId!=="string" || typeof body.challengeId!=="string" || !body.response || typeof body.response.id!=="string")
    return json({error:"Dati di registrazione incompleti"},400,origin,env.WEBAUTHN_ORIGIN);
  const user=await env.DB.prepare("SELECT id,name,status,role FROM app_users WHERE id=? AND role='family'").bind(body.userId).first();
  if (!user || user.status!=="pending") return json({error:"Richiesta familiare non più valida."},404,origin,env.WEBAUTHN_ORIGIN);
  const challenge=await env.DB.prepare("SELECT challenge FROM webauthn_challenges WHERE id=? AND user_id=? AND purpose='family-registration' AND expires_at>unixepoch()").bind(body.challengeId,body.userId).first();
  if (!challenge) return json({error:"Registrazione scaduta. Ripeti la richiesta."},401,origin,env.WEBAUTHN_ORIGIN);
  let verification;
  try {
    verification=await verifyRegistrationResponse({
      response:body.response, expectedChallenge:challenge.challenge,
      expectedOrigin:env.WEBAUTHN_ORIGIN, expectedRPID:env.WEBAUTHN_RP_ID,
      requireUserVerification:true
    });
  } catch { return json({error:"Verifica della Passkey non riuscita."},400,origin,env.WEBAUTHN_ORIGIN); }
  if (!verification.verified || !verification.registrationInfo) return json({error:"Passkey non verificata."},400,origin,env.WEBAUTHN_ORIGIN);
  const credential=verification.registrationInfo.credential;
  const transports=Array.isArray(credential.transports)?JSON.stringify(credential.transports):null;
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO webauthn_credentials (id,user_id,credential_id,public_key,sign_count,transports,device_name) SELECT ?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM app_users WHERE id=? AND role='family' AND status='pending') AND EXISTS (SELECT 1 FROM webauthn_challenges WHERE id=? AND user_id=? AND purpose='family-registration' AND expires_at>unixepoch())")
        .bind(crypto.randomUUID(),body.userId,credential.id,credential.publicKey,credential.counter,transports,user.name,body.userId,body.challengeId,body.userId),
      env.DB.prepare("DELETE FROM webauthn_challenges WHERE id=? AND user_id=? AND purpose='family-registration'").bind(body.challengeId,body.userId)
    ]);
  } catch { return json({error:"Impossibile salvare la Passkey. Potrebbe essere già registrata."},409,origin,env.WEBAUTHN_ORIGIN); }
  return json({ok:true,pendingApproval:true,message:"Richiesta inviata. Attendi l'approvazione del MASTER."},200,origin,env.WEBAUTHN_ORIGIN);
}

async function familyAuthenticationOptions(request, env, origin) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  if (!(await checkFamilyRateLimit(request,env))) return json({error:"Troppi tentativi. Riprova più tardi."},429,origin,env.WEBAUTHN_ORIGIN);
  let body;
  try { body=await readJson(request); } catch { return json({error:"Richiesta non valida"},400,origin,env.WEBAUTHN_ORIGIN); }
  const name=typeof body.name==="string"?body.name.trim().replace(/\s+/g," ").slice(0,50):"";
  if (!name) return json({error:"Inserisci il nome."},400,origin,env.WEBAUTHN_ORIGIN);
  const user=await env.DB.prepare("SELECT id,name,status FROM app_users WHERE role='family' AND lower(name)=lower(?) LIMIT 1").bind(name).first();
  if (!user || user.status!=="active") return json({error:"Accesso non ancora autorizzato. Se hai appena inviato la richiesta, attendi l'approvazione del MASTER."},403,origin,env.WEBAUTHN_ORIGIN);
  const creds=await env.DB.prepare("SELECT credential_id,transports FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL").bind(user.id).all();
  const rows=creds.results||[];
  if (!rows.length) return json({error:"Nessuna Passkey attiva per questo account."},403,origin,env.WEBAUTHN_ORIGIN);
  const options=await generateAuthenticationOptions({
    rpID:env.WEBAUTHN_RP_ID,timeout:60000,userVerification:"required",
    allowCredentials:rows.map(row=>({id:row.credential_id,transports:row.transports?JSON.parse(row.transports):undefined}))
  });
  const challengeId=crypto.randomUUID();
  await env.DB.prepare("INSERT INTO webauthn_challenges (id,user_id,challenge,purpose,expires_at) VALUES (?,?,?,'family-authentication',unixepoch()+?)").bind(challengeId,user.id,options.challenge,CHALLENGE_TTL_SECONDS).run();
  return json({ok:true,userId:user.id,challengeId,options},200,origin,env.WEBAUTHN_ORIGIN);
}

async function familyAuthenticationVerify(request, env, origin) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  if (!(await checkFamilyRateLimit(request,env))) return json({error:"Troppi tentativi. Riprova più tardi."},429,origin,env.WEBAUTHN_ORIGIN);
  let body;
  try { body=await readJson(request); } catch { return json({error:"Richiesta non valida"},400,origin,env.WEBAUTHN_ORIGIN); }
  if (typeof body.userId!=="string" || typeof body.challengeId!=="string" || !body.response || typeof body.response.id!=="string")
    return json({error:"Dati di accesso incompleti"},400,origin,env.WEBAUTHN_ORIGIN);
  const user=await env.DB.prepare("SELECT id,name,status FROM app_users WHERE id=? AND role='family' AND status='active'").bind(body.userId).first();
  if (!user) return json({error:"Account familiare non autorizzato."},403,origin,env.WEBAUTHN_ORIGIN);
  const challenge=await env.DB.prepare("SELECT challenge FROM webauthn_challenges WHERE id=? AND user_id=? AND purpose='family-authentication' AND expires_at>unixepoch()").bind(body.challengeId,user.id).first();
  if (!challenge) return json({error:"Richiesta scaduta. Riprova."},401,origin,env.WEBAUTHN_ORIGIN);
  const stored=await env.DB.prepare("SELECT id,credential_id,public_key,sign_count,transports FROM webauthn_credentials WHERE credential_id=? AND user_id=? AND revoked_at IS NULL").bind(body.response.id,user.id).first();
  if (!stored) return json({error:"Passkey non riconosciuta."},401,origin,env.WEBAUTHN_ORIGIN);
  let verification;
  try {
    verification=await verifyAuthenticationResponse({
      response:body.response,expectedChallenge:challenge.challenge,
      expectedOrigin:env.WEBAUTHN_ORIGIN,expectedRPID:env.WEBAUTHN_RP_ID,
      credential:{id:stored.credential_id,publicKey:new Uint8Array(stored.public_key),counter:Number(stored.sign_count||0),transports:stored.transports?JSON.parse(stored.transports):undefined},
      requireUserVerification:true
    });
  } catch { return json({error:"Verifica della Passkey non riuscita."},401,origin,env.WEBAUTHN_ORIGIN); }
  if (!verification.verified) return json({error:"Autenticazione non verificata."},401,origin,env.WEBAUTHN_ORIGIN);
  await ensureSessionTable(env);
  const sessionToken=randomToken(),tokenHash=await sha256Hex(sessionToken),sessionId=crypto.randomUUID();
  const results=await env.DB.batch([
    env.DB.prepare("INSERT INTO webauthn_sessions (id,user_id,token_hash,challenge_id,expires_at) SELECT ?,?,?,?,unixepoch()+2592000 WHERE EXISTS (SELECT 1 FROM webauthn_challenges WHERE id=? AND user_id=? AND challenge=? AND purpose='family-authentication' AND expires_at>unixepoch()) AND EXISTS (SELECT 1 FROM app_users WHERE id=? AND status='active' AND role='family')")
      .bind(sessionId,user.id,tokenHash,body.challengeId,body.challengeId,user.id,challenge.challenge,user.id),
    env.DB.prepare("UPDATE webauthn_credentials SET sign_count=?,last_used_at=unixepoch() WHERE id=? AND user_id=? AND revoked_at IS NULL").bind(Number(verification.authenticationInfo.newCounter||0),stored.id,user.id),
    env.DB.prepare("DELETE FROM webauthn_challenges WHERE id=? AND user_id=? AND purpose='family-authentication'").bind(body.challengeId,user.id)
  ]);
  if (Number(results?.[0]?.meta?.changes||0)!==1) return json({error:"Richiesta già utilizzata. Riprova."},401,origin,env.WEBAUTHN_ORIGIN);
  return json({ok:true,verified:true,user:user.name,role:"family",sessionToken,expiresIn:2592000},200,origin,env.WEBAUTHN_ORIGIN);
}

async function familySessionStatus(request, env, origin) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  const auth=request.headers.get("Authorization")||"",token=auth.startsWith("Bearer ")?auth.slice(7):"";
  if (!token||token.length>256) return json({authenticated:false},401,origin,env.WEBAUTHN_ORIGIN);
  await ensureSessionTable(env);
  const hash=await sha256Hex(token);
  const session=await env.DB.prepare("SELECT s.id,u.name,u.role FROM webauthn_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>unixepoch() AND s.revoked_at IS NULL AND u.status='active' AND u.role='family'").bind(hash).first();
  if (!session) return json({authenticated:false},401,origin,env.WEBAUTHN_ORIGIN);
  await env.DB.prepare("UPDATE webauthn_sessions SET last_used_at=unixepoch(),expires_at=unixepoch()+2592000 WHERE id=? AND revoked_at IS NULL").bind(session.id).run();
  return json({authenticated:true,user:session.name,role:"family",expiresIn:2592000},200,origin,env.WEBAUTHN_ORIGIN);
}

async function familySessionLogout(request, env, origin) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  const auth=request.headers.get("Authorization")||"",token=auth.startsWith("Bearer ")?auth.slice(7):"";
  if (!token||token.length>256) return json({ok:true,revoked:false},200,origin,env.WEBAUTHN_ORIGIN);
  await ensureSessionTable(env);
  const hash=await sha256Hex(token);
  const result=await env.DB.prepare("UPDATE webauthn_sessions SET revoked_at=unixepoch() WHERE token_hash=? AND revoked_at IS NULL AND user_id IN (SELECT id FROM app_users WHERE role='family')").bind(hash).run();
  return json({ok:true,revoked:Number(result?.meta?.changes||0)===1},200,origin,env.WEBAUTHN_ORIGIN);
}

async function masterFamilyList(request, env, origin, status) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  const master=await getActiveMasterSession(request,env);
  if (!master) return json({error:"Sessione MASTER non valida."},401,origin,env.WEBAUTHN_ORIGIN);
  const rows=await env.DB.prepare(
    "SELECT u.id,u.name,u.status,u.rowid AS created_order,(SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id=u.id AND c.revoked_at IS NULL) AS credentials FROM app_users u WHERE u.role='family' AND u.status=? ORDER BY u.rowid DESC"
  ).bind(status).all();
  return json({ok:true,users:rows.results||[]},200,origin,env.WEBAUTHN_ORIGIN);
}

async function masterFamilyDecision(request, env, origin, action) {
  if (!allowedRequestOrigin(request,env)) return json({error:"Origine non autorizzata"},403,origin,env.WEBAUTHN_ORIGIN);
  const master=await getActiveMasterSession(request,env);
  if (!master) return json({error:"Sessione MASTER non valida."},401,origin,env.WEBAUTHN_ORIGIN);
  let body;
  try { body=await readJson(request); } catch { return json({error:"Richiesta non valida"},400,origin,env.WEBAUTHN_ORIGIN); }
  if (typeof body.userId!=="string") return json({error:"Utente non valido"},400,origin,env.WEBAUTHN_ORIGIN);
  if (action==="approve") {
    const result=await env.DB.prepare("UPDATE app_users SET status='active' WHERE id=? AND role='family' AND status='pending' AND EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=? AND revoked_at IS NULL)").bind(body.userId,body.userId).run();
    if (Number(result?.meta?.changes||0)!==1) return json({error:"Richiesta non trovata o Passkey mancante."},404,origin,env.WEBAUTHN_ORIGIN);
  } else if (action==="reject") {
    await env.DB.batch([
      env.DB.prepare("UPDATE app_users SET status='rejected' WHERE id=? AND role='family' AND status='pending'").bind(body.userId),
      env.DB.prepare("DELETE FROM webauthn_credentials WHERE user_id=?").bind(body.userId)
    ]);
  } else if (action==="revoke") {
    await env.DB.batch([
      env.DB.prepare("UPDATE app_users SET status='revoked' WHERE id=? AND role='family' AND status='active'").bind(body.userId),
      env.DB.prepare("UPDATE webauthn_sessions SET revoked_at=unixepoch() WHERE user_id=? AND revoked_at IS NULL").bind(body.userId)
    ]);
  } else return json({error:"Operazione non valida"},400,origin,env.WEBAUTHN_ORIGIN);
  return json({ok:true,action},200,origin,env.WEBAUTHN_ORIGIN);
}

async function masterSessionStatus(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!token || token.length > 256) {
    return json({ authenticated: false }, 401, origin, env.WEBAUTHN_ORIGIN);
  }
  await ensureSessionTable(env);
  const tokenHash = await sha256Hex(token);
  const session = await env.DB.prepare(
    "SELECT s.id, u.name, u.role FROM webauthn_sessions s JOIN app_users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.user_id = ? AND s.expires_at > unixepoch() AND s.revoked_at IS NULL AND u.status = 'active' AND u.role = 'master'"
  ).bind(tokenHash, MASTER_ID).first();
  if (!session) {
    return json({ authenticated: false }, 401, origin, env.WEBAUTHN_ORIGIN);
  }
  await env.DB.prepare(
    "UPDATE webauthn_sessions SET last_used_at = unixepoch(), expires_at = unixepoch() + 2592000 WHERE id = ? AND revoked_at IS NULL"
  ).bind(session.id).run();
  return json({ authenticated: true, user: session.name, role: session.role, expiresIn: 2592000 }, 200, origin, env.WEBAUTHN_ORIGIN);
}

async function masterSessionLogout(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!token || token.length > 256) {
    return json({ ok: true, revoked: false }, 200, origin, env.WEBAUTHN_ORIGIN);
  }
  await ensureSessionTable(env);
  const tokenHash = await sha256Hex(token);
  const result = await env.DB.prepare(
    "UPDATE webauthn_sessions SET revoked_at = unixepoch() WHERE token_hash = ? AND user_id = ? AND revoked_at IS NULL"
  ).bind(tokenHash, MASTER_ID).run();
  return json({ ok: true, revoked: Number(result?.meta?.changes || 0) === 1 }, 200, origin, env.WEBAUTHN_ORIGIN);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      if (!allowedRequestOrigin(request, env)) {
        return new Response(null, { status: 403 });
      }

      const headers = new Headers({
        "Access-Control-Allow-Origin": env.WEBAUTHN_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin"
      });
      return new Response(null, { status: 204, headers });
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        service: "casa-smart-api-webauthn-preview",
        status: "preparation-only",
        productionConnected: false
      }, 200, origin, env.WEBAUTHN_ORIGIN);
    }

    if (request.method === "GET" && url.pathname === "/health/db") {
      try {
        const row = await env.DB.prepare("SELECT 1 AS ok").first();
        return json({
          ok: row?.ok === 1,
          database: row?.ok === 1 ? "connected" : "unexpected-response",
          service: "casa-smart-api-webauthn-preview",
          productionConnected: false
        }, row?.ok === 1 ? 200 : 500, origin, env.WEBAUTHN_ORIGIN);
      } catch {
        return json({
          ok: false,
          database: "error",
          service: "casa-smart-api-webauthn-preview",
          productionConnected: false
        }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/register/options") {
      try {
        return await masterRegistrationOptions(request, env, origin);
      } catch {
        return json({ error: "Errore interno durante la preparazione della registrazione" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/register/verify") {
      try {
        return await verifyMasterRegistration(request, env, origin);
      } catch {
        return json({ error: "Errore interno durante la verifica della Passkey" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }


    if (request.method === "POST" && url.pathname === "/webauthn/master/authenticate/options") {
      try {
        return await masterAuthenticationOptions(request, env, origin);
      } catch {
        return json({ error: "Errore interno durante la preparazione dell'accesso" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/authenticate/verify") {
      try {
        return await verifyMasterAuthentication(request, env, origin);
      } catch {
        return json({ error: "Errore interno durante la verifica dell'accesso" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/passkey-pair/options") {
      try {
        return await masterPasskeyPairOptions(request, env, origin);
      } catch {
        return json({ error: "Errore durante la preparazione dell'abbinamento" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/passkey-pair/verify") {
      try {
        return await masterPasskeyPairVerify(request, env, origin);
      } catch {
        return json({ error: "Errore durante la conferma MASTER" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/passkey-add/options") {
      try {
        return await masterPasskeyAddOptions(request, env, origin);
      } catch {
        return json({ error: "Errore durante la preparazione della nuova Passkey" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/passkey-add/verify") {
      try {
        return await masterPasskeyAddVerify(request, env, origin);
      } catch {
        return json({ error: "Errore durante la verifica della nuova Passkey" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }


    if (request.method === "POST" && url.pathname === "/webauthn/family/register/options") {
      try { return await familyRegistrationOptions(request,env,origin); }
      catch { return json({error:"Errore durante la preparazione della registrazione familiare."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/webauthn/family/register/verify") {
      try { return await familyRegistrationVerify(request,env,origin); }
      catch { return json({error:"Errore durante la verifica della Passkey familiare."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/webauthn/family/authenticate/options") {
      try { return await familyAuthenticationOptions(request,env,origin); }
      catch { return json({error:"Errore durante la preparazione dell'accesso familiare."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/webauthn/family/authenticate/verify") {
      try { return await familyAuthenticationVerify(request,env,origin); }
      catch { return json({error:"Errore durante la verifica dell'accesso familiare."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "GET" && url.pathname === "/webauthn/family/session") {
      try { return await familySessionStatus(request,env,origin); }
      catch { return json({error:"Errore durante il controllo della sessione familiare."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/webauthn/family/logout") {
      try { return await familySessionLogout(request,env,origin); }
      catch { return json({error:"Errore durante la chiusura della sessione familiare."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "GET" && url.pathname === "/admin/family/requests") {
      try { return await masterFamilyList(request,env,origin,"pending"); }
      catch { return json({error:"Errore nel caricamento delle richieste."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "GET" && url.pathname === "/admin/family/users") {
      try { return await masterFamilyList(request,env,origin,"active"); }
      catch { return json({error:"Errore nel caricamento dei familiari."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/admin/family/approve") {
      try { return await masterFamilyDecision(request,env,origin,"approve"); }
      catch { return json({error:"Errore durante l'approvazione."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/admin/family/reject") {
      try { return await masterFamilyDecision(request,env,origin,"reject"); }
      catch { return json({error:"Errore durante il rifiuto."},500,origin,env.WEBAUTHN_ORIGIN); }
    }
    if (request.method === "POST" && url.pathname === "/admin/family/revoke") {
      try { return await masterFamilyDecision(request,env,origin,"revoke"); }
      catch { return json({error:"Errore durante la revoca."},500,origin,env.WEBAUTHN_ORIGIN); }
    }

    if (request.method === "GET" && url.pathname === "/webauthn/master/session") {
      try {
        return await masterSessionStatus(request, env, origin);
      } catch {
        return json({ error: "Errore interno durante il controllo della sessione" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    if (request.method === "POST" && url.pathname === "/webauthn/master/logout") {
      try {
        return await masterSessionLogout(request, env, origin);
      } catch {
        return json({ error: "Errore interno durante la chiusura della sessione" }, 500, origin, env.WEBAUTHN_ORIGIN);
      }
    }

    return json({
      error: "Endpoint non disponibile nel Preview di preparazione",
      productionConnected: false
    }, 404, origin, env.WEBAUTHN_ORIGIN);
  }
};
