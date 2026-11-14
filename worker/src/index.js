// CASA SMART API — isolated WebAuthn preparation preview.
// This is deliberately NOT the production API.
// The production Shelly endpoints and credentials are not connected here.

import {
  generateRegistrationOptions,
  verifyRegistrationResponse
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

async function masterRegistrationOptions(request, env, origin) {
  if (!allowedRequestOrigin(request, env)) {
    return json({ error: "Origine non autorizzata" }, 403, origin, env.WEBAUTHN_ORIGIN);
  }

  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Troppi tentativi. Riprova più tardi." }, 429, origin, env.WEBAUTHN_ORIGIN);
  }

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

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO app_users (id, name, role, status) VALUES (?, 'Alessandro', 'master', 'active') ON CONFLICT(id) DO NOTHING"
    ).bind(MASTER_ID),
    env.DB.prepare(
      "INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at) VALUES (?, ?, ?, 'master-registration', unixepoch() + ?)"
    ).bind(challengeId, MASTER_ID, options.challenge, CHALLENGE_TTL_SECONDS)
  ]);

  return json({
    ok: true,
    challengeId,
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

  if (!hasEnrollmentSecret(request, env)) {
    return json({ error: "Autorizzazione non valida" }, 401, origin, env.WEBAUTHN_ORIGIN);
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
    return json({ error: "Dati di registrazione incompleti" }, 400, origin, env.WEBAUTHN_ORIGIN);
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

  const results = await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, device_name) SELECT ?, ?, ?, ?, ?, ?, 'MASTER' WHERE EXISTS (SELECT 1 FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-registration' AND expires_at > unixepoch()) AND NOT EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ?)"
    ).bind(
      crypto.randomUUID(),
      MASTER_ID,
      credential.id,
      credential.publicKey,
      credential.counter,
      transports,
      body.challengeId,
      MASTER_ID,
      MASTER_ID
    ),
    env.DB.prepare(
      "DELETE FROM webauthn_challenges WHERE id = ? AND user_id = ? AND purpose = 'master-registration'"
    ).bind(body.challengeId, MASTER_ID)
  ]);

  const inserted = Number(results?.[0]?.meta?.changes || 0);
  if (inserted !== 1) {
    return json({ error: "Registrazione già completata o challenge non più valida" }, 409, origin, env.WEBAUTHN_ORIGIN);
  }

  return json({
    ok: true,
    verified: true,
    user: "Alessandro",
    role: "master",
    credentialSaved: true,
    nextStep: "master-passkey-created"
  }, 200, origin, env.WEBAUTHN_ORIGIN);
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

    return json({
      error: "Endpoint non disponibile nel Preview di preparazione",
      productionConnected: false
    }, 404, origin, env.WEBAUTHN_ORIGIN);
  }
};
