// CASA SMART API — isolated WebAuthn preparation preview.
// This is deliberately NOT the production API.
// The production Shelly endpoints and credentials are not connected here.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "casa-smart-api-webauthn-preview",
        status: "preparation-only",
        productionConnected: false
      });
    }

    // Safe read-only check: confirms that the isolated Preview D1 binding works.
    if (request.method === "GET" && url.pathname === "/health/db") {
      try {
        const row = await env.DB.prepare("SELECT 1 AS ok").first();
        return Response.json({
          ok: row?.ok === 1,
          database: row?.ok === 1 ? "connected" : "unexpected-response",
          service: "casa-smart-api-webauthn-preview",
          productionConnected: false
        }, { status: row?.ok === 1 ? 200 : 500 });
      } catch {
        return Response.json({
          ok: false,
          database: "error",
          service: "casa-smart-api-webauthn-preview",
          productionConnected: false
        }, { status: 500 });
      }
    }

    return Response.json(
      {
        error: "Preview di preparazione: API non ancora attiva",
        productionConnected: false
      },
      { status: 503 }
    );
  }
};
