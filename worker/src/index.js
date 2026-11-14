// CASA SMART API — isolated WebAuthn preparation preview.
// This is deliberately NOT the production API.
// The production Shelly endpoints and credentials are not connected here.

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "casa-smart-api-webauthn-preview",
        status: "preparation-only",
        productionConnected: false
      });
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
