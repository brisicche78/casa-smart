# Casa Smart API — preparazione Passkey

Questa cartella contiene il progetto Cloudflare Worker separato dalla PWA.

## Stato

- Progetto isolato nel branch `webauthn-prep`.
- Worker configurato con nome dedicato `casa-smart-api-webauthn-preview`.
- Dipendenza WebAuthn: `@simplewebauthn/server` 14.1.0.
- Wrangler 4.135.0 o superiore, necessario per Worker Previews.
- Il file attuale `src/index.js` è solo un segnaposto sicuro: non espone i comandi Shelly e non usa il database di produzione.

## Sicurezza

Non collegare questa configurazione al Worker di produzione e non inserire segreti nel repository.
Prima di collegare Workers Builds occorre configurare una Preview isolata, con un database D1 di test e segreti di test. Il ramo `main` della PWA non viene modificato da questo progetto.

## Prossimi passaggi

1. Integrare e verificare il codice Worker esistente.
2. Implementare i flussi WebAuthn di registrazione e autenticazione.
3. Configurare database e segreti esclusivamente per Preview.
4. Testare revoca, scadenza challenge, origin, RP ID, firma e contatore.
5. Solo dopo approvazione esplicita valutare il rilascio in produzione.

