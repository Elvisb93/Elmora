# Elmora

A small production-ready Next.js landing page for Elmora, designed for deployment on a free `vercel.app` domain and for Google OAuth testing/verification.

## Pages

- `/` — landing page
- `/privacy` — privacy policy
- `/terms` — terms of service
- `/connect/google?runtime=<runtime-id>` — signed Google OAuth connect screen for a specific client runtime
- `/oauth/google/callback` — server-side OAuth callback screen

## Local development

```bash
npm install
npm run dev
```

## Build

```bash
npm test
npm run typecheck
npm run build
```

## Vercel deployment

Import this repository into Vercel and deploy with the default Next.js settings. Vercel will provide a free `*.vercel.app` deployment domain.

No Google client secret is stored in this repo. Store secrets only in Vercel environment variables and perform token exchange server-side.

Optional public env vars for UI-only preview behavior:

```bash
NEXT_PUBLIC_SITE_URL=https://your-elmora-site.vercel.app
NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
```

The public Google OAuth client ID can safely appear in browser code. The Google OAuth client secret must never be committed or exposed to the browser.

Server-only env vars for multi-client-safe OAuth:

```bash
GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret
ELMORA_STATE_SIGNING_SECRET=at-least-32-random-characters
ELMORA_ALLOWED_RUNTIME_IDS=elmora-demo,client-a,client-b
```

The Connect page signs the selected `runtime` into the OAuth `state` value. The callback verifies the state signature, expiry, and runtime allowlist before exchanging the Google code or routing tokens.

Server-only env vars for writing `google_token.json` into a client runtime via a storage webhook:

```bash
ELMORA_TOKEN_WEBHOOK_URL=https://your-client-runtime.example.com/oauth/google/token
ELMORA_TOKEN_WEBHOOK_SECRET=shared-webhook-secret
```

The callback sends the verified `runtimeId` plus a Hermes-compatible `google_token.json` payload to the webhook. The receiver must map runtime IDs to fixed server-side Hermes home paths and reject arbitrary paths. If no token webhook is configured, a successful OAuth exchange is proved and the token is discarded. Do not put Google client secrets, refresh tokens, signing secrets, or webhook secrets in public `NEXT_PUBLIC_*` variables.
