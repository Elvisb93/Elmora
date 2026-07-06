# Elmora

A small production-ready Next.js landing page for Elmora, designed for deployment on a free `vercel.app` domain and for Google OAuth testing/verification.

## Pages

- `/` — landing page
- `/privacy` — privacy policy
- `/terms` — terms of service
- `/connect/google` — Google OAuth connect preview screen
- `/oauth/google/callback` — server-side OAuth callback screen

## Local development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

## Vercel deployment

Import this repository into Vercel and deploy with the default Next.js settings. Vercel will provide a free `*.vercel.app` deployment domain.

No Google client secret is stored in this repo. When implementing the real OAuth flow, store secrets only in Vercel environment variables and perform token exchange server-side.

Optional public env vars for UI-only preview behavior:

```bash
NEXT_PUBLIC_SITE_URL=https://your-elmora-site.vercel.app
NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
```

The public Google OAuth client ID can safely appear in browser code. The Google OAuth client secret must never be committed or exposed to the browser.

Server-only env var for the callback token exchange:

```bash
GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret
```

The demo callback has the public Google OAuth client ID configured in code and can exchange an authorization code server-side when the secret variable is configured.

Optional server-only env vars for writing `google_token.json` into a client runtime via a storage webhook:

```bash
ELMORA_CLIENT_RUNTIME_ID=elmora-demo
ELMORA_TOKEN_WEBHOOK_URL=https://your-client-runtime.example.com/oauth/google/token
ELMORA_TOKEN_WEBHOOK_SECRET=shared-webhook-secret
```

If no token webhook is configured, a successful OAuth exchange is proved and the token is discarded. Do not put Google client secrets, refresh tokens, or webhook secrets in public `NEXT_PUBLIC_*` variables.
