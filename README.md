# Elmora

A small production-ready Next.js landing page for Elmora, designed for deployment on a free `vercel.app` domain and for Google OAuth testing/verification.

## Pages

- `/` — landing page
- `/privacy` — privacy policy
- `/terms` — terms of service
- `/connect/google` — placeholder Google OAuth connect screen
- `/oauth/google/callback` — placeholder OAuth callback screen

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

Optional public env vars for UI-only placeholder behavior:

```bash
NEXT_PUBLIC_SITE_URL=https://your-elmora-site.vercel.app
NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
```

The real OAuth connector still needs a server-side callback/token exchange service. Do not put Google client secrets or refresh tokens in public `NEXT_PUBLIC_*` variables.
