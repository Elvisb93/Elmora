# Elmora

A small production-ready Next.js landing page for Elmora, designed for deployment on a free `vercel.app` domain and for Google OAuth testing/verification.

## Pages

- `/` — landing page
- `/privacy` — privacy policy
- `/terms` — terms of service
- `/connect/google?runtime=<runtime-id>` — debug-only signed Google OAuth connect screen for a specific client runtime
- `/connect/google/[token]` — private one-time Google OAuth connect page created for an agent/client request
- `/api/connect-sessions` — agent-authenticated API for creating one-time connect links
- `/api/connect-sessions/[sessionId]/status` — agent-authenticated status check for a connect session
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

The legacy/debug Connect page signs the selected `runtime` into the OAuth `state` value. The production one-time link flow signs a `connectSessionId` into `state`; the callback then resolves the runtime from Vercel KV session metadata, not from the browser URL.

## Agent-created one-time connect links

Elmora’s preferred no-portal flow is:

1. The client asks their agent to connect Google.
2. The agent calls `POST /api/connect-sessions` with its private bearer secret.
3. Elmora creates a short-lived Vercel KV session and returns `/connect/google/[token]`.
4. The client opens that private link, sees the client/agent identity, and authorises Google.
5. The callback verifies signed state, verifies the Google account email/domain, stores `google_token.json` into the mapped runtime, then marks the session used and deletes the public token lookup.

Required Vercel KV / Redis env vars are provided by the Vercel storage integration, typically:

```bash
KV_REST_API_URL=...
KV_REST_API_TOKEN=...
```

Agent auth and metadata use server-only env vars:

```bash
# Runtime IDs that may receive OAuth tokens.
ELMORA_ALLOWED_RUNTIME_IDS=client-a

# SHA-256 hashes of the raw secrets agents present as Bearer tokens.
ELMORA_AGENT_CONNECT_SECRETS=client-a:sha256-hex-of-agent-secret

# Optional richer display + account policy. Keys must match runtime IDs.
ELMORA_AGENT_RUNTIME_REGISTRY={"client-a":{"agentName":"Acme Inbox Agent","clientName":"Acme Events","allowedProviders":["google"],"requestedEmail":"owner@acme.com","allowedDomains":["acme.com"]}}
```

Generate a secret hash locally without printing the secret into the repo:

```bash
python - <<'PY'
import getpass, hashlib
secret = getpass.getpass('Agent connect secret: ')
print(hashlib.sha256(secret.encode()).hexdigest())
PY
```

Example agent request:

```bash
curl -sS -X POST https://elmora-kappa.vercel.app/api/connect-sessions \
  -H 'authorization: Bearer <agent-bearer-token>' \
  -H 'content-type: application/json' \
  -d '{"provider":"google","requestedEmail":"owner@acme.com"}'
```

Response:

```json
{
  "sessionId": "ocs_...",
  "provider": "google",
  "runtimeId": "client-a",
  "expiresAt": "...",
  "connectUrl": "https://elmora-kappa.vercel.app/connect/google/ecs_..."
}
```

The raw `ecs_...` token is shown only once to the agent. KV stores its SHA-256 hash. Once OAuth succeeds, the public token lookup is deleted; old links show an expired/unavailable message.

## Requested Google Workspace scopes

Elmora currently requests a broad Workspace worker profile through normal user-consent OAuth, plus `openid`, `email`, and `profile` so the callback can verify the Google account that completed consent:

- Gmail manage/send: `https://www.googleapis.com/auth/gmail.modify`, `https://www.googleapis.com/auth/gmail.send`
- Calendar: `https://www.googleapis.com/auth/calendar`
- Drive: `https://www.googleapis.com/auth/drive`
- Docs: `https://www.googleapis.com/auth/documents`
- Sheets: `https://www.googleapis.com/auth/spreadsheets`
- Slides: `https://www.googleapis.com/auth/presentations`
- Tasks: `https://www.googleapis.com/auth/tasks`
- Contacts: `https://www.googleapis.com/auth/contacts`

Google Keep is intentionally not included in this normal OAuth bundle. Google rejects `https://www.googleapis.com/auth/keep` in the user-consent flow used by this test app; handle Keep later as a separate Workspace/admin/domain-wide-delegation integration rather than blocking Gmail, Drive, Docs, Sheets, Slides, Tasks, Calendar, and Contacts.

Destructive or externally visible actions should still be approval-gated by the agent runtime even when OAuth grants broad permissions.

Server-only env vars for writing `google_token.json` into a client runtime via a storage webhook:

```bash
ELMORA_TOKEN_WEBHOOK_URL=https://your-client-runtime.example.com/oauth/google/token
ELMORA_TOKEN_WEBHOOK_SECRET=shared-webhook-secret
```

The callback sends the verified `runtimeId` plus a Hermes-compatible `google_token.json` payload to the webhook. The receiver must map runtime IDs to fixed server-side Hermes home paths and reject arbitrary paths. If no token webhook is configured, a successful OAuth exchange is proved and the token is discarded. Do not put Google client secrets, refresh tokens, signing secrets, or webhook secrets in public `NEXT_PUBLIC_*` variables.
