# Elmora

A small production-ready Next.js landing page for Elmora, designed for deployment on a free `vercel.app` domain and for Google OAuth testing/verification.

## Pages

- `/` — landing page
- `/privacy` — privacy policy
- `/terms` — terms of service
- `/connect/google?runtime=<runtime-id>` — debug-only signed Google OAuth connect screen for a specific client runtime
- `/connect/google#token=<opaque-token>` — private one-time Google OAuth connect page; the fragment is never sent in the HTTP request path
- `/api/agent-runtimes` — admin-authenticated API for provisioning an agent in KV
- `/api/agent-runtimes/[runtimeId]` — admin-authenticated sanitized agent status (`GET`) and revocation (`DELETE`)
- `/api/connect-sessions` — agent-authenticated API for creating one-time connect links
- `/api/connect-sessions/resolve` — bounded no-store POST resolver used after the browser clears the private fragment
- `/api/connect-sessions/[sessionId]/status` — agent-authenticated status check for a connect session
- `/api/readiness` — admin-authenticated OAuth, receiver, and KV readiness check
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
ELMORA_AGENT_REGISTRY_ADMIN_SECRET=one-global-platform-admin-secret
```

Agent names, runtime IDs, provider policy, account policy, and hashed agent bearer tokens are records in Vercel KV. They are not deployment environment variables. `ELMORA_AGENT_REGISTRY_ADMIN_SECRET` is the single global credential used by the trusted Elmora provisioning service to create or revoke those KV records.

The optional legacy/debug Connect page may still use `ELMORA_ALLOWED_RUNTIME_IDS` when `ELMORA_ENABLE_DEBUG_CONNECT=1`. The production one-time link flow does not use that allowlist: it signs a `connectSessionId` into state and resolves the active agent/runtime from KV.

## Agent-created one-time connect links

Elmora’s preferred no-portal flow is:

1. The client asks their agent to connect Google.
2. The agent calls `POST /api/connect-sessions` with its private bearer secret.
3. Elmora creates a short-lived Vercel KV session and returns `/connect/google#token=<opaque-token>`; the browser clears the fragment before resolving it by POST.
4. The client opens that private link, sees the client/agent identity, and authorises Google.
5. The callback verifies signed state and the Google account email/domain, atomically claims the pending session, revalidates the active KV registry version immediately before handoff, stores `google_token.json` into the mapped runtime, then atomically marks the session used and deletes the public token lookup.

A receiver persistence error is **not** a connected result. Explicit receiver rejection ends as `failed`; an ambiguous transport outcome or receiver acceptance followed by control-plane finalization failure ends as `reconciliation_required`. Terminal status responses expose only a bounded `outcomeCode` and `outcomeAt`, never receiver exception details. Elmora removes terminal sessions from the public-link path and does not automatically redeliver a token because an ambiguous network failure may already have reached the receiver. The registry/version check narrows the control-plane race immediately before handoff, but the Phase 2 receiver must still reject inactive or unknown local runtimes.

Required Vercel KV / Redis env vars are provided by the Vercel storage integration, typically:

```bash
KV_REST_API_URL=...
KV_REST_API_TOKEN=...
```

Provision an agent once through the admin API:

```bash
curl -sS -X POST https://elmora-kappa.vercel.app/api/agent-runtimes \
  -H "authorization: Bearer $ELMORA_REGISTRY_ADMIN_BEARER" \
  -H 'content-type: application/json' \
  -d '{
    "runtimeId":"client-a",
    "registryEpoch":1,
    "agentName":"Acme Inbox Agent",
    "clientName":"Acme Events",
    "allowedProviders":["google"],
    "requestedEmail":"owner@acme.com",
    "allowedDomains":["acme.com"]
  }'
```

The response returns the new `agentConnectSecret` once. Store it inside that agent's isolated runtime. Elmora stores only its SHA-256 hash in KV. Provisioning or revoking another agent changes KV immediately and does not require a Vercel env edit or redeployment.

Inspect one runtime without exposing client identity, bearer hashes, account policy, or registry versions:

```bash
curl -fsS https://elmora-kappa.vercel.app/api/agent-runtimes/client-a \
  -H "authorization: Bearer $ELMORA_AGENT_REGISTRY_ADMIN_SECRET"
```

The response is limited to `runtimeId`, lifecycle `status`, authoritative `registryEpoch`, `allowedProviders`, `createdAt`, and `updatedAt`. This is an operator synchronization signal, not a replacement for container health or local tenant readiness checks.

The runtime-resource module exports only `GET` and `DELETE`. Next.js owns automatic `HEAD`/`OPTIONS` behavior and unsupported-method `405` responses; clients must not depend on a custom JSON body or a custom `Allow` header for those framework-generated responses.

Revoke an agent with:

```bash
curl -sS -X DELETE https://elmora-kappa.vercel.app/api/agent-runtimes/client-a \
  -H "authorization: Bearer $ELMORA_REGISTRY_ADMIN_BEARER"
```

Example agent request:

```bash
curl -sS -X POST https://elmora-kappa.vercel.app/api/connect-sessions \
  -H "authorization: Bearer $ELMORA_AGENT_CONNECT_BEARER" \
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
  "connectUrl": "https://elmora-kappa.vercel.app/connect/google#token=ecs_..."
}
```

The raw `ecs_...` token is shown only once to the agent. It is carried in the URL fragment so Vercel and intermediary HTTP request logs do not receive it. The browser clears the fragment before sending the token in a bounded, same-origin, no-store POST to `/api/connect-sessions/resolve`; that response never reflects the raw token or runtime ID. KV stores only the token's SHA-256 hash. Once OAuth succeeds, the public token lookup is deleted; old links show an expired/unavailable message.

## First-client rollout gate

Run the deterministic local gates before deployment:

```bash
npm test
npm run typecheck
npm run build
npm audit --omit=dev --audit-level=moderate
```

After deployment, verify authenticated control-plane readiness without exposing configuration details. A ready response means OAuth signing, Google exchange, managed token receiver, and KV configuration are all available:

```bash
curl -fsS https://elmora-kappa.vercel.app/api/readiness \
  -H "authorization: Bearer $ELMORA_AGENT_REGISTRY_ADMIN_SECRET"
```

For the full first-client gate, use environment variables so credentials never appear in command history or process arguments:

```bash
export ELMORA_READINESS_BASE_URL=https://elmora-kappa.vercel.app
export ELMORA_READINESS_RUNTIME_ID=client-a
export ELMORA_READINESS_AGENT_CONNECT_SECRET="$CLIENT_A_CONNECT_SECRET"
npm run verify:first-client
```

`verify:first-client` reads `ELMORA_AGENT_REGISTRY_ADMIN_SECRET` from the environment and checks the authenticated readiness endpoint, active runtime/provider policy, fragment-only one-time connect-link shape, bounded POST resolution, and connect-page referrer protection. It exits nonzero with a fixed generic message on any failure and never prints credentials or the generated capability token. Omit `ELMORA_READINESS_AGENT_CONNECT_SECRET` only when running the reduced control-plane/runtime preflight rather than the full first-client gate.

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
ELMORA_TOKEN_WEBHOOK_URL=https://your-client-runtime.example.com/v1/oauth/google/token
ELMORA_TOKEN_WEBHOOK_KEY_ID=active-key-id
ELMORA_TOKEN_WEBHOOK_SECRET=matching-hmac-key-material
```

The callback signs the exact HMAC-v1 request body, runtime ID, authoritative registry epoch, timestamp, nonce, key ID, and content digest before sending the Hermes-compatible `google_token.json` payload. The receiver must verify the signature and replay window, resolve runtime IDs to fixed server-side Hermes home paths, enforce the exact active epoch, and reject arbitrary paths. Managed one-time sessions fail closed if the complete receiver configuration is absent; only the legacy debug OAuth path may skip storage. Do not put Google client secrets, refresh tokens, signing secrets, or webhook secrets in public `NEXT_PUBLIC_*` variables.
