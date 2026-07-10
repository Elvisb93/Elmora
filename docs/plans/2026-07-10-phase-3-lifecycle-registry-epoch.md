# Elmora Phase 3 Lifecycle and Registry Epoch Implementation Plan

> **For Hermes:** Use subagent-driven-development and test-driven-development task by task. Do not provision real tenants, use real provider credentials, or deploy until the fixture-only contract is green and independently reviewed.

**Goal:** Reconcile the Elmora control plane with the runtime registry so token handoff signs an authoritative runtime lifecycle epoch rather than misusing the opaque KV optimistic-lock version.

**Architecture:** Preserve two distinct immutable values: `registryVersion` remains the control-plane KV compare-and-swap token, while `registryEpoch` is the positive integer issued by the runtime registry for one lifecycle generation. Runtime registration carries both; connect sessions freeze both; callback claim/recheck requires both; HMAC-v1 signs only `registryEpoch`. A fixture-only lifecycle adapter proves this contract before any Docker orchestration.

**Tech Stack:** Next.js/TypeScript, Redis/Vercel KV Lua transactions, Node `crypto` HMAC-SHA256, Python FastAPI receiver, SQLite runtime registry, Node test runner, pytest.

---

### Task 1: Define the authoritative epoch registration contract

**Objective:** Require a positive safe integer `registryEpoch` when a runtime is registered and preserve it without normalization.

**Files:**
- Modify: `src/app/api/agent-runtimes/route.ts`
- Modify: `src/lib/connectSessions.ts`
- Test: `tests/connectSessionRoutes.test.mts`
- Test: `tests/connectSessions.test.mts`

**Steps:**
1. Add RED route tests: missing, zero, negative, fractional, string, and unsafe-large epochs return 400; a positive safe integer is returned and stored unchanged.
2. Run the focused tests and confirm failure is due to the absent contract.
3. Add `readonly registryEpoch: number` to runtime entries and strict request parsing.
4. Preserve epoch through atomic memory/KV upsert without deriving it from `registryVersion`.
5. Run focused tests, typecheck, and existing KV compatibility tests.

### Task 2: Freeze epoch into connect sessions and atomic checks

**Objective:** Ensure every connect session carries the exact runtime epoch and cannot outlive an epoch change.

**Files:**
- Modify: `src/lib/connectSessions.ts`
- Modify: `src/app/api/connect-sessions/route.ts`
- Test: `tests/connectSessions.test.mts`
- Test: `tests/connectSessionsKvCompatibility.test.mts`
- Test: `tests/connectSessionRoutes.test.mts`

**Steps:**
1. Add RED tests proving session creation copies the exact epoch and rejects absent/mutated values.
2. Add RED tests proving claim and completion fail when the runtime epoch differs even if opaque `registryVersion` still matches.
3. Update memory-store and Lua create/claim/complete scripts to compare positive integer epochs exactly.
4. Keep `expectedAgentRegistryVersion` immutable and separate.
5. Run focused tests and typecheck.

### Task 3: Implement pure HMAC-v1 request construction

**Objective:** Produce byte-for-byte compatible requests for the Phase 2 receiver without logging token material.

**Files:**
- Create: `src/lib/elmoraTokenHandoff.ts`
- Create: `tests/elmoraTokenHandoff.test.mts`

**Steps:**
1. Add RED known-answer tests matching `elmora_runtime.signing.canonical_bytes` and `make_headers` for fixed body/key/kid/timestamp/nonce/runtime/epoch.
2. Add RED validation tests for unsafe kid/runtime ID/key, noncanonical nonce, nonpositive epoch, invalid timestamp, and oversize body.
3. Implement exact UTF-8 body bytes, lowercase SHA-256, eight-line canonical ASCII payload, and lowercase HMAC-SHA256.
4. Use cryptographically random 16–32 byte nonce by default; inject nonce/time only for tests.
5. Run TypeScript focused tests and a Python cross-language fixture verifier.

### Task 4: Replace bearer persistence with signed HMAC receiver calls

**Objective:** Make managed callback persistence require complete HMAC configuration and exact frozen epoch before Google exchange.

**Files:**
- Modify: `src/lib/googleOAuth.ts`
- Modify: `src/lib/googleOAuthCallback.ts`
- Test: `tests/googleOAuth.test.mts`
- Test: `tests/googleOAuthCallbackSession.test.mts`

**Steps:**
1. Add RED tests proving managed preflight requires receiver URL, HMAC key ID, and HMAC key before Google exchange; deprecated bearer secret is rejected.
2. Add RED tests asserting exact signed headers/body and no Authorization bearer header.
3. Add RED callback tests proving epoch drift leaves invalid-account/signature/nonce paths unclaimed and prevents receiver calls.
4. Implement signed persistence with injected clock/nonce for deterministic tests.
5. Preserve duplicate-callback at-most-once handoff and honest reconciliation status.

### Task 5: Fixture-only control-plane/runtime reconciliation

**Objective:** Prove epoch acquisition and revocation behavior without Docker or real tenants.

**Files:**
- Create: `tests/runtimeLifecycleFixture.test.mts`
- Optionally create: `src/lib/runtimeLifecycle.ts`
- Modify only if required: `elmora-runtime` fixture helpers/tests

**Steps:**
1. Create a temporary runtime registry fixture and register/activate one fake runtime.
2. Feed its returned epoch into the control-plane registration fixture.
3. Create a connect session, revoke or advance runtime epoch, and prove the stale session cannot hand off.
4. Create a fresh session at the new authorized epoch and prove a fake-token HMAC request verifies through the real Python receiver/signing code.
5. Assert no real provider, Docker, Vercel, KV, or network service was contacted.

### Task 6: Parent gates and independent review

**Objective:** Close fixture-only Phase 3 before enabling real orchestration.

**Steps:**
1. Run `npm test`, `npm run typecheck`, `npm run build`, `npm audit --omit=dev`, and diff checks.
2. Run runtime pytest, Ruff, mypy, Docker security tests, Compose renders, and disposable installed-CLI smoke.
3. Run cross-language fake-token end-to-end smoke.
4. Independently review epoch/version separation, atomic callback ordering, HMAC compatibility, and secret hygiene.
5. Only after sign-off design real provision/revoke saga and operator recovery behavior; do not deploy or connect real Google during this fixture gate.
