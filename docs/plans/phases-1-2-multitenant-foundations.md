# Elmora Multi-Tenant Foundations — Phases 1 and 2 Implementation Plan

> **For Hermes:** Execute with `subagent-driven-development`; parent session owns verification, commits, pushes, deployment checks, and final claims.

**Goal:** Finish and deploy Elmora’s KV-backed agent registry safely, then build a separately testable `elmora-runtime` data plane for isolated client containers and constrained OAuth token delivery.

**Architecture:** `Elmora` remains the Vercel OAuth/control plane. A new `elmora-runtime` Python project becomes the server data plane: tenant registry, provisioner, HMAC-authenticated token receiver, fixed runtime-to-home mapping, atomic private token writes, Docker Compose templates, and isolation tests. `AI Agent Builder` remains a catalog/control-plane and is not converted into the runtime host.

**Tech Stack:** Next.js/TypeScript/node:test/Vercel KV; Python 3.11 managed with uv; FastAPI/Pydantic/Typer/pytest; Docker Compose on Linux-compatible containers.

---

## Global safety boundaries

- Preserve existing user work; never reset or discard the current Elmora staged/unstaged changes.
- Never copy redacted `authorization` snippets from tool output into source.
- No real Google tokens, OAuth secrets, bearer tokens, or HMAC secrets in source, tests, logs, git, or chat.
- No client container may receive the registry-admin secret, receiver HMAC secret, Docker socket, host `/opt`, or another tenant’s home.
- Vercel KV stores agent metadata, secret digests, and temporary connection state only—never durable Google refresh tokens.
- Receiver accepts `runtimeId` and token JSON, never caller-selected paths or filenames.
- Parent must verify every side effect and external deployment independently.

## Phase 1 — Finish and deploy the KV-backed Elmora registry

### Task 1.1: Reconcile the split working tree

**Repository:** `C:\Users\longs\Documents\GitHub\Elmora`

- Inspect `git diff`, `git diff --cached`, and all `MM`/`AM` files.
- Preserve useful staged and unstaged fixes.
- Treat the current unstaged callback sequence as suspect: it marks a session connected before receiver persistence.
- Produce one coherent working tree; do not commit or push from the implementer subagent.

### Task 1.2: Lock registry and route behavior with TDD

Tests must cover:

- Per-agent names, runtime IDs, provider policy, account policy, and bearer-secret digests live in KV—not env.
- Provision, authenticate, rotate/re-register, and revoke without redeploy.
- Unique registry versions prevent same-millisecond stale authorization.
- Wrong bearer, unknown runtime, revoked runtime, unsupported provider, malformed body, and unavailable KV fail closed.
- API errors do not leak internal exception strings.
- Legacy debug routes cannot issue production OAuth links unless explicitly enabled.

### Task 1.3: Correct OAuth callback ordering and races

Required invariant:

1. Verify signed/expiring state and pending session.
2. Verify Google identity.
3. Atomically claim the session to prevent duplicate callback persistence.
4. Revalidate active runtime/registry version immediately before token handoff.
5. Deliver token to the constrained receiver.
6. Only after receiver success, atomically mark session connected and delete the public token lookup.
7. If receiver persistence fails, never report connected and never consume the session as successfully connected. Record a safe failed/processing outcome according to the tested retry policy.
8. A revoked/re-registered runtime must not authorize a stale session snapshot.

Do not claim a zero-width race that Vercel alone cannot guarantee. The Phase 2 receiver must independently reject inactive/unknown local runtimes.

### Task 1.4: Full local gates

Run and capture:

```bash
npm test
npm run typecheck
npm run build
npm audit --omit=dev --audit-level=moderate
git diff --check
git status --short
```

### Task 1.5: Reviews and deployment

- Independent spec-compliance review.
- Independent security/code-quality review.
- Parent fixes/rechecks any blocking findings.
- Parent stages the verified tree, confirms no `MM`/`AM`, commits with `[verified]` prefix, pushes `main`, and verifies the new Vercel production deployment/aliases/routes.
- Verify unauthenticated registry/session endpoints reject requests and public/debug pages expose no OAuth URL.
- Do not claim live provisioning until KV and the one global registry-admin secret are actually configured.

**Phase 1 exit:** Production can provision/revoke agents through KV without env edits; callback marks connected only after confirmed receiver persistence; all gates and live boundaries pass.

## Phase 2 — Build `elmora-runtime`

### Task 2.1: Create the standalone project

**Path:** `C:\Users\longs\Documents\GitHub\elmora-runtime`

Create a uv-managed Python 3.11 project with:

```text
elmora-runtime/
  pyproject.toml
  README.md
  .gitignore
  src/elmora_runtime/
    config.py
    registry.py
    signing.py
    receiver.py
    provisioner.py
    cli.py
  tests/
  docker/
    receiver.Dockerfile
    tenant.Dockerfile
    compose.yaml
    tenant-compose.template.yaml
  scripts/
```

Initialize git locally but do not create/push a GitHub repository until parent review passes.

### Task 2.2: Tenant registry and path confinement via TDD

Use SQLite or an equivalently simple local durable registry. Each active runtime maps to one canonical server-owned path under a configured root such as `/opt/hermes-clients`.

Tests must prove:

- runtime IDs obey a strict format;
- canonical tenant homes are unique;
- unknown/revoked runtime lookup fails;
- duplicate path assignments fail;
- caller input cannot escape the configured root;
- registry never accepts a caller-provided token filename/path for receiver writes.

### Task 2.3: HMAC receiver authentication via TDD

Contract headers:

- timestamp
- cryptographically random nonce
- HMAC-SHA256 signature over timestamp, nonce, and exact request-body digest

Tests must prove rejection of:

- missing headers;
- bad signatures;
- stale timestamps;
- reused nonces;
- body tampering;
- unknown/revoked runtimes;
- extra path/filename fields;
- malformed token payloads.

Use constant-time signature comparison. Store used nonces durably enough to enforce the replay window. Never log request token bodies or signature secrets.

### Task 2.4: Atomic private token writes via TDD

Receiver writes only:

```text
<registered-hermes-home>/google_token.json
```

Requirements:

- temporary file in target directory;
- flush/fsync where practical;
- atomic rename/replace;
- mode `0600` on Linux;
- restrictive parent directory permissions;
- safe metadata-only response;
- failed writes leave no partial token;
- existing token remains intact if replacement fails.

### Task 2.5: Tenant provisioner via TDD

CLI contract:

```bash
uv run elmora-runtime provision <runtime-id>
uv run elmora-runtime revoke <runtime-id>
uv run elmora-runtime inspect <runtime-id>
uv run elmora-runtime verify-isolation <runtime-a> <runtime-b>
```

Provisioning creates a portable tenant unit with distinct:

- `hermes-home/`
- `workspace/`
- `documents/`
- `backups/`
- tenant Compose env/config

It must not place global admin/receiver secrets in the client container. Online Elmora registration must be explicit and injectable/testable; offline tests use a fake control-plane transport.

### Task 2.6: Docker isolation

Compose/containers must enforce:

- per-tenant mounts only;
- no `/var/run/docker.sock` in tenant containers;
- no broad `/opt` bind;
- no privileged mode;
- dropped capabilities where viable;
- `no-new-privileges`;
- read-only root filesystem where viable;
- tmpfs for temporary writable paths;
- CPU/memory/PID limits;
- unprivileged runtime user;
- receiver separated from tenant containers.

### Task 2.7: Verification

Parent runs:

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy src
# build/validate Compose and Docker images when Docker is available
```

Then create two fixture tenants and verify markers/tokens cannot cross homes, unknown/revoked writes fail, path traversal fails, and token mode is restrictive.

- Independent spec review.
- Independent security/code-quality review.
- Parent verifies artifacts and command output.

**Phase 2 exit:** A locally verified, portable runtime data plane exists with two fixture tenants, strict HMAC receiver, fixed paths, atomic `0600` token writes, Docker isolation configuration, and no live client secrets.
