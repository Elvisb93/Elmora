import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NextRequest } from "next/server";
import * as runtimeRoute from "../src/app/api/agent-runtimes/[runtimeId]/route.ts";
import {
  agentRuntimeKey,
  createMemoryConnectSessionStore,
  registerAgentRuntime,
  type ConnectSessionStore,
} from "../src/lib/connectSessions.ts";

const adminSecret = "registry-admin-test-secret-with-32-plus-chars";
const runtimeId = "test-agent-2";
const runtimeUrl = `https://elmora.example/api/agent-runtimes/${runtimeId}`;
const genericErrors = {
  invalid: { error: "Invalid request" },
  unauthorized: { error: "Unauthorized" },
  unavailable: { error: "Service temporarily unavailable" },
  notFound: { error: "Not found" },
} as const;

type RuntimeStatusHandler = (
  request: NextRequest,
  props: { params: Promise<{ runtimeId: string }> },
  getStore?: () => Promise<ConnectSessionStore>,
) => Promise<Response>;

function getRuntimeStatusHandler() {
  const handler = (runtimeRoute as Record<string, unknown>).handleGetAgentRuntimeStatusRequest;
  assert.equal(typeof handler, "function", "GET runtime status handler is not implemented");
  return handler as RuntimeStatusHandler;
}

function runtimeRequest(method = "GET", authorization = `Bearer ${adminSecret}`) {
  return new NextRequest(runtimeUrl, { method, headers: { authorization } });
}

async function withRegistryAdmin<T>(callback: () => Promise<T>) {
  const previous = process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET;
  process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET = adminSecret;
  try {
    return await callback();
  } finally {
    if (previous === undefined) {
      delete process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET;
    } else {
      process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET = previous;
    }
  }
}

async function registeredRuntimeStore() {
  const store = createMemoryConnectSessionStore();
  await registerAgentRuntime({
    store,
    registryEpoch: 41,
    runtimeId,
    agentName: "Elmora Test Worker",
    clientName: "Elmora Test Client",
    rawConnectSecret: "agent-connect-test-secret-with-at-least-32-chars",
  });
  return store;
}

describe("authenticated agent-runtime status GET", () => {
  it("exports only the supported route handlers", () => {
    assert.equal(typeof runtimeRoute.GET, "function");
    assert.equal(typeof runtimeRoute.DELETE, "function");
    for (const method of ["POST", "PUT", "PATCH", "HEAD", "OPTIONS"]) {
      assert.equal((runtimeRoute as Record<string, unknown>)[method], undefined, method);
    }
  });

  it("authenticates before validating the runtime id", async () => {
    const handler = getRuntimeStatusHandler();
    let storeCalls = 0;

    await withRegistryAdmin(async () => {
      const response = await handler(
        runtimeRequest("GET", "Bearer wrong-secret"),
        { params: Promise.resolve({ runtimeId: "Invalid_Runtime" }) },
        async () => {
          storeCalls += 1;
          return createMemoryConnectSessionStore();
        },
      );

      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), genericErrors.unauthorized);
      assert.equal(storeCalls, 0);
    });
  });

  it("rejects noncanonical runtime ids before store access", async () => {
    const handler = getRuntimeStatusHandler();

    await withRegistryAdmin(async () => {
      for (const invalidId of ["ab", "Test-agent", "test_agent", " test-agent", `a${"b".repeat(63)}`]) {
        let storeCalls = 0;
        const response = await handler(
          runtimeRequest(),
          { params: Promise.resolve({ runtimeId: invalidId }) },
          async () => {
            storeCalls += 1;
            return createMemoryConnectSessionStore();
          },
        );

        assert.equal(response.status, 400, invalidId);
        assert.deepEqual(await response.json(), genericErrors.invalid, invalidId);
        assert.equal(storeCalls, 0, invalidId);
      }
    });
  });

  it("requires the existing registry admin bearer secret before store access", async () => {
    const handler = getRuntimeStatusHandler();

    await withRegistryAdmin(async () => {
      for (const authorization of ["", "Bearer wrong-secret", adminSecret]) {
        let storeCalls = 0;
        const response = await handler(
          runtimeRequest("GET", authorization),
          { params: Promise.resolve({ runtimeId }) },
          async () => {
            storeCalls += 1;
            return createMemoryConnectSessionStore();
          },
        );

        assert.equal(response.status, 401, authorization);
        assert.deepEqual(await response.json(), genericErrors.unauthorized, authorization);
        assert.equal(storeCalls, 0, authorization);
      }
    });
  });

  it("returns only the sanitized public runtime status fields", async () => {
    const handler = getRuntimeStatusHandler();
    const store = createMemoryConnectSessionStore();
    const createdAt = "2026-07-09T10:00:00.000Z";
    const updatedAt = "2026-07-10T11:30:00.000Z";
    await store.set(agentRuntimeKey(runtimeId), {
      runtimeId,
      status: "active",
      registryEpoch: 41,
      allowedProviders: ["google"],
      createdAt,
      updatedAt,
      connectSecretHash: "sensitive-connect-secret-hash",
      registryVersion: "sensitive-registry-version",
      requestedEmail: "owner@example.com",
      allowedDomains: ["example.com"],
      agentName: "Sensitive Agent Name",
      clientName: "Sensitive Client Name",
      session: { email: "connected@example.com", token: "sensitive-token" },
      email: "connected@example.com",
      token: "sensitive-token",
      filesystem: { root: "C:/sensitive/path" },
    });

    await withRegistryAdmin(async () => {
      const response = await handler(runtimeRequest(), { params: Promise.resolve({ runtimeId }) }, async () => store);
      const payload = await response.json();

      assert.equal(response.status, 200);
      assert.equal(response.headers.get("cache-control"), "private, no-store");
      assert.deepEqual(payload, {
        runtimeId,
        status: "active",
        registryEpoch: 41,
        allowedProviders: ["google"],
        createdAt,
        updatedAt,
      });
      assert.deepEqual(Object.keys(payload).sort(), [
        "allowedProviders",
        "createdAt",
        "registryEpoch",
        "runtimeId",
        "status",
        "updatedAt",
      ]);
      assert.doesNotMatch(
        JSON.stringify(payload),
        /connectSecretHash|registryVersion|requestedEmail|allowedDomains|agentName|clientName|session|email|token|filesystem|sensitive/i,
      );
    });
  });

  it("returns 404 when the runtime is absent", async () => {
    const handler = getRuntimeStatusHandler();
    const store = createMemoryConnectSessionStore();

    await withRegistryAdmin(async () => {
      const response = await handler(runtimeRequest(), { params: Promise.resolve({ runtimeId }) }, async () => store);
      assert.equal(response.status, 404);
      assert.deepEqual(await response.json(), genericErrors.notFound);
    });
  });

  it("maps store failures to a generic 503 without leaking details", async () => {
    const handler = getRuntimeStatusHandler();
    const store = createMemoryConnectSessionStore();
    const failingStore: ConnectSessionStore = {
      ...store,
      async get<T>(): Promise<T | null> {
        throw new Error("sensitive Redis endpoint, registry secret, token, and filesystem path");
      },
    };

    await withRegistryAdmin(async () => {
      const response = await handler(
        runtimeRequest(),
        { params: Promise.resolve({ runtimeId }) },
        async () => failingStore,
      );
      const payload = await response.json();

      assert.equal(response.status, 503);
      assert.deepEqual(payload, genericErrors.unavailable);
      assert.match(response.headers.get("x-elmora-request-id") ?? "", /^eoe_[A-Za-z0-9_-]{22}$/);
      assert.equal(response.headers.get("x-elmora-error-code"), "agent_runtime_status_unavailable");
      assert.doesNotMatch(JSON.stringify(payload), /redis|registry secret|token|filesystem/i);
    });
  });

  it("does not weaken DELETE admin authentication", async () => {
    const store = await registeredRuntimeStore();

    await withRegistryAdmin(async () => {
      const response = await runtimeRoute.handleRevokeAgentRuntimeRequest(
        runtimeRequest("DELETE", "Bearer wrong-secret"),
        { params: Promise.resolve({ runtimeId }) },
        async () => store,
      );
      assert.equal(response.status, 401);
      assert.equal((await store.get<{ status: string }>(agentRuntimeKey(runtimeId)))?.status, "active");
    });
  });

  it("preserves authenticated DELETE revocation", async () => {
    const store = await registeredRuntimeStore();

    await withRegistryAdmin(async () => {
      const response = await runtimeRoute.handleRevokeAgentRuntimeRequest(
        runtimeRequest("DELETE"),
        { params: Promise.resolve({ runtimeId }) },
        async () => store,
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { runtimeId, status: "revoked" });
      assert.equal((await store.get<{ status: string }>(agentRuntimeKey(runtimeId)))?.status, "revoked");
    });
  });
});
