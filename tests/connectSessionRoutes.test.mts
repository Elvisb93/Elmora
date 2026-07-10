import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NextRequest } from "next/server";
import * as createRoute from "../src/app/api/connect-sessions/route.ts";
import * as statusRoute from "../src/app/api/connect-sessions/[sessionId]/status/route.ts";
import * as registryRoute from "../src/app/api/agent-runtimes/route.ts";
import * as revokeRegistryRoute from "../src/app/api/agent-runtimes/[runtimeId]/route.ts";
import {
  agentRuntimeKey,
  connectSessionKey,
  createMemoryConnectSessionStore,
  registerAgentRuntime,
  type ConnectSessionStore,
} from "../src/lib/connectSessions.ts";

const adminSecret = "registry-admin-test-secret-with-32-plus-chars";
const agentSecret = "agent-connect-test-secret-with-at-least-32-chars";
const runtimeId = "test-agent-2";
const validSessionId = "ocs_abcdefghijklmnopqrstuvwx";
const genericErrors = {
  invalid: { error: "Invalid request" },
  unauthorized: { error: "Unauthorized" },
  forbidden: { error: "Forbidden" },
  unavailable: { error: "Service temporarily unavailable" },
  method: { error: "Method not allowed" },
} as const;

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

function registryRequest(body: unknown, method = "POST", authorization = `Bearer ${adminSecret}`) {
  return new NextRequest("https://elmora.example/api/agent-runtimes", {
    method,
    headers: { authorization, "content-type": "application/json" },
    ...(method === "POST" ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}),
  });
}

function connectRequest(body: unknown, method = "POST", authorization = `Bearer ${agentSecret}`) {
  return new NextRequest("https://elmora.example/api/connect-sessions", {
    method,
    headers: { authorization, "content-type": "application/json" },
    ...(method === "POST" ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}),
  });
}

async function registeredStore(options: { requestedEmail?: string; allowedProviders?: [] | ["google"] } = {}) {
  const store = createMemoryConnectSessionStore();
  await registerAgentRuntime({
    store,
    registryEpoch: 41,
    runtimeId,
    agentName: "Elmora Test Worker",
    clientName: "Elmora Test Client",
    rawConnectSecret: agentSecret,
    requestedEmail: options.requestedEmail,
    allowedProviders: options.allowedProviders,
  });
  return store;
}

async function assertMethodNotAllowed(response: Response, allow: string) {
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), allow);
  assert.deepEqual(await response.json(), genericErrors.method);
}

describe("route helpers enforce HTTP methods", () => {
  it("rejects non-POST registry methods before auth, parsing, or store access", async () => {
    await withRegistryAdmin(async () => {
      for (const method of ["GET", "PUT", "DELETE", "PATCH"]) {
        let storeCalls = 0;
        const response = await registryRoute.handleRegisterAgentRuntimeRequest(
          registryRequest({}, method, "Bearer wrong-secret"),
          async () => {
            storeCalls += 1;
            return createMemoryConnectSessionStore();
          },
        );
        await assertMethodNotAllowed(response, "POST");
        assert.equal(storeCalls, 0);
      }
    });
  });

  it("rejects non-POST connect-session methods before store access", async () => {
    for (const method of ["GET", "PUT", "DELETE", "PATCH"]) {
      let storeCalls = 0;
      const response = await createRoute.handleCreateConnectSessionRequest(connectRequest({}, method), async () => {
        storeCalls += 1;
        return createMemoryConnectSessionStore();
      });
      await assertMethodNotAllowed(response, "POST");
      assert.equal(storeCalls, 0);
    }
  });

  it("rejects non-DELETE revoke methods before store access", async () => {
    await withRegistryAdmin(async () => {
      for (const method of ["GET", "POST", "PUT", "PATCH"]) {
        let storeCalls = 0;
        const request = new NextRequest(`https://elmora.example/api/agent-runtimes/${runtimeId}`, {
          method,
          headers: { authorization: `Bearer ${adminSecret}` },
        });
        const response = await revokeRegistryRoute.handleRevokeAgentRuntimeRequest(
          request,
          { params: Promise.resolve({ runtimeId }) },
          async () => {
            storeCalls += 1;
            return createMemoryConnectSessionStore();
          },
        );
        await assertMethodNotAllowed(response, "DELETE");
        assert.equal(storeCalls, 0);
      }
    });
  });

  it("rejects non-GET status methods before store access", async () => {
    for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
      let storeCalls = 0;
      const request = new NextRequest(`https://elmora.example/api/connect-sessions/${validSessionId}/status`, {
        method,
        headers: { authorization: `Bearer ${agentSecret}` },
      });
      const response = await statusRoute.handleConnectSessionStatusRequest(
        request,
        { params: Promise.resolve({ sessionId: validSessionId }) },
        async () => {
          storeCalls += 1;
          return createMemoryConnectSessionStore();
        },
      );
      await assertMethodNotAllowed(response, "GET");
      assert.equal(storeCalls, 0);
    }
  });
});

describe("agent-registry route validation and error hygiene", () => {
  it("authenticates before attempting to parse an admin request body", async () => {
    await withRegistryAdmin(async () => {
      let storeCalls = 0;
      const response = await registryRoute.handleRegisterAgentRuntimeRequest(
        registryRequest("{not-json", "POST", "Bearer invalid-secret"),
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

  it("rejects malformed JSON without store access", async () => {
    await withRegistryAdmin(async () => {
      let storeCalls = 0;
      const response = await registryRoute.handleRegisterAgentRuntimeRequest(registryRequest("{not-json"), async () => {
        storeCalls += 1;
        return createMemoryConnectSessionStore();
      });
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), genericErrors.invalid);
      assert.equal(storeCalls, 0);
    });
  });

  it("rejects unknown, ambiguous, injected, weak, duplicate, and oversized fields before store access", async () => {
    await withRegistryAdmin(async () => {
      const valid = {
        registryEpoch: 41,
        runtimeId,
        agentName: "Elmora Test Worker",
        clientName: "Elmora Test Client",
        allowedProviders: ["google"],
        requestedEmail: "Owner@Example.com",
        allowedDomains: ["Example.com"],
        agentConnectSecret: agentSecret,
      };
      const invalidBodies: Array<[string, unknown]> = [
        ["array body", []],
        ["unknown key", { ...valid, admin: true }],
        ["missing registry epoch", { ...valid, registryEpoch: undefined }],
        ["zero registry epoch", { ...valid, registryEpoch: 0 }],
        ["negative registry epoch", { ...valid, registryEpoch: -1 }],
        ["fractional registry epoch", { ...valid, registryEpoch: 1.5 }],
        ["string registry epoch", { ...valid, registryEpoch: "41" }],
        ["NaN registry epoch", { ...valid, registryEpoch: Number.NaN }],
        ["unsafe registry epoch", { ...valid, registryEpoch: Number.MAX_SAFE_INTEGER + 1 }],
        ["short runtime", { ...valid, runtimeId: "ab" }],
        ["uppercase runtime", { ...valid, runtimeId: "Test-agent" }],
        ["underscore runtime", { ...valid, runtimeId: "test_agent" }],
        ["leading runtime whitespace", { ...valid, runtimeId: " test-agent" }],
        ["oversized runtime", { ...valid, runtimeId: `a${"b".repeat(63)}` }],
        ["empty name", { ...valid, agentName: "" }],
        ["name edge whitespace", { ...valid, agentName: " Elmora" }],
        ["name control", { ...valid, clientName: "Elmora\nClient" }],
        ["oversized name", { ...valid, clientName: "x".repeat(101) }],
        ["invalid email", { ...valid, requestedEmail: "owner@@example.com" }],
        ["email whitespace", { ...valid, requestedEmail: " owner@example.com" }],
        ["invalid domain", { ...valid, allowedDomains: ["https://example.com"] }],
        ["duplicate domains", { ...valid, allowedDomains: ["example.com", "EXAMPLE.COM"] }],
        ["too many domains", { ...valid, allowedDomains: Array.from({ length: 33 }, (_, i) => `d${i}.example.com`) }],
        ["empty providers", { ...valid, allowedProviders: [] }],
        ["duplicate providers", { ...valid, allowedProviders: ["google", "google"] }],
        ["unsupported provider", { ...valid, allowedProviders: ["google", "github"] }],
        ["weak secret", { ...valid, agentConnectSecret: "short-secret" }],
        ["whitespace secret", { ...valid, agentConnectSecret: `${"x".repeat(32)} ` }],
        ["oversized secret", { ...valid, agentConnectSecret: "x".repeat(257) }],
      ];

      for (const [label, body] of invalidBodies) {
        let storeCalls = 0;
        const response = await registryRoute.handleRegisterAgentRuntimeRequest(registryRequest(body), async () => {
          storeCalls += 1;
          return createMemoryConnectSessionStore();
        });
        assert.equal(response.status, 400, label);
        assert.deepEqual(await response.json(), genericErrors.invalid, label);
        assert.equal(storeCalls, 0, label);
      }
    });
  });

  it("preserves an authoritative positive safe registry epoch in the response and stored runtime", async () => {
    await withRegistryAdmin(async () => {
      const store = createMemoryConnectSessionStore();
      const registryEpoch = Number.MAX_SAFE_INTEGER;
      const response = await registryRoute.handleRegisterAgentRuntimeRequest(
        registryRequest({
          registryEpoch,
          runtimeId,
          agentName: "Elmora Test Worker",
          clientName: "Elmora Test Client",
          allowedProviders: ["google"],
          agentConnectSecret: agentSecret,
        }),
        async () => store,
      );
      const payload = await response.json();

      assert.equal(response.status, 201);
      assert.equal(payload.registryEpoch, registryEpoch);
      assert.equal(
        (await store.get<{ registryEpoch: number }>(
          agentRuntimeKey(runtimeId),
        ))?.registryEpoch,
        registryEpoch,
      );
      assert.equal(typeof payload.registryEpoch, "number");
    });
  });

  it("accepts canonical boundaries and intentionally lowercases email and domain policy", async () => {
    await withRegistryAdmin(async () => {
      const store = createMemoryConnectSessionStore();
      const response = await registryRoute.handleRegisterAgentRuntimeRequest(
        registryRequest({
          registryEpoch: 1,
          runtimeId: `a${"b".repeat(62)}`,
          agentName: "A",
          clientName: "C".repeat(100),
          allowedProviders: ["google"],
          requestedEmail: "Owner@Example.com",
          allowedDomains: ["Example.com"],
          agentConnectSecret: "x".repeat(32),
        }),
        async () => store,
      );
      const payload = await response.json();
      assert.equal(response.status, 201);
      assert.equal(payload.requestedEmail, "owner@example.com");
      assert.deepEqual(payload.allowedDomains, ["example.com"]);
      assert.equal(payload.agentConnectSecret, undefined);
    });
  });

  it("maps registry storage errors to a generic 503 without leaking details", async () => {
    await withRegistryAdmin(async () => {
      const store = createMemoryConnectSessionStore();
      const failingStore: ConnectSessionStore = {
        ...store,
        async upsertAgentRuntime(): Promise<never> {
          throw new Error("sensitive redis endpoint, secret index, and request id");
        },
      };
      const response = await registryRoute.handleRegisterAgentRuntimeRequest(
        registryRequest({ registryEpoch: 1, runtimeId, agentName: "Agent", clientName: "Client" }),
        async () => failingStore,
      );
      const payload = await response.json();
      assert.equal(response.status, 503);
      assert.deepEqual(payload, genericErrors.unavailable);
      assert.doesNotMatch(JSON.stringify(payload), /redis|secret|index|request id/i);
    });
  });

  it("rejects invalid revoke runtime ids before store access", async () => {
    await withRegistryAdmin(async () => {
      for (const invalidId of ["ab", "Test-agent", "test_agent", " test-agent", `a${"b".repeat(63)}`]) {
        let storeCalls = 0;
        const request = new NextRequest("https://elmora.example/api/agent-runtimes/invalid", {
          method: "DELETE",
          headers: { authorization: `Bearer ${adminSecret}` },
        });
        const response = await revokeRegistryRoute.handleRevokeAgentRuntimeRequest(
          request,
          { params: Promise.resolve({ runtimeId: invalidId }) },
          async () => {
            storeCalls += 1;
            return createMemoryConnectSessionStore();
          },
        );
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), genericErrors.invalid);
        assert.equal(storeCalls, 0);
      }
    });
  });
});

describe("connect-session create route validation and error hygiene", () => {
  it("authenticates before parsing and returns a generic unauthorized response", async () => {
    const store = await registeredStore();
    const response = await createRoute.handleCreateConnectSessionRequest(
      connectRequest("{not-json", "POST", "Bearer does-not-exist"),
      async () => store,
    );
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), genericErrors.unauthorized);
  });

  it("strictly rejects malformed JSON, unknown fields, coercion, unsupported providers, invalid emails, and invalid TTLs", async () => {
    const store = await registeredStore();
    const invalidBodies: Array<[string, unknown]> = [
      ["malformed json", "{not-json"],
      ["array body", []],
      ["unknown field", { provider: "google", extra: true }],
      ["missing provider", {}],
      ["provider case", { provider: "Google" }],
      ["unsupported provider", { provider: "github" }],
      ["provider coercion", { provider: ["google"] }],
      ["email coercion", { provider: "google", requestedEmail: 7 }],
      ["empty email", { provider: "google", requestedEmail: "" }],
      ["invalid email", { provider: "google", requestedEmail: "owner@@example.com" }],
      ["ttl coercion", { provider: "google", ttlSeconds: "900" }],
      ["ttl NaN encoding", { provider: "google", ttlSeconds: null }],
      ["fractional ttl", { provider: "google", ttlSeconds: 300.5 }],
      ["ttl too low", { provider: "google", ttlSeconds: 299 }],
      ["ttl too high", { provider: "google", ttlSeconds: 3601 }],
    ];

    for (const [label, body] of invalidBodies) {
      const response = await createRoute.handleCreateConnectSessionRequest(connectRequest(body), async () => store);
      assert.equal(response.status, 400, label);
      assert.deepEqual(await response.json(), genericErrors.invalid, label);
    }
  });

  it("accepts both TTL boundaries without clamping", async () => {
    const store = await registeredStore();
    const before = Date.now();
    for (const ttlSeconds of [300, 3600]) {
      const response = await createRoute.handleCreateConnectSessionRequest(
        connectRequest({ provider: "google", ttlSeconds }),
        async () => store,
      );
      const payload = await response.json();
      assert.equal(response.status, 201);
      const actualTtl = new Date(payload.expiresAt).getTime() - before;
      assert.ok(actualTtl >= ttlSeconds * 1000 - 1_000);
      assert.ok(actualTtl <= ttlSeconds * 1000 + 1_000);
    }
  });

  it("rejects a body email that conflicts with fixed agent policy but accepts equivalent case", async () => {
    const store = await registeredStore({ requestedEmail: "owner@example.com" });
    const conflict = await createRoute.handleCreateConnectSessionRequest(
      connectRequest({ provider: "google", requestedEmail: "other@example.com" }),
      async () => store,
    );
    assert.equal(conflict.status, 403);
    assert.deepEqual(await conflict.json(), genericErrors.forbidden);

    const equivalent = await createRoute.handleCreateConnectSessionRequest(
      connectRequest({ provider: "google", requestedEmail: "OWNER@EXAMPLE.COM" }),
      async () => store,
    );
    assert.equal(equivalent.status, 201);
  });

  it("returns a generic forbidden response when the authenticated policy disables Google", async () => {
    const store = await registeredStore({ allowedProviders: [] });
    const response = await createRoute.handleCreateConnectSessionRequest(
      connectRequest({ provider: "google" }),
      async () => store,
    );
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), genericErrors.forbidden);
  });

  it("maps session storage errors to a generic 503", async () => {
    const store = await registeredStore();
    const failingStore: ConnectSessionStore = {
      ...store,
      async createConnectSessionAtomically(): Promise<never> {
        throw new Error("sensitive KV URL and secret");
      },
    };
    const response = await createRoute.handleCreateConnectSessionRequest(
      connectRequest({ provider: "google" }),
      async () => failingStore,
    );
    const payload = await response.json();
    assert.equal(response.status, 503);
    assert.deepEqual(payload, genericErrors.unavailable);
    assert.doesNotMatch(JSON.stringify(payload), /KV URL|secret/i);
  });
});

describe("connect-session status route validation and error hygiene", () => {
  it("rejects noncanonical session ids before store initialization", async () => {
    for (const invalidId of ["ocs_test", "OCS_abcdefghijklmnopqrstuvwx", "ocs_abc/def", `${validSessionId}x`]) {
      let storeCalls = 0;
      const request = new NextRequest("https://elmora.example/api/connect-sessions/invalid/status", {
        headers: { authorization: `Bearer ${agentSecret}` },
      });
      const response = await statusRoute.handleConnectSessionStatusRequest(
        request,
        { params: Promise.resolve({ sessionId: invalidId }) },
        async () => {
          storeCalls += 1;
          return createMemoryConnectSessionStore();
        },
      );
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), genericErrors.invalid);
      assert.equal(storeCalls, 0);
    }
  });

  it("returns generic unauthorized, forbidden, and storage failure responses", async () => {
    const store = await registeredStore();
    const unauthorizedRequest = new NextRequest(
      `https://elmora.example/api/connect-sessions/${validSessionId}/status`,
      { headers: { authorization: "Bearer unknown-secret" } },
    );
    const unauthorized = await statusRoute.handleConnectSessionStatusRequest(
      unauthorizedRequest,
      { params: Promise.resolve({ sessionId: validSessionId }) },
      async () => store,
    );
    assert.equal(unauthorized.status, 401);
    assert.deepEqual(await unauthorized.json(), genericErrors.unauthorized);

    await store.set(connectSessionKey(validSessionId), {
      id: validSessionId,
      tokenHash: "hash",
      provider: "google",
      runtimeId: "other-agent",
      registryVersion: "version",
      agentName: "Other",
      clientName: "Other",
      status: "pending",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
    });
    const authorizedRequest = new NextRequest(
      `https://elmora.example/api/connect-sessions/${validSessionId}/status`,
      { headers: { authorization: `Bearer ${agentSecret}` } },
    );
    const forbidden = await statusRoute.handleConnectSessionStatusRequest(
      authorizedRequest,
      { params: Promise.resolve({ sessionId: validSessionId }) },
      async () => store,
    );
    assert.equal(forbidden.status, 403);
    assert.deepEqual(await forbidden.json(), genericErrors.forbidden);

    const failingStore: ConnectSessionStore = {
      ...store,
      async get<T>(key: string): Promise<T | null> {
        if (key === connectSessionKey(validSessionId)) {
          throw new Error("sensitive Redis endpoint");
        }
        return store.get<T>(key);
      },
    };
    const unavailable = await statusRoute.handleConnectSessionStatusRequest(
      authorizedRequest,
      { params: Promise.resolve({ sessionId: validSessionId }) },
      async () => failingStore,
    );
    const payload = await unavailable.json();
    assert.equal(unavailable.status, 503);
    assert.deepEqual(payload, genericErrors.unavailable);
    assert.doesNotMatch(JSON.stringify(payload), /Redis|endpoint/i);
  });
});
