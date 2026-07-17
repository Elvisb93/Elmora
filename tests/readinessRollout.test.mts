import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NextRequest } from "next/server";
import {
  handleReadinessRequest,
  probeTokenReceiverHealth,
} from "../src/app/api/readiness/route.ts";
import {
  createMemoryConnectSessionStore,
  createVercelKvConnectSessionStore,
  getGoogleOAuthScopes,
  type ConnectSessionStore,
} from "../src/lib/connectSessions.ts";
import {
  verifyFirstClientRollout,
} from "../scripts/verify-first-client-rollout.ts";

const adminSecret = "readiness-admin-secret-with-at-least-32-chars";
const agentSecret = "readiness-agent-secret-with-at-least-32-chars";
const runtimeId = "test-agent-2";
const baseUrl = "https://elmora.example";
const rawToken = `ecs_${"A".repeat(43)}`;
const googleClientId = "582633394629-pilot.apps.googleusercontent.com";

function validGoogleOAuthUrl() {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", googleClientId);
  url.searchParams.set("redirect_uri", `${baseUrl}/oauth/google/callback`);
  url.searchParams.set("scope", getGoogleOAuthScopes().join(" "));
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("state", "signed-state-with-sufficient-length");
  url.searchParams.set("nonce", "oauth-nonce-with-at-least-32-characters");
  return url;
}

function rolloutFetch({
  connectUrl = `${baseUrl}/connect/google#token=${rawToken}`,
  oauthUrl = validGoogleOAuthUrl().toString(),
}: {
  connectUrl?: string;
  oauthUrl?: string;
} = {}): typeof fetch {
  return async (input) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const parsed = new URL(url);
    if (parsed.pathname === "/api/readiness") {
      return Response.json({ ready: true }, { status: 200, headers: { "cache-control": "private, no-store" } });
    }
    if (parsed.pathname === `/api/agent-runtimes/${runtimeId}`) {
      return Response.json(
        { runtimeId, status: "active", allowedProviders: ["google"], registryEpoch: 3 },
        { status: 200, headers: { "cache-control": "private, no-store" } },
      );
    }
    if (parsed.pathname === "/api/connect-sessions") {
      return Response.json({ runtimeId, connectUrl }, { status: 201 });
    }
    if (parsed.pathname === "/api/connect-sessions/resolve") {
      return Response.json({ view: { configured: true, oauthUrl } });
    }
    if (parsed.pathname === "/connect/google") {
      return new Response('<meta name="referrer" content="no-referrer">', { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
}
const readyEnv = {
  ELMORA_AGENT_REGISTRY_ADMIN_SECRET: adminSecret,
  ELMORA_STATE_SIGNING_SECRET: "state-signing-secret-with-at-least-32-chars",
  GOOGLE_OAUTH_CLIENT_SECRET: "google-client-secret-without-whitespace",
  ELMORA_TOKEN_WEBHOOK_URL: "https://receiver.example/v1/oauth/google/token",
  ELMORA_TOKEN_WEBHOOK_KEY_ID: "pilot-v1",
  ELMORA_TOKEN_WEBHOOK_SECRET: Buffer.alloc(32, 7).toString("base64url"),
};

async function withAdminSecret<T>(callback: () => Promise<T>) {
  const previous = process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET;
  process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET = adminSecret;
  try {
    return await callback();
  } finally {
    if (previous === undefined) delete process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET;
    else process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET = previous;
  }
}

describe("authenticated readiness route", () => {
  it("requires the exact bounded receiver health contract", async () => {
    const webhookUrl = new URL(readyEnv.ELMORA_TOKEN_WEBHOOK_URL);
    const valid = await probeTokenReceiverHealth(webhookUrl, async (input, init) => {
      assert.equal(String(input), "https://receiver.example/healthz");
      assert.equal(init?.redirect, "error");
      return Response.json({ status: "ok", protocolVersion: "1" });
    });
    assert.equal(valid, true);

    const invalidResponses = [
      () => new Response("<html>ok</html>", { status: 200, headers: { "content-type": "text/html" } }),
      () => new Response("not-json", { status: 200, headers: { "content-type": "application/json" } }),
      () => Response.json({ status: "ok", protocolVersion: "2" }),
      () => Response.json({ status: "degraded", protocolVersion: "1" }),
      () => Response.json({ status: "ok", protocolVersion: "1", padding: "x".repeat(20_000) }),
    ];
    for (const response of invalidResponses) {
      assert.equal(await probeTokenReceiverHealth(webhookUrl, async () => response()), false);
    }
  });

  it("authenticates before store access and returns a no-store ready response", async () => {
    let storeCalls = 0;
    const unauthorized = await handleReadinessRequest(
      new NextRequest(`${baseUrl}/api/readiness`),
      async () => {
        storeCalls += 1;
        return createMemoryConnectSessionStore();
      },
      readyEnv,
    );
    assert.equal(unauthorized.status, 401);
    assert.equal(storeCalls, 0);

    await withAdminSecret(async () => {
      const ready = await handleReadinessRequest(
        new NextRequest(`${baseUrl}/api/readiness`, {
          headers: { authorization: `Bearer ${adminSecret}` },
        }),
        async () => {
          storeCalls += 1;
          return createMemoryConnectSessionStore();
        },
        readyEnv,
        async () => true,
      );
      assert.equal(ready.status, 200);
      assert.deepEqual(await ready.json(), { ready: true });
      assert.equal(ready.headers.get("cache-control"), "private, no-store");
      assert.equal(storeCalls, 1);
    });
  });

  it("maps dependency failures to a generic observable 503", async () => {
    await withAdminSecret(async () => {
      const store: ConnectSessionStore = {
        ...createMemoryConnectSessionStore(),
        async probeReadiness(): Promise<boolean> {
          throw new Error("sensitive Redis endpoint and credential");
        },
      };
      const response = await handleReadinessRequest(
        new NextRequest(`${baseUrl}/api/readiness`, {
          headers: { authorization: `Bearer ${adminSecret}` },
        }),
        async () => store,
        readyEnv,
      );
      const payload = await response.json();
      assert.equal(response.status, 503);
      assert.deepEqual(payload, { ready: false });
      assert.equal(response.headers.get("x-elmora-error-code"), "readiness_check_failed");
      assert.match(response.headers.get("x-elmora-request-id") ?? "", /^eoe_[A-Za-z0-9_-]{22}$/);
      assert.doesNotMatch(JSON.stringify(payload), /redis|credential|endpoint/i);
    });
  });

  it("fails closed when the configured token receiver is unreachable", async () => {
    let receiverProbeCalls = 0;
    await withAdminSecret(async () => {
      const response = await handleReadinessRequest(
        new NextRequest(`${baseUrl}/api/readiness`, {
          headers: { authorization: `Bearer ${adminSecret}` },
        }),
        async () => createMemoryConnectSessionStore(),
        readyEnv,
        async (webhookUrl) => {
          receiverProbeCalls += 1;
          assert.equal(webhookUrl.toString(), readyEnv.ELMORA_TOKEN_WEBHOOK_URL);
          return false;
        },
      );
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { ready: false });
      assert.equal(response.headers.get("x-elmora-error-code"), "readiness_check_failed");
    });
    assert.equal(receiverProbeCalls, 1);
  });

  it("requires a bounded KV write-read-delete and EVAL capability probe", async () => {
    const commands: string[] = [];
    const store = createVercelKvConnectSessionStore({
      async get<T>(): Promise<T | null> {
        commands.push("get");
        return null;
      },
      async set() {
        commands.push("set");
        return "OK";
      },
      async del() {
        commands.push("del");
        return 1;
      },
      async eval(script) {
        commands.push("eval");
        assert.match(script, /redis\.call\("SET"/);
        assert.match(script, /redis\.call\("GET"/);
        assert.match(script, /redis\.call\("DEL"/);
        return 1;
      },
    });

    await withAdminSecret(async () => {
      const response = await handleReadinessRequest(
        new NextRequest(`${baseUrl}/api/readiness`, {
          headers: { authorization: `Bearer ${adminSecret}` },
        }),
        async () => store,
        readyEnv,
        async () => true,
      );
      assert.equal(response.status, 200);
      assert.deepEqual(commands, ["eval"]);
    });
  });

  it("fails closed before store access when OAuth receiver configuration is incomplete", async () => {
    let storeCalls = 0;
    const response = await handleReadinessRequest(
      new NextRequest(`${baseUrl}/api/readiness`, {
        headers: { authorization: `Bearer ${adminSecret}` },
      }),
      async () => {
        storeCalls += 1;
        return createMemoryConnectSessionStore();
      },
      { ELMORA_AGENT_REGISTRY_ADMIN_SECRET: adminSecret },
    );
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { ready: false });
    assert.equal(storeCalls, 0);
  });
});

describe("first-client rollout verifier", () => {
  it("rejects credential-bearing and noncanonical rollout base URLs before fetch", async () => {
    let fetchCalls = 0;
    const fakeFetch: typeof fetch = async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run");
    };

    for (const invalidBaseUrl of [
      "https://operator:secret@elmora.example/",
      "https://elmora.example/?target=other",
      "https://elmora.example/#other",
    ]) {
      await assert.rejects(
        verifyFirstClientRollout(
          { baseUrl: invalidBaseUrl, runtimeId, adminSecret },
          fakeFetch,
        ),
        /rollout verification failed/,
      );
    }
    assert.equal(fetchCalls, 0);
  });

  it("rejects misrouted, credential-bearing, fragmented, or incomplete OAuth contracts", async () => {
    const invalidCases: Array<{ label: string; connectUrl?: string; oauthUrl?: string }> = [
      {
        label: "credential-bearing connect URL",
        connectUrl: `https://operator:secret@elmora.example/connect/google#token=${rawToken}`,
      },
      {
        label: "credential-bearing OAuth URL",
        oauthUrl: validGoogleOAuthUrl().toString().replace("https://", "https://operator:secret@"),
      },
      {
        label: "wrong callback",
        oauthUrl: (() => {
          const url = validGoogleOAuthUrl();
          url.searchParams.set("redirect_uri", "https://attacker.example/callback");
          return url.toString();
        })(),
      },
      {
        label: "malformed client id",
        oauthUrl: (() => {
          const url = validGoogleOAuthUrl();
          url.searchParams.set("client_id", "attacker.example");
          return url.toString();
        })(),
      },
      {
        label: "OAuth fragment",
        oauthUrl: `${validGoogleOAuthUrl().toString()}#leak`,
      },
      {
        label: "missing offline access",
        oauthUrl: (() => {
          const url = validGoogleOAuthUrl();
          url.searchParams.delete("access_type");
          return url.toString();
        })(),
      },
      {
        label: "missing required scope",
        oauthUrl: (() => {
          const url = validGoogleOAuthUrl();
          url.searchParams.set("scope", getGoogleOAuthScopes().slice(1).join(" "));
          return url.toString();
        })(),
      },
    ];

    for (const testCase of invalidCases) {
      await assert.rejects(
        verifyFirstClientRollout(
          { baseUrl, runtimeId, adminSecret, agentConnectSecret: agentSecret },
          rolloutFetch(testCase),
        ),
        /rollout verification failed/,
        testCase.label,
      );
    }
  });

  it("checks live contracts without returning secrets or capability tokens", async () => {
    const calls: Array<{ url: string; authorization: string | null }> = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const headers = new Headers(init?.headers);
      calls.push({ url, authorization: headers.get("authorization") });
      const parsed = new URL(url);

      if (parsed.pathname === "/api/readiness") {
        return Response.json(
          { ready: true },
          { status: 200, headers: { "cache-control": "private, no-store" } },
        );
      }
      if (parsed.pathname === `/api/agent-runtimes/${runtimeId}`) {
        return Response.json(
          { runtimeId, status: "active", allowedProviders: ["google"], registryEpoch: 3 },
          { status: 200, headers: { "cache-control": "private, no-store" } },
        );
      }
      if (parsed.pathname === "/api/connect-sessions") {
        return Response.json(
          {
            sessionId: "ocs_abcdefghijklmnopqrstuvwx",
            runtimeId,
            provider: "google",
            expiresAt: "2026-07-15T12:05:00.000Z",
            connectUrl: `${baseUrl}/connect/google#token=${rawToken}`,
          },
          { status: 201 },
        );
      }
      if (parsed.pathname === "/api/connect-sessions/resolve") {
        return Response.json({
          view: {
            configured: true,
            oauthUrl: validGoogleOAuthUrl().toString(),
          },
        });
      }
      if (parsed.pathname === "/connect/google") {
        return new Response('<meta name="referrer" content="no-referrer">', { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };

    const result = await verifyFirstClientRollout(
      { baseUrl, runtimeId, adminSecret, agentConnectSecret: agentSecret },
      fakeFetch,
    );

    assert.deepEqual(result, {
      ready: true,
      checks: [
        "control-plane-readiness",
        "runtime-active",
        "fragment-connect-link",
        "connect-resolver",
        "connect-page-referrer-policy",
      ],
    });
    assert.doesNotMatch(JSON.stringify(result), /ecs_|admin-secret|agent-secret|owner@/i);
    assert.equal(calls[0]?.authorization, `Bearer ${adminSecret}`);
    assert.equal(calls[1]?.authorization, `Bearer ${adminSecret}`);
    assert.equal(calls[2]?.authorization, `Bearer ${agentSecret}`);
  });
});
