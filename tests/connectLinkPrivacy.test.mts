import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { describe, it } from "node:test";

import { NextRequest } from "next/server";
import {
  handleResolveConnectSessionRequest,
} from "../src/app/api/connect-sessions/resolve/route.ts";
import {
  createConnectSession,
  createMemoryConnectSessionStore,
  registerAgentRuntime,
} from "../src/lib/connectSessions.ts";
import { takeConnectTokenFromBrowserLocation } from "../src/lib/connectLink.ts";

const rawToken = `ecs_${"A".repeat(43)}`;
const env = {
  NEXT_PUBLIC_SITE_URL: "https://elmora.example",
  NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID: "google-client-id.apps.googleusercontent.com",
  ELMORA_STATE_SIGNING_SECRET: "state-signing-secret-with-at-least-thirty-two-characters",
};

async function pendingSessionStore() {
  const store = createMemoryConnectSessionStore();
  const now = new Date("2026-07-12T12:00:00.000Z");
  const { agent } = await registerAgentRuntime({
    store,
    registryEpoch: 7,
    runtimeId: "test-agent-2",
    agentName: "Elmora Test Worker",
    clientName: "Elmora Test Client",
    requestedEmail: "owner@example.com",
    rawConnectSecret: "agent-connect-secret-with-at-least-32-chars",
    now,
  });
  await createConnectSession({
    store,
    provider: "google",
    runtimeId: agent.runtimeId,
    expectedAgentRegistryEpoch: agent.registryEpoch,
    expectedAgentRegistryVersion: agent.registryVersion,
    agentName: agent.agentName,
    clientName: agent.clientName,
    requestedEmail: agent.requestedEmail,
    rawToken,
    sessionId: "ocs_abcdefghijklmnopqrstuvwx",
    now,
  });
  return store;
}

function resolveRequest(body: unknown, method = "POST") {
  const init: RequestInit = {
    method,
    headers: { "content-type": "application/json" },
  };
  if (method !== "GET" && method !== "HEAD") {
    init.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  return new NextRequest("https://elmora.example/api/connect-sessions/resolve", init);
}

describe("private fragment connect links", () => {
  it("extracts one canonical token and clears the fragment before returning it", () => {
    const replacements: string[] = [];
    const location = {
      hash: `#token=${rawToken}`,
      pathname: "/connect/google",
      search: "",
    };
    const history = {
      replaceState(_data: unknown, _unused: string, url?: string | URL | null) {
        replacements.push(String(url));
        location.hash = "";
      },
    };

    assert.equal(takeConnectTokenFromBrowserLocation(location, history), rawToken);
    assert.deepEqual(replacements, ["/connect/google"]);
    assert.equal(location.hash, "");
  });

  it("rejects malformed or ambiguous fragments without reflecting them", () => {
    for (const hash of ["", "#token=", "#token=wrong", `#token=${rawToken}&extra=1`, `#x=1&token=${rawToken}`]) {
      const location = { hash, pathname: "/connect/google", search: "" };
      const history = { replaceState() {} };
      assert.equal(takeConnectTokenFromBrowserLocation(location, history), null, hash);
    }
  });

  it("resolves a pending token from a bounded POST body without returning the token", async () => {
    const store = await pendingSessionStore();
    const response = await handleResolveConnectSessionRequest(
      resolveRequest({ token: rawToken }),
      async () => store,
      env,
      new Date("2026-07-12T12:01:00.000Z"),
    );
    const payload = await response.json();
    const serialized = JSON.stringify(payload);

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(payload.view.configured, true);
    assert.equal(payload.view.runtimeId, "private");
    assert.equal(payload.view.connectionSession.clientName, "Elmora Test Client");
    assert.equal("id" in payload.view.connectionSession, false);
    assert.match(payload.view.oauthUrl, /^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/);
    assert.doesNotMatch(serialized, /ecs_|agent-connect-secret|test-agent-2|ocs_abcdefghijklmnopqrstuvwx/);
  });

  it("rejects malformed, oversized, unknown, and non-POST requests generically", async () => {
    const store = await pendingSessionStore();
    const cases: Array<[string, NextRequest, number]> = [
      ["unknown field", resolveRequest({ token: rawToken, extra: true }), 400],
      ["wrong token", resolveRequest({ token: "not-a-token" }), 400],
      ["malformed", resolveRequest("{not-json"), 400],
      ["oversized", resolveRequest(JSON.stringify({ token: `ecs_${"A".repeat(3000)}` })), 413],
      ["method", resolveRequest({ token: rawToken }, "GET"), 405],
      ["unknown", resolveRequest({ token: `ecs_${"B".repeat(43)}` }), 404],
    ];

    for (const [label, request, status] of cases) {
      const response = await handleResolveConnectSessionRequest(
        request,
        async () => store,
        env,
        new Date("2026-07-12T12:01:00.000Z"),
      );
      const payload = await response.json();
      assert.equal(response.status, status, label);
      assert.deepEqual(payload, { error: status === 413 ? "Request too large" : status === 405 ? "Method not allowed" : status === 404 ? "Connection link unavailable" : "Invalid request" }, label);
      assert.doesNotMatch(JSON.stringify(payload), /ecs_|not-a-token|Google|Redis|token hash/i, label);
    }
  });

  it("returns a generic unavailable response when the store fails", async () => {
    const response = await handleResolveConnectSessionRequest(
      resolveRequest({ token: rawToken }),
      async () => {
        throw new Error("sensitive Redis URL and capability token");
      },
      env,
      new Date("2026-07-12T12:00:00.000Z"),
    );
    const payload = await response.json();
    assert.equal(response.status, 503);
    assert.deepEqual(payload, { error: "Service temporarily unavailable" });
    assert.match(response.headers.get("x-elmora-request-id") ?? "", /^eoe_[A-Za-z0-9_-]{22}$/);
    assert.equal(response.headers.get("x-elmora-error-code"), "connect_session_resolve_unavailable");
    assert.doesNotMatch(JSON.stringify(payload), /redis|capability|token/i);
  });

  it("has no legacy dynamic token page", () => {
    assert.equal(existsSync("src/app/connect/google/[token]/page.tsx"), false);
  });
});
