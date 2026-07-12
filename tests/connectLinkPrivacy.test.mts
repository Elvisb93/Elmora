import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { NextRequest } from "next/server";
import { handleResolveConnectSessionRequest } from "../src/app/api/connect-sessions/resolve/route.ts";
import {
  createConnectSession,
  createMemoryConnectSessionStore,
  registerAgentRuntime,
} from "../src/lib/connectSessions.ts";

const env = {
  NEXT_PUBLIC_SITE_URL: "https://elmora.example",
  NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID: "client-id.apps.googleusercontent.com",
  ELMORA_STATE_SIGNING_SECRET: "state-signing-test-secret-with-32-plus-chars",
};

async function fixture() {
  const store = createMemoryConnectSessionStore();
  const { agent } = await registerAgentRuntime({
    store,
    registryEpoch: 7,
    runtimeId: "private-runtime",
    agentName: "Private Worker",
    clientName: "Private Client",
    requestedEmail: "owner@example.com",
    allowedDomains: ["example.com"],
    allowedProviders: ["google"],
    rawConnectSecret: "private-agent-connect-secret-value",
  });
  const created = await createConnectSession({
    store,
    provider: "google",
    runtimeId: agent.runtimeId,
    expectedAgentRegistryEpoch: agent.registryEpoch,
    expectedAgentRegistryVersion: agent.registryVersion,
    agentName: agent.agentName,
    clientName: agent.clientName,
    requestedEmail: agent.requestedEmail,
    allowedDomains: agent.allowedDomains,
    ttlSeconds: 900,
  });
  return { created, store };
}

function request(token: string, contentType = "text/plain") {
  return new NextRequest("https://elmora.example/api/connect-sessions/resolve", {
    method: "POST",
    headers: { "content-type": contentType },
    body: token,
  });
}

describe("fragment-only private Google connect links", () => {
  it("resolves a strict text-body token without reflecting token, runtime id, or session id", async () => {
    const { created, store } = await fixture();
    const response = await handleResolveConnectSessionRequest(
      request(created.rawToken),
      async () => store,
      env,
    );
    const payload = await response.json();
    const serialized = JSON.stringify(payload);

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(payload.view.runtimeId, "private");
    assert.equal(payload.view.configured, true);
    assert.match(payload.view.oauthUrl, /^https:\/\/accounts\.google\.com\//);
    assert.doesNotMatch(serialized, new RegExp(created.rawToken));
    assert.doesNotMatch(serialized, /private-runtime/);
    assert.doesNotMatch(serialized, new RegExp(created.session.id));
  });

  it("rejects malformed bodies before store access and returns generic unavailable results", async () => {
    let storeCalls = 0;
    const malformed = await handleResolveConnectSessionRequest(
      request("ecs_short"),
      async () => {
        storeCalls += 1;
        throw new Error("must not initialize store");
      },
      env,
    );
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), { error: "Invalid request" });
    assert.equal(storeCalls, 0);

    const oversizedWithoutLength = await handleResolveConnectSessionRequest(
      new NextRequest("https://elmora.example/api/connect-sessions/resolve", {
        method: "POST",
        headers: { "content-type": "text/plain", "content-length": "" },
        body: "x".repeat(129),
      }),
      async () => {
        storeCalls += 1;
        throw new Error("must not initialize store");
      },
      env,
    );
    assert.equal(oversizedWithoutLength.status, 400);
    assert.equal(storeCalls, 0);

    const oversizedWithUnderstatedLength = await handleResolveConnectSessionRequest(
      new NextRequest("https://elmora.example/api/connect-sessions/resolve", {
        method: "POST",
        headers: { "content-type": "text/plain", "content-length": "1" },
        body: "x".repeat(129),
      }),
      async () => {
        storeCalls += 1;
        throw new Error("must not initialize store");
      },
      env,
    );
    assert.equal(oversizedWithUnderstatedLength.status, 400);
    assert.equal(storeCalls, 0);

    const { store } = await fixture();
    const unavailable = await handleResolveConnectSessionRequest(
      request(`ecs_${"A".repeat(43)}`),
      async () => store,
      env,
    );
    assert.equal(unavailable.status, 404);
    assert.deepEqual(await unavailable.json(), { error: "Connection link unavailable" });
  });

  it("clears the URL fragment before posting the token and has no token-path page", () => {
    const source = readFileSync("src/components/GoogleConnectBootstrap.tsx", "utf8");
    const clearIndex = source.indexOf("window.history.replaceState");
    const fetchIndex = source.indexOf("fetch(");
    assert.ok(clearIndex >= 0 && fetchIndex > clearIndex);
    assert.doesNotMatch(source, /console\.(?:log|info|warn|error)/);
    assert.throws(() => readFileSync("src/app/connect/google/[token]/page.tsx", "utf8"));
  });
});
