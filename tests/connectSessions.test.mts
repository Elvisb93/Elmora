import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createConnectSession,
  createMemoryConnectSessionStore,
  getConnectSessionByToken,
  markConnectSessionConnected,
  resolveGoogleConnectSessionViewModel,
} from "../src/lib/connectSessions.ts";
import { verifyOAuthState } from "../src/lib/oauthState.ts";

const env = {
  NEXT_PUBLIC_SITE_URL: "https://elmora-kappa.vercel.app",
  NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID: "client-id.apps.googleusercontent.com",
  ELMORA_STATE_SIGNING_SECRET: "state-signing-test-secret-with-32-plus-chars",
  ELMORA_ALLOWED_RUNTIME_IDS: "test-agent-2",
};

describe("KV-backed one-time OAuth connect sessions", () => {
  it("creates an opaque one-time token without exposing the runtime id in the public URL token", async () => {
    const store = createMemoryConnectSessionStore();

    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      requestedEmail: "owner@example.com",
      now: new Date("2026-07-07T12:00:00.000Z"),
      rawToken: "cs_test_opaque_token",
    });

    assert.equal(created.session.provider, "google");
    assert.equal(created.session.runtimeId, "test-agent-2");
    assert.equal(created.rawToken, "cs_test_opaque_token");
    assert.doesNotMatch(created.rawToken, /test-agent-2/);

    const loaded = await getConnectSessionByToken({
      store,
      rawToken: created.rawToken,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });

    assert.equal(loaded?.id, created.session.id);
    assert.equal(loaded?.status, "pending");
  });

  it("renders a temporary Google connect page with state bound to the connect session id", async () => {
    const store = createMemoryConnectSessionStore();
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      requestedEmail: "owner@example.com",
      now: new Date("2026-07-07T12:00:00.000Z"),
      rawToken: "cs_test_opaque_token",
      sessionId: "ocs_test_session",
    });

    const view = await resolveGoogleConnectSessionViewModel({
      store,
      rawToken: created.rawToken,
      env,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });

    assert.equal(view.configured, true);
    assert.equal(view.runtimeId, "test-agent-2");
    assert.equal(view.connectionSession?.id, "ocs_test_session");
    assert.equal(view.connectionSession?.clientName, "Elmora Test Client");
    assert.ok(view.oauthUrl);

    const state = new URL(view.oauthUrl).searchParams.get("state") ?? "";
    const verified = verifyOAuthState({
      state,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      allowedRuntimeIds: ["test-agent-2"],
      now: new Date("2026-07-07T12:01:00.000Z"),
    });

    assert.equal(verified.connectSessionId, "ocs_test_session");
    assert.equal(verified.runtimeId, undefined);
    assert.match(new URL(view.oauthUrl).searchParams.get("scope") ?? "", /\bopenid\b/);
    assert.match(new URL(view.oauthUrl).searchParams.get("scope") ?? "", /\bemail\b/);
  });

  it("marks the session connected and removes public token lookup after successful callback", async () => {
    const store = createMemoryConnectSessionStore();
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      requestedEmail: "owner@example.com",
      now: new Date("2026-07-07T12:00:00.000Z"),
      rawToken: "cs_test_opaque_token",
      sessionId: "ocs_test_session",
    });

    const connected = await markConnectSessionConnected({
      store,
      sessionId: created.session.id,
      connectedEmail: "owner@example.com",
      now: new Date("2026-07-07T12:03:00.000Z"),
    });

    assert.equal(connected.status, "connected");
    assert.equal(connected.connectedEmail, "owner@example.com");
    assert.equal(connected.usedAt, "2026-07-07T12:03:00.000Z");

    const loadedByPublicToken = await getConnectSessionByToken({
      store,
      rawToken: created.rawToken,
      now: new Date("2026-07-07T12:04:00.000Z"),
    });

    assert.equal(loadedByPublicToken, null);
  });
});
