import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createConnectSession,
  createMemoryConnectSessionStore,
  getConnectSessionByToken,
} from "../src/lib/connectSessions.ts";
import { handleGoogleOAuthCallback } from "../src/lib/googleOAuthCallback.ts";
import { createOAuthState } from "../src/lib/oauthState.ts";

const env = {
  NEXT_PUBLIC_SITE_URL: "https://elmora-kappa.vercel.app",
  GOOGLE_OAUTH_CLIENT_ID: "client-id.apps.googleusercontent.com",
  GOOGLE_OAUTH_CLIENT_SECRET: "google-client-secret",
  ELMORA_STATE_SIGNING_SECRET: "state-signing-test-secret-with-32-plus-chars",
  ELMORA_ALLOWED_RUNTIME_IDS: "test-agent-2",
  ELMORA_TOKEN_WEBHOOK_URL: "https://runtime.example.com/oauth/google/token",
  ELMORA_TOKEN_WEBHOOK_SECRET: "runtime-webhook-secret",
};

function base64UrlJson(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function fakeIdToken(payload: Record<string, unknown>) {
  return [base64UrlJson({ alg: "none", typ: "JWT" }), base64UrlJson(payload), "signature"].join(".");
}

describe("Google OAuth callback connect-session handling", () => {
  it("stores the token to the session runtime and expires the public link after verified Google email", async () => {
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
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const persistedBodies: unknown[] = [];
    const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
      const urlString = url.toString();
      if (urlString === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "access-token",
            refresh_token: "refresh-token",
            expires_in: 3600,
            scope: "openid email profile https://www.googleapis.com/auth/gmail.modify",
            id_token: fakeIdToken({
              iss: "https://accounts.google.com",
              aud: env.GOOGLE_OAUTH_CLIENT_ID,
              exp: Math.floor(new Date("2026-07-07T13:00:00.000Z").getTime() / 1000),
              email: "owner@example.com",
              email_verified: true,
            }),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (urlString === env.ELMORA_TOKEN_WEBHOOK_URL) {
        persistedBodies.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      throw new Error(`Unexpected fetch ${urlString}`);
    };

    const result = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      store,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "success");
    assert.equal(result.runtimeId, "test-agent-2");
    assert.equal(result.connectedEmail, "owner@example.com");
    assert.equal(result.storage, "stored");
    assert.equal(persistedBodies.length, 1);
    assert.deepEqual(persistedBodies[0], {
      clientRuntimeId: "test-agent-2",
      filename: "google_token.json",
      token: {
        type: "authorized_user",
        client_id: env.GOOGLE_OAUTH_CLIENT_ID,
        client_secret: env.GOOGLE_OAUTH_CLIENT_SECRET,
        refresh_token: "refresh-token",
        token_uri: "https://oauth2.googleapis.com/token",
        token: "access-token",
        expiry: "2026-07-07T13:02:00.000Z",
        scopes: ["openid", "email", "profile", "https://www.googleapis.com/auth/gmail.modify"],
      },
    });

    assert.equal(
      await getConnectSessionByToken({
        store,
        rawToken: "cs_test_opaque_token",
        now: new Date("2026-07-07T12:03:00.000Z"),
      }),
      null,
    );
  });

  it("rejects a Google account that does not match the requested email without consuming the link", async () => {
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
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const fetchImpl = async () =>
      new Response(
        JSON.stringify({
          access_token: "access-token",
          refresh_token: "refresh-token",
          id_token: fakeIdToken({
            iss: "https://accounts.google.com",
            aud: env.GOOGLE_OAUTH_CLIENT_ID,
            exp: Math.floor(new Date("2026-07-07T13:00:00.000Z").getTime() / 1000),
            email: "intruder@example.com",
            email_verified: true,
          }),
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );

    const result = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      store,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    assert.match(result.message, /does not match requested account/);
    assert.equal(
      (await getConnectSessionByToken({
        store,
        rawToken: "cs_test_opaque_token",
        now: new Date("2026-07-07T12:03:00.000Z"),
      }))?.status,
      "pending",
    );
  });
});
