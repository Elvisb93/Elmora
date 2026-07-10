import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { describe, it } from "node:test";

import {
  buildGoogleOAuthUrl,
  buildGoogleAuthorizedUserToken,
  exchangeGoogleOAuthCode,
  persistGoogleOAuthToken,
} from "../src/lib/googleOAuth.ts";
import { createOAuthNonce, createOAuthState, verifyOAuthState } from "../src/lib/oauthState.ts";

describe("Google OAuth helpers", () => {
  it("builds an authorization URL with the exact hosted callback and encoded scopes", () => {
    const url = buildGoogleOAuthUrl({
      clientId: "client-id.apps.googleusercontent.com",
      redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
      scopes: ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"],
      state: "secure-state",
    });

    assert.equal(url.origin, "https://accounts.google.com");
    assert.equal(url.pathname, "/o/oauth2/v2/auth");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("client_id"), "client-id.apps.googleusercontent.com");
    assert.equal(url.searchParams.get("redirect_uri"), "https://elmora-kappa.vercel.app/oauth/google/callback");
    assert.equal(url.searchParams.get("scope"), "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify");
    assert.equal(url.searchParams.get("access_type"), "offline");
    assert.equal(url.searchParams.get("prompt"), "consent");
    assert.equal(url.searchParams.get("state"), "secure-state");
    assert.match(url.toString(), /gmail\.readonly%20https%3A%2F%2Fwww\.googleapis\.com%2Fauth%2Fgmail\.modify/);
  });

  it("requires and forwards an exact nonce whenever openid is requested", () => {
    const nonce = createOAuthNonce();
    assert.match(nonce, /^[A-Za-z0-9_-]{43}$/);

    assert.throws(
      () =>
        buildGoogleOAuthUrl({
          clientId: "client-id.apps.googleusercontent.com",
          redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
          scopes: ["openid", "email"],
          state: "secure-state",
        }),
      /nonce/i,
    );

    const url = buildGoogleOAuthUrl({
      clientId: "client-id.apps.googleusercontent.com",
      redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
      scopes: ["openid", "email"],
      state: "secure-state",
      nonce,
    });
    assert.equal(url.searchParams.get("nonce"), nonce);
  });

  it("exchanges an authorization code with Google using server-only client credentials", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(
        JSON.stringify({
          access_token: "test-access-token",
          refresh_token: "test-refresh-token",
          expires_in: 3600,
          scope: "https://www.googleapis.com/auth/gmail.readonly",
          token_type: "Bearer",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const token = await exchangeGoogleOAuthCode(
      {
        code: "auth-code",
        clientId: "client-id.apps.googleusercontent.com",
        clientSecret: "server-only-test-secret",
        redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
      },
      fetchImpl,
    );

    assert.equal(token.access_token, "test-access-token");
    assert.equal(token.refresh_token, "test-refresh-token");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://oauth2.googleapis.com/token");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers?.["content-type" as keyof HeadersInit], "application/x-www-form-urlencoded");

    const body = new URLSearchParams(String(calls[0].init.body));
    assert.equal(body.get("code"), "auth-code");
    assert.equal(body.get("client_id"), "client-id.apps.googleusercontent.com");
    assert.equal(body.get("client_secret"), "server-only-test-secret");
    assert.equal(body.get("redirect_uri"), "https://elmora-kappa.vercel.app/oauth/google/callback");
    assert.equal(body.get("grant_type"), "authorization_code");
  });

  it("throws a useful error when Google rejects the token exchange", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "invalid_grant", error_description: "Bad code" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });

    await assert.rejects(
      () =>
        exchangeGoogleOAuthCode(
          {
            code: "bad-code",
            clientId: "client-id.apps.googleusercontent.com",
            clientSecret: "server-only-test-secret",
            redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
          },
          fetchImpl,
        ),
      /Google token exchange failed: invalid_grant — Bad code/,
    );
  });

  it("builds a Hermes-compatible authorized_user google_token.json payload", () => {
    const tokenFile = buildGoogleAuthorizedUserToken({
      token: {
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        expires_in: 3600,
        scope: "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.events",
        token_type: "Bearer",
      },
      clientId: "client-id.apps.googleusercontent.com",
      clientSecret: "server-only-test-secret",
      now: new Date("2026-07-06T12:00:00.000Z"),
    });

    assert.deepEqual(tokenFile, {
      type: "authorized_user",
      client_id: "client-id.apps.googleusercontent.com",
      client_secret: "server-only-test-secret",
      refresh_token: "test-refresh-token",
      token_uri: "https://oauth2.googleapis.com/token",
      token: "test-access-token",
      expiry: "2026-07-06T13:00:00.000Z",
      scopes: ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/calendar.events"],
    });
  });

  it("posts the exact HMAC-v1 token payload and signed headers to the runtime receiver", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ runtimeId: "elmora-demo", registryEpoch: 7, written: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const key = Buffer.alloc(32, 0x6b);
    const nonceBytes = Buffer.alloc(16, 0x6e);

    const result = await persistGoogleOAuthToken(
      {
        clientRuntimeId: "elmora-demo",
        registryEpoch: 7,
        storageWebhookUrl: "https://runtime.example.com/v1/oauth/google/token",
        storageWebhookKeyId: "primary-v1",
        storageWebhookSecret: key.toString("base64url"),
        now: new Date("2026-07-06T12:00:00.000Z"),
        nonceBytes,
        tokenFile: {
          type: "authorized_user",
          client_id: "client-id.apps.googleusercontent.com",
          client_secret: "server-only-test-secret",
          refresh_token: "test-refresh-token",
          token_uri: "https://oauth2.googleapis.com/token",
          token: "test-access-token",
          expiry: "2026-07-06T13:00:00.000Z",
          scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
        },
      },
      fetchImpl,
    );

    assert.deepEqual(result, { status: "stored" });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://runtime.example.com/v1/oauth/google/token");
    assert.equal(calls[0].init.method, "POST");
    const headers = calls[0].init.headers as Record<string, string>;
    assert.equal(headers["content-type"], "application/json");
    assert.equal(headers["X-Elmora-Version"], "1");
    assert.equal(headers["X-Elmora-Key-Id"], "primary-v1");
    assert.equal(headers["X-Elmora-Timestamp"], "1783339200");
    assert.equal(headers["X-Elmora-Nonce"], nonceBytes.toString("base64url"));
    assert.equal(headers["X-Elmora-Runtime-Id"], "elmora-demo");
    assert.equal(headers["X-Elmora-Registry-Epoch"], "7");

    const body = String(calls[0].init.body);
    assert.deepEqual(JSON.parse(body), {
      protocolVersion: "1",
      runtimeId: "elmora-demo",
      registryEpoch: 7,
      token: {
        type: "authorized_user",
        client_id: "client-id.apps.googleusercontent.com",
        client_secret: "server-only-test-secret",
        refresh_token: "test-refresh-token",
        token_uri: "https://oauth2.googleapis.com/token",
        token: "test-access-token",
        expiry: "2026-07-06T13:00:00.000Z",
        scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
      },
    });
    const digest = createHash("sha256").update(body, "utf8").digest("hex");
    assert.equal(headers["X-Elmora-Body-SHA256"], digest);
    const canonical = [
      "elmora-runtime-token-hmac",
      "version:1",
      "kid:primary-v1",
      "timestamp:1783339200",
      `nonce:${nonceBytes.toString("base64url")}`,
      "runtime-id:elmora-demo",
      "registry-epoch:7",
      `body-sha256:${digest}`,
    ].join("\n");
    assert.equal(headers["X-Elmora-Signature"], createHmac("sha256", key).update(canonical).digest("hex"));
    assert.equal("authorization" in headers, false);
  });

  it("retains the legacy skipped result only when no storage webhook URL is configured", async () => {
    let fetchCalls = 0;
    const result = await persistGoogleOAuthToken(
      {
        clientRuntimeId: "elmora-demo",
        tokenFile: {
          type: "authorized_user",
          client_id: "client-id.apps.googleusercontent.com",
          client_secret: "server-only-test-secret",
          refresh_token: "test-refresh-token",
          token_uri: "https://oauth2.googleapis.com/token",
        },
      },
      async () => {
        fetchCalls += 1;
        throw new Error("fetch must not run");
      },
    );

    assert.deepEqual(result, { status: "skipped", reason: "No token storage webhook configured" });
    assert.equal(fetchCalls, 0);
  });

  it("fails closed and never sends a configured webhook without a nonempty signing secret", async () => {
    for (const storageWebhookSecret of [undefined, "", "   ", "secret\nvalue"]) {
      let fetchCalls = 0;
      await assert.rejects(
        () =>
          persistGoogleOAuthToken(
            {
              clientRuntimeId: "elmora-demo",
              registryEpoch: 7,
              storageWebhookUrl: "https://runtime.example.com/oauth/google/token",
              storageWebhookKeyId: "primary-v1",
              storageWebhookSecret,
              tokenFile: {
                type: "authorized_user",
                client_id: "client-id.apps.googleusercontent.com",
                client_secret: "server-only-test-secret",
                refresh_token: "test-refresh-token",
                token_uri: "https://oauth2.googleapis.com/token",
              },
            },
            async () => {
              fetchCalls += 1;
              return new Response(null, { status: 204 });
            },
          ),
        { message: "Invalid token storage configuration" },
      );
      assert.equal(fetchCalls, 0);
    }
  });

  it("rejects insecure, credential-bearing, and malformed webhook URLs before fetch", async () => {
    for (const storageWebhookUrl of [
      "http://runtime.example.com/token",
      "https://user:password@runtime.example.com/token",
      "not-a-url",
    ]) {
      let fetchCalls = 0;
      await assert.rejects(
        () =>
          persistGoogleOAuthToken(
            {
              clientRuntimeId: "elmora-demo",
              registryEpoch: 7,
              storageWebhookUrl,
              storageWebhookKeyId: "primary-v1",
              storageWebhookSecret: "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s",
              tokenFile: {
                type: "authorized_user",
                client_id: "client-id.apps.googleusercontent.com",
                client_secret: "server-only-test-secret",
                refresh_token: "test-refresh-token",
                token_uri: "https://oauth2.googleapis.com/token",
              },
            },
            async () => {
              fetchCalls += 1;
              return new Response(null, { status: 204 });
            },
          ),
        { message: "Invalid token storage configuration" },
      );
      assert.equal(fetchCalls, 0);
    }
  });

  it("validates the canonical runtime id and fixed authorized-user payload before fetch", async () => {
    const validTokenFile = {
      type: "authorized_user" as const,
      client_id: "client-id.apps.googleusercontent.com",
      client_secret: "server-only-test-secret",
      refresh_token: "test-refresh-token",
      token_uri: "https://oauth2.googleapis.com/token" as const,
    };
    const invalidInputs = [
      { clientRuntimeId: "Elmora-demo", tokenFile: validTokenFile },
      { clientRuntimeId: "ab", tokenFile: validTokenFile },
      {
        clientRuntimeId: "elmora-demo",
        tokenFile: { ...validTokenFile, filename: "other.json" } as typeof validTokenFile,
      },
      {
        clientRuntimeId: "elmora-demo",
        tokenFile: { ...validTokenFile, token_uri: "https://attacker.example/token" } as typeof validTokenFile,
      },
    ];

    for (const input of invalidInputs) {
      let fetchCalls = 0;
      await assert.rejects(
        () =>
          persistGoogleOAuthToken(
            {
              ...input,
              registryEpoch: 7,
              storageWebhookUrl: "https://runtime.example.com/oauth/google/token",
              storageWebhookKeyId: "primary-v1",
              storageWebhookSecret: "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s",
            },
            async () => {
              fetchCalls += 1;
              return new Response(null, { status: 204 });
            },
          ),
        { message: "Invalid token storage request" },
      );
      assert.equal(fetchCalls, 0);
    }
  });

  it("does not leak receiver status details when token storage fails", async () => {
    await assert.rejects(
      () =>
        persistGoogleOAuthToken(
          {
            clientRuntimeId: "elmora-demo",
            registryEpoch: 7,
            storageWebhookUrl: "https://runtime.example.com/oauth/google/token",
            storageWebhookKeyId: "primary-v1",
            storageWebhookSecret: "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s",
            tokenFile: {
              type: "authorized_user",
              client_id: "client-id.apps.googleusercontent.com",
              client_secret: "server-only-test-secret",
              refresh_token: "test-refresh-token",
              token_uri: "https://oauth2.googleapis.com/token",
            },
          },
          async () => new Response("receiver database exploded", { status: 599, statusText: "Secret Failure" }),
        ),
      { message: "Token storage request failed" },
    );
  });
});

describe("signed multi-client OAuth state", () => {
  const secret = "state-signing-test-secret-with-32-plus-chars";
  const allowedRuntimeIds = ["elmora-demo", "client-a"];
  const now = new Date("2026-07-06T12:00:00.000Z");
  const stateNonce = "state_nonce_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  it("creates and verifies a signed state for an allowed runtime id", () => {
    const state = createOAuthState({
      runtimeId: "client-a",
      secret,
      now,
      nonce: stateNonce,
      ttlSeconds: 600,
    });

    const verified = verifyOAuthState({ state, secret, allowedRuntimeIds, now });

    assert.equal(verified.runtimeId, "client-a");
    assert.equal(verified.nonce, stateNonce);
    assert.equal(verified.expiresAt, "2026-07-06T12:10:00.000Z");
  });

  it("rejects tampered state", () => {
    const state = createOAuthState({ runtimeId: "client-a", secret, now, nonce: stateNonce });
    const tampered = state.replace(/.$/, state.endsWith("a") ? "b" : "a");

    assert.throws(() => verifyOAuthState({ state: tampered, secret, allowedRuntimeIds, now }), /Invalid OAuth state signature/);
  });

  it("rejects expired state", () => {
    const state = createOAuthState({ runtimeId: "client-a", secret, now, nonce: stateNonce, ttlSeconds: 60 });
    const later = new Date("2026-07-06T12:02:00.000Z");

    assert.throws(() => verifyOAuthState({ state, secret, allowedRuntimeIds, now: later }), /OAuth state expired/);
  });

  it("rejects runtime IDs that are not in the allowlist", () => {
    const state = createOAuthState({ runtimeId: "client-b", secret, now, nonce: stateNonce });

    assert.throws(() => verifyOAuthState({ state, secret, allowedRuntimeIds, now }), /OAuth runtime is not allowed/);
  });

  it("rejects malformed nonces and unknown signed state fields", () => {
    for (const nonce of ["short", "contains+plus/", "x".repeat(129)]) {
      assert.throws(() => createOAuthState({ runtimeId: "client-a", secret, now, nonce }), /nonce/i);
    }

    const payload = Buffer.from(
      JSON.stringify({
        runtimeId: "client-a",
        nonce: stateNonce,
        expiresAt: "2026-07-06T12:10:00.000Z",
        redirectUri: "https://attacker.example/callback",
      }),
    ).toString("base64url");
    const signature = createHmac("sha256", secret).update(payload).digest("base64url");
    assert.throws(
      () => verifyOAuthState({ state: `${payload}.${signature}`, secret, allowedRuntimeIds, now }),
      /payload/i,
    );
  });
});
