import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createConnectSession,
  createMemoryConnectSessionStore,
  connectSessionKey,
  getAgentRuntime,
  getConnectSessionByToken,
  registerAgentRuntime,
  revokeAgentRuntime,
} from "../src/lib/connectSessions.ts";
import { handleGoogleOAuthCallback } from "../src/lib/googleOAuthCallback.ts";
import { createOAuthState } from "../src/lib/oauthState.ts";
import {
  createGoogleOidcTestContext,
  googleOidcNonce,
  googleOidcNow,
} from "./googleOidcFixtures.mts";

const env = {
  NEXT_PUBLIC_SITE_URL: "https://elmora-kappa.vercel.app",
  GOOGLE_OAUTH_CLIENT_ID: "client-id.apps.googleusercontent.com",
  GOOGLE_OAUTH_CLIENT_SECRET: "google-client-secret",
  ELMORA_STATE_SIGNING_SECRET: "state-signing-test-secret-with-32-plus-chars",
  ELMORA_TOKEN_WEBHOOK_URL: "https://runtime.example.com/v1/oauth/google/token",
  ELMORA_TOKEN_WEBHOOK_KEY_ID: "primary-v1",
  ELMORA_TOKEN_WEBHOOK_SECRET: "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s",
};

const oidcContextPromise = createGoogleOidcTestContext();

async function signedIdToken(payload: Record<string, unknown> = {}) {
  return (await oidcContextPromise).signIdToken(payload);
}

const callbackFixtureNow = new Date("2026-07-07T12:00:00.000Z");

async function registerCallbackFixture(store: ReturnType<typeof createMemoryConnectSessionStore>) {
  const { agent } = await registerAgentRuntime({
    store,
    registryEpoch: 41,
    runtimeId: "test-agent-2",
    agentName: "Elmora Test Worker",
    clientName: "Elmora Test Client",
    allowedProviders: ["google"],
    requestedEmail: "owner@example.com",
    allowedDomains: ["example.com"],
    rawConnectSecret: "agent-one-time-bearer-secret",
    now: callbackFixtureNow,
  });
  return agent;
}

async function createManagedCallbackFixture(suffix: string) {
  const store = createMemoryConnectSessionStore();
  const agent = await registerCallbackFixture(store);
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
    now: callbackFixtureNow,
    rawToken: `cs_${suffix}_opaque_token`,
    sessionId: `ocs_${suffix}_session`,
  });
  const state = createOAuthState({
    connectSessionId: created.session.id,
    secret: env.ELMORA_STATE_SIGNING_SECRET,
    nonce: googleOidcNonce,
    now: new Date("2026-07-07T12:01:00.000Z"),
  });
  return { store, created, state };
}

describe("Google OAuth callback OIDC enforcement", () => {
  it("verifies the signed ID-token nonce before a debug receiver handoff", async () => {
    const state = createOAuthState({
      runtimeId: "test-agent-2",
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    let receiverHandoffs = 0;
    const fetchImpl = async (url: string | URL | Request) => {
      if (url.toString() === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "access-token",
            refresh_token: "refresh-token",
            token_type: "Bearer",
            id_token: await signedIdToken({ nonce: "wrong_nonce_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" }),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      receiverHandoffs += 1;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    const result = await handleGoogleOAuthCallback({
      code: "debug-google-code",
      state,
      env: { ...env, ELMORA_ALLOWED_RUNTIME_IDS: "test-agent-2" },
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: googleOidcNow,
    });

    assert.equal(result.status, "failed");
    assert.equal(receiverHandoffs, 0);
  });
});

describe("Google OAuth callback connect-session handling", () => {
  it("rejects a stale same-millisecond registry session before any Google or receiver request", async () => {
    const store = createMemoryConnectSessionStore();
    const fixedNow = new Date("2026-07-07T12:00:00.000Z");
    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker A",
      clientName: "Elmora Test Client A",
      allowedProviders: ["google"],
      requestedEmail: "owner-a@example-a.com",
      allowedDomains: ["example-a.com"],
      rawConnectSecret: "agent-a-one-time-bearer-secret",
      now: fixedNow,
    });
    const agentA = await getAgentRuntime({ store, runtimeId: "test-agent-2" });
    assert.ok(agentA);
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: agentA.runtimeId,
      agentName: agentA.agentName,
      clientName: agentA.clientName,
      requestedEmail: agentA.requestedEmail,
      allowedDomains: agentA.allowedDomains,
      expectedAgentRegistryEpoch: agentA.registryEpoch,
      expectedAgentRegistryVersion: agentA.registryVersion,
      now: fixedNow,
      rawToken: "cs_stale_same_millisecond",
      sessionId: "ocs_stale_same_millisecond",
    });

    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker B",
      clientName: "Elmora Test Client B",
      allowedProviders: ["google"],
      requestedEmail: "owner-b@example-b.com",
      allowedDomains: ["example-b.com"],
      rawConnectSecret: "agent-b-one-time-bearer-secret",
      now: fixedNow,
    });
    const agentB = await getAgentRuntime({ store, runtimeId: "test-agent-2" });
    assert.ok(agentB);
    assert.notEqual(agentB.registryVersion, agentA.registryVersion);
    assert.equal(agentB.updatedAt, agentA.updatedAt);

    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    let externalRequests = 0;
    let tokenHandoffs = 0;
    const fetchImpl = async (url: string | URL | Request) => {
      externalRequests += 1;
      if (url.toString() === env.ELMORA_TOKEN_WEBHOOK_URL) {
        tokenHandoffs += 1;
      }
      throw new Error(`Unexpected external request ${url.toString()}`);
    };

    const result = await handleGoogleOAuthCallback({
      code: "stale-google-code",
      state,
      store,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    assert.equal(externalRequests, 0);
    assert.equal(tokenHandoffs, 0);
    assert.notEqual(
      (await store.get<{ status: string }>(connectSessionKey(created.session.id)))?.status,
      "connected",
    );
    assert.equal(
      await getConnectSessionByToken({
        store,
        rawToken: created.rawToken,
        now: new Date("2026-07-07T12:03:00.000Z"),
      }),
      null,
    );
  });

  it("preflights every managed secret and receiver setting before Google exchange or claim", async () => {
    const configurations = [
      ["missing Google secret", { ...env, GOOGLE_OAUTH_CLIENT_SECRET: undefined }],
      ["unsafe Google secret", { ...env, GOOGLE_OAUTH_CLIENT_SECRET: "  " }],
      ["invalid Google client", { ...env, GOOGLE_OAUTH_CLIENT_ID: "not-a-google-client" }],
      ["missing receiver URL", { ...env, ELMORA_TOKEN_WEBHOOK_URL: undefined }],
      ["missing receiver key id", { ...env, ELMORA_TOKEN_WEBHOOK_KEY_ID: undefined }],
      ["missing receiver secret", { ...env, ELMORA_TOKEN_WEBHOOK_SECRET: undefined }],
      ["invalid receiver URL", { ...env, ELMORA_TOKEN_WEBHOOK_URL: "http://runtime.example.com/token" }],
    ] as const;

    for (const [name, callbackEnv] of configurations) {
      const fixture = await createManagedCallbackFixture(name.replaceAll(" ", "_").toLowerCase());
      let externalRequests = 0;
      let claims = 0;
      const guardedStore = {
        ...fixture.store,
        async claimConnectSessionForPersistence(
          options: Parameters<NonNullable<typeof fixture.store.claimConnectSessionForPersistence>>[0],
        ) {
          claims += 1;
          return fixture.store.claimConnectSessionForPersistence?.(options) ?? null;
        },
      };

      const result = await handleGoogleOAuthCallback({
        code: "google-code",
        state: fixture.state,
        store: guardedStore,
        env: callbackEnv,
        fetchImpl: (async () => {
          externalRequests += 1;
          throw new Error("preflight must prevent external requests");
        }) as typeof fetch,
        idTokenKeyResolver: (await oidcContextPromise).keyResolver,
        now: new Date("2026-07-07T12:02:00.000Z"),
      });

      assert.ok(result.status === "missing-config" || result.status === "failed", name);
      assert.equal(externalRequests, 0, name);
      assert.equal(claims, 0, name);
      assert.equal(
        (await fixture.store.get<{ status: string }>(connectSessionKey(fixture.created.session.id)))?.status,
        "pending",
        name,
      );
    }
  });

  it("stores the token to the session runtime and expires the public link after verified Google email", async () => {
    const store = createMemoryConnectSessionStore();
    const agent = await registerCallbackFixture(store);
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
      now: callbackFixtureNow,
      rawToken: "cs_test_opaque_token",
      sessionId: "ocs_test_session",
    });
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const persistedBodies: unknown[] = [];
    const sessionStatusesWhenPersisted: string[] = [];
    const externalCallOrder: string[] = [];
    const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
      const urlString = url.toString();
      if (urlString === "https://oauth2.googleapis.com/token") {
        externalCallOrder.push("google-exchange");
        return new Response(
          JSON.stringify({
            access_token: "access-token",
            refresh_token: "refresh-token",
            expires_in: 3600,
            scope: "openid email profile https://www.googleapis.com/auth/gmail.modify",
            id_token: await signedIdToken({
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
        externalCallOrder.push("receiver-handoff");
        sessionStatusesWhenPersisted.push(
          (await store.get<{ status: string }>(connectSessionKey(created.session.id)))?.status ?? "missing",
        );
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
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "success");
    assert.equal(result.runtimeId, "test-agent-2");
    assert.equal(result.connectedEmail, "owner@example.com");
    assert.equal(result.storage, "stored");
    assert.deepEqual(externalCallOrder, ["google-exchange", "receiver-handoff"]);
    assert.deepEqual(sessionStatusesWhenPersisted, ["processing"]);
    assert.equal(persistedBodies.length, 1);
    assert.deepEqual(persistedBodies[0], {
      protocolVersion: "1",
      runtimeId: "test-agent-2",
      registryEpoch: 41,
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

    const duplicateResult = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      store,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:03:00.000Z"),
    });
    assert.equal(duplicateResult.status, "failed");
    assert.equal(persistedBodies.length, 1);
  });

  it("rejects a Google account that does not match the requested email without consuming the link", async () => {
    const store = createMemoryConnectSessionStore();
    const agent = await registerCallbackFixture(store);
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
      now: callbackFixtureNow,
      rawToken: "cs_test_opaque_token",
      sessionId: "ocs_test_session",
    });
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const fetchImpl = async () =>
      new Response(
        JSON.stringify({
          access_token: "access-token",
          refresh_token: "refresh-token",
          id_token: await signedIdToken({
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
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    assert.equal(result.message, "This Google connection could not be completed. Ask your Elmora agent for a fresh link.");
    assert.doesNotMatch(result.message, /owner|intruder|example\.com/i);
    assert.equal(
      (await getConnectSessionByToken({
        store,
        rawToken: "cs_test_opaque_token",
        now: new Date("2026-07-07T12:03:00.000Z"),
      }))?.status,
      "pending",
    );
  });

  it("rejects invalid tokens and incomplete managed token responses before claim or receiver handoff", async () => {
    const validIdToken = await signedIdToken();
    const [header, payload, signature] = validIdToken.split(".");
    const forgedIdToken = `${header}.${payload}.${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
    const variants = [
      ["forged_signature", { id_token: forgedIdToken, refresh_token: "refresh-token" }],
      [
        "nonce_mismatch",
        {
          id_token: await signedIdToken({
            nonce: "different_nonce_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
          }),
          refresh_token: "refresh-token",
        },
      ],
      ["missing_nonce", { id_token: await signedIdToken({ nonce: undefined }), refresh_token: "refresh-token" }],
      ["missing_id_token", { refresh_token: "refresh-token" }],
      ["missing_refresh_token", { id_token: validIdToken }],
      ["unsafe_refresh_token", { id_token: validIdToken, refresh_token: " refresh-token " }],
      ["invalid_expiry", { id_token: validIdToken, refresh_token: "refresh-token", expires_in: -1 }],
    ] as const;

    for (const [name, tokenFields] of variants) {
      const fixture = await createManagedCallbackFixture(name);
      let googleExchanges = 0;
      let receiverHandoffs = 0;
      let claims = 0;
      const guardedStore = {
        ...fixture.store,
        async claimConnectSessionForPersistence(
          options: Parameters<NonNullable<typeof fixture.store.claimConnectSessionForPersistence>>[0],
        ) {
          claims += 1;
          return fixture.store.claimConnectSessionForPersistence?.(options) ?? null;
        },
      };
      const fetchImpl = async (url: string | URL | Request) => {
        if (url.toString() === "https://oauth2.googleapis.com/token") {
          googleExchanges += 1;
          return new Response(
            JSON.stringify({ access_token: "access-token", ...tokenFields }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (url.toString() === env.ELMORA_TOKEN_WEBHOOK_URL) {
          receiverHandoffs += 1;
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        }
        throw new Error(`Unexpected fetch ${url.toString()}`);
      };

      const result = await handleGoogleOAuthCallback({
        code: "google-code",
        state: fixture.state,
        store: guardedStore,
        env,
        fetchImpl: fetchImpl as typeof fetch,
        idTokenKeyResolver: (await oidcContextPromise).keyResolver,
        now: new Date("2026-07-07T12:02:00.000Z"),
      });

      assert.equal(result.status, "failed", name);
      assert.equal(googleExchanges, 1, name);
      assert.equal(receiverHandoffs, 0, name);
      assert.equal(claims, 0, name);
      assert.equal(
        (await fixture.store.get<{ status: string }>(connectSessionKey(fixture.created.session.id)))?.status,
        "pending",
        name,
      );
    }
  });

  it("finalizes an explicit receiver-persistence rejection as failed and never reports connected", async () => {
    const store = createMemoryConnectSessionStore();
    const agent = await registerCallbackFixture(store);
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
      now: callbackFixtureNow,
      rawToken: "cs_test_persist_failure",
      sessionId: "ocs_test_persist_failure",
    });
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const fetchImpl = async (url: string | URL | Request) => {
      if (url.toString() === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "access-token",
            refresh_token: "refresh-token",
            id_token: await signedIdToken({
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
      if (url.toString() === env.ELMORA_TOKEN_WEBHOOK_URL) {
        return new Response(JSON.stringify({ ok: false }), { status: 503 });
      }
      throw new Error("Unexpected fetch");
    };

    const result = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      store,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    const rejected = await store.get<{ status: string; outcomeCode?: string }>(connectSessionKey(created.session.id));
    assert.equal(rejected?.status, "failed");
    assert.equal(rejected?.outcomeCode, "receiver_rejected");
    assert.equal(
      await getConnectSessionByToken({ store, rawToken: created.rawToken, now: new Date("2026-07-07T12:03:00.000Z") }),
      null,
    );
  });

  it("fails closed when the runtime is revoked after callback claim but before token persistence authorization", async () => {
    const store = createMemoryConnectSessionStore();
    const agent = await registerCallbackFixture(store);
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
      now: callbackFixtureNow,
      rawToken: "cs_test_revoke_after_claim",
      sessionId: "ocs_test_revoke_after_claim",
    });
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    let persistedTokens = 0;
    const fetchImpl = async (url: string | URL | Request) => {
      const urlString = url.toString();
      if (urlString === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "access-token",
            refresh_token: "refresh-token",
            expires_in: 3600,
            id_token: await signedIdToken({
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
        persistedTokens += 1;
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      throw new Error(`Unexpected fetch ${urlString}`);
    };
    const racingStore = {
      ...store,
      async claimConnectSessionForPersistence(options: Parameters<NonNullable<typeof store.claimConnectSessionForPersistence>>[0]) {
        const claimed = await store.claimConnectSessionForPersistence?.(options);
        await revokeAgentRuntime({
          store,
          runtimeId: "test-agent-2",
          now: new Date("2026-07-07T12:02:30.000Z"),
        });
        return claimed ?? null;
      },
    };

    const result = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      store: racingStore,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    assert.equal(result.message, "This Google connection could not be completed. Ask your Elmora agent for a fresh link.");
    assert.equal(persistedTokens, 0);
  });

  it("honestly reports receiver acceptance when final session completion fails", async () => {
    const store = createMemoryConnectSessionStore();
    const agent = await registerCallbackFixture(store);
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
      now: callbackFixtureNow,
      rawToken: "cs_test_completion_failure",
      sessionId: "ocs_test_completion_failure",
    });
    const state = createOAuthState({
      connectSessionId: created.session.id,
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const fetchImpl = async (url: string | URL | Request) => {
      if (url.toString() === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "access-token",
            refresh_token: "refresh-token",
            id_token: await signedIdToken({
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
      if (url.toString() === env.ELMORA_TOKEN_WEBHOOK_URL) {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      throw new Error("Unexpected fetch");
    };
    const completionFailingStore = {
      ...store,
      async completeConnectSessionPersistenceClaim() {
        return null;
      },
    };

    const result = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      store: completionFailingStore,
      env,
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    assert.match(result.message, /receiver accepted.*could not finalize.*status/i);
    const terminal = await store.get<{ status: string; outcomeCode?: string }>(connectSessionKey(created.session.id));
    assert.equal(terminal?.status, "reconciliation_required");
    assert.equal(terminal?.outcomeCode, "finalization_failed");
  });

  it("does not expose provider exception details in public callback failures", async () => {
    const state = createOAuthState({
      runtimeId: "test-agent-2",
      secret: env.ELMORA_STATE_SIGNING_SECRET,
      nonce: googleOidcNonce,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    const fetchImpl = async () =>
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "sensitive provider correlation id 12345",
        }),
        { status: 400, headers: { "content-type": "application/json" } },
      );

    const result = await handleGoogleOAuthCallback({
      code: "google-code",
      state,
      env: { ...env, ELMORA_ALLOWED_RUNTIME_IDS: "test-agent-2" },
      fetchImpl: fetchImpl as typeof fetch,
      idTokenKeyResolver: (await oidcContextPromise).keyResolver,
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(result.status, "failed");
    assert.equal(result.message, "This Google connection could not be completed. Ask your Elmora agent for a fresh link.");
    assert.doesNotMatch(result.message, /invalid_grant|correlation id|12345/i);
  });
});
