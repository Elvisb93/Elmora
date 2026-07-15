import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  agentConnectSecretKey,
  agentRuntimeKey,
  authorizeAgentConnectRequest,
  authorizeAgentRegistryAdminRequest,
  claimConnectSessionForPersistence,
  completeConnectSessionPersistenceClaim,
  connectSessionKey,
  connectSessionTokenKey,
  createConnectSession,
  createConnectSessionId,
  createMemoryConnectSessionStore,
  finalizeConnectSessionPersistenceOutcome,
  getAgentRuntime,
  getConnectSessionByToken,
  hashConnectToken,
  registerAgentRuntime,
  resolveGoogleConnectSessionViewModel,
  revokeAgentRuntime,
} from "../src/lib/connectSessions.ts";
import { verifyOAuthState } from "../src/lib/oauthState.ts";

const env = {
  NEXT_PUBLIC_SITE_URL: "https://elmora-kappa.vercel.app",
  NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID: "client-id.apps.googleusercontent.com",
  ELMORA_STATE_SIGNING_SECRET: "state-signing-test-secret-with-32-plus-chars",
};

describe("KV-backed agent runtime registry", () => {
  it("registers and authenticates an agent without per-agent environment variables", async () => {
    const store = createMemoryConnectSessionStore();
    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      requestedEmail: "owner@example.com",
      allowedDomains: ["example.com"],
      rawConnectSecret: "agent-one-time-bearer-secret",
    });

    const agent = await authorizeAgentConnectRequest({
      store,
      authorization: "Bearer agent-one-time-bearer-secret",
    });

    assert.equal(agent?.runtimeId, "test-agent-2");
    assert.equal(agent?.agentName, "Elmora Test Worker");
    assert.equal(agent?.requestedEmail, "owner@example.com");
    assert.deepEqual(agent?.allowedDomains, ["example.com"]);
    assert.equal(
      await authorizeAgentConnectRequest({ store, authorization: "Bearer wrong-secret" }),
      null,
    );
  });

  it("preserves registryEpoch exactly and keeps registryVersion as a separate opaque token", async () => {
    const store = createMemoryConnectSessionStore();
    const registryEpoch = Number.MAX_SAFE_INTEGER;
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch,
      runtimeId: "epoch-contract-agent",
      agentName: "Epoch Contract Worker",
      clientName: "Epoch Contract Client",
      rawConnectSecret: "epoch-contract-agent-connect-secret",
    });

    assert.equal(agent.registryEpoch, registryEpoch);
    assert.match(agent.registryVersion, /^erv_[A-Za-z0-9_-]+$/);
    assert.notEqual(agent.registryVersion, String(registryEpoch));
    assert.equal(
      (await getAgentRuntime({ store, runtimeId: agent.runtimeId }))?.registryEpoch,
      registryEpoch,
    );
  });

  it("rejects non-positive, fractional, unsafe, non-number, and absent direct registry epochs", async () => {
    const invalidEpochs: unknown[] = [
      undefined,
      0,
      -1,
      1.5,
      "41",
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 1,
    ];

    for (const [index, registryEpoch] of invalidEpochs.entries()) {
      const store = createMemoryConnectSessionStore();
      await assert.rejects(
        registerAgentRuntime({
          store,
          registryEpoch,
          runtimeId: `invalid-epoch-agent-${index}`,
          agentName: "Invalid Epoch Worker",
          clientName: "Invalid Epoch Client",
          rawConnectSecret: `invalid-epoch-agent-connect-secret-${index}`,
        } as Parameters<typeof registerAgentRuntime>[0]),
        /registry epoch/i,
      );
      assert.equal(store.dump().size, 0);
    }
  });

  it("accepts same or higher authoritative epochs but atomically rejects epoch rollback", async () => {
    const store = createMemoryConnectSessionStore();
    const registration = {
      store,
      runtimeId: "epoch-update-agent",
      agentName: "Epoch Update Worker",
      clientName: "Epoch Update Client",
      rawConnectSecret: "epoch-update-agent-connect-secret",
    };
    const first = await registerAgentRuntime({ ...registration, registryEpoch: 101 });
    const same = await registerAgentRuntime({ ...registration, registryEpoch: 101 });
    const advanced = await registerAgentRuntime({ ...registration, registryEpoch: 4_294_967_311 });

    assert.equal(same.agent.registryEpoch, 101);
    assert.notEqual(same.agent.registryVersion, first.agent.registryVersion);
    assert.equal(advanced.agent.registryEpoch, 4_294_967_311);
    await assert.rejects(
      registerAgentRuntime({ ...registration, registryEpoch: 4_294_967_310 }),
      /registry epoch/i,
    );

    const stored = await getAgentRuntime({ store, runtimeId: registration.runtimeId });
    assert.equal(stored?.registryEpoch, 4_294_967_311);
    assert.equal(stored?.registryVersion, advanced.agent.registryVersion);
  });

  it("revokes an agent in KV without a deployment or env edit", async () => {
    const store = createMemoryConnectSessionStore();
    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      rawConnectSecret: "agent-one-time-bearer-secret",
    });

    await revokeAgentRuntime({ store, runtimeId: "test-agent-2" });

    assert.equal(
      await authorizeAgentConnectRequest({
        store,
        authorization: "Bearer agent-one-time-bearer-secret",
      }),
      null,
    );
  });

  it("rejects a bearer secret already assigned to another runtime", async () => {
    const store = createMemoryConnectSessionStore();
    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      rawConnectSecret: "agent-one-time-bearer-secret",
    });

    await assert.rejects(
      registerAgentRuntime({
        store,
        registryEpoch: 41,
        runtimeId: "test-agent-3",
        agentName: "Elmora Other Worker",
        clientName: "Elmora Other Client",
        rawConnectSecret: "agent-one-time-bearer-secret",
      }),
      /already assigned/,
    );
    assert.equal(
      (await authorizeAgentConnectRequest({ store, authorization: "Bearer agent-one-time-bearer-secret" }))?.runtimeId,
      "test-agent-2",
    );
  });

  it("atomically assigns a bearer secret to only one concurrent runtime registration", async () => {
    const store = createMemoryConnectSessionStore();
    let secretIndexReads = 0;
    let releaseReads!: () => void;
    const bothSecretIndexesRead = new Promise<void>((resolve) => {
      releaseReads = resolve;
    });
    const racingStore = {
      ...store,
      async get<T>(key: string) {
        if (key.startsWith("elmora:agent-runtime:secret:")) {
          secretIndexReads += 1;
          if (secretIndexReads === 2) {
            releaseReads();
          }
          await bothSecretIndexesRead;
        }
        return store.get<T>(key);
      },
    };

    const registrations = await Promise.allSettled([
      registerAgentRuntime({
        store: racingStore,
        registryEpoch: 41,
        runtimeId: "test-agent-2",
        agentName: "Elmora Test Worker",
        clientName: "Elmora Test Client",
        rawConnectSecret: "shared-agent-bearer-secret",
      }),
      registerAgentRuntime({
        store: racingStore,
        registryEpoch: 41,
        runtimeId: "test-agent-3",
        agentName: "Elmora Other Worker",
        clientName: "Elmora Other Client",
        rawConnectSecret: "shared-agent-bearer-secret",
      }),
    ]);

    assert.equal(registrations.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(registrations.filter((result) => result.status === "rejected").length, 1);
    const authorized = await authorizeAgentConnectRequest({
      store,
      authorization: "Bearer shared-agent-bearer-secret",
    });
    assert.ok(authorized?.runtimeId === "test-agent-2" || authorized?.runtimeId === "test-agent-3");
  });

  it("atomically refuses a callback claim after the registry version is revoked", async () => {
    const store = createMemoryConnectSessionStore();
    const { agent: activeAgent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      rawConnectSecret: "agent-one-time-bearer-secret",
      now: new Date("2026-07-07T12:00:00.000Z"),
    });
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: activeAgent.runtimeId,
      expectedAgentRegistryEpoch: activeAgent.registryEpoch,
      expectedAgentRegistryVersion: activeAgent.registryVersion,
      agentName: activeAgent.agentName,
      clientName: activeAgent.clientName,
      now: new Date("2026-07-07T12:00:00.000Z"),
      sessionId: "ocs_claim_after_revoke",
    });
    await revokeAgentRuntime({
      store,
      runtimeId: "test-agent-2",
      now: new Date("2026-07-07T12:01:00.000Z"),
    });

    const claim = await claimConnectSessionForPersistence({
      store,
      sessionId: created.session.id,
      runtimeId: "test-agent-2",
      provider: "google",
      expectedAgentRegistryVersion: activeAgent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      now: new Date("2026-07-07T12:02:00.000Z"),
      claimId: "claim_test",
    });

    assert.equal(claim, null);
  });

  it("uses a unique registry version so same-millisecond revoke and re-register do not authorize stale snapshots", async () => {
    const store = createMemoryConnectSessionStore();
    const fixedNow = new Date("2026-07-07T12:00:00.000Z");
    const { agent: originalAgent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      rawConnectSecret: "agent-one-time-bearer-secret",
      now: fixedNow,
    });
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: originalAgent.runtimeId,
      expectedAgentRegistryEpoch: originalAgent.registryEpoch,
      expectedAgentRegistryVersion: originalAgent.registryVersion,
      agentName: originalAgent.agentName,
      clientName: originalAgent.clientName,
      now: fixedNow,
      sessionId: "ocs_same_ms_version",
    });

    await revokeAgentRuntime({ store, runtimeId: "test-agent-2", now: fixedNow });
    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      rawConnectSecret: "agent-one-time-bearer-secret",
      now: fixedNow,
    });
    const reRegisteredAgent = await getAgentRuntime({ store, runtimeId: "test-agent-2" });

    assert.equal(reRegisteredAgent?.updatedAt, originalAgent.updatedAt);
    assert.notEqual(reRegisteredAgent?.registryVersion, originalAgent.registryVersion);
    const staleClaim = await claimConnectSessionForPersistence({
      store,
      sessionId: created.session.id,
      runtimeId: "test-agent-2",
      provider: "google",
      expectedAgentRegistryVersion: originalAgent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      now: new Date("2026-07-07T12:00:01.000Z"),
      claimId: "claim_stale_version",
    });

    assert.equal(staleClaim, null);
  });

  it("atomically refuses session issuance when the authenticated registry snapshot rotates before the write", async () => {
    const store = createMemoryConnectSessionStore();
    const fixedNow = new Date("2026-07-07T12:00:00.000Z");
    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker A",
      clientName: "Elmora Test Client A",
      allowedProviders: ["google"],
      rawConnectSecret: "agent-a-one-time-bearer-secret",
      now: fixedNow,
    });
    const authorizedA = await authorizeAgentConnectRequest({
      store,
      authorization: "Bearer agent-a-one-time-bearer-secret",
    });
    assert.ok(authorizedA);

    await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker B",
      clientName: "Elmora Test Client B",
      allowedProviders: ["google"],
      rawConnectSecret: "agent-b-one-time-bearer-secret",
      now: fixedNow,
    });

    const rawToken = "cs_atomic_issuance_race";
    const sessionId = "ocs_atomic_issuance_race";
    await assert.rejects(
      createConnectSession({
        store,
        provider: "google",
        runtimeId: authorizedA.runtimeId,
        agentName: authorizedA.agentName,
        clientName: authorizedA.clientName,
        expectedAgentRegistryEpoch: authorizedA.registryEpoch,
        expectedAgentRegistryVersion: authorizedA.registryVersion,
        rawToken,
        sessionId,
        now: fixedNow,
      }),
      /authorization changed/i,
    );

    assert.equal(await store.get(connectSessionKey(sessionId)), null);
    assert.equal(await store.get(connectSessionTokenKey(hashConnectToken(rawToken))), null);
  });

  it("freezes the authoritative registry epoch and rejects epoch drift at every atomic session transition", async () => {
    const store = createMemoryConnectSessionStore();
    const now = new Date("2026-07-07T12:00:00.000Z");
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "epoch-transition-agent",
      agentName: "Epoch Transition Worker",
      clientName: "Epoch Transition Client",
      rawConnectSecret: "epoch-transition-agent-secret",
      now,
    });
    const runtimeKey = agentRuntimeKey(agent.runtimeId);
    const epoch42 = { ...agent, registryEpoch: 42 };

    await store.set(runtimeKey, epoch42);
    await assert.rejects(
      createConnectSession({
        store,
        provider: "google",
        runtimeId: agent.runtimeId,
        expectedAgentRegistryVersion: agent.registryVersion,
        expectedAgentRegistryEpoch: agent.registryEpoch,
        agentName: agent.agentName,
        clientName: agent.clientName,
        rawToken: "epoch-drift-before-issuance-token",
        sessionId: "ocs_epoch_drift_before_issuance",
        now,
      }),
      /authorization changed/i,
    );

    await store.set(runtimeKey, agent);
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: agent.runtimeId,
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedAgentRegistryEpoch: agent.registryEpoch,
      agentName: agent.agentName,
      clientName: agent.clientName,
      rawToken: "epoch-transition-token",
      sessionId: "ocs_epoch_transition",
      now,
    });
    assert.equal(created.session.registryEpoch, 41);

    await store.set(runtimeKey, epoch42);
    const staleClaim = await claimConnectSessionForPersistence({
      store,
      sessionId: created.session.id,
      runtimeId: agent.runtimeId,
      provider: "google",
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      claimId: "occ_epoch_stale_claim",
      now,
    });
    assert.equal(staleClaim, null);

    await store.set(runtimeKey, agent);
    const completionSession = await createConnectSession({
      store,
      provider: "google",
      runtimeId: agent.runtimeId,
      expectedAgentRegistryEpoch: agent.registryEpoch,
      expectedAgentRegistryVersion: agent.registryVersion,
      agentName: agent.agentName,
      clientName: agent.clientName,
      rawToken: "epoch-completion-token",
      sessionId: "ocs_epoch_completion",
      now,
    });
    const claimed = await claimConnectSessionForPersistence({
      store,
      sessionId: completionSession.session.id,
      runtimeId: agent.runtimeId,
      provider: "google",
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: completionSession.session.tokenHash,
      claimId: "occ_epoch_valid_claim",
      now,
    });
    assert.ok(claimed);

    await store.set(runtimeKey, epoch42);
    const staleCompletion = await completeConnectSessionPersistenceClaim({
      store,
      sessionId: completionSession.session.id,
      runtimeId: agent.runtimeId,
      provider: "google",
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: completionSession.session.tokenHash,
      claimId: "occ_epoch_valid_claim",
      connectedEmail: "owner@example.com",
      now,
    });
    assert.equal(staleCompletion, null);
  });

  it("rejects internal namespace identifiers before creating runtime, session, or index keys", async () => {
    const reservedIdentifiers = ["__none__", "__NONE__", "__reserved__", "__RESERVED__"];

    for (const runtimeId of reservedIdentifiers) {
      const store = createMemoryConnectSessionStore();
      await assert.rejects(
        registerAgentRuntime({
          store,
          registryEpoch: 41,
          runtimeId,
          agentName: "Elmora Reserved Worker",
          clientName: "Elmora Reserved Client",
          rawConnectSecret: "reserved-agent-bearer-secret",
        }),
        /invalid connect-session runtime id/i,
      );
      assert.equal(store.dump().size, 0);
      assert.throws(() => agentRuntimeKey(runtimeId), /invalid connect-session runtime id/i);
    }

    const store = createMemoryConnectSessionStore();
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "reserved-id-test-agent",
      agentName: "Elmora Reserved Worker",
      clientName: "Elmora Reserved Client",
      rawConnectSecret: "reserved-agent-bearer-secret",
    });
    const keysBefore = store.dump().size;
    for (const sessionId of reservedIdentifiers) {
      await assert.rejects(
        createConnectSession({
          store,
          provider: "google",
          runtimeId: agent.runtimeId,
          expectedAgentRegistryEpoch: agent.registryEpoch,
          expectedAgentRegistryVersion: agent.registryVersion,
          agentName: agent.agentName,
          clientName: agent.clientName,
          sessionId,
        }),
        /invalid connect-session session id/i,
      );
      assert.equal(store.dump().size, keysBefore);
      assert.throws(() => connectSessionKey(sessionId), /invalid connect-session session id/i);
      assert.throws(() => connectSessionTokenKey(sessionId), /invalid connect-session hash index/i);
      assert.throws(() => agentConnectSecretKey(sessionId), /invalid connect-session hash index/i);
    }
  });

  it("uses one versioned static Redis Cluster hash tag for every control-plane key", () => {
    const hash = hashConnectToken("cluster-slot-test-secret");
    const keys = [
      agentRuntimeKey("cluster-slot-runtime"),
      agentConnectSecretKey(hash),
      connectSessionKey("ocs_cluster_slot_session"),
      connectSessionTokenKey(hash),
    ];
    const tags = keys.map((key) => /\{([^{}]+)\}/.exec(key)?.[1]);

    assert.deepEqual(tags, ["elmora-control", "elmora-control", "elmora-control", "elmora-control"]);
    for (const key of keys) {
      assert.match(key, /^elmora:\{elmora-control\}:v1:/);
      assert.equal((key.match(/\{/g) ?? []).length, 1);
      assert.equal((key.match(/\}/g) ?? []).length, 1);
    }
  });
});

describe("agent registry admin bearer authorization", () => {
  const adminSecret = "registry-admin-test-secret-with-32-plus-chars";

  it("accepts only the exact Bearer header using the configured secret", () => {
    assert.equal(
      authorizeAgentRegistryAdminRequest({ authorization: `Bearer ${adminSecret}`, adminSecret }),
      true,
    );

    const adversarialHeaders = [
      undefined,
      "",
      adminSecret,
      `bearer ${adminSecret}`,
      `Bearer  ${adminSecret}`,
      `Bearer\t${adminSecret}`,
      ` Bearer ${adminSecret}`,
      `Bearer ${adminSecret} `,
      `Bearer ${adminSecret}\t`,
      `Bearer ${adminSecret}\r`,
      `Bearer ${adminSecret}\n`,
      `Basic ignored, Bearer ${adminSecret}`,
      `Bearer ${adminSecret}, Basic ignored`,
      `Bearer Bearer ${adminSecret}`,
      "Bearer short-secret",
    ];
    for (const authorization of adversarialHeaders) {
      assert.equal(
        authorizeAgentRegistryAdminRequest({ authorization, adminSecret }),
        false,
        `unexpectedly accepted ${JSON.stringify(authorization)}`,
      );
    }
  });

  it("does not normalize whitespace on the configured admin secret", () => {
    for (const paddedSecret of [` ${adminSecret}`, `${adminSecret} `, `${adminSecret}\t`, `${adminSecret}\n`]) {
      assert.equal(
        authorizeAgentRegistryAdminRequest({ authorization: `Bearer ${adminSecret}`, adminSecret: paddedSecret }),
        false,
      );
      assert.equal(
        authorizeAgentRegistryAdminRequest({ authorization: `Bearer ${paddedSecret}`, adminSecret: paddedSecret }),
        false,
      );
    }
  });
});

describe("KV-backed one-time OAuth connect sessions", () => {
  it("accepts the complete Base64URL alphabet emitted by the session-id generator", () => {
    assert.doesNotThrow(() => connectSessionKey(`ocs_-${"a".repeat(23)}`));
    assert.doesNotThrow(() => connectSessionKey(`ocs__${"a".repeat(23)}`));
    for (let index = 0; index < 1_000; index += 1) {
      assert.doesNotThrow(() => connectSessionKey(createConnectSessionId()));
    }
  });

  it("creates an opaque one-time token without exposing the runtime id in the public URL token", async () => {
    const store = createMemoryConnectSessionStore();
    const now = new Date("2026-07-07T12:00:00.000Z");
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      requestedEmail: "owner@example.com",
      rawConnectSecret: "agent-one-time-bearer-secret",
      now,
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
      now,
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

  it("atomically finalizes a claimed receiver rejection and removes the one-time token index", async () => {
    const store = createMemoryConnectSessionStore();
    const now = new Date("2026-07-07T12:00:00.000Z");
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      rawConnectSecret: "agent-one-time-bearer-secret",
      now,
    });
    const created = await createConnectSession({
      store,
      provider: "google",
      runtimeId: agent.runtimeId,
      expectedAgentRegistryEpoch: agent.registryEpoch,
      expectedAgentRegistryVersion: agent.registryVersion,
      agentName: agent.agentName,
      clientName: agent.clientName,
      rawToken: "cs_test_terminal_failure",
      sessionId: "ocs_test_terminal_failure",
      now,
    });
    const claimId = "occ_test_terminal_failure";
    const claimed = await claimConnectSessionForPersistence({
      store,
      sessionId: created.session.id,
      runtimeId: agent.runtimeId,
      provider: "google",
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      claimId,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    assert.equal(claimed?.status, "processing");

    const finalized = await finalizeConnectSessionPersistenceOutcome({
      store,
      sessionId: created.session.id,
      runtimeId: agent.runtimeId,
      provider: "google",
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      claimId,
      status: "failed",
      outcomeCode: "receiver_rejected",
      now: new Date("2026-07-07T12:02:00.000Z"),
    });

    assert.equal(finalized?.status, "failed");
    assert.equal(finalized?.outcomeCode, "receiver_rejected");
    assert.equal(finalized?.outcomeAt, "2026-07-07T12:02:00.000Z");
    assert.equal(
      await getConnectSessionByToken({
        store,
        rawToken: created.rawToken,
        now: new Date("2026-07-07T12:03:00.000Z"),
      }),
      null,
    );
    assert.equal(
      await finalizeConnectSessionPersistenceOutcome({
        store,
        sessionId: created.session.id,
        runtimeId: agent.runtimeId,
        provider: "google",
        expectedAgentRegistryVersion: agent.registryVersion,
        expectedTokenHash: created.session.tokenHash,
        claimId,
        status: "failed",
        outcomeCode: "receiver_rejected",
        now: new Date("2026-07-07T12:04:00.000Z"),
      }),
      null,
    );
  });

  it("renders a temporary Google connect page with state bound to the connect session id", async () => {
    const store = createMemoryConnectSessionStore();
    const now = new Date("2026-07-07T12:00:00.000Z");
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      requestedEmail: "owner@example.com",
      rawConnectSecret: "agent-one-time-bearer-secret",
      now,
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
      now,
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
    assert.equal(new URL(view.oauthUrl).searchParams.get("nonce"), verified.nonce);
    assert.match(new URL(view.oauthUrl).searchParams.get("scope") ?? "", /\bopenid\b/);
    assert.match(new URL(view.oauthUrl).searchParams.get("scope") ?? "", /\bemail\b/);
  });

  it("requires an exact claim before completion and preserves the public index after invalid attempts", async () => {
    const store = createMemoryConnectSessionStore();
    const createdAt = new Date("2026-07-07T12:00:00.000Z");
    const { agent } = await registerAgentRuntime({
      store,
      registryEpoch: 41,
      runtimeId: "test-agent-2",
      agentName: "Elmora Test Worker",
      clientName: "Elmora Test Client",
      allowedProviders: ["google"],
      requestedEmail: "owner@example.com",
      rawConnectSecret: "agent-one-time-bearer-secret",
      now: createdAt,
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
      now: createdAt,
      rawToken: "cs_test_opaque_token",
      sessionId: "ocs_test_session",
    });
    const tokenIndexKey = connectSessionTokenKey(created.session.tokenHash);
    const claimId = "claim_exact_completion";
    const completionOptions = {
      store,
      sessionId: created.session.id,
      runtimeId: agent.runtimeId,
      provider: "google" as const,
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      claimId,
      connectedEmail: "owner@example.com",
      now: new Date("2026-07-07T12:03:00.000Z"),
    };
    const assertStatusAndPublicIndex = async (status: "pending" | "processing") => {
      assert.equal((await store.get<{ status: string }>(connectSessionKey(created.session.id)))?.status, status);
      assert.equal(await store.get(tokenIndexKey), created.session.id);
    };

    assert.equal(await completeConnectSessionPersistenceClaim(completionOptions), null);
    await assertStatusAndPublicIndex("pending");

    const claimed = await claimConnectSessionForPersistence({
      store,
      sessionId: created.session.id,
      runtimeId: agent.runtimeId,
      provider: "google",
      expectedAgentRegistryVersion: agent.registryVersion,
      expectedTokenHash: created.session.tokenHash,
      claimId,
      now: new Date("2026-07-07T12:01:00.000Z"),
    });
    assert.equal(claimed?.status, "processing");
    await assertStatusAndPublicIndex("processing");

    assert.equal(
      await completeConnectSessionPersistenceClaim({ ...completionOptions, claimId: "claim_wrong_completion" }),
      null,
    );
    await assertStatusAndPublicIndex("processing");

    assert.equal(
      await completeConnectSessionPersistenceClaim({
        ...completionOptions,
        expectedAgentRegistryVersion: "erv_wrong_registry_generation",
      }),
      null,
    );
    await assertStatusAndPublicIndex("processing");

    assert.equal(
      await completeConnectSessionPersistenceClaim({ ...completionOptions, expectedTokenHash: "0".repeat(64) }),
      null,
    );
    await assertStatusAndPublicIndex("processing");

    const connected = await completeConnectSessionPersistenceClaim(completionOptions);
    assert.equal(connected?.status, "connected");
    assert.equal(connected?.connectedEmail, "owner@example.com");
    assert.equal(connected?.usedAt, "2026-07-07T12:03:00.000Z");
    assert.equal(await store.get(tokenIndexKey), null);
    assert.equal(
      await getConnectSessionByToken({
        store,
        rawToken: created.rawToken,
        now: new Date("2026-07-07T12:04:00.000Z"),
      }),
      null,
    );
  });
});
