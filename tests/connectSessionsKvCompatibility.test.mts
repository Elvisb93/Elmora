import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  agentConnectSecretKey,
  agentRuntimeKey,
  connectSessionKey,
  connectSessionTokenKey,
  createVercelKvConnectSessionStore,
  hashConnectToken,
  type ConnectSessionRecord,
  type RuntimeRegistryEntry,
} from "../src/lib/connectSessions.ts";

type EvalCall = [script: string, keys: string[], args: string[]];

class FakeVercelKvClient {
  readonly calls: EvalCall[] = [];
  readonly values = new Map<string, unknown>();
  readonly evalResults: unknown[] = [];

  async get<T>(key: string): Promise<T | null> {
    return (this.values.get(key) as T | undefined) ?? null;
  }

  async set(): Promise<"OK"> {
    return "OK";
  }

  async del(): Promise<number> {
    return 0;
  }

  async eval(script: string, keys: string[], args: string[]): Promise<unknown> {
    this.calls.push([script, keys, args]);
    return this.evalResults.shift();
  }
}

describe("@vercel/kv Lua adapter compatibility", () => {
  it("passes script, KEYS array, and ARGV array positionally for every atomic operation", async () => {
    const client = new FakeVercelKvClient();
    const store = createVercelKvConnectSessionStore(client);
    const runtimeId = "kv-adapter-runtime";
    const secretHash = hashConnectToken("kv-adapter-agent-connect-secret");
    const registryVersion = "erv_adapter_registry_version";
    const registryEpoch = Number.MAX_SAFE_INTEGER;
    const now = new Date("2026-07-07T12:00:00.000Z");
    const agent: RuntimeRegistryEntry = {
      runtimeId,
      agentName: "KV Adapter Worker",
      clientName: "KV Adapter Client",
      allowedProviders: ["google"],
      connectSecretHash: secretHash,
      status: "active",
      registryVersion,
      registryEpoch,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
    };

    client.evalResults.push([1, JSON.stringify(agent)]);
    assert.deepEqual(await store.upsertAgentRuntime?.(agent), agent);
    assert.deepEqual(client.calls[0]?.[1], [
      agentRuntimeKey(runtimeId),
      agentConnectSecretKey(secretHash),
      agentConnectSecretKey(secretHash),
    ]);
    assert.deepEqual(client.calls[0]?.[2], [JSON.stringify(agent), "", ""]);
    assert.equal(JSON.parse(client.calls[0]?.[2][0] ?? "{}").registryEpoch, registryEpoch);

    client.values.set(agentRuntimeKey(runtimeId), agent);
    const revoked = {
      ...agent,
      status: "revoked" as const,
      registryVersion: "erv_adapter_revoked_version",
      updatedAt: "2026-07-07T12:01:00.000Z",
    };
    client.evalResults.push([1, JSON.stringify(revoked)]);
    assert.deepEqual(
      await store.revokeAgentRuntime?.(runtimeId, revoked.registryVersion, revoked.updatedAt),
      revoked,
    );
    assert.deepEqual(client.calls[1]?.[1], [agentRuntimeKey(runtimeId), agentConnectSecretKey(secretHash)]);
    assert.deepEqual(client.calls[1]?.[2], [
      revoked.registryVersion,
      revoked.updatedAt,
      registryVersion,
      secretHash,
    ]);

    const tokenHash = hashConnectToken("kv-adapter-connect-token");
    const session: ConnectSessionRecord = {
      id: "ocs_kv_adapter_session",
      tokenHash,
      provider: "google",
      runtimeId,
      registryEpoch,
      registryVersion,
      agentName: agent.agentName,
      clientName: agent.clientName,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt: "2026-07-07T12:30:00.000Z",
    };
    client.evalResults.push(JSON.stringify(session));
    assert.deepEqual(
      await store.createConnectSessionAtomically?.({
        session,
        expectedAgentRegistryEpoch: registryEpoch,
        expectedAgentRegistryVersion: registryVersion,
        ttlSeconds: 1800,
      }),
      session,
    );
    assert.deepEqual(client.calls[2]?.[1], [
      agentRuntimeKey(runtimeId),
      connectSessionKey(session.id),
      connectSessionTokenKey(tokenHash),
    ]);
    assert.deepEqual(client.calls[2]?.[2], [
      registryVersion,
      JSON.stringify(session),
      "1800",
      runtimeId,
      "google",
      session.id,
      tokenHash,
      String(registryEpoch),
    ]);

    const claimed = {
      ...session,
      status: "processing" as const,
      claimId: "occ_kv_adapter_claim",
      claimedAt: "2026-07-07T12:01:00.000Z",
    };
    client.evalResults.push(JSON.stringify(claimed));
    assert.deepEqual(
      await store.claimConnectSessionForPersistence?.({
        sessionId: session.id,
        runtimeId,
        provider: "google",
        expectedAgentRegistryVersion: registryVersion,
        expectedTokenHash: tokenHash,
        claimId: claimed.claimId,
        now: new Date(claimed.claimedAt),
      }),
      claimed,
    );
    assert.deepEqual(client.calls[3]?.[1], [
      agentRuntimeKey(runtimeId),
      connectSessionKey(session.id),
      connectSessionTokenKey(tokenHash),
    ]);
    assert.deepEqual(client.calls[3]?.[2], [
      registryVersion,
      claimed.claimId,
      claimed.claimedAt,
      runtimeId,
      "google",
      session.id,
      tokenHash,
    ]);

    const connected = {
      ...claimed,
      status: "connected" as const,
      usedAt: "2026-07-07T12:02:00.000Z",
      connectedEmail: "owner@example.com",
    };
    client.values.set(connectSessionKey(session.id), connected);
    client.evalResults.push(1);
    assert.deepEqual(
      await store.completeConnectSessionPersistenceClaim?.({
        sessionId: session.id,
        runtimeId,
        provider: "google",
        expectedAgentRegistryVersion: registryVersion,
        expectedTokenHash: tokenHash,
        claimId: claimed.claimId,
        connectedEmail: connected.connectedEmail,
        now: new Date(connected.usedAt),
      }),
      connected,
    );
    assert.deepEqual(client.calls[4]?.[1], [
      agentRuntimeKey(runtimeId),
      connectSessionKey(session.id),
      connectSessionTokenKey(tokenHash),
    ]);
    assert.deepEqual(client.calls[4]?.[2], [
      registryVersion,
      claimed.claimId,
      connected.usedAt,
      runtimeId,
      "google",
      session.id,
      connected.connectedEmail,
      "86400",
      tokenHash,
    ]);

    for (const [script, keys, args] of client.calls) {
      assert.ok(Array.isArray(keys));
      assert.ok(Array.isArray(args));
      assert.ok(keys.length > 0);
      assert.ok(keys.every((key) => key.includes("{elmora-control}")));
      assert.ok(args.every((arg) => typeof arg === "string"));

      for (const match of script.matchAll(/redis\.call\("[A-Z]+",\s*([^,\n)]+)/g)) {
        assert.match(match[1]?.trim() ?? "", /^KEYS\[\d+\]$/);
      }
      assert.doesNotMatch(script, /ARGV\[\d+\]\s*\.\./);
    }
  });
});
