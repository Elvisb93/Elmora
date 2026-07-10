import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { buildGoogleOAuthUrl } from "./googleOAuth";
import { createOAuthNonce, createOAuthState } from "./oauthState";
import {
  defaultGoogleOAuthClientId,
  getSiteUrl,
  googleWorkspaceProvider,
  type GoogleConnectViewModel,
} from "./oauthConnect";

export type OAuthProviderSlug = "google";
export type ConnectSessionStatus = "pending" | "processing" | "connected";

export type ConnectSessionRecord = {
  id: string;
  tokenHash: string;
  provider: OAuthProviderSlug;
  runtimeId: string;
  readonly registryEpoch: number;
  readonly registryVersion: string;
  agentName: string;
  clientName: string;
  requestedEmail?: string;
  allowedDomains?: string[];
  status: ConnectSessionStatus;
  createdAt: string;
  expiresAt: string;
  claimId?: string;
  claimedAt?: string;
  usedAt?: string;
  connectedEmail?: string;
};

export type ClaimConnectSessionForPersistenceOptions = {
  sessionId: string;
  runtimeId: string;
  provider: OAuthProviderSlug;
  expectedAgentRegistryVersion: string;
  expectedTokenHash: string;
  claimId: string;
  now: Date;
};

export type CompleteConnectSessionPersistenceClaimOptions = {
  sessionId: string;
  runtimeId: string;
  provider: OAuthProviderSlug;
  expectedAgentRegistryVersion: string;
  expectedTokenHash: string;
  claimId: string;
  connectedEmail?: string;
  now: Date;
};

export type ConnectSessionStore = {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, options?: { ex?: number }): Promise<unknown>;
  del(...keys: string[]): Promise<unknown>;
  upsertAgentRuntime?(agent: RuntimeRegistryEntry): Promise<RuntimeRegistryEntry | null>;
  revokeAgentRuntime?(
    runtimeId: string,
    registryVersion: string,
    updatedAt: string,
  ): Promise<RuntimeRegistryEntry | null>;
  createConnectSessionAtomically?(options: {
    session: ConnectSessionRecord;
    expectedAgentRegistryEpoch: number;
    expectedAgentRegistryVersion: string;
    ttlSeconds: number;
  }): Promise<ConnectSessionRecord | null>;
  claimConnectSessionForPersistence?(
    options: ClaimConnectSessionForPersistenceOptions,
  ): Promise<ConnectSessionRecord | null>;
  completeConnectSessionPersistenceClaim?(
    options: CompleteConnectSessionPersistenceClaimOptions,
  ): Promise<ConnectSessionRecord | null>;
};

export type CreateConnectSessionOptions = {
  store: ConnectSessionStore;
  provider: OAuthProviderSlug;
  runtimeId: string;
  expectedAgentRegistryEpoch: number;
  expectedAgentRegistryVersion: string;
  agentName: string;
  clientName: string;
  requestedEmail?: string;
  allowedDomains?: string[];
  now?: Date;
  ttlSeconds?: number;
  rawToken?: string;
  sessionId?: string;
};

export type GetConnectSessionByTokenOptions = {
  store: ConnectSessionStore;
  rawToken: string;
  now?: Date;
};

export type ResolveGoogleConnectSessionViewModelOptions = {
  store: ConnectSessionStore;
  rawToken: string;
  env?: Record<string, string | undefined>;
  now?: Date;
};

export type RuntimeRegistryEntry = {
  readonly registryEpoch: number;
  runtimeId: string;
  agentName: string;
  clientName: string;
  allowedProviders: OAuthProviderSlug[];
  requestedEmail?: string;
  allowedDomains?: string[];
  connectSecretHash: string;
  status: "active" | "revoked";
  registryVersion: string;
  createdAt: string;
  updatedAt: string;
};

export type AuthorizedAgent = RuntimeRegistryEntry;

export type RegisterAgentRuntimeOptions = {
  store: ConnectSessionStore;
  readonly registryEpoch: number;
  runtimeId: string;
  agentName: string;
  clientName: string;
  allowedProviders?: OAuthProviderSlug[];
  requestedEmail?: string;
  allowedDomains?: string[];
  rawConnectSecret?: string;
  now?: Date;
};

const defaultSessionTtlSeconds = 30 * 60;
const connectedRecordTtlSeconds = 24 * 60 * 60;
const tokenPrefix = "ecs_";
const sessionPrefix = "ocs_";
// Namespace v1 is centralized here because this control-plane data is new and has no live migration contract yet.
// The fixed hash tag must never contain runtime input: every key touched by one Lua script stays in one Cluster slot.
const controlPlaneKvNamespaceVersion = "v1";
const controlPlaneRedisHashTag = "{elmora-control}";
const controlPlaneKvPrefix = `elmora:${controlPlaneRedisHashTag}:${controlPlaneKvNamespaceVersion}`;
const kvPrefix = `${controlPlaneKvPrefix}:connect-session`;
const agentRegistryPrefix = `${controlPlaneKvPrefix}:agent-runtime`;
const agentSecretPrefix = "eac_";
const atomicAgentRuntimeUpsertScript = `
local proposed = cjson.decode(ARGV[1])
if type(proposed.registryEpoch) ~= "number"
  or proposed.registryEpoch < 1
  or proposed.registryEpoch % 1 ~= 0 then
  return {-2}
end
local secretOwner = redis.call("GET", KEYS[2])
if secretOwner and secretOwner ~= proposed.runtimeId then
  return {0}
end

local existingRaw = redis.call("GET", KEYS[1])
if existingRaw then
  local existing = cjson.decode(existingRaw)
  if ARGV[2] == ""
    or tostring(existing.registryVersion or "") ~= ARGV[2]
    or tostring(existing.connectSecretHash or "") ~= ARGV[3] then
    return {-1}
  end
  if type(existing.registryEpoch) ~= "number"
    or existing.registryEpoch < 1
    or existing.registryEpoch % 1 ~= 0
    or proposed.registryEpoch < existing.registryEpoch then
    return {-2}
  end
  proposed.createdAt = existing.createdAt or proposed.createdAt
  if existing.connectSecretHash ~= proposed.connectSecretHash then
    local oldSecretOwner = redis.call("GET", KEYS[3])
    if oldSecretOwner == proposed.runtimeId then
      redis.call("DEL", KEYS[3])
    end
  end
elseif ARGV[2] ~= "" or ARGV[3] ~= "" then
  return {-1}
end

local encoded = cjson.encode(proposed)
redis.call("SET", KEYS[1], encoded)
redis.call("SET", KEYS[2], proposed.runtimeId)
return {1, encoded}
`;

const atomicAgentRuntimeRevokeScript = `
local existingRaw = redis.call("GET", KEYS[1])
if not existingRaw then
  return {0}
end

local existing = cjson.decode(existingRaw)
if tostring(existing.registryVersion or "") ~= ARGV[3]
  or tostring(existing.connectSecretHash or "") ~= ARGV[4] then
  return {-1}
end
existing.status = "revoked"
existing.registryVersion = ARGV[1]
existing.updatedAt = ARGV[2]
local encoded = cjson.encode(existing)
redis.call("SET", KEYS[1], encoded)
local secretOwner = redis.call("GET", KEYS[2])
if secretOwner == existing.runtimeId then
  redis.call("DEL", KEYS[2])
end
return {1, encoded}
`;

const atomicConnectSessionCreateScript = `
local agentRaw = redis.call("GET", KEYS[1])
if not agentRaw then
  return false
end

local agent = cjson.decode(agentRaw)
local session = cjson.decode(ARGV[2])
if agent.status ~= "active"
  or type(agent.registryEpoch) ~= "number"
  or agent.registryEpoch < 1
  or agent.registryEpoch % 1 ~= 0
  or type(session.registryEpoch) ~= "number"
  or session.registryEpoch ~= agent.registryEpoch
  or tostring(session.registryEpoch) ~= ARGV[8]
  or tostring(agent.registryVersion or "") ~= ARGV[1]
  or tostring(session.registryVersion or "") ~= ARGV[1]
  or tostring(agent.runtimeId or "") ~= ARGV[4]
  or tostring(session.runtimeId or "") ~= ARGV[4]
  or tostring(session.provider or "") ~= ARGV[5]
  or tostring(session.id or "") ~= ARGV[6]
  or tostring(session.tokenHash or "") ~= ARGV[7]
  or session.status ~= "pending" then
  return false
end

local providerAllowed = false
for _, provider in ipairs(agent.allowedProviders or {}) do
  if provider == ARGV[5] then
    providerAllowed = true
    break
  end
end
if not providerAllowed or redis.call("EXISTS", KEYS[2], KEYS[3]) ~= 0 then
  return false
end

local encoded = cjson.encode(session)
redis.call("SET", KEYS[2], encoded, "EX", ARGV[3])
redis.call("SET", KEYS[3], ARGV[6], "EX", ARGV[3])
return encoded
`;

const atomicConnectSessionClaimScript = `
local agentRaw = redis.call("GET", KEYS[1])
local sessionRaw = redis.call("GET", KEYS[2])
local tokenSessionId = redis.call("GET", KEYS[3])
if not agentRaw or not sessionRaw or not tokenSessionId then
  return false
end

local agent = cjson.decode(agentRaw)
local session = cjson.decode(sessionRaw)
if tostring(session.id or "") ~= ARGV[6]
  or tostring(session.runtimeId or "") ~= ARGV[4]
  or tostring(session.provider or "") ~= ARGV[5]
  or tostring(session.tokenHash or "") ~= ARGV[7]
  or tokenSessionId ~= ARGV[6]
  or session.status ~= "pending" then
  return false
end

local providerAllowed = false
for _, provider in ipairs(agent.allowedProviders or {}) do
  if provider == ARGV[5] then
    providerAllowed = true
    break
  end
end
if agent.status ~= "active"
  or type(agent.registryEpoch) ~= "number"
  or agent.registryEpoch < 1
  or agent.registryEpoch % 1 ~= 0
  or type(session.registryEpoch) ~= "number"
  or session.registryEpoch ~= agent.registryEpoch
  or tostring(agent.registryVersion or "") ~= ARGV[1]
  or tostring(session.registryVersion or "") ~= ARGV[1]
  or not providerAllowed then
  redis.call("DEL", KEYS[3])
  return false
end

local ttl = redis.call("PTTL", KEYS[2])
if ttl <= 0 then
  return false
end
session.status = "processing"
session.claimId = ARGV[2]
session.claimedAt = ARGV[3]
local encoded = cjson.encode(session)
redis.call("SET", KEYS[2], encoded, "PX", ttl)
return encoded
`;

const atomicConnectSessionCompleteScript = `
local agentRaw = redis.call("GET", KEYS[1])
local sessionRaw = redis.call("GET", KEYS[2])
if not agentRaw or not sessionRaw then
  return 0
end

local agent = cjson.decode(agentRaw)
local session = cjson.decode(sessionRaw)
local providerAllowed = false
for _, provider in ipairs(agent.allowedProviders or {}) do
  if provider == ARGV[5] then
    providerAllowed = true
    break
  end
end
if agent.status ~= "active"
  or type(agent.registryEpoch) ~= "number"
  or agent.registryEpoch < 1
  or agent.registryEpoch % 1 ~= 0
  or type(session.registryEpoch) ~= "number"
  or session.registryEpoch ~= agent.registryEpoch
  or tostring(agent.registryVersion or "") ~= ARGV[1]
  or tostring(session.registryVersion or "") ~= ARGV[1]
  or not providerAllowed then
  return 0
end
if tostring(session.id or "") ~= ARGV[6]
  or tostring(session.runtimeId or "") ~= ARGV[4]
  or tostring(session.provider or "") ~= ARGV[5]
  or session.status ~= "processing"
  or tostring(session.claimId or "") ~= ARGV[2]
  or tostring(session.tokenHash or "") ~= ARGV[9]
  or redis.call("GET", KEYS[3]) ~= ARGV[6] then
  return 0
end
local ttl = redis.call("PTTL", KEYS[2])
if ttl <= 0 then
  return 0
end
session.status = "connected"
session.usedAt = ARGV[3]
if ARGV[7] ~= "" then
  session.connectedEmail = ARGV[7]
end
redis.call("SET", KEYS[2], cjson.encode(session), "EX", ARGV[8])
redis.call("DEL", KEYS[3])
return 1
`;

export function createMemoryConnectSessionStore(): ConnectSessionStore & { dump(): Map<string, unknown> } {
  const values = new Map<string, { value: unknown; expiresAt?: number }>();

  function isExpired(record?: { expiresAt?: number }) {
    return typeof record?.expiresAt === "number" && record.expiresAt <= Date.now();
  }

  return {
    async get<T>(key: string) {
      const record = values.get(key);
      if (!record || isExpired(record)) {
        values.delete(key);
        return null;
      }
      return record.value as T;
    },
    async set(key: string, value: unknown, options?: { ex?: number }) {
      values.set(key, {
        value,
        expiresAt: options?.ex ? Date.now() + options.ex * 1000 : undefined,
      });
      return "OK";
    },
    async del(...keys: string[]) {
      for (const key of keys) {
        values.delete(key);
      }
      return keys.length;
    },
    async upsertAgentRuntime(agent) {
      const secretKey = agentConnectSecretKey(agent.connectSecretHash);
      const existingSecretOwner = values.get(secretKey)?.value as string | undefined;
      if (existingSecretOwner && existingSecretOwner !== agent.runtimeId) {
        return null;
      }

      const runtimeKey = agentRuntimeKey(agent.runtimeId);
      const existing = values.get(runtimeKey)?.value as RuntimeRegistryEntry | undefined;
      if (
        existing &&
        (!Number.isSafeInteger(existing.registryEpoch) ||
          existing.registryEpoch < 1 ||
          agent.registryEpoch < existing.registryEpoch)
      ) {
        return null;
      }
      const storedAgent = {
        ...agent,
        createdAt: existing?.createdAt ?? agent.createdAt,
      };
      if (existing?.connectSecretHash && existing.connectSecretHash !== agent.connectSecretHash) {
        const oldSecretKey = agentConnectSecretKey(existing.connectSecretHash);
        if (values.get(oldSecretKey)?.value === agent.runtimeId) {
          values.delete(oldSecretKey);
        }
      }
      values.set(runtimeKey, { value: storedAgent });
      values.set(secretKey, { value: agent.runtimeId });
      return storedAgent;
    },
    async revokeAgentRuntime(runtimeId, registryVersion, updatedAt) {
      const runtimeKey = agentRuntimeKey(runtimeId);
      const existing = values.get(runtimeKey)?.value as RuntimeRegistryEntry | undefined;
      if (!existing) {
        return null;
      }
      const revoked: RuntimeRegistryEntry = {
        ...existing,
        status: "revoked",
        registryVersion,
        updatedAt,
      };
      values.set(runtimeKey, { value: revoked });
      const secretKey = agentConnectSecretKey(existing.connectSecretHash);
      if (values.get(secretKey)?.value === runtimeId) {
        values.delete(secretKey);
      }
      return revoked;
    },
    async createConnectSessionAtomically(options) {
      const { session, expectedAgentRegistryEpoch, expectedAgentRegistryVersion, ttlSeconds } = options;
      const agentRecord = values.get(agentRuntimeKey(session.runtimeId));
      if (!agentRecord || isExpired(agentRecord)) {
        return null;
      }

      const agent = agentRecord.value as RuntimeRegistryEntry;
      const sessionKey = connectSessionKey(session.id);
      const tokenKey = connectSessionTokenKey(session.tokenHash);
      if (
        agent.status !== "active" ||
        !Number.isSafeInteger(agent.registryEpoch) ||
        agent.registryEpoch < 1 ||
        agent.registryEpoch !== expectedAgentRegistryEpoch ||
        session.registryEpoch !== expectedAgentRegistryEpoch ||
        agent.registryVersion !== expectedAgentRegistryVersion ||
        session.registryVersion !== expectedAgentRegistryVersion ||
        !agent.allowedProviders.includes(session.provider) ||
        values.has(sessionKey) ||
        values.has(tokenKey)
      ) {
        return null;
      }

      const expiresAt = Date.now() + ttlSeconds * 1000;
      values.set(sessionKey, { value: session, expiresAt });
      values.set(tokenKey, { value: session.id, expiresAt });
      return session;
    },
    async claimConnectSessionForPersistence(options) {
      const agentRecord = values.get(agentRuntimeKey(options.runtimeId));
      const sessionRecord = values.get(connectSessionKey(options.sessionId));
      const tokenKey = connectSessionTokenKey(options.expectedTokenHash);
      const tokenRecord = values.get(tokenKey);
      if (
        !agentRecord ||
        isExpired(agentRecord) ||
        !sessionRecord ||
        isExpired(sessionRecord) ||
        !tokenRecord ||
        isExpired(tokenRecord)
      ) {
        return null;
      }

      const agent = agentRecord.value as RuntimeRegistryEntry;
      const session = sessionRecord.value as ConnectSessionRecord;
      if (
        session.id !== options.sessionId ||
        session.runtimeId !== options.runtimeId ||
        session.provider !== options.provider ||
        session.tokenHash !== options.expectedTokenHash ||
        tokenRecord.value !== options.sessionId ||
        session.status !== "pending" ||
        isSessionExpired(session, options.now)
      ) {
        return null;
      }
      if (
        agent.status !== "active" ||
        !Number.isSafeInteger(agent.registryEpoch) ||
        agent.registryEpoch < 1 ||
        session.registryEpoch !== agent.registryEpoch ||
        agent.registryVersion !== options.expectedAgentRegistryVersion ||
        session.registryVersion !== options.expectedAgentRegistryVersion ||
        !agent.allowedProviders.includes(options.provider)
      ) {
        values.delete(tokenKey);
        return null;
      }

      const claimed: ConnectSessionRecord = {
        ...session,
        status: "processing",
        claimId: options.claimId,
        claimedAt: options.now.toISOString(),
      };
      values.set(connectSessionKey(options.sessionId), {
        value: claimed,
        expiresAt: sessionRecord.expiresAt,
      });
      return claimed;
    },
    async completeConnectSessionPersistenceClaim(options) {
      const agentRecord = values.get(agentRuntimeKey(options.runtimeId));
      const sessionRecord = values.get(connectSessionKey(options.sessionId));
      const tokenKey = connectSessionTokenKey(options.expectedTokenHash);
      const tokenRecord = values.get(tokenKey);
      if (
        !agentRecord ||
        isExpired(agentRecord) ||
        !sessionRecord ||
        isExpired(sessionRecord) ||
        !tokenRecord ||
        isExpired(tokenRecord)
      ) {
        return null;
      }

      const agent = agentRecord.value as RuntimeRegistryEntry;
      const session = sessionRecord.value as ConnectSessionRecord;
      if (
        agent.status !== "active" ||
        !Number.isSafeInteger(agent.registryEpoch) ||
        agent.registryEpoch < 1 ||
        session.registryEpoch !== agent.registryEpoch ||
        agent.registryVersion !== options.expectedAgentRegistryVersion ||
        session.registryVersion !== options.expectedAgentRegistryVersion ||
        !agent.allowedProviders.includes(options.provider) ||
        session.id !== options.sessionId ||
        session.runtimeId !== options.runtimeId ||
        session.provider !== options.provider ||
        session.status !== "processing" ||
        session.claimId !== options.claimId ||
        session.tokenHash !== options.expectedTokenHash ||
        tokenRecord.value !== options.sessionId ||
        isSessionExpired(session, options.now)
      ) {
        return null;
      }

      const connected: ConnectSessionRecord = {
        ...session,
        status: "connected",
        usedAt: options.now.toISOString(),
        connectedEmail: options.connectedEmail,
      };
      values.set(connectSessionKey(options.sessionId), {
        value: connected,
        expiresAt: Date.now() + connectedRecordTtlSeconds * 1000,
      });
      values.delete(connectSessionTokenKey(session.tokenHash));
      return connected;
    },
    dump() {
      return new Map([...values].map(([key, record]) => [key, record.value]));
    },
  };
}

type VercelKvClient = {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, options?: { ex?: number }): Promise<unknown>;
  del(...keys: string[]): Promise<unknown>;
  eval(script: string, keys: string[], args: string[]): Promise<unknown>;
};

function parseStoredJson<T>(stored: unknown): T {
  return (typeof stored === "string" ? JSON.parse(stored) : stored) as T;
}

function parseAtomicMutationResult(result: unknown) {
  if (!Array.isArray(result)) {
    return { status: Number.NaN, value: undefined };
  }
  return { status: Number(result[0]), value: result[1] };
}

export function createVercelKvConnectSessionStore(kv: VercelKvClient): ConnectSessionStore {
  return {
    get<T>(key: string) {
      return kv.get<T>(key);
    },
    set(key: string, value: unknown, options?: { ex?: number }) {
      return kv.set(key, value, options);
    },
    del(...keys: string[]) {
      return kv.del(...keys);
    },
    async upsertAgentRuntime(agent) {
      const runtimeKey = agentRuntimeKey(agent.runtimeId);
      const newSecretKey = agentConnectSecretKey(agent.connectSecretHash);
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const existing = await kv.get<RuntimeRegistryEntry>(runtimeKey);
        const oldSecretKey = existing
          ? agentConnectSecretKey(existing.connectSecretHash)
          : newSecretKey;
        const result = parseAtomicMutationResult(
          await kv.eval(
            atomicAgentRuntimeUpsertScript,
            [runtimeKey, newSecretKey, oldSecretKey],
            [
              JSON.stringify(agent),
              existing?.registryVersion ?? "",
              existing?.connectSecretHash ?? "",
            ],
          ),
        );
        if (result.status === -1) {
          continue;
        }
        if (result.status !== 1 || !result.value) {
          return null;
        }
        return parseStoredJson<RuntimeRegistryEntry>(result.value);
      }
      throw new Error("Agent runtime registry changed too frequently during atomic update");
    },
    async revokeAgentRuntime(runtimeId, registryVersion, updatedAt) {
      const runtimeKey = agentRuntimeKey(runtimeId);
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const existing = await kv.get<RuntimeRegistryEntry>(runtimeKey);
        if (!existing) {
          return null;
        }
        const result = parseAtomicMutationResult(
          await kv.eval(
            atomicAgentRuntimeRevokeScript,
            [runtimeKey, agentConnectSecretKey(existing.connectSecretHash)],
            [
              registryVersion,
              updatedAt,
              existing.registryVersion,
              existing.connectSecretHash,
            ],
          ),
        );
        if (result.status === -1) {
          continue;
        }
        if (result.status !== 1 || !result.value) {
          return null;
        }
        return parseStoredJson<RuntimeRegistryEntry>(result.value);
      }
      throw new Error("Agent runtime registry changed too frequently during atomic revoke");
    },
    async createConnectSessionAtomically(options) {
      const { session, expectedAgentRegistryEpoch, expectedAgentRegistryVersion, ttlSeconds } = options;
      const stored = await kv.eval(
        atomicConnectSessionCreateScript,
        [
          agentRuntimeKey(session.runtimeId),
          connectSessionKey(session.id),
          connectSessionTokenKey(session.tokenHash),
        ],
        [
          expectedAgentRegistryVersion,
          JSON.stringify(session),
          String(ttlSeconds),
          session.runtimeId,
          session.provider,
          session.id,
          session.tokenHash,
          String(expectedAgentRegistryEpoch),
        ],
      );
      if (!stored) {
        return null;
      }
      return parseStoredJson<ConnectSessionRecord>(stored);
    },
    async claimConnectSessionForPersistence(options) {
      const claimed = await kv.eval(
        atomicConnectSessionClaimScript,
        [
          agentRuntimeKey(options.runtimeId),
          connectSessionKey(options.sessionId),
          connectSessionTokenKey(options.expectedTokenHash),
        ],
        [
          options.expectedAgentRegistryVersion,
          options.claimId,
          options.now.toISOString(),
          options.runtimeId,
          options.provider,
          options.sessionId,
          options.expectedTokenHash,
        ],
      );
      if (!claimed) {
        return null;
      }
      return parseStoredJson<ConnectSessionRecord>(claimed);
    },
    async completeConnectSessionPersistenceClaim(options) {
      const connected = await kv.eval(
        atomicConnectSessionCompleteScript,
        [
          agentRuntimeKey(options.runtimeId),
          connectSessionKey(options.sessionId),
          connectSessionTokenKey(options.expectedTokenHash),
        ],
        [
          options.expectedAgentRegistryVersion,
          options.claimId,
          options.now.toISOString(),
          options.runtimeId,
          options.provider,
          options.sessionId,
          options.connectedEmail ?? "",
          String(connectedRecordTtlSeconds),
          options.expectedTokenHash,
        ],
      );
      if (Number(connected) !== 1) {
        return null;
      }
      return kv.get<ConnectSessionRecord>(connectSessionKey(options.sessionId));
    },
  };
}

export async function getVercelKvConnectSessionStore(): Promise<ConnectSessionStore> {
  try {
    const { kv } = (await import("@vercel/kv")) as { kv: VercelKvClient };
    return createVercelKvConnectSessionStore(kv);
  } catch (error) {
    throw new Error(
      `Vercel KV is not available. Install @vercel/kv and connect a Vercel KV/Redis store. ${
        error instanceof Error ? error.message : ""
      }`.trim(),
    );
  }
}

export function connectSessionKey(sessionId: string) {
  assertSafeSessionId(sessionId);
  return `${kvPrefix}:id:${sessionId}`;
}

export function connectSessionTokenKey(tokenHash: string) {
  assertSafeHashIndex(tokenHash);
  return `${kvPrefix}:token:${tokenHash}`;
}

export function agentRuntimeKey(runtimeId: string) {
  assertSafeRuntimeId(runtimeId);
  return `${agentRegistryPrefix}:id:${runtimeId}`;
}

export function agentConnectSecretKey(secretHash: string) {
  assertSafeHashIndex(secretHash);
  return `${agentRegistryPrefix}:secret:${secretHash}`;
}

export function hashConnectToken(rawToken: string) {
  return createHash("sha256").update(rawToken).digest("hex");
}

export function createRawAgentConnectSecret() {
  return `${agentSecretPrefix}${randomBytes(32).toString("base64url")}`;
}

export function createAgentRegistryVersion() {
  return `erv_${randomBytes(18).toString("base64url")}`;
}

export function createRawConnectToken() {
  return `${tokenPrefix}${randomBytes(32).toString("base64url")}`;
}

export function createConnectSessionId() {
  return `${sessionPrefix}${randomBytes(18).toString("base64url")}`;
}

export function createConnectSessionClaimId() {
  return `occ_${randomBytes(18).toString("base64url")}`;
}

function assertSafeRuntimeId(runtimeId: string) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(runtimeId)) {
    throw new Error("Invalid connect-session runtime id");
  }
}

function assertSafeSessionId(sessionId: string) {
  if (!/^ocs_[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$/.test(sessionId)) {
    throw new Error("Invalid connect-session session id");
  }
}

function assertSafeHashIndex(hashIndex: string) {
  if (!/^[a-f0-9]{64}$/.test(hashIndex)) {
    throw new Error("Invalid connect-session hash index");
  }
}

function assertSafeProvider(provider: string): asserts provider is OAuthProviderSlug {
  if (provider !== "google") {
    throw new Error("Unsupported connect-session provider");
  }
}

function secondsUntilExpiry(expiresAt: string, now: Date) {
  return Math.max(1, Math.ceil((new Date(expiresAt).getTime() - now.getTime()) / 1000));
}

function isSessionExpired(session: ConnectSessionRecord, now: Date) {
  return new Date(session.expiresAt).getTime() <= now.getTime();
}

export async function getAgentRuntime({
  store,
  runtimeId,
}: {
  store: ConnectSessionStore;
  runtimeId: string;
}) {
  assertSafeRuntimeId(runtimeId);
  return store.get<RuntimeRegistryEntry>(agentRuntimeKey(runtimeId));
}

export async function registerAgentRuntime({
  store,
  registryEpoch,
  runtimeId,
  agentName,
  clientName,
  allowedProviders = ["google"],
  requestedEmail,
  allowedDomains = [],
  rawConnectSecret,
  now = new Date(),
}: RegisterAgentRuntimeOptions) {
  assertSafeRuntimeId(runtimeId);
  if (!Number.isSafeInteger(registryEpoch) || registryEpoch < 1) {
    throw new Error("Registry epoch must be a positive safe integer");
  }
  if (!agentName.trim() || !clientName.trim()) {
    throw new Error("Agent name and client name are required");
  }
  for (const provider of allowedProviders) {
    assertSafeProvider(provider);
  }

  const generatedSecret = rawConnectSecret ?? createRawAgentConnectSecret();
  if (generatedSecret.length < 24) {
    throw new Error("Agent connect secret must be at least 24 characters");
  }
  const connectSecretHash = hashConnectToken(generatedSecret);
  const timestamp = now.toISOString();
  const proposedAgent: RuntimeRegistryEntry = {
    registryEpoch,
    runtimeId,
    agentName: agentName.trim(),
    clientName: clientName.trim(),
    allowedProviders: [...new Set(allowedProviders)],
    requestedEmail: requestedEmail?.trim().toLowerCase() || undefined,
    allowedDomains: [...new Set(allowedDomains.map((domain) => domain.trim().toLowerCase()).filter(Boolean))],
    connectSecretHash,
    status: "active",
    registryVersion: createAgentRegistryVersion(),
    createdAt: timestamp,
    updatedAt: timestamp,
  };

  if (!store.upsertAgentRuntime) {
    throw new Error("Agent runtime store does not support atomic registry updates");
  }
  const agent = await store.upsertAgentRuntime(proposedAgent);
  if (!agent) {
    throw new Error(
      "Agent connect secret is already assigned to another runtime or registry epoch would decrease",
    );
  }

  return {
    agent,
    rawConnectSecret: rawConnectSecret ? undefined : generatedSecret,
  };
}

export async function revokeAgentRuntime({
  store,
  runtimeId,
  now = new Date(),
}: {
  store: ConnectSessionStore;
  runtimeId: string;
  now?: Date;
}) {
  assertSafeRuntimeId(runtimeId);
  if (!store.revokeAgentRuntime) {
    throw new Error("Agent runtime store does not support atomic registry updates");
  }
  const revoked = await store.revokeAgentRuntime(
    runtimeId,
    createAgentRegistryVersion(),
    now.toISOString(),
  );
  return Boolean(revoked);
}

export async function authorizeAgentConnectRequest({
  store,
  authorization,
}: {
  store: ConnectSessionStore;
  authorization?: string | null;
}): Promise<AuthorizedAgent | null> {
  const rawSecret = authorizationBearerSecret(authorization);
  if (!rawSecret) {
    return null;
  }

  const presentedHash = hashConnectToken(rawSecret);
  const runtimeId = await store.get<string>(agentConnectSecretKey(presentedHash));
  if (!runtimeId) {
    return null;
  }
  const agent = await getAgentRuntime({ store, runtimeId });
  if (!agent || agent.status !== "active" || !safeEqualHex(presentedHash, agent.connectSecretHash)) {
    return null;
  }
  return agent;
}

export async function createConnectSession({
  store,
  provider,
  runtimeId,
  expectedAgentRegistryEpoch,
  expectedAgentRegistryVersion,
  agentName,
  clientName,
  requestedEmail,
  allowedDomains = [],
  now = new Date(),
  ttlSeconds = defaultSessionTtlSeconds,
  rawToken = createRawConnectToken(),
  sessionId = createConnectSessionId(),
}: CreateConnectSessionOptions) {
  assertSafeProvider(provider);
  assertSafeRuntimeId(runtimeId);
  if (!Number.isSafeInteger(expectedAgentRegistryEpoch) || expectedAgentRegistryEpoch < 1) {
    throw new Error("Registry epoch must be a positive safe integer");
  }

  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
  const tokenHash = hashConnectToken(rawToken);
  const session: ConnectSessionRecord = {
    id: sessionId,
    tokenHash,
    provider,
    runtimeId,
    registryEpoch: expectedAgentRegistryEpoch,
    registryVersion: expectedAgentRegistryVersion,
    agentName,
    clientName,
    requestedEmail,
    allowedDomains,
    status: "pending",
    createdAt: now.toISOString(),
    expiresAt,
  };
  const ex = secondsUntilExpiry(expiresAt, now);
  if (!store.createConnectSessionAtomically) {
    throw new Error("Connect-session store does not support atomic authenticated issuance");
  }
  const storedSession = await store.createConnectSessionAtomically({
    session,
    expectedAgentRegistryEpoch,
    expectedAgentRegistryVersion,
    ttlSeconds: ex,
  });
  if (!storedSession) {
    throw new Error("Connect-session authorization changed before session issuance");
  }

  return { rawToken, session: storedSession };
}

export async function claimConnectSessionForPersistence({
  store,
  ...options
}: { store: ConnectSessionStore } & ClaimConnectSessionForPersistenceOptions) {
  if (!store.claimConnectSessionForPersistence) {
    throw new Error("Connect-session store does not support atomic callback claims");
  }
  return store.claimConnectSessionForPersistence(options);
}

export async function completeConnectSessionPersistenceClaim({
  store,
  ...options
}: { store: ConnectSessionStore } & CompleteConnectSessionPersistenceClaimOptions) {
  if (!store.completeConnectSessionPersistenceClaim) {
    throw new Error("Connect-session store does not support atomic callback completion");
  }
  return store.completeConnectSessionPersistenceClaim(options);
}

export async function getConnectSessionById({
  store,
  sessionId,
  now = new Date(),
}: {
  store: ConnectSessionStore;
  sessionId: string;
  now?: Date;
}) {
  const session = await store.get<ConnectSessionRecord>(connectSessionKey(sessionId));
  if (!session) {
    return null;
  }
  if (session.status !== "pending" || isSessionExpired(session, now)) {
    return null;
  }
  return session;
}

export async function getConnectSessionByToken({ store, rawToken, now = new Date() }: GetConnectSessionByTokenOptions) {
  const tokenHash = hashConnectToken(rawToken);
  const sessionId = await store.get<string>(connectSessionTokenKey(tokenHash));
  if (!sessionId) {
    return null;
  }
  return getConnectSessionById({ store, sessionId, now });
}

export function getGoogleOAuthScopes() {
  return [
    "openid",
    "email",
    "profile",
    ...googleWorkspaceProvider.scopes.map((item) => item.scope),
  ];
}

export async function resolveGoogleConnectSessionViewModel({
  store,
  rawToken,
  env = process.env,
  now = new Date(),
}: ResolveGoogleConnectSessionViewModelOptions): Promise<GoogleConnectViewModel> {
  const redirectUri = `${getSiteUrl(env)}${googleWorkspaceProvider.callbackPath}`;
  const clientId = env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ?? env.GOOGLE_OAUTH_CLIENT_ID ?? defaultGoogleOAuthClientId;
  const signingSecret = env.ELMORA_STATE_SIGNING_SECRET;
  const baseView: GoogleConnectViewModel = {
    provider: googleWorkspaceProvider,
    mode: "client",
    configured: false,
    showDeveloperDetails: false,
    runtimeId: "pending",
    redirectUri,
    heading: "Connect Google Workspace",
    eyebrow: "Private Workspace connection",
    intro: googleWorkspaceProvider.summary,
    primaryButtonLabel: "Connect Google Workspace",
  };

  const session = await getConnectSessionByToken({ store, rawToken, now });
  if (!session) {
    return {
      ...baseView,
      error: "This Google connection link has expired or has already been used. Ask your Elmora agent for a fresh link.",
    };
  }

  const sessionView = {
    id: session.id,
    agentName: session.agentName,
    clientName: session.clientName,
    requestedEmail: session.requestedEmail,
    expiresAt: session.expiresAt,
  };

  if (!signingSecret) {
    return {
      ...baseView,
      runtimeId: session.runtimeId,
      connectionSession: sessionView,
      error: "ELMORA_STATE_SIGNING_SECRET is not configured.",
    };
  }

  const registeredAgent = await getAgentRuntime({ store, runtimeId: session.runtimeId });
  if (
    !registeredAgent ||
    registeredAgent.status !== "active" ||
    registeredAgent.registryEpoch !== session.registryEpoch ||
    registeredAgent.registryVersion !== session.registryVersion ||
    !registeredAgent.allowedProviders.includes(session.provider)
  ) {
    return {
      ...baseView,
      runtimeId: session.runtimeId,
      connectionSession: sessionView,
      error: "This agent is not registered or is no longer allowed to create Google connection links.",
    };
  }

  const nonce = createOAuthNonce();
  const state = createOAuthState({
    connectSessionId: session.id,
    secret: signingSecret,
    nonce,
    ttlSeconds: secondsUntilExpiry(session.expiresAt, now),
    now,
  });
  const oauthUrl = buildGoogleOAuthUrl({
    clientId,
    redirectUri,
    scopes: getGoogleOAuthScopes(),
    state,
    nonce,
  }).toString();

  return {
    ...baseView,
    configured: true,
    runtimeId: session.runtimeId,
    connectionSession: sessionView,
    oauthUrl,
  };
}

function safeEqualHex(a: string, b: string) {
  const aBuffer = Buffer.from(a, "hex");
  const bBuffer = Buffer.from(b, "hex");
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
}

function authorizationBearerSecret(authorization?: string | null) {
  const match = /^Bearer\s+(.+)$/i.exec(authorization ?? "");
  return match?.[1]?.trim();
}

function safeEqualUtf8(a: string, b: string) {
  const aBuffer = Buffer.from(a, "utf8");
  const bBuffer = Buffer.from(b, "utf8");
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
}

export function authorizeAgentRegistryAdminRequest({
  authorization,
  adminSecret,
}: {
  authorization?: string | null;
  adminSecret?: string;
}) {
  if (
    typeof authorization !== "string" ||
    typeof adminSecret !== "string" ||
    adminSecret.length < 24 ||
    /[\u0000-\u0020\u007f]/.test(adminSecret)
  ) {
    return false;
  }
  return safeEqualUtf8(authorization, `Bearer ${adminSecret}`);
}
