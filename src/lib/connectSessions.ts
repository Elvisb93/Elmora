import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { buildGoogleOAuthUrl } from "./googleOAuth";
import {
  createOAuthState,
  parseRuntimeAllowlist,
} from "./oauthState";
import {
  defaultGoogleOAuthClientId,
  getSiteUrl,
  googleWorkspaceProvider,
  type GoogleConnectViewModel,
} from "./oauthConnect";

export type OAuthProviderSlug = "google";
export type ConnectSessionStatus = "pending" | "connected";

export type ConnectSessionRecord = {
  id: string;
  tokenHash: string;
  provider: OAuthProviderSlug;
  runtimeId: string;
  agentName: string;
  clientName: string;
  requestedEmail?: string;
  allowedDomains?: string[];
  status: ConnectSessionStatus;
  createdAt: string;
  expiresAt: string;
  usedAt?: string;
  connectedEmail?: string;
};

export type ConnectSessionStore = {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown, options?: { ex?: number }): Promise<unknown>;
  del(...keys: string[]): Promise<unknown>;
};

export type CreateConnectSessionOptions = {
  store: ConnectSessionStore;
  provider: OAuthProviderSlug;
  runtimeId: string;
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

export type MarkConnectSessionConnectedOptions = {
  store: ConnectSessionStore;
  sessionId: string;
  connectedEmail?: string;
  now?: Date;
};

export type ResolveGoogleConnectSessionViewModelOptions = {
  store: ConnectSessionStore;
  rawToken: string;
  env?: Record<string, string | undefined>;
  now?: Date;
};

export type RuntimeRegistryEntry = {
  runtimeId: string;
  agentName: string;
  clientName: string;
  allowedProviders: OAuthProviderSlug[];
  requestedEmail?: string;
  allowedDomains?: string[];
  connectSecretHash?: string;
};

export type AuthorizedAgent = RuntimeRegistryEntry;

const defaultSessionTtlSeconds = 30 * 60;
const connectedRecordTtlSeconds = 24 * 60 * 60;
const tokenPrefix = "ecs_";
const sessionPrefix = "ocs_";
const kvPrefix = "elmora:connect-session";

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
    dump() {
      return new Map([...values].map(([key, record]) => [key, record.value]));
    },
  };
}

export async function getVercelKvConnectSessionStore(): Promise<ConnectSessionStore> {
  try {
    const { kv } = (await import("@vercel/kv")) as { kv: ConnectSessionStore };
    return kv;
  } catch (error) {
    throw new Error(
      `Vercel KV is not available. Install @vercel/kv and connect a Vercel KV/Redis store. ${
        error instanceof Error ? error.message : ""
      }`.trim(),
    );
  }
}

export function connectSessionKey(sessionId: string) {
  return `${kvPrefix}:id:${sessionId}`;
}

export function connectSessionTokenKey(tokenHash: string) {
  return `${kvPrefix}:token:${tokenHash}`;
}

export function hashConnectToken(rawToken: string) {
  return createHash("sha256").update(rawToken).digest("hex");
}

export function createRawConnectToken() {
  return `${tokenPrefix}${randomBytes(32).toString("base64url")}`;
}

export function createConnectSessionId() {
  return `${sessionPrefix}${randomBytes(18).toString("base64url")}`;
}

function assertSafeRuntimeId(runtimeId: string) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(runtimeId)) {
    throw new Error("Invalid connect-session runtime id");
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

export async function createConnectSession({
  store,
  provider,
  runtimeId,
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

  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
  const tokenHash = hashConnectToken(rawToken);
  const session: ConnectSessionRecord = {
    id: sessionId,
    tokenHash,
    provider,
    runtimeId,
    agentName,
    clientName,
    requestedEmail,
    allowedDomains,
    status: "pending",
    createdAt: now.toISOString(),
    expiresAt,
  };
  const ex = secondsUntilExpiry(expiresAt, now);

  await store.set(connectSessionKey(session.id), session, { ex });
  await store.set(connectSessionTokenKey(tokenHash), session.id, { ex });

  return { rawToken, session };
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

export async function markConnectSessionConnected({
  store,
  sessionId,
  connectedEmail,
  now = new Date(),
}: MarkConnectSessionConnectedOptions) {
  const session = await store.get<ConnectSessionRecord>(connectSessionKey(sessionId));
  if (!session) {
    throw new Error("Connect session not found");
  }
  if (session.status !== "pending") {
    throw new Error("Connect session has already been used");
  }
  if (isSessionExpired(session, now)) {
    throw new Error("Connect session expired");
  }

  const connected: ConnectSessionRecord = {
    ...session,
    status: "connected",
    usedAt: now.toISOString(),
    connectedEmail,
  };

  await store.set(connectSessionKey(session.id), connected, { ex: connectedRecordTtlSeconds });
  await store.del(connectSessionTokenKey(session.tokenHash));

  return connected;
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
  const allowedRuntimeIds = parseRuntimeAllowlist(env.ELMORA_ALLOWED_RUNTIME_IDS);
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

  if (!allowedRuntimeIds.includes(session.runtimeId)) {
    return {
      ...baseView,
      runtimeId: session.runtimeId,
      connectionSession: sessionView,
      error: `Runtime ${session.runtimeId} is not allowed for OAuth connection.`,
    };
  }

  const state = createOAuthState({
    connectSessionId: session.id,
    secret: signingSecret,
    ttlSeconds: secondsUntilExpiry(session.expiresAt, now),
    now,
  });
  const oauthUrl = buildGoogleOAuthUrl({
    clientId,
    redirectUri,
    scopes: getGoogleOAuthScopes(),
    state,
  }).toString();

  return {
    ...baseView,
    configured: true,
    runtimeId: session.runtimeId,
    connectionSession: sessionView,
    oauthUrl,
  };
}

export function parseRuntimeRegistry(value?: string): Record<string, Omit<RuntimeRegistryEntry, "runtimeId">> {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value) as Record<string, Partial<Omit<RuntimeRegistryEntry, "runtimeId">>>;
    return Object.fromEntries(
      Object.entries(parsed).map(([runtimeId, item]) => [
        runtimeId,
        {
          agentName: item.agentName || runtimeId,
          clientName: item.clientName || runtimeId,
          allowedProviders: (item.allowedProviders?.filter((provider) => provider === "google") as OAuthProviderSlug[]) || [
            "google",
          ],
          requestedEmail: item.requestedEmail,
          allowedDomains: item.allowedDomains || [],
          connectSecretHash: item.connectSecretHash,
        },
      ]),
    );
  } catch {
    return {};
  }
}

export function parseAgentConnectSecretHashes(value?: string) {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce<Record<string, string>>((map, item) => {
      const [runtimeId, secretHash, ...extra] = item.split(":");
      if (!runtimeId || !secretHash || extra.length > 0) {
        return map;
      }
      map[runtimeId.trim()] = secretHash.trim().replace(/^sha256:/, "");
      return map;
    }, {});
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

export function authorizeAgentConnectRequest({
  authorization,
  env = process.env,
}: {
  authorization?: string | null;
  env?: Record<string, string | undefined>;
}): AuthorizedAgent | null {
  const rawSecret = authorizationBearerSecret(authorization);
  if (!rawSecret) {
    return null;
  }

  const allowedRuntimeIds = parseRuntimeAllowlist(env.ELMORA_ALLOWED_RUNTIME_IDS);
  const registry = parseRuntimeRegistry(env.ELMORA_AGENT_RUNTIME_REGISTRY);
  const secretHashes = parseAgentConnectSecretHashes(env.ELMORA_AGENT_CONNECT_SECRETS);
  const presentedHash = hashConnectToken(rawSecret);

  for (const runtimeId of allowedRuntimeIds) {
    const registryEntry = registry[runtimeId];
    const expectedHash = registryEntry?.connectSecretHash?.replace(/^sha256:/, "") || secretHashes[runtimeId];
    if (!expectedHash || !safeEqualHex(presentedHash, expectedHash)) {
      continue;
    }

    return {
      runtimeId,
      agentName: registryEntry?.agentName || runtimeId,
      clientName: registryEntry?.clientName || runtimeId,
      allowedProviders: registryEntry?.allowedProviders || ["google"],
      requestedEmail: registryEntry?.requestedEmail,
      allowedDomains: registryEntry?.allowedDomains || [],
      connectSecretHash: expectedHash,
    };
  }

  return null;
}
