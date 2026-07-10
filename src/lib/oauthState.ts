import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type OAuthStatePayload = {
  runtimeId?: string;
  connectSessionId?: string;
  nonce: string;
  expiresAt: string;
};

export type CreateOAuthStateOptions = {
  runtimeId?: string;
  connectSessionId?: string;
  secret: string;
  now?: Date;
  nonce?: string;
  ttlSeconds?: number;
};

export type VerifyOAuthStateOptions = {
  state: string;
  secret: string;
  allowedRuntimeIds: string[];
  now?: Date;
};

const defaultTtlSeconds = 10 * 60;
const maximumTtlSeconds = 60 * 60;
const oauthNoncePattern = /^[A-Za-z0-9_-]{32,128}$/;

function base64UrlEncode(value: string | Buffer) {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signPayload(encodedPayload: string, secret: string) {
  return createHmac("sha256", secret).update(encodedPayload).digest("base64url");
}

function assertSafeRuntimeId(runtimeId: string) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(runtimeId)) {
    throw new Error("Invalid OAuth runtime id");
  }
}

function assertSafeConnectSessionId(connectSessionId: string) {
  if (!/^ocs_[a-zA-Z0-9_-]{8,80}$/.test(connectSessionId)) {
    throw new Error("Invalid OAuth connect session id");
  }
}

function assertSecret(secret: string) {
  if (secret.length < 32) {
    throw new Error("OAuth state signing secret must be at least 32 characters");
  }
}

export function parseRuntimeAllowlist(value?: string) {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function createOAuthNonce() {
  return randomBytes(32).toString("base64url");
}

function assertSafeNonce(nonce: unknown): asserts nonce is string {
  if (typeof nonce !== "string" || !oauthNoncePattern.test(nonce)) {
    throw new Error("Invalid OAuth state nonce");
  }
}

export function createOAuthState({
  runtimeId,
  connectSessionId,
  secret,
  now = new Date(),
  nonce = createOAuthNonce(),
  ttlSeconds = defaultTtlSeconds,
}: CreateOAuthStateOptions) {
  assertSecret(secret);
  assertSafeNonce(nonce);
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > maximumTtlSeconds) {
    throw new Error("Invalid OAuth state lifetime");
  }
  if (!runtimeId && !connectSessionId) {
    throw new Error("OAuth state requires a runtime id or connect session id");
  }
  if (runtimeId && connectSessionId) {
    throw new Error("OAuth state cannot contain both runtime id and connect session id");
  }
  if (runtimeId) {
    assertSafeRuntimeId(runtimeId);
  }
  if (connectSessionId) {
    assertSafeConnectSessionId(connectSessionId);
  }

  const payload: OAuthStatePayload = {
    ...(runtimeId ? { runtimeId } : {}),
    ...(connectSessionId ? { connectSessionId } : {}),
    nonce,
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = signPayload(encodedPayload, secret);

  return `${encodedPayload}.${signature}`;
}

export function verifyOAuthState({ state, secret, allowedRuntimeIds, now = new Date() }: VerifyOAuthStateOptions) {
  assertSecret(secret);
  const [encodedPayload, signature, extra] = state.split(".");

  if (
    !encodedPayload ||
    !signature ||
    extra !== undefined ||
    !/^[A-Za-z0-9_-]+$/.test(encodedPayload) ||
    !/^[A-Za-z0-9_-]{43}$/.test(signature)
  ) {
    throw new Error("Invalid OAuth state format");
  }

  const expectedSignature = signPayload(encodedPayload, secret);
  const signatureBuffer = Buffer.from(signature, "ascii");
  const expectedBuffer = Buffer.from(expectedSignature, "ascii");

  if (signatureBuffer.length !== expectedBuffer.length || !timingSafeEqual(signatureBuffer, expectedBuffer)) {
    throw new Error("Invalid OAuth state signature");
  }

  let payload: OAuthStatePayload;
  try {
    const parsed = JSON.parse(base64UrlDecode(encodedPayload)) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    const record = parsed as Record<string, unknown>;
    const allowedKeys = new Set(["runtimeId", "connectSessionId", "nonce", "expiresAt"]);
    if (Object.keys(record).some((key) => !allowedKeys.has(key))) {
      throw new Error("unknown field");
    }
    if (
      (record.runtimeId !== undefined && typeof record.runtimeId !== "string") ||
      (record.connectSessionId !== undefined && typeof record.connectSessionId !== "string") ||
      typeof record.nonce !== "string" ||
      typeof record.expiresAt !== "string"
    ) {
      throw new Error("invalid field type");
    }
    payload = record as OAuthStatePayload;
  } catch {
    throw new Error("Invalid OAuth state payload");
  }

  if (Boolean(payload.runtimeId) === Boolean(payload.connectSessionId)) {
    throw new Error("Invalid OAuth state route target");
  }

  if (payload.runtimeId) {
    assertSafeRuntimeId(payload.runtimeId);
    if (!allowedRuntimeIds.includes(payload.runtimeId)) {
      throw new Error("OAuth runtime is not allowed");
    }
  } else if (payload.connectSessionId) {
    assertSafeConnectSessionId(payload.connectSessionId);
  }

  const expiresAt = Date.parse(payload.expiresAt);
  if (
    Number.isNaN(expiresAt) ||
    new Date(expiresAt).toISOString() !== payload.expiresAt ||
    expiresAt <= now.getTime() ||
    expiresAt > now.getTime() + maximumTtlSeconds * 1000
  ) {
    throw new Error("OAuth state expired");
  }

  assertSafeNonce(payload.nonce);
  return payload;
}
