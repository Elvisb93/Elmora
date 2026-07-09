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

export function createOAuthState({
  runtimeId,
  connectSessionId,
  secret,
  now = new Date(),
  nonce = randomBytes(18).toString("base64url"),
  ttlSeconds = defaultTtlSeconds,
}: CreateOAuthStateOptions) {
  assertSecret(secret);
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

  if (!encodedPayload || !signature || extra !== undefined) {
    throw new Error("Invalid OAuth state format");
  }

  const expectedSignature = signPayload(encodedPayload, secret);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (signatureBuffer.length !== expectedBuffer.length || !timingSafeEqual(signatureBuffer, expectedBuffer)) {
    throw new Error("Invalid OAuth state signature");
  }

  let payload: OAuthStatePayload;
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload)) as OAuthStatePayload;
  } catch {
    throw new Error("Invalid OAuth state payload");
  }

  if (payload.runtimeId) {
    assertSafeRuntimeId(payload.runtimeId);

    if (!allowedRuntimeIds.includes(payload.runtimeId)) {
      throw new Error("OAuth runtime is not allowed");
    }
  } else if (payload.connectSessionId) {
    assertSafeConnectSessionId(payload.connectSessionId);
  } else {
    throw new Error("OAuth state route target missing");
  }

  if (Number.isNaN(Date.parse(payload.expiresAt)) || new Date(payload.expiresAt).getTime() <= now.getTime()) {
    throw new Error("OAuth state expired");
  }

  if (!payload.nonce) {
    throw new Error("OAuth state nonce missing");
  }

  return payload;
}
