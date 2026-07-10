import { createHash, createHmac, randomBytes } from "node:crypto";

export type GoogleOAuthUrlOptions = {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  nonce?: string;
};

export type GoogleOAuthExchangeOptions = {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
};

export type GoogleOAuthTokenResponse = {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  id_token?: string;
};

export type GoogleAuthorizedUserToken = {
  type: "authorized_user";
  client_id: string;
  client_secret: string;
  refresh_token: string;
  token_uri: "https://oauth2.googleapis.com/token";
  token?: string;
  expiry?: string;
  scopes?: string[];
};

export type BuildGoogleAuthorizedUserTokenOptions = {
  token: GoogleOAuthTokenResponse;
  clientId: string;
  clientSecret: string;
  now?: Date;
};

export type PersistGoogleOAuthTokenOptions = {
  clientRuntimeId: string;
  registryEpoch?: number;
  tokenFile: GoogleAuthorizedUserToken;
  storageWebhookUrl?: string;
  storageWebhookKeyId?: string;
  storageWebhookSecret?: string;
  now?: Date;
  nonceBytes?: Uint8Array;
};

export type PersistGoogleOAuthTokenResult =
  | { status: "stored" }
  | { status: "skipped"; reason: string };

type GoogleOAuthErrorResponse = {
  error?: string;
  error_description?: string;
};

export function buildGoogleOAuthUrl({ clientId, redirectUri, scopes, state, nonce }: GoogleOAuthUrlOptions) {
  if (scopes.includes("openid") && (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(nonce))) {
    throw new Error("A valid OIDC nonce is required when requesting openid");
  }

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("state", state);
  if (nonce) {
    url.searchParams.set("nonce", nonce);
  }

  return new URL(url.toString().replace(/\+/g, "%20"));
}

export async function exchangeGoogleOAuthCode(
  { code, clientId, clientSecret, redirectUri }: GoogleOAuthExchangeOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<GoogleOAuthTokenResponse> {
  const body = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });

  const response = await fetchImpl("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  const payload = (await response.json()) as GoogleOAuthTokenResponse & GoogleOAuthErrorResponse;

  if (!response.ok) {
    const reason = [payload.error, payload.error_description].filter(Boolean).join(" — ");
    throw new Error(`Google token exchange failed: ${reason || response.status}`);
  }

  return payload;
}

export function buildGoogleAuthorizedUserToken({
  token,
  clientId,
  clientSecret,
  now = new Date(),
}: BuildGoogleAuthorizedUserTokenOptions): GoogleAuthorizedUserToken {
  if (!token.refresh_token) {
    throw new Error("Google token response did not include a refresh token");
  }

  const tokenFile: GoogleAuthorizedUserToken = {
    type: "authorized_user",
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: token.refresh_token,
    token_uri: "https://oauth2.googleapis.com/token",
  };

  if (token.access_token) {
    tokenFile.token = token.access_token;
  }

  if (token.expires_in) {
    tokenFile.expiry = new Date(now.getTime() + token.expires_in * 1000).toISOString();
  }

  if (token.scope) {
    tokenFile.scopes = token.scope.split(/\s+/).filter(Boolean);
  }

  if (!isValidAuthorizedUserToken(tokenFile)) {
    throw new Error("Google token response could not produce a safe authorized-user token");
  }
  return tokenFile;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isSafeTokenString(value: unknown, maximum = 8192): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    value === value.trim() &&
    !/[\u0000-\u001f\u007f-\u009f]/.test(value)
  );
}

function isValidAuthorizedUserToken(value: unknown): value is GoogleAuthorizedUserToken {
  if (!isRecord(value)) {
    return false;
  }
  const allowedKeys = new Set([
    "type",
    "client_id",
    "client_secret",
    "refresh_token",
    "token_uri",
    "token",
    "expiry",
    "scopes",
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    return false;
  }
  if (
    value.type !== "authorized_user" ||
    value.token_uri !== "https://oauth2.googleapis.com/token" ||
    !isSafeTokenString(value.client_id, 512) ||
    !isSafeTokenString(value.client_secret) ||
    !isSafeTokenString(value.refresh_token) ||
    (value.token !== undefined && !isSafeTokenString(value.token))
  ) {
    return false;
  }
  if (
    value.expiry !== undefined &&
    (typeof value.expiry !== "string" ||
      value.expiry.length > 64 ||
      !Number.isFinite(Date.parse(value.expiry)) ||
      new Date(value.expiry).toISOString() !== value.expiry)
  ) {
    return false;
  }
  if (value.scopes !== undefined) {
    if (!Array.isArray(value.scopes) || value.scopes.length === 0 || value.scopes.length > 100) {
      return false;
    }
    const scopes = value.scopes;
    if (
      scopes.some((scope) => !isSafeTokenString(scope, 2048)) ||
      new Set(scopes).size !== scopes.length
    ) {
      return false;
    }
  }
  return true;
}

function parseSecureWebhookUrl(value: string): URL | null {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.hash
    ) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

function decodeWebhookHmacKey(value: string | undefined): Buffer | null {
  if (!value || value.includes("=") || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length < 32 || decoded.toString("base64url") !== value) {
    return null;
  }
  return decoded;
}

export function assertGoogleTokenStorageConfiguration({
  storageWebhookUrl,
  storageWebhookKeyId,
  storageWebhookSecret,
}: Pick<
  PersistGoogleOAuthTokenOptions,
  "storageWebhookUrl" | "storageWebhookKeyId" | "storageWebhookSecret"
>) {
  const webhookUrl = storageWebhookUrl ? parseSecureWebhookUrl(storageWebhookUrl) : null;
  const key = decodeWebhookHmacKey(storageWebhookSecret);
  if (
    !webhookUrl ||
    typeof storageWebhookKeyId !== "string" ||
    !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(storageWebhookKeyId) ||
    !key
  ) {
    throw new Error("Invalid token storage configuration");
  }
  return { webhookUrl, key };
}

export async function persistGoogleOAuthToken(
  {
    clientRuntimeId,
    registryEpoch,
    storageWebhookUrl,
    storageWebhookKeyId,
    storageWebhookSecret,
    tokenFile,
    now = new Date(),
    nonceBytes = randomBytes(32),
  }: PersistGoogleOAuthTokenOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<PersistGoogleOAuthTokenResult> {
  if (
    !/^[a-z][a-z0-9-]{2,62}$/.test(clientRuntimeId) ||
    !isValidAuthorizedUserToken(tokenFile)
  ) {
    throw new Error("Invalid token storage request");
  }

  if (!storageWebhookUrl) {
    return { status: "skipped", reason: "No token storage webhook configured" };
  }
  if (
    !Number.isSafeInteger(registryEpoch) ||
    (registryEpoch ?? 0) < 1 ||
    !Number.isFinite(now.getTime()) ||
    nonceBytes.length < 16 ||
    nonceBytes.length > 32
  ) {
    throw new Error("Invalid token storage request");
  }

  const { webhookUrl, key } = assertGoogleTokenStorageConfiguration({
    storageWebhookUrl,
    storageWebhookKeyId,
    storageWebhookSecret,
  });
  const timestamp = Math.floor(now.getTime() / 1000).toString();
  const nonce = Buffer.from(nonceBytes).toString("base64url");
  const body = JSON.stringify({
    protocolVersion: "1",
    runtimeId: clientRuntimeId,
    registryEpoch,
    token: tokenFile,
  });
  const digest = createHash("sha256").update(body, "utf8").digest("hex");
  const canonical = [
    "elmora-runtime-token-hmac",
    "version:1",
    `kid:${storageWebhookKeyId}`,
    `timestamp:${timestamp}`,
    `nonce:${nonce}`,
    `runtime-id:${clientRuntimeId}`,
    `registry-epoch:${registryEpoch}`,
    `body-sha256:${digest}`,
  ].join("\n");
  const signature = createHmac("sha256", key).update(canonical, "ascii").digest("hex");

  let response: Response;
  try {
    response = await fetchImpl(webhookUrl.toString(), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Elmora-Version": "1",
        "X-Elmora-Key-Id": storageWebhookKeyId!,
        "X-Elmora-Timestamp": timestamp,
        "X-Elmora-Nonce": nonce,
        "X-Elmora-Runtime-Id": clientRuntimeId,
        "X-Elmora-Registry-Epoch": String(registryEpoch),
        "X-Elmora-Body-SHA256": digest,
        "X-Elmora-Signature": signature,
      },
      body,
    });
  } catch {
    throw new Error("Token storage request failed");
  }

  if (!response.ok) {
    throw new Error("Token storage request failed");
  }

  return { status: "stored" };
}
