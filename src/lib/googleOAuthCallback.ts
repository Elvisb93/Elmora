import {
  buildGoogleAuthorizedUserToken,
  exchangeGoogleOAuthCode,
  persistGoogleOAuthToken,
  type GoogleOAuthTokenResponse,
} from "./googleOAuth";
import { defaultGoogleOAuthClientId, getSiteUrl, googleWorkspaceProvider } from "./oauthConnect";
import { parseRuntimeAllowlist, verifyOAuthState } from "./oauthState";
import {
  getConnectSessionById,
  getVercelKvConnectSessionStore,
  markConnectSessionConnected,
  type ConnectSessionStore,
} from "./connectSessions";

export type GoogleOAuthCallbackResult =
  | { status: "idle" }
  | { status: "missing-config"; missing: string[] }
  | { status: "failed"; message: string }
  | {
      status: "success";
      runtimeId: string;
      hasRefreshToken: boolean;
      expiresIn?: number;
      scope?: string;
      storage: "stored" | "skipped";
      storageDetail?: string;
      connectedEmail?: string;
      connectSessionId?: string;
    };

export type HandleGoogleOAuthCallbackOptions = {
  code?: string;
  state?: string;
  env?: Record<string, string | undefined>;
  store?: ConnectSessionStore;
  fetchImpl?: typeof fetch;
  now?: Date;
};

type GoogleIdTokenClaims = {
  iss?: string;
  aud?: string;
  exp?: number;
  email?: string;
  email_verified?: boolean | string;
  hd?: string;
};

function getServerConfig(env: Record<string, string | undefined>) {
  const clientId = env.GOOGLE_OAUTH_CLIENT_ID ?? env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ?? defaultGoogleOAuthClientId;
  const clientSecret = env.GOOGLE_OAUTH_CLIENT_SECRET;
  const stateSigningSecret = env.ELMORA_STATE_SIGNING_SECRET;
  const allowedRuntimeIds = parseRuntimeAllowlist(env.ELMORA_ALLOWED_RUNTIME_IDS);
  const storageWebhookUrl = env.ELMORA_TOKEN_WEBHOOK_URL;
  const storageWebhookSecret = env.ELMORA_TOKEN_WEBHOOK_SECRET;
  const redirectUri = `${getSiteUrl(env)}${googleWorkspaceProvider.callbackPath}`;
  const missing: string[] = [];

  if (!clientSecret) {
    missing.push("GOOGLE_OAUTH_CLIENT_SECRET");
  }
  if (!stateSigningSecret) {
    missing.push("ELMORA_STATE_SIGNING_SECRET");
  }
  if (allowedRuntimeIds.length === 0) {
    missing.push("ELMORA_ALLOWED_RUNTIME_IDS");
  }

  return {
    clientId,
    clientSecret,
    stateSigningSecret,
    allowedRuntimeIds,
    storageWebhookUrl,
    storageWebhookSecret,
    redirectUri,
    missing,
  };
}

function base64UrlDecodeJson<T>(value: string): T {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as T;
}

export function decodeGoogleIdTokenClaims(idToken: string): GoogleIdTokenClaims {
  const [, payload, extra] = idToken.split(".");
  if (!payload || extra === undefined) {
    throw new Error("Google ID token is malformed");
  }
  try {
    return base64UrlDecodeJson<GoogleIdTokenClaims>(payload);
  } catch {
    throw new Error("Google ID token payload is malformed");
  }
}

export function verifyGoogleIdTokenForConnectSession({
  token,
  clientId,
  requestedEmail,
  allowedDomains = [],
  now = new Date(),
}: {
  token: GoogleOAuthTokenResponse;
  clientId: string;
  requestedEmail?: string;
  allowedDomains?: string[];
  now?: Date;
}) {
  if (!token.id_token) {
    throw new Error("Google did not return an ID token; cannot verify the connected account");
  }

  const claims = decodeGoogleIdTokenClaims(token.id_token);
  const issuerAllowed = claims.iss === "https://accounts.google.com" || claims.iss === "accounts.google.com";
  if (!issuerAllowed) {
    throw new Error("Google ID token issuer is invalid");
  }
  if (claims.aud !== clientId) {
    throw new Error("Google ID token audience is invalid");
  }
  if (typeof claims.exp !== "number" || claims.exp * 1000 <= now.getTime()) {
    throw new Error("Google ID token is expired");
  }
  if (claims.email_verified !== true && claims.email_verified !== "true") {
    throw new Error("Google account email is not verified");
  }
  if (!claims.email) {
    throw new Error("Google ID token did not include an email address");
  }

  const email = claims.email.toLowerCase();
  if (requestedEmail && email !== requestedEmail.toLowerCase()) {
    throw new Error(`Google account ${claims.email} does not match requested account ${requestedEmail}`);
  }

  const domain = email.split("@").pop()?.toLowerCase();
  const hostedDomain = claims.hd?.toLowerCase();
  const normalizedAllowedDomains = allowedDomains.map((item) => item.toLowerCase());
  if (
    normalizedAllowedDomains.length > 0 &&
    !normalizedAllowedDomains.includes(domain ?? "") &&
    !normalizedAllowedDomains.includes(hostedDomain ?? "")
  ) {
    throw new Error(`Google account ${claims.email} is not in an allowed Workspace domain`);
  }

  return claims.email;
}

export async function handleGoogleOAuthCallback({
  code,
  state,
  env = process.env,
  store,
  fetchImpl = fetch,
  now = new Date(),
}: HandleGoogleOAuthCallbackOptions): Promise<GoogleOAuthCallbackResult> {
  if (!code) {
    return { status: "idle" };
  }
  if (!state) {
    return { status: "failed", message: "Missing OAuth state; cannot route token to a client runtime" };
  }

  const config = getServerConfig(env);
  if (!config.stateSigningSecret || config.allowedRuntimeIds.length === 0) {
    return { status: "missing-config", missing: config.missing };
  }

  try {
    const verifiedState = verifyOAuthState({
      state,
      secret: config.stateSigningSecret,
      allowedRuntimeIds: config.allowedRuntimeIds,
      now,
    });

    let runtimeId = verifiedState.runtimeId;
    let requestedEmail: string | undefined;
    let allowedDomains: string[] = [];
    let connectSessionId: string | undefined;
    let resolvedStore = store;

    if (verifiedState.connectSessionId) {
      resolvedStore = resolvedStore ?? (await getVercelKvConnectSessionStore());
      const session = await getConnectSessionById({
        store: resolvedStore,
        sessionId: verifiedState.connectSessionId,
        now,
      });
      if (!session) {
        throw new Error("Connect session expired, missing, or already used");
      }
      if (session.provider !== "google") {
        throw new Error("Connect session provider mismatch");
      }
      if (!config.allowedRuntimeIds.includes(session.runtimeId)) {
        throw new Error("Connect session runtime is not allowed");
      }
      runtimeId = session.runtimeId;
      requestedEmail = session.requestedEmail;
      allowedDomains = session.allowedDomains ?? [];
      connectSessionId = session.id;
    }

    if (!runtimeId) {
      throw new Error("OAuth state did not resolve a runtime id");
    }
    if (!config.clientId || !config.clientSecret) {
      return { status: "missing-config", missing: config.missing };
    }

    const token = await exchangeGoogleOAuthCode(
      {
        code,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: config.redirectUri,
      },
      fetchImpl,
    );

    const connectedEmail = connectSessionId
      ? verifyGoogleIdTokenForConnectSession({
          token,
          clientId: config.clientId,
          requestedEmail,
          allowedDomains,
          now,
        })
      : undefined;

    const tokenFile = buildGoogleAuthorizedUserToken({
      token,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      now,
    });
    const storage = await persistGoogleOAuthToken(
      {
        clientRuntimeId: runtimeId,
        storageWebhookUrl: config.storageWebhookUrl,
        storageWebhookSecret: config.storageWebhookSecret,
        tokenFile,
      },
      fetchImpl,
    );

    if (connectSessionId && resolvedStore) {
      await markConnectSessionConnected({
        store: resolvedStore,
        sessionId: connectSessionId,
        connectedEmail,
        now,
      });
    }

    return {
      status: "success",
      runtimeId,
      connectSessionId,
      connectedEmail,
      hasRefreshToken: Boolean(token.refresh_token),
      expiresIn: token.expires_in,
      scope: token.scope,
      storage: storage.status,
      storageDetail: storage.status === "skipped" ? storage.reason : undefined,
    };
  } catch (error) {
    return {
      status: "failed",
      message: error instanceof Error ? error.message : "Unknown OAuth token exchange error",
    };
  }
}
