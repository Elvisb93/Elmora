import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import {
  assertGoogleTokenStorageConfiguration,
  buildGoogleAuthorizedUserToken,
  exchangeGoogleOAuthCode,
  persistGoogleOAuthToken,
  TokenStorageDeliveryError,
  type GoogleOAuthTokenResponse,
} from "./googleOAuth";
import { defaultGoogleOAuthClientId, getSiteUrl, googleWorkspaceProvider } from "./oauthConnect";
import { emitOperationalEvent, type OperationalOutcomeCode } from "./operationalTelemetry";
import { parseRuntimeAllowlist, verifyOAuthState } from "./oauthState";
import {
  claimConnectSessionForPersistence,
  completeConnectSessionPersistenceClaim,
  createConnectSessionClaimId,
  finalizeConnectSessionPersistenceOutcome,
  getAgentRuntime,
  getConnectSessionById,
  getVercelKvConnectSessionStore,
  markConnectSessionPersistenceDeliveryStarted,
  recoverStaleConnectSessionPersistenceClaim,
  type ConnectSessionOutcomeCode,
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
  idTokenKeyResolver?: JWTVerifyGetKey;
  now?: Date;
};

const googleIdTokenKeyResolver = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);
const googleIdTokenIssuers = ["https://accounts.google.com", "accounts.google.com"];
const googleIdTokenClockToleranceSeconds = 30;
const googleIdTokenMaximumAgeSeconds = 10 * 60;

const genericCallbackFailureMessage =
  "This Google connection could not be completed. Ask your Elmora agent for a fresh link.";
const receiverAcceptedFinalizationFailureMessage =
  "The token receiver accepted the Google token, but Elmora could not finalize the connection status. Ask your Elmora agent to reconcile the connection or provide a fresh link.";

function getServerConfig(env: Record<string, string | undefined>) {
  const clientId = env.GOOGLE_OAUTH_CLIENT_ID ?? env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ?? defaultGoogleOAuthClientId;
  const clientSecret = env.GOOGLE_OAUTH_CLIENT_SECRET;
  const stateSigningSecret = env.ELMORA_STATE_SIGNING_SECRET;
  const allowedRuntimeIds = parseRuntimeAllowlist(env.ELMORA_ALLOWED_RUNTIME_IDS);
  const storageWebhookUrl = env.ELMORA_TOKEN_WEBHOOK_URL;
  const storageWebhookKeyId = env.ELMORA_TOKEN_WEBHOOK_KEY_ID;
  const storageWebhookSecret = env.ELMORA_TOKEN_WEBHOOK_SECRET;
  const redirectUri = `${getSiteUrl(env)}${googleWorkspaceProvider.callbackPath}`;
  const missing: string[] = [];

  if (!clientSecret) {
    missing.push("GOOGLE_OAUTH_CLIENT_SECRET");
  }
  if (!stateSigningSecret) {
    missing.push("ELMORA_STATE_SIGNING_SECRET");
  }

  return {
    clientId,
    clientSecret,
    stateSigningSecret,
    allowedRuntimeIds,
    storageWebhookUrl,
    storageWebhookKeyId,
    storageWebhookSecret,
    redirectUri,
    missing,
  };
}

function canonicalGoogleEmail(value: unknown) {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 320 ||
    value !== value.trim() ||
    /[\u0000-\u0020\u007f]/.test(value)
  ) {
    return null;
  }
  const parts = value.split("@");
  if (parts.length !== 2) {
    return null;
  }
  const [localPart, rawDomain] = parts;
  const domain = rawDomain.toLowerCase();
  if (
    !localPart ||
    localPart.length > 64 ||
    !domain ||
    domain.length > 253 ||
    !domain.includes(".") ||
    domain.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    return null;
  }
  return `${localPart.toLowerCase()}@${domain}`;
}

function isSafeOAuthResponseString(value: unknown, maximum = 8192): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    value === value.trim() &&
    !/[\u0000-\u001f\u007f-\u009f]/.test(value)
  );
}

export async function verifyGoogleIdTokenForConnectSession({
  token,
  clientId,
  expectedNonce,
  requestedEmail,
  allowedDomains = [],
  keyResolver = googleIdTokenKeyResolver,
  now = new Date(),
}: {
  token: GoogleOAuthTokenResponse;
  clientId: string;
  expectedNonce: string;
  requestedEmail?: string;
  allowedDomains?: string[];
  keyResolver?: JWTVerifyGetKey;
  now?: Date;
}) {
  if (
    !isSafeOAuthResponseString(token.id_token, 16_384) ||
    !isSafeOAuthResponseString(token.refresh_token) ||
    (token.access_token !== undefined && !isSafeOAuthResponseString(token.access_token)) ||
    (token.scope !== undefined && !isSafeOAuthResponseString(token.scope, 16_384)) ||
    (token.token_type !== undefined &&
      (typeof token.token_type !== "string" || token.token_type.toLowerCase() !== "bearer")) ||
    (token.expires_in !== undefined &&
      (!Number.isSafeInteger(token.expires_in) || token.expires_in <= 0 || token.expires_in > 86_400))
  ) {
    throw new Error("Google token response is incomplete or invalid");
  }
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(expectedNonce)) {
    throw new Error("Google ID token nonce expectation is invalid");
  }

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token.id_token, keyResolver, {
      algorithms: ["RS256"],
      issuer: googleIdTokenIssuers,
      audience: clientId,
      requiredClaims: ["exp", "iat", "sub", "email", "email_verified", "nonce"],
      clockTolerance: googleIdTokenClockToleranceSeconds,
      maxTokenAge: googleIdTokenMaximumAgeSeconds,
      currentDate: now,
    }));
  } catch {
    throw new Error("Google ID token verification failed");
  }

  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (
    typeof payload.iat !== "number" ||
    payload.iat > nowSeconds + googleIdTokenClockToleranceSeconds ||
    typeof payload.sub !== "string" ||
    payload.sub.length === 0 ||
    payload.sub.length > 255 ||
    /[\u0000-\u0020\u007f]/.test(payload.sub) ||
    payload.email_verified !== true ||
    typeof payload.nonce !== "string" ||
    payload.nonce !== expectedNonce
  ) {
    throw new Error("Google ID token identity claims are invalid");
  }

  const authorizedParty = payload.azp;
  if (
    (authorizedParty !== undefined && authorizedParty !== clientId) ||
    (Array.isArray(payload.aud) && payload.aud.length > 1 && authorizedParty !== clientId)
  ) {
    throw new Error("Google ID token authorized party is invalid");
  }

  const email = canonicalGoogleEmail(payload.email);
  if (!email) {
    throw new Error("Google ID token email is invalid");
  }
  if (requestedEmail && email !== requestedEmail.toLowerCase()) {
    throw new Error("Google account does not match the requested account");
  }

  const emailDomain = email.slice(email.lastIndexOf("@") + 1);
  if (payload.hd !== undefined) {
    if (typeof payload.hd !== "string" || payload.hd.toLowerCase() !== emailDomain) {
      throw new Error("Google hosted domain is inconsistent with the account email");
    }
  }
  const normalizedAllowedDomains = allowedDomains.map((item) => item.toLowerCase());
  if (normalizedAllowedDomains.length > 0 && !normalizedAllowedDomains.includes(emailDomain)) {
    throw new Error("Google account is outside the allowed domain policy");
  }

  return email;
}

export async function handleGoogleOAuthCallback({
  code,
  state,
  env = process.env,
  store,
  fetchImpl = fetch,
  idTokenKeyResolver = googleIdTokenKeyResolver,
  now = new Date(),
}: HandleGoogleOAuthCallbackOptions): Promise<GoogleOAuthCallbackResult> {
  if (!code) {
    return { status: "idle" };
  }
  if (!state) {
    return { status: "failed", message: "Missing OAuth state; cannot route token to a client runtime" };
  }

  const config = getServerConfig(env);
  if (!config.stateSigningSecret) {
    return { status: "missing-config", missing: config.missing };
  }

  let receiverAcceptedToken = false;
  let knownFailureCode: ConnectSessionOutcomeCode | undefined;
  let persistenceContext:
    | {
        store: ConnectSessionStore;
        sessionId: string;
        runtimeId: string;
        expectedAgentRegistryVersion: string;
        expectedTokenHash: string;
        claimId: string;
      }
    | undefined;

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
    let expectedAgentRegistryEpoch: number | undefined;
    let expectedAgentRegistryVersion: string | undefined;
    let callbackClaimId: string | undefined;
    let connectSessionTokenHash: string | undefined;
    let resolvedStore = store;

    if (verifiedState.connectSessionId) {
      resolvedStore = resolvedStore ?? (await getVercelKvConnectSessionStore());
      const recoveredSession = await recoverStaleConnectSessionPersistenceClaim({
        store: resolvedStore,
        sessionId: verifiedState.connectSessionId,
        now,
      });
      if (recoveredSession?.status === "reconciliation_required") {
        knownFailureCode = "delivery_unknown";
        throw new Error("Connect session requires token-delivery reconciliation");
      }
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
      runtimeId = session.runtimeId;
      requestedEmail = session.requestedEmail;
      allowedDomains = session.allowedDomains ?? [];
      connectSessionId = session.id;
      expectedAgentRegistryEpoch = session.registryEpoch;
      expectedAgentRegistryVersion = session.registryVersion;
      connectSessionTokenHash = session.tokenHash;

      const activeAgent = await getAgentRuntime({ store: resolvedStore, runtimeId: session.runtimeId });
      if (
        !activeAgent ||
        activeAgent.status !== "active" ||
        activeAgent.registryEpoch !== session.registryEpoch ||
        activeAgent.registryVersion !== session.registryVersion ||
        !activeAgent.allowedProviders.includes(session.provider)
      ) {
        knownFailureCode = "authorization_revoked";
        await claimConnectSessionForPersistence({
          store: resolvedStore,
          sessionId: session.id,
          runtimeId: session.runtimeId,
          provider: session.provider,
          expectedAgentRegistryVersion: session.registryVersion,
          expectedTokenHash: session.tokenHash,
          claimId: createConnectSessionClaimId(),
          now,
        });
        throw new Error(
          "Connect session agent was revoked before token persistence was authorized",
        );
      }
    }

    if (!runtimeId) {
      throw new Error("OAuth state did not resolve a runtime id");
    }
    if (
      !isSafeOAuthResponseString(config.clientId, 512) ||
      !config.clientId.endsWith(".apps.googleusercontent.com") ||
      !isSafeOAuthResponseString(config.clientSecret, 4096) ||
      /\s/.test(config.clientSecret)
    ) {
      return { status: "missing-config", missing: ["Google OAuth client configuration"] };
    }
    if (connectSessionId) {
      if (
        !config.storageWebhookUrl ||
        !config.storageWebhookKeyId ||
        !config.storageWebhookSecret
      ) {
        return { status: "missing-config", missing: ["managed token receiver"] };
      }
      assertGoogleTokenStorageConfiguration({
        storageWebhookUrl: config.storageWebhookUrl,
        storageWebhookKeyId: config.storageWebhookKeyId,
        storageWebhookSecret: config.storageWebhookSecret,
      });
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

    const connectedEmail = await verifyGoogleIdTokenForConnectSession({
      token,
      clientId: config.clientId,
      expectedNonce: verifiedState.nonce,
      requestedEmail,
      allowedDomains,
      keyResolver: idTokenKeyResolver,
      now,
    });

    const tokenFile = buildGoogleAuthorizedUserToken({
      token,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      now,
    });

    if (connectSessionId) {
      if (
        !resolvedStore ||
        !expectedAgentRegistryEpoch ||
        !expectedAgentRegistryVersion ||
        !connectSessionTokenHash
      ) {
        throw new Error("Connect session callback authorization is unavailable");
      }
      callbackClaimId = createConnectSessionClaimId();
      const claimedSession = await claimConnectSessionForPersistence({
        store: resolvedStore,
        sessionId: connectSessionId,
        runtimeId,
        provider: "google",
        expectedAgentRegistryVersion,
        expectedTokenHash: connectSessionTokenHash,
        claimId: callbackClaimId,
        now,
      });
      if (!claimedSession) {
        throw new Error("Connect session agent was revoked or its authorization changed");
      }
      persistenceContext = {
        store: resolvedStore,
        sessionId: connectSessionId,
        runtimeId,
        expectedAgentRegistryVersion,
        expectedTokenHash: connectSessionTokenHash,
        claimId: callbackClaimId,
      };

      const activeAgent = await getAgentRuntime({ store: resolvedStore, runtimeId });
      if (
        !activeAgent ||
        activeAgent.status !== "active" ||
        activeAgent.registryEpoch !== expectedAgentRegistryEpoch ||
        activeAgent.registryVersion !== expectedAgentRegistryVersion ||
        !activeAgent.allowedProviders.includes("google")
      ) {
        knownFailureCode = "authorization_revoked";
        throw new Error(
          "Connect session agent was revoked before token persistence was authorized",
        );
      }
      const deliveryMarked = await markConnectSessionPersistenceDeliveryStarted({
        store: resolvedStore,
        sessionId: connectSessionId,
        runtimeId,
        provider: "google",
        expectedAgentRegistryVersion,
        expectedTokenHash: connectSessionTokenHash,
        claimId: callbackClaimId,
        now,
      });
      if (!deliveryMarked) {
        knownFailureCode = "authorization_revoked";
        throw new Error("Connect session authorization changed before token delivery");
      }
    }

    const storage = connectSessionId
      ? await persistGoogleOAuthToken(
          {
            clientRuntimeId: runtimeId,
            registryEpoch: expectedAgentRegistryEpoch,
            storageWebhookUrl: config.storageWebhookUrl,
            storageWebhookKeyId: config.storageWebhookKeyId,
            storageWebhookSecret: config.storageWebhookSecret,
            tokenFile,
            now,
          },
          fetchImpl,
        )
      : { status: "skipped" as const, reason: "Debug OAuth state has no authoritative registry epoch" };

    if (connectSessionId) {
      if (storage.status !== "stored") {
        throw new Error("Connect session token receiver is unavailable");
      }
      receiverAcceptedToken = true;
      if (
        !resolvedStore ||
        !expectedAgentRegistryEpoch ||
        !expectedAgentRegistryVersion ||
        !callbackClaimId ||
        !connectSessionTokenHash
      ) {
        throw new Error("Connect session callback authorization is unavailable");
      }
      const completedSession = await completeConnectSessionPersistenceClaim({
        store: resolvedStore,
        sessionId: connectSessionId,
        runtimeId,
        provider: "google",
        expectedAgentRegistryVersion,
        expectedTokenHash: connectSessionTokenHash,
        claimId: callbackClaimId,
        connectedEmail,
        now,
      });
      if (!completedSession) {
        throw new Error("Connect session agent was revoked before token persistence was authorized");
      }
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
    let terminalStatus: "failed" | "reconciliation_required" = "failed";
    let outcomeCode: ConnectSessionOutcomeCode = knownFailureCode ?? "callback_failed";
    let message = genericCallbackFailureMessage;

    if (receiverAcceptedToken) {
      terminalStatus = "reconciliation_required";
      outcomeCode = "finalization_failed";
      message = receiverAcceptedFinalizationFailureMessage;
    } else if (error instanceof TokenStorageDeliveryError) {
      terminalStatus = error.outcome === "unknown" ? "reconciliation_required" : "failed";
      outcomeCode = error.outcome === "unknown" ? "delivery_unknown" : "receiver_rejected";
      message =
        error.outcome === "unknown"
          ? receiverAcceptedFinalizationFailureMessage
          : genericCallbackFailureMessage;
    }

    const operationalOutcome: OperationalOutcomeCode =
      outcomeCode === "receiver_rejected"
        ? "persistence_rejected"
        : outcomeCode === "delivery_unknown"
          ? "persistence_unknown"
          : outcomeCode === "finalization_failed"
            ? "finalization_failed"
            : outcomeCode === "authorization_revoked"
              ? "authorization_revoked"
              : "internal_error";
    emitOperationalEvent("oauth_callback_failed", operationalOutcome);

    if (persistenceContext) {
      try {
        await finalizeConnectSessionPersistenceOutcome({
          ...persistenceContext,
          provider: "google",
          status: terminalStatus,
          outcomeCode,
          now,
        });
      } catch {
        emitOperationalEvent("oauth_outcome_finalize_unavailable", "dependency_unavailable");
      }
    }

    return { status: "failed", message };
  }
}
