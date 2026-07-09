import { buildGoogleOAuthUrl } from "./googleOAuth";
import { createOAuthState, parseRuntimeAllowlist } from "./oauthState";

export const defaultGoogleOAuthClientId =
  "582633394629-vmksatd8h7n0u1o4h0ub6el9eof5h0v5.apps.googleusercontent.com";

export type OAuthScopeDescription = {
  label: string;
  scope: string;
  reason: string;
};

export type OAuthProviderDefinition = {
  slug: string;
  displayName: string;
  shortName: string;
  summary: string;
  approvalNote: string;
  tokenFilename: string;
  callbackPath: string;
  scopes: OAuthScopeDescription[];
};

export const googleWorkspaceProvider: OAuthProviderDefinition = {
  slug: "google",
  displayName: "Google Workspace",
  shortName: "Google",
  tokenFilename: "google_token.json",
  callbackPath: "/oauth/google/callback",
  summary:
    "Connect Gmail, Calendar, Drive, Docs, Sheets, Slides, Tasks, and Contacts so your Elmora worker can help with inbox, documents, scheduling, and client communication.",
  approvalNote:
    "Elmora can prepare work in the background, but destructive or externally visible actions still stay behind approval gates in the worker workflow.",
  scopes: [
    {
      label: "Gmail",
      scope: "https://www.googleapis.com/auth/gmail.modify",
      reason: "Read, label, archive, and manage Gmail messages without granting permanent-delete power.",
    },
    {
      label: "Gmail send",
      scope: "https://www.googleapis.com/auth/gmail.send",
      reason: "Send user-approved replies and outbound emails.",
    },
    {
      label: "Calendar",
      scope: "https://www.googleapis.com/auth/calendar",
      reason: "Read, create, update, and manage calendar events when approved.",
    },
    {
      label: "Drive",
      scope: "https://www.googleapis.com/auth/drive",
      reason: "Find, read, create, update, organise, upload, download, and share Drive files.",
    },
    {
      label: "Docs",
      scope: "https://www.googleapis.com/auth/documents",
      reason: "Read, create, and edit Google Docs documents.",
    },
    {
      label: "Sheets",
      scope: "https://www.googleapis.com/auth/spreadsheets",
      reason: "Read, create, and edit Google Sheets spreadsheets.",
    },
    {
      label: "Slides",
      scope: "https://www.googleapis.com/auth/presentations",
      reason: "Read, create, and edit Google Slides presentations.",
    },
    {
      label: "Tasks",
      scope: "https://www.googleapis.com/auth/tasks",
      reason: "Read, create, update, and manage Google Tasks.",
    },
    {
      label: "Contacts",
      scope: "https://www.googleapis.com/auth/contacts",
      reason: "Read and manage Google Contacts for client communications.",
    },
  ],
};

export type ConnectSearchParams = {
  client?: string;
  debug?: string;
  runtime?: string;
};

export type ResolveGoogleConnectViewModelOptions = {
  env?: Record<string, string | undefined>;
  routeClientSlug?: string;
  searchParams: ConnectSearchParams;
};

export type GoogleConnectViewModel = {
  provider: OAuthProviderDefinition;
  mode: "client" | "debug";
  configured: boolean;
  showDeveloperDetails: boolean;
  clientSlug?: string;
  runtimeId: string;
  redirectUri: string;
  heading: string;
  eyebrow: string;
  intro: string;
  primaryButtonLabel: string;
  oauthUrl?: string;
  error?: string;
  connectionSession?: {
    id: string;
    agentName: string;
    clientName: string;
    requestedEmail?: string;
    expiresAt: string;
  };
};

const defaultRuntimeId = "elmora-demo";

export function parseClientRuntimeMap(value?: string) {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce<Record<string, string>>((map, item) => {
      const [rawClient, rawRuntime, ...extra] = item.split(":");
      const clientSlug = rawClient?.trim();
      const runtimeId = rawRuntime?.trim();
      if (!clientSlug || !runtimeId || extra.length > 0) {
        return map;
      }
      map[clientSlug] = runtimeId;
      return map;
    }, {});
}

export function isDebugMode(value?: string) {
  return ["1", "true", "yes", "debug"].includes((value ?? "").toLowerCase());
}

export function getSiteUrl(env: Record<string, string | undefined> = process.env) {
  return (
    env.NEXT_PUBLIC_SITE_URL ??
    env.VERCEL_PROJECT_PRODUCTION_URL?.replace(/^/, "https://") ??
    "https://elmora-kappa.vercel.app"
  ).replace(/\/$/, "");
}

function resolveRuntimeId({
  clientSlug,
  env,
  requestedRuntime,
}: {
  clientSlug?: string;
  env: Record<string, string | undefined>;
  requestedRuntime?: string;
}) {
  if (!clientSlug) {
    return {
      runtimeId: requestedRuntime || defaultRuntimeId,
    };
  }

  const clientRuntimeMap = parseClientRuntimeMap(env.ELMORA_CLIENT_RUNTIME_MAP);
  const mappedRuntimeId = clientRuntimeMap[clientSlug];
  if (mappedRuntimeId) {
    return { runtimeId: mappedRuntimeId };
  }

  const allowedRuntimeIds = parseRuntimeAllowlist(env.ELMORA_ALLOWED_RUNTIME_IDS);
  if (Object.keys(clientRuntimeMap).length === 0 && allowedRuntimeIds.includes(clientSlug)) {
    return { runtimeId: clientSlug };
  }

  return {
    runtimeId: requestedRuntime || defaultRuntimeId,
    error: `Client ${clientSlug} is not mapped to an OAuth runtime.`,
  };
}

export function resolveGoogleConnectViewModel({
  env = process.env,
  routeClientSlug,
  searchParams,
}: ResolveGoogleConnectViewModelOptions): GoogleConnectViewModel {
  const mode: "client" | "debug" = isDebugMode(searchParams.debug) ? "debug" : "client";
  const clientSlug = routeClientSlug || searchParams.client;
  const redirectUri = `${getSiteUrl(env)}${googleWorkspaceProvider.callbackPath}`;
  const clientId = env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ?? env.GOOGLE_OAUTH_CLIENT_ID ?? defaultGoogleOAuthClientId;
  const signingSecret = env.ELMORA_STATE_SIGNING_SECRET;
  const allowedRuntimeIds = parseRuntimeAllowlist(env.ELMORA_ALLOWED_RUNTIME_IDS);
  const runtimeResolution = resolveRuntimeId({
    clientSlug,
    env,
    requestedRuntime: searchParams.runtime,
  });
  const runtimeId = runtimeResolution.runtimeId;
  const showDeveloperDetails = mode === "debug";
  const baseView = {
    provider: googleWorkspaceProvider,
    mode,
    clientSlug,
    runtimeId,
    redirectUri,
    showDeveloperDetails,
    eyebrow: mode === "debug" ? "Google Workspace connection · debug" : "Workspace connection",
    heading: mode === "debug" ? "Connect Google to Elmora" : "Connect Google Workspace",
    intro: googleWorkspaceProvider.summary,
    primaryButtonLabel: mode === "debug" ? `Start Google OAuth for ${runtimeId}` : "Connect Google Workspace",
  };

  if (runtimeResolution.error) {
    return {
      ...baseView,
      configured: false,
      error: runtimeResolution.error,
    };
  }

  if (!signingSecret) {
    return {
      ...baseView,
      configured: false,
      error: "ELMORA_STATE_SIGNING_SECRET is not configured.",
    };
  }

  if (!allowedRuntimeIds.includes(runtimeId)) {
    return {
      ...baseView,
      configured: false,
      error: `Runtime ${runtimeId} is not allowed for OAuth connection.`,
    };
  }

  const state = createOAuthState({
    runtimeId,
    secret: signingSecret,
  });
  const oauthUrl = buildGoogleOAuthUrl({
    clientId,
    redirectUri,
    scopes: googleWorkspaceProvider.scopes.map((item) => item.scope),
    state,
  }).toString();

  return {
    ...baseView,
    configured: Boolean(clientId),
    oauthUrl,
  };
}

export function getSupportedOAuthProviders() {
  return [googleWorkspaceProvider];
}
