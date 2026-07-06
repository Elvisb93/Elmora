export type GoogleOAuthUrlOptions = {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
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
  tokenFile: GoogleAuthorizedUserToken;
  storageWebhookUrl?: string;
  storageWebhookSecret?: string;
};

export type PersistGoogleOAuthTokenResult =
  | { status: "stored" }
  | { status: "skipped"; reason: string };

type GoogleOAuthErrorResponse = {
  error?: string;
  error_description?: string;
};

export function buildGoogleOAuthUrl({ clientId, redirectUri, scopes, state }: GoogleOAuthUrlOptions) {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("state", state);

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

  return tokenFile;
}

export async function persistGoogleOAuthToken(
  { clientRuntimeId, storageWebhookUrl, storageWebhookSecret, tokenFile }: PersistGoogleOAuthTokenOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<PersistGoogleOAuthTokenResult> {
  if (!storageWebhookUrl) {
    return { status: "skipped", reason: "No token storage webhook configured" };
  }

  const response = await fetchImpl(storageWebhookUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(storageWebhookSecret ? { authorization: `Bearer ${storageWebhookSecret}` } : {}),
    },
    body: JSON.stringify({
      clientRuntimeId,
      filename: "google_token.json",
      token: tokenFile,
    }),
  });

  if (!response.ok) {
    throw new Error(`Google token storage webhook failed: HTTP ${response.status}`);
  }

  return { status: "stored" };
}
