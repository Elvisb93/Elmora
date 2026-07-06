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
