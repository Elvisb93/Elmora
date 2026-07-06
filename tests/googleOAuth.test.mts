import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildGoogleOAuthUrl, exchangeGoogleOAuthCode } from "../src/lib/googleOAuth.ts";

describe("Google OAuth helpers", () => {
  it("builds an authorization URL with the exact hosted callback and encoded scopes", () => {
    const url = buildGoogleOAuthUrl({
      clientId: "client-id.apps.googleusercontent.com",
      redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
      scopes: ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"],
      state: "secure-state",
    });

    assert.equal(url.origin, "https://accounts.google.com");
    assert.equal(url.pathname, "/o/oauth2/v2/auth");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("client_id"), "client-id.apps.googleusercontent.com");
    assert.equal(url.searchParams.get("redirect_uri"), "https://elmora-kappa.vercel.app/oauth/google/callback");
    assert.equal(url.searchParams.get("scope"), "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify");
    assert.equal(url.searchParams.get("access_type"), "offline");
    assert.equal(url.searchParams.get("prompt"), "consent");
    assert.equal(url.searchParams.get("state"), "secure-state");
    assert.match(url.toString(), /gmail\.readonly%20https%3A%2F%2Fwww\.googleapis\.com%2Fauth%2Fgmail\.modify/);
  });

  it("exchanges an authorization code with Google using server-only client credentials", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl: typeof fetch = async (url, init) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(
        JSON.stringify({
          access_token: "access-token",
          refresh_token: "refresh-token",
          expires_in: 3600,
          scope: "https://www.googleapis.com/auth/gmail.readonly",
          token_type: "Bearer",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const token = await exchangeGoogleOAuthCode(
      {
        code: "auth-code",
        clientId: "client-id.apps.googleusercontent.com",
        clientSecret: "server-only-secret",
        redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
      },
      fetchImpl,
    );

    assert.equal(token.access_token, "access-token");
    assert.equal(token.refresh_token, "refresh-token");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://oauth2.googleapis.com/token");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers?.["content-type" as keyof HeadersInit], "application/x-www-form-urlencoded");

    const body = new URLSearchParams(String(calls[0].init.body));
    assert.equal(body.get("code"), "auth-code");
    assert.equal(body.get("client_id"), "client-id.apps.googleusercontent.com");
    assert.equal(body.get("client_secret"), "server-only-secret");
    assert.equal(body.get("redirect_uri"), "https://elmora-kappa.vercel.app/oauth/google/callback");
    assert.equal(body.get("grant_type"), "authorization_code");
  });

  it("throws a useful error when Google rejects the token exchange", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "invalid_grant", error_description: "Bad code" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });

    await assert.rejects(
      () =>
        exchangeGoogleOAuthCode(
          {
            code: "bad-code",
            clientId: "client-id.apps.googleusercontent.com",
            clientSecret: "server-only-secret",
            redirectUri: "https://elmora-kappa.vercel.app/oauth/google/callback",
          },
          fetchImpl,
        ),
      /Google token exchange failed: invalid_grant — Bad code/,
    );
  });
});
