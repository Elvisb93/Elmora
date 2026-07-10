import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { SignJWT, generateKeyPair } from "jose";

import { verifyGoogleIdTokenForConnectSession } from "../src/lib/googleOAuthCallback.ts";
import {
  createGoogleOidcTestContext,
  googleOidcClientId,
  googleOidcKeyId,
  googleOidcNonce,
  googleOidcNow,
} from "./googleOidcFixtures.mts";

function encodeJson(value: unknown) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function tokenResponse(idToken: string, refreshToken = "refresh-token") {
  return {
    access_token: "access-token",
    refresh_token: refreshToken,
    id_token: idToken,
  };
}

describe("cryptographic Google ID token verification", () => {
  it("accepts a real RSA RS256 token through createLocalJWKSet and canonicalizes the email", async () => {
    const context = await createGoogleOidcTestContext();
    const idToken = await context.signIdToken();

    const email = await verifyGoogleIdTokenForConnectSession({
      token: tokenResponse(idToken),
      clientId: googleOidcClientId,
      expectedNonce: googleOidcNonce,
      requestedEmail: "owner@example.com",
      allowedDomains: ["example.com"],
      keyResolver: context.keyResolver,
      now: googleOidcNow,
    });

    assert.equal(email, "owner@example.com");
  });

  it("rejects unsigned, forged, wrong-key, wrong-kid, unsupported-algorithm, and malformed JWTs", async () => {
    const context = await createGoogleOidcTestContext();
    const validToken = await context.signIdToken();
    const [header, payload] = validToken.split(".");
    const unsecured = `${encodeJson({ alg: "none", typ: "JWT" })}.${payload}.`;

    const attacker = await generateKeyPair("RS256");
    const forged = await new SignJWT(JSON.parse(Buffer.from(payload, "base64url").toString("utf8")))
      .setProtectedHeader({ alg: "RS256", kid: googleOidcKeyId })
      .sign(attacker.privateKey);
    const wrongKid = await context.signIdToken({}, { kid: "unknown-google-key" });
    const unsupportedAlgorithm = await new SignJWT(
      JSON.parse(Buffer.from(payload, "base64url").toString("utf8")),
    )
      .setProtectedHeader({ alg: "HS256", kid: googleOidcKeyId })
      .sign(new TextEncoder().encode("not-an-rsa-google-signing-key-32-bytes"));

    const variants = [
      ["alg:none", unsecured],
      ["forged signature", forged],
      ["wrong kid", wrongKid],
      ["unsupported algorithm", unsupportedAlgorithm],
      ["malformed compact JWT", "not-a-jwt"],
      ["extra compact segment", `${header}.${payload}.signature.extra`],
    ] as const;

    for (const [name, idToken] of variants) {
      await assert.rejects(
        verifyGoogleIdTokenForConnectSession({
          token: tokenResponse(idToken),
          clientId: googleOidcClientId,
          expectedNonce: googleOidcNonce,
          keyResolver: context.keyResolver,
          now: googleOidcNow,
        }),
        undefined,
        name,
      );
    }
  });

  it("rejects invalid issuer, audience, authorized party, email verification, and account identity claims", async () => {
    const context = await createGoogleOidcTestContext();
    const variants: Array<[string, Record<string, unknown>]> = [
      ["wrong issuer", { iss: "https://attacker.example" }],
      ["wrong audience", { aud: "other-client.apps.googleusercontent.com" }],
      ["wrong authorized party", { azp: "other-client.apps.googleusercontent.com" }],
      ["missing verified flag", { email_verified: undefined }],
      ["false verified flag", { email_verified: false }],
      ["string verified flag", { email_verified: "true" }],
      ["missing email", { email: undefined }],
      ["invalid email", { email: "not-an-email" }],
      ["email with whitespace", { email: "owner @example.com" }],
      ["missing subject", { sub: undefined }],
      ["empty subject", { sub: "" }],
      ["non-string subject", { sub: 123 }],
    ];

    for (const [name, overrides] of variants) {
      const idToken = await context.signIdToken(overrides);
      await assert.rejects(
        verifyGoogleIdTokenForConnectSession({
          token: tokenResponse(idToken),
          clientId: googleOidcClientId,
          expectedNonce: googleOidcNonce,
          keyResolver: context.keyResolver,
          now: googleOidcNow,
        }),
        undefined,
        name,
      );
    }
  });

  it("rejects missing or invalid times, expiry, excessive age, and materially future issuance", async () => {
    const context = await createGoogleOidcTestContext();
    const nowSeconds = Math.floor(googleOidcNow.getTime() / 1000);
    const variants: Array<[string, Record<string, unknown>]> = [
      ["missing expiration", { exp: undefined }],
      ["invalid expiration", { exp: "later" }],
      ["expired", { exp: nowSeconds - 31 }],
      ["missing issued at", { iat: undefined }],
      ["invalid issued at", { iat: "earlier" }],
      ["too old", { iat: nowSeconds - 631 }],
      ["future issued", { iat: nowSeconds + 120 }],
    ];

    for (const [name, overrides] of variants) {
      const idToken = await context.signIdToken(overrides);
      await assert.rejects(
        verifyGoogleIdTokenForConnectSession({
          token: tokenResponse(idToken),
          clientId: googleOidcClientId,
          expectedNonce: googleOidcNonce,
          keyResolver: context.keyResolver,
          now: googleOidcNow,
        }),
        undefined,
        name,
      );
    }
  });

  it("requires an exact nonce and rejects inconsistent hosted-domain claims", async () => {
    const context = await createGoogleOidcTestContext();
    const variants: Array<[string, Record<string, unknown>, string[], string | undefined]> = [
      ["missing nonce", { nonce: undefined }, [], undefined],
      ["wrong nonce", { nonce: "different_nonce_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" }, [], undefined],
      ["hosted domain inconsistent with email", { hd: "attacker.example" }, ["example.com"], undefined],
      ["hosted domain cannot authorize unrelated email", { hd: "allowed.example" }, ["allowed.example"], undefined],
    ];

    for (const [name, overrides, allowedDomains, requestedEmail] of variants) {
      const idToken = await context.signIdToken(overrides);
      await assert.rejects(
        verifyGoogleIdTokenForConnectSession({
          token: tokenResponse(idToken),
          clientId: googleOidcClientId,
          expectedNonce: googleOidcNonce,
          requestedEmail,
          allowedDomains,
          keyResolver: context.keyResolver,
          now: googleOidcNow,
        }),
        undefined,
        name,
      );
    }
  });
});
