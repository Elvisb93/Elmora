import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type CryptoKey,
  type JWTVerifyGetKey,
} from "jose";

export const googleOidcClientId = "client-id.apps.googleusercontent.com";
export const googleOidcKeyId = "google-test-key";
export const googleOidcNow = new Date("2026-07-07T12:02:00.000Z");
export const googleOidcNonce = "oidc_nonce_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

type GoogleOidcClaims = Record<string, unknown>;

type GoogleOidcTestContext = {
  privateKey: CryptoKey;
  keyResolver: JWTVerifyGetKey;
  signIdToken(overrides?: GoogleOidcClaims, headerOverrides?: Record<string, unknown>): Promise<string>;
};

export async function createGoogleOidcTestContext(): Promise<GoogleOidcTestContext> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const keyResolver = createLocalJWKSet({
    keys: [{ ...publicJwk, alg: "RS256", kid: googleOidcKeyId, use: "sig" }],
  });

  return {
    privateKey,
    keyResolver,
    async signIdToken(overrides = {}, headerOverrides = {}) {
      const nowSeconds = Math.floor(googleOidcNow.getTime() / 1000);
      return new SignJWT({
        iss: "https://accounts.google.com",
        aud: googleOidcClientId,
        azp: googleOidcClientId,
        sub: "google-subject-123",
        email: "Owner@Example.com",
        email_verified: true,
        nonce: googleOidcNonce,
        iat: nowSeconds - 30,
        exp: nowSeconds + 3600,
        ...overrides,
      })
        .setProtectedHeader({ alg: "RS256", kid: googleOidcKeyId, typ: "JWT", ...headerOverrides })
        .sign(privateKey);
    },
  };
}
