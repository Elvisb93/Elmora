import Link from "next/link";
import { buildGoogleOAuthUrl } from "../../../lib/googleOAuth";

export const metadata = {
  title: "Connect Google — Elmora",
  description: "Google OAuth connect preview for Elmora workspace integrations.",
};

const requestedScopes = [
  {
    label: "Gmail read",
    scope: "https://www.googleapis.com/auth/gmail.readonly",
    reason: "Read and summarise incoming business enquiries.",
  },
  {
    label: "Gmail workflow labels",
    scope: "https://www.googleapis.com/auth/gmail.modify",
    reason: "Apply status labels such as needs reply, awaiting client, complete, or spam.",
  },
  {
    label: "Gmail send",
    scope: "https://www.googleapis.com/auth/gmail.send",
    reason: "Send user-approved replies only; no autonomous sending by default.",
  },
  {
    label: "Calendar read",
    scope: "https://www.googleapis.com/auth/calendar.readonly",
    reason: "Check availability and booking context for operations workers.",
  },
];

const defaultGoogleOAuthClientId =
  "582633394629-vmksatd8h7n0u1o4h0ub6el9eof5h0v5.apps.googleusercontent.com";

function getSiteUrl() {
  return (
    process.env.NEXT_PUBLIC_SITE_URL ??
    process.env.VERCEL_PROJECT_PRODUCTION_URL?.replace(/^/, "https://") ??
    "https://elmora-kappa.vercel.app"
  ).replace(/\/$/, "");
}

function buildPreviewUrl() {
  const clientId = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ?? defaultGoogleOAuthClientId;
  const redirectUri = `${getSiteUrl()}/oauth/google/callback`;
  const url = buildGoogleOAuthUrl({
    clientId,
    redirectUri,
    scopes: requestedScopes.map((item) => item.scope),
    state: "preview-state-replace-with-secure-random-state",
  });

  return {
    configured: Boolean(clientId),
    redirectUri,
    url: url.toString(),
  };
}

export default function GoogleConnectPage() {
  const preview = buildPreviewUrl();

  return (
    <main className="container doc-page">
      <article className="doc-card">
        <p className="eyebrow">Google Workspace connection</p>
        <h1>Connect Google to Elmora</h1>
        <p>
          Elmora uses Google OAuth so clients can connect Gmail and Calendar through Google’s own
          consent screen. Clients never share their email password, and token exchange must happen
          server-side in the real hosted connector.
        </p>

        <div className="notice">
          {preview.configured ? (
            <span>A public Google OAuth client ID is configured for this preview link.</span>
          ) : (
            <span>
              No public Google client ID is configured yet. The generated URL below is a safe
              placeholder for Google verification/content review, not a live connector.
            </span>
          )}
        </div>

        <h2>Planned first-client Workspace scopes</h2>
        <ul>
          {requestedScopes.map((item) => (
            <li key={item.scope}>
              <strong>{item.label}:</strong> {item.reason}
              <br />
              <span className="inline-code">{item.scope}</span>
            </li>
          ))}
        </ul>

        <h2>Redirect URI for Google Cloud</h2>
        <p>
          Add the deployed version of this callback URL to your Google OAuth Web application when
          the hosted connector is ready:
        </p>
        <p className="code-box">{preview.redirectUri}</p>

        <h2>OAuth preview URL</h2>
        <p>
          The real flow will replace the preview state with a secure per-client nonce, validate it
          on callback, exchange the authorization code on the server, then write the resulting token
          into that client’s isolated Hermes home folder.
        </p>
        <p className="code-box">{preview.url}</p>

        <div className="cta-row">
          <a className="button primary" href={preview.url}>
            Start Google OAuth preview
          </a>
          <Link className="button" href="/oauth/google/callback?state=preview-state">
            Preview callback page
          </Link>
          <Link className="button" href="/privacy">
            Read privacy policy
          </Link>
        </div>
      </article>
    </main>
  );
}
