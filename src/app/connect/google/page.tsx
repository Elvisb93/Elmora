import Link from "next/link";
import { buildGoogleOAuthUrl } from "../../../lib/googleOAuth";
import { createOAuthState, parseRuntimeAllowlist } from "../../../lib/oauthState";

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
  {
    label: "Drive read",
    scope: "https://www.googleapis.com/auth/drive.readonly",
    reason: "Search, inspect, and download existing Drive files when the user asks.",
  },
];

export const defaultGoogleOAuthClientId =
  "582633394629-vmksatd8h7n0u1o4h0ub6el9eof5h0v5.apps.googleusercontent.com";

function getSiteUrl() {
  return (
    process.env.NEXT_PUBLIC_SITE_URL ??
    process.env.VERCEL_PROJECT_PRODUCTION_URL?.replace(/^/, "https://") ??
    "https://elmora-kappa.vercel.app"
  ).replace(/\/$/, "");
}

function getAllowedRuntimeIds() {
  return parseRuntimeAllowlist(process.env.ELMORA_ALLOWED_RUNTIME_IDS);
}

function buildPreviewUrl(runtimeId: string) {
  const clientId = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ?? defaultGoogleOAuthClientId;
  const redirectUri = `${getSiteUrl()}/oauth/google/callback`;
  const signingSecret = process.env.ELMORA_STATE_SIGNING_SECRET;
  const allowedRuntimeIds = getAllowedRuntimeIds();

  if (!signingSecret) {
    return {
      configured: false,
      redirectUri,
      runtimeId,
      error: "ELMORA_STATE_SIGNING_SECRET is not configured.",
    };
  }

  if (!allowedRuntimeIds.includes(runtimeId)) {
    return {
      configured: false,
      redirectUri,
      runtimeId,
      error: `Runtime ${runtimeId} is not allowed for OAuth connection.`,
    };
  }

  const state = createOAuthState({
    runtimeId,
    secret: signingSecret,
  });
  const url = buildGoogleOAuthUrl({
    clientId,
    redirectUri,
    scopes: requestedScopes.map((item) => item.scope),
    state,
  });

  return {
    configured: Boolean(clientId),
    redirectUri,
    runtimeId,
    url: url.toString(),
  };
}

type GoogleConnectPageProps = {
  searchParams: Promise<{
    runtime?: string;
  }>;
};

export default async function GoogleConnectPage({ searchParams }: GoogleConnectPageProps) {
  const params = await searchParams;
  const runtimeId = params.runtime ?? "elmora-demo";
  const preview = buildPreviewUrl(runtimeId);

  return (
    <main className="container doc-page">
      <article className="doc-card">
        <p className="eyebrow">Google Workspace connection</p>
        <h1>Connect Google to Elmora</h1>
        <p>
          Elmora uses Google OAuth so clients can connect Gmail, Calendar, and Drive through
          Google’s own consent screen. Clients never share their email password, and token exchange
          happens server-side before being routed to the correct isolated client runtime.
        </p>

        <div className="notice">
          {"error" in preview ? (
            <span>{preview.error}</span>
          ) : (
            <span>
              This link is signed for runtime <strong>{preview.runtimeId}</strong>. Tokens produced by
              this flow can only be handed to that runtime’s registered storage endpoint.
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

        <h2>Runtime and redirect URI</h2>
        <ul>
          <li>runtime: <span className="inline-code">{preview.runtimeId}</span></li>
          <li>redirect: <span className="inline-code">{preview.redirectUri}</span></li>
        </ul>

        <h2>OAuth URL</h2>
        {"url" in preview ? (
          <p className="code-box">{preview.url}</p>
        ) : (
          <p className="code-box">Configure the missing server-side value, then reload this page.</p>
        )}

        <div className="cta-row">
          {"url" in preview ? (
            <a className="button primary" href={preview.url}>
              Start Google OAuth for {preview.runtimeId}
            </a>
          ) : null}
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
