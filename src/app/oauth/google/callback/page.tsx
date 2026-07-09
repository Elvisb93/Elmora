import Link from "next/link";
import {
  handleGoogleOAuthCallback,
  type GoogleOAuthCallbackResult,
} from "../../../../lib/googleOAuthCallback";

export const metadata = {
  title: "Google OAuth Callback — Elmora",
  description: "Server-side Google OAuth callback route for Elmora.",
};

export const dynamic = "force-dynamic";

type CallbackPageProps = {
  searchParams: Promise<{
    code?: string;
    error?: string;
    state?: string;
    scope?: string;
  }>;
};

function ExchangeStatus({ result }: { result: GoogleOAuthCallbackResult }) {
  if (result.status === "missing-config") {
    return (
      <div className="notice">
        Authorization code received, but server token exchange is not configured yet. Missing:{" "}
        <strong>{result.missing.join(", ")}</strong>.
      </div>
    );
  }

  if (result.status === "success") {
    return (
      <div className="notice">
        Google token exchange succeeded server-side for runtime <strong>{result.runtimeId}</strong>.
        {result.connectedEmail ? (
          <>
            {" "}Connected Google account: <strong>{result.connectedEmail}</strong>.
          </>
        ) : null}{" "}
        Refresh token: <strong>{result.hasRefreshToken ? "present" : "not returned"}</strong>
        {result.expiresIn ? `, access token expires in ${result.expiresIn} seconds` : ""}. Token storage:{" "}
        <strong>{result.storage}</strong>
        {result.storageDetail ? ` (${result.storageDetail})` : ""}.
        {result.connectSessionId ? " This one-time connection link is now expired." : ""}
      </div>
    );
  }

  if (result.status === "failed") {
    return (
      <div className="notice">
        Google token exchange failed: <strong>{result.message}</strong>
      </div>
    );
  }

  return <div className="notice">No authorization code was provided.</div>;
}

export default async function GoogleCallbackPage({ searchParams }: CallbackPageProps) {
  const params = await searchParams;
  const hasCode = Boolean(params.code);
  const hasError = Boolean(params.error);
  const exchangeResult = hasError
    ? { status: "idle" as const }
    : await handleGoogleOAuthCallback({ code: params.code, state: params.state });

  return (
    <main className="container doc-page">
      <article className="doc-card">
        <p className="eyebrow">OAuth callback</p>
        <h1>Google connection callback</h1>
        <p>
          Elmora received Google’s OAuth redirect at <strong>/oauth/google/callback</strong>. Token
          exchange runs only on the server, verifies signed state, and never exposes the Google client
          secret to browser code.
        </p>

        {hasError ? (
          <div className="notice">
            Google returned an OAuth error: <strong>{params.error}</strong>
          </div>
        ) : (
          <ExchangeStatus result={exchangeResult} />
        )}

        <h2>Received query fields</h2>
        <ul>
          <li>code: {hasCode ? "present" : "not present"}</li>
          <li>state: {params.state ? "present" : "not present"}</li>
          <li>scope: {params.scope ? "present" : "not present"}</li>
          <li>error: {hasError ? params.error : "not present"}</li>
        </ul>

        <p>
          One-time connect sessions route tokens by server-stored session metadata. Legacy debug state
          can still route by a signed runtime id for local verification.
        </p>

        <div className="cta-row">
          <Link className="button primary" href="/connect/google">
            Back to Google Connect
          </Link>
          <Link className="button" href="/">
            Return home
          </Link>
        </div>
      </article>
    </main>
  );
}
