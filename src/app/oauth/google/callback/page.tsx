import Link from "next/link";
import { defaultGoogleOAuthClientId } from "../../../connect/google/page";
import { exchangeGoogleOAuthCode } from "../../../../lib/googleOAuth";

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

type ExchangeResult =
  | { status: "idle" }
  | { status: "missing-config"; missing: string[] }
  | { status: "success"; hasRefreshToken: boolean; expiresIn?: number; scope?: string }
  | { status: "failed"; message: string };

const redirectUri = "https://elmora-kappa.vercel.app/oauth/google/callback";

function getServerConfig() {
  const clientId =
    process.env.GOOGLE_OAUTH_CLIENT_ID ??
    process.env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ??
    defaultGoogleOAuthClientId;
  const clientSecret = process.env.GOOGLE_OAUTH_CLIENT_SECRET;
  const missing: string[] = [];

  if (!clientSecret) {
    missing.push("GOOGLE_OAUTH_CLIENT_SECRET");
  }

  return {
    clientId,
    clientSecret,
    missing,
  };
}

async function exchangeCodeIfConfigured(code?: string): Promise<ExchangeResult> {
  if (!code) {
    return { status: "idle" };
  }

  const config = getServerConfig();
  if (config.missing.length > 0 || !config.clientId || !config.clientSecret) {
    return { status: "missing-config", missing: config.missing };
  }

  try {
    const token = await exchangeGoogleOAuthCode({
      code,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri,
    });

    return {
      status: "success",
      hasRefreshToken: Boolean(token.refresh_token),
      expiresIn: token.expires_in,
      scope: token.scope,
    };
  } catch (error) {
    return {
      status: "failed",
      message: error instanceof Error ? error.message : "Unknown OAuth token exchange error",
    };
  }
}

function ExchangeStatus({ result }: { result: ExchangeResult }) {
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
        Google token exchange succeeded server-side. Access token was received, refresh token:{" "}
        <strong>{result.hasRefreshToken ? "present" : "not returned"}</strong>
        {result.expiresIn ? `, expires in ${result.expiresIn} seconds` : ""}.
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
  const exchangeResult = hasError ? { status: "idle" as const } : await exchangeCodeIfConfigured(params.code);

  return (
    <main className="container doc-page">
      <article className="doc-card">
        <p className="eyebrow">OAuth callback</p>
        <h1>Google connection callback</h1>
        <p>
          Elmora received Google’s OAuth redirect at <strong>/oauth/google/callback</strong>. Token
          exchange runs only on the server and never exposes the Google client secret to browser code.
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
          Next production step: validate a signed per-client state value, then store the Google token
          inside that client’s isolated Hermes home folder instead of displaying token details here.
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
