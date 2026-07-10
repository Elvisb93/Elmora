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

export function ExchangeStatus({ result }: { result: GoogleOAuthCallbackResult }) {
  if (result.status === "missing-config") {
    return (
      <div className="notice">
        The Google connection service is temporarily unavailable. Please try again later or ask your Elmora agent for
        help.
      </div>
    );
  }

  if (result.status === "success") {
    return (
      <div className="notice">
        Google Workspace connected successfully.
        {result.connectSessionId ? " This one-time connection link is now expired." : ""}
      </div>
    );
  }

  if (result.status === "failed") {
    return (
      <div className="notice">
        This Google connection could not be completed. Ask your Elmora agent for a fresh link.
      </div>
    );
  }

  return <div className="notice">No Google authorization response was provided.</div>;
}

export function ProviderErrorNotice() {
  return (
    <div className="notice">
      Google declined or could not complete the connection. You can try again from a fresh connection link.
    </div>
  );
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
        <p className="eyebrow">Google connection</p>
        <h1>Google connection callback</h1>
        <p>
          Elmora received Google’s response. Connection processing runs securely on the server and does not expose
          server credentials to browser code.
        </p>

        {hasError ? (
          <ProviderErrorNotice />
        ) : (
          <ExchangeStatus result={exchangeResult} />
        )}

        <h2>Connection response</h2>
        <ul>
          <li>authorization response: {hasCode ? "present" : "not present"}</li>
          <li>security state: {params.state ? "present" : "not present"}</li>
          <li>permissions response: {params.scope ? "present" : "not present"}</li>
          <li>provider error: {hasError ? "present" : "not present"}</li>
        </ul>

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
