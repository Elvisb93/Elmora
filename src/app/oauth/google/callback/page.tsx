import Link from "next/link";

export const metadata = {
  title: "Google OAuth Callback — Elmora",
  description: "Placeholder Google OAuth callback route for Elmora.",
};

type CallbackPageProps = {
  searchParams: Promise<{
    code?: string;
    error?: string;
    state?: string;
    scope?: string;
  }>;
};

export default async function GoogleCallbackPage({ searchParams }: CallbackPageProps) {
  const params = await searchParams;
  const hasCode = Boolean(params.code);
  const hasError = Boolean(params.error);

  return (
    <main className="container doc-page">
      <article className="doc-card">
        <p className="eyebrow">OAuth callback</p>
        <h1>Google connection callback</h1>
        <p>
          This placeholder route confirms that Elmora can receive Google OAuth redirects at
          <strong> /oauth/google/callback</strong>. It does not exchange authorization codes or store tokens.
        </p>

        {hasError ? (
          <div className="notice">Google returned an OAuth error: <strong>{params.error}</strong></div>
        ) : hasCode ? (
          <div className="notice">Authorization code received. Token exchange is intentionally not implemented here.</div>
        ) : (
          <div className="notice">No authorization code was provided. This is expected for placeholder testing.</div>
        )}

        <h2>Received query fields</h2>
        <ul>
          <li>code: {hasCode ? "present" : "not present"}</li>
          <li>state: {params.state ? "present" : "not present"}</li>
          <li>scope: {params.scope ? "present" : "not present"}</li>
          <li>error: {hasError ? params.error : "not present"}</li>
        </ul>

        <p>
          When the real Connect Google flow is built, this route should validate state, exchange the code
          server-side, store tokens securely, and redirect the user to an Elmora onboarding status page.
        </p>

        <div className="cta-row">
          <Link className="button primary" href="/connect/google">Back to Google Connect</Link>
          <Link className="button" href="/">Return home</Link>
        </div>
      </article>
    </main>
  );
}
