import Link from "next/link";

export const metadata = {
  title: "Connect Google — Elmora",
  description: "Placeholder Google OAuth connect page for Elmora verification and testing.",
};

function buildPlaceholderUrl() {
  const clientId = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID;
  const redirectPath = "/oauth/google/callback";
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId ?? "YOUR_GOOGLE_CLIENT_ID",
    redirect_uri: redirectPath,
    scope: "openid email profile",
    access_type: "offline",
    prompt: "consent",
    state: "placeholder-state",
  });

  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

export default function GoogleConnectPage() {
  const configured = Boolean(process.env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID);
  const placeholderUrl = buildPlaceholderUrl();

  return (
    <main className="container doc-page">
      <article className="doc-card">
        <p className="eyebrow">Google OAuth placeholder</p>
        <h1>Connect Google to Elmora</h1>
        <p>
          This page is ready for Google OAuth verification and future hosted Connect Google flow work.
          It intentionally does not contain client secrets or perform a token exchange in the browser.
        </p>

        <div className="notice">
          {configured ? (
            <span>A public Google OAuth client ID is configured for the UI placeholder.</span>
          ) : (
            <span>No public Google client ID is configured yet. Add one in Vercel only when ready.</span>
          )}
        </div>

        <h2>Production implementation notes</h2>
        <ul>
          <li>Keep the Google client secret only in server-side environment variables.</li>
          <li>Exchange OAuth authorization codes on a server route, never in client-side code.</li>
          <li>Request the smallest Google scopes needed for each Elmora worker.</li>
          <li>Use the deployed Vercel callback URL in Google Cloud Console.</li>
        </ul>

        <p className="code-box">{placeholderUrl}</p>

        <div className="cta-row">
          <Link className="button primary" href="/oauth/google/callback?state=placeholder-state">
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
