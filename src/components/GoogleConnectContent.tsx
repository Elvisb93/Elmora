import Link from "next/link";
import type { GoogleConnectViewModel } from "../lib/oauthConnect";

export function GoogleConnectContent({ view }: { view: GoogleConnectViewModel }) {
  return (
    <main className="container doc-page">
      <article className="doc-card connect-card">
        <p className="eyebrow">{view.eyebrow}</p>
        <h1>{view.heading}</h1>
        <p className="lede connect-lede">{view.intro}</p>

        <div className="notice">
          {view.error ? (
            <span>{view.error}</span>
          ) : view.showDeveloperDetails ? (
            <span>
              Debug link signed for runtime <strong>{view.runtimeId}</strong>. Tokens produced by this flow can only be
              handed to that runtime’s registered storage endpoint.
            </span>
          ) : (
            <span>
              You’ll be redirected to Google to approve access. Elmora never sees your Google password, and you can
              revoke access from your Google Account at any time.
            </span>
          )}
        </div>

        <section className="connect-section" aria-labelledby="permissions-title">
          <h2 id="permissions-title">What this allows</h2>
          <p>{view.provider.approvalNote}</p>
          <div className="permission-grid">
            {view.provider.scopes.map((item) => (
              <div className="permission-card" key={item.scope}>
                <strong>{item.label}</strong>
                <span>{item.reason}</span>
              </div>
            ))}
          </div>
        </section>

        <details className="details-box">
          <summary>Show exact Google permissions</summary>
          <ul>
            {view.provider.scopes.map((item) => (
              <li key={item.scope}>
                <strong>{item.label}:</strong> <span className="inline-code">{item.scope}</span>
              </li>
            ))}
          </ul>
          <p>
            Google Keep is handled separately because its documented scope is rejected by normal user-consent OAuth in
            this test flow.
          </p>
        </details>

        {view.showDeveloperDetails ? (
          <section className="connect-section" aria-labelledby="developer-title">
            <h2 id="developer-title">Developer diagnostics</h2>
            <ul>
              {view.clientSlug ? (
                <li>
                  client: <span className="inline-code">{view.clientSlug}</span>
                </li>
              ) : null}
              <li>
                runtime: <span className="inline-code">{view.runtimeId}</span>
              </li>
              <li>
                redirect: <span className="inline-code">{view.redirectUri}</span>
              </li>
            </ul>
            <h3>OAuth URL</h3>
            <p className="code-box">{view.oauthUrl ?? "Configure the missing server-side value, then reload this page."}</p>
          </section>
        ) : null}

        <div className="cta-row">
          {view.oauthUrl ? (
            <a className="button primary" href={view.oauthUrl}>
              {view.primaryButtonLabel}
            </a>
          ) : null}
          {view.showDeveloperDetails ? (
            <Link className="button" href="/oauth/google/callback?state=preview-state">
              Preview callback page
            </Link>
          ) : null}
          <Link className="button" href="/privacy">
            Read privacy policy
          </Link>
        </div>
      </article>
    </main>
  );
}
