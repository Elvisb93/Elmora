import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ExchangeStatus, ProviderErrorNotice } from "../src/app/oauth/google/callback/page.tsx";
import { createUnavailableGoogleConnectView } from "../src/app/connect/google/[token]/page.tsx";
import { GoogleConnectContent } from "../src/components/GoogleConnectContent.tsx";

describe("public OAuth page error hygiene", () => {
  it("renders fixed generic callback copy instead of internal failure messages", () => {
    const sensitive = "redis://secret-host runtime-id=customer-prod webhook=https://internal.example/token";
    const html = renderToStaticMarkup(
      createElement(ExchangeStatus, { result: { status: "failed", message: sensitive } }),
    );

    assert.match(html, /Google connection could not be completed/i);
    assert.doesNotMatch(html, /redis|secret-host|customer-prod|internal\.example|token/i);
  });

  it("does not render missing environment variable names", () => {
    const html = renderToStaticMarkup(
      createElement(ExchangeStatus, {
        result: {
          status: "missing-config",
          missing: ["GOOGLE_OAUTH_CLIENT_SECRET", "ELMORA_STATE_SIGNING_SECRET"],
        },
      }),
    );

    assert.match(html, /temporarily unavailable/i);
    assert.doesNotMatch(html, /GOOGLE_OAUTH_CLIENT_SECRET|ELMORA_STATE_SIGNING_SECRET|Missing:/i);
  });

  it("does not render runtime ids, receiver details, or token metadata after success", () => {
    const html = renderToStaticMarkup(
      createElement(ExchangeStatus, {
        result: {
          status: "success",
          runtimeId: "customer-prod-runtime",
          hasRefreshToken: true,
          expiresIn: 3600,
          storage: "skipped",
          storageDetail: "No token storage webhook configured at https://internal.example/token",
          connectedEmail: "owner@example.com",
          connectSessionId: "ocs_abcdefghijklmnopqrstuvwx",
        },
      }),
    );

    assert.match(html, /connected successfully/i);
    assert.doesNotMatch(
      html,
      /customer-prod-runtime|refresh token|3600|storage|internal\.example|owner@example\.com|ocs_/i,
    );
  });

  it("does not reflect raw provider query errors or URLs", () => {
    const html = renderToStaticMarkup(createElement(ProviderErrorNotice));

    assert.match(html, /Google declined or could not complete the connection/i);
    assert.doesNotMatch(html, /access_denied|internal\.example|oauth-secret|gmail\.readonly/i);
  });

  it("uses a fixed connect-link failure view instead of an exception message", () => {
    const view = createUnavailableGoogleConnectView();
    const html = renderToStaticMarkup(createElement(GoogleConnectContent, { view }));

    assert.match(html, /connection link is unavailable/i);
    assert.doesNotMatch(html, /KV|Redis|environment|runtime|webhook|URL/i);
  });
});
