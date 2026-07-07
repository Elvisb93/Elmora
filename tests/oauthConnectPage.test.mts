import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  googleWorkspaceProvider,
  resolveGoogleConnectViewModel,
  parseClientRuntimeMap,
} from "../src/lib/oauthConnect.ts";

describe("OAuth connect page view model", () => {
  const baseEnv = {
    NEXT_PUBLIC_SITE_URL: "https://elmora-kappa.vercel.app",
    NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID: "client-id.apps.googleusercontent.com",
    ELMORA_STATE_SIGNING_SECRET: "state-signing-test-secret-with-32-plus-chars",
    ELMORA_ALLOWED_RUNTIME_IDS: "elmora-demo,test-agent-2",
    ELMORA_CLIENT_RUNTIME_MAP: "acme:test-agent-2, demo:elmora-demo",
  };

  it("describes Google Workspace as a client-facing provider without leaking raw scope URLs in the summary copy", () => {
    assert.equal(googleWorkspaceProvider.slug, "google");
    assert.equal(googleWorkspaceProvider.displayName, "Google Workspace");
    assert.equal(googleWorkspaceProvider.scopes.length, 9);
    assert.match(googleWorkspaceProvider.summary, /Gmail, Calendar, Drive, Docs, Sheets, Slides, Tasks, and Contacts/);
    assert.doesNotMatch(googleWorkspaceProvider.summary, /googleapis\.com\/auth/);
  });

  it("parses a server-owned client slug to runtime map", () => {
    assert.deepEqual(parseClientRuntimeMap(" acme:test-agent-2, demo : elmora-demo , broken , :missing"), {
      acme: "test-agent-2",
      demo: "elmora-demo",
    });
  });

  it("renders client mode for a friendly client route while signing the mapped runtime internally", () => {
    const view = resolveGoogleConnectViewModel({
      env: baseEnv,
      routeClientSlug: "acme",
      searchParams: {},
    });

    assert.equal(view.mode, "client");
    assert.equal(view.clientSlug, "acme");
    assert.equal(view.runtimeId, "test-agent-2");
    assert.equal(view.heading, "Connect Google Workspace");
    assert.equal(view.primaryButtonLabel, "Connect Google Workspace");
    assert.equal(view.redirectUri, "https://elmora-kappa.vercel.app/oauth/google/callback");
    assert.ok(view.oauthUrl);
    assert.equal(new URL(view.oauthUrl).searchParams.get("redirect_uri"), "https://elmora-kappa.vercel.app/oauth/google/callback");
    assert.match(new URL(view.oauthUrl).searchParams.get("state") ?? "", /^ey/);
    assert.equal(view.showDeveloperDetails, false);
  });

  it("keeps developer diagnostics behind debug mode for runtime test links", () => {
    const view = resolveGoogleConnectViewModel({
      env: baseEnv,
      searchParams: { runtime: "test-agent-2", debug: "1" },
    });

    assert.equal(view.mode, "debug");
    assert.equal(view.runtimeId, "test-agent-2");
    assert.equal(view.primaryButtonLabel, "Start Google OAuth for test-agent-2");
    assert.equal(view.showDeveloperDetails, true);
    assert.ok(view.oauthUrl?.includes("accounts.google.com"));
  });

  it("rejects an unknown client slug before any OAuth URL is produced", () => {
    const view = resolveGoogleConnectViewModel({
      env: baseEnv,
      routeClientSlug: "unknown-client",
      searchParams: {},
    });

    assert.equal(view.mode, "client");
    assert.equal(view.configured, false);
    assert.equal(view.oauthUrl, undefined);
    assert.match(view.error ?? "", /Client unknown-client is not mapped to an OAuth runtime/);
  });
});
