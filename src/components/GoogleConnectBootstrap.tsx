"use client";

import { useEffect, useRef, useState } from "react";
import { takeConnectTokenFromBrowserLocation } from "../lib/connectLink";
import {
  googleWorkspaceProvider,
  type GoogleConnectDisplayViewModel,
} from "../lib/oauthConnect";
import { GoogleConnectContent } from "./GoogleConnectContent";

type BootstrapState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; view: GoogleConnectDisplayViewModel }
  | { status: "error" };

export function createUnavailableGoogleConnectView(): GoogleConnectDisplayViewModel {
  return {
    provider: googleWorkspaceProvider,
    mode: "client",
    configured: false,
    showDeveloperDetails: false,
    runtimeId: "private",
    redirectUri: "/oauth/google/callback",
    heading: "Connect Google Workspace",
    eyebrow: "Private Workspace connection",
    intro: googleWorkspaceProvider.summary,
    primaryButtonLabel: "Connect Google Workspace",
    error: "This connection link is unavailable. Ask your Elmora agent for a fresh link.",
  };
}

function ConnectMessage({ message }: { message: string }) {
  return (
    <main className="container doc-page">
      <article className="doc-card connect-card">
        <p className="eyebrow">Private Workspace connection</p>
        <h1>Connect Google Workspace</h1>
        <p className="lede connect-lede">{message}</p>
      </article>
    </main>
  );
}

export function GoogleConnectBootstrap({ fallbackView }: { fallbackView: GoogleConnectDisplayViewModel }) {
  const started = useRef(false);
  const [state, setState] = useState<BootstrapState>({ status: "idle" });

  useEffect(() => {
    if (started.current) {
      return;
    }
    started.current = true;
    const hadFragment = window.location.hash.length > 0;
    const token = takeConnectTokenFromBrowserLocation(window.location, window.history);
    if (!hadFragment) {
      return;
    }
    if (!token) {
      setState({ status: "error" });
      return;
    }

    const controller = new AbortController();
    setState({ status: "loading" });
    void fetch("/api/connect-sessions/resolve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
      cache: "no-store",
      credentials: "same-origin",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error("connect link unavailable");
        }
        const payload = (await response.json()) as { view?: GoogleConnectDisplayViewModel };
        if (!payload.view?.oauthUrl || !payload.view.configured) {
          throw new Error("connect link unavailable");
        }
        setState({ status: "ready", view: payload.view });
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setState({ status: "error" });
        }
      });

    return () => controller.abort();
  }, []);

  if (state.status === "idle") {
    return <GoogleConnectContent view={fallbackView} />;
  }
  if (state.status === "loading") {
    return <ConnectMessage message="Checking this private one-time connection link…" />;
  }
  if (state.status === "ready") {
    return <GoogleConnectContent view={state.view} />;
  }
  return <GoogleConnectContent view={createUnavailableGoogleConnectView()} />;
}
