"use client";

import { useEffect, useRef, useState } from "react";
import type { GoogleConnectDisplayViewModel } from "../lib/oauthConnect";
import { googleWorkspaceProvider } from "../lib/oauthConnect";
import { GoogleConnectContent } from "./GoogleConnectContent";

const tokenPattern = /^ecs_[A-Za-z0-9_-]{43}$/;

function privateView(message: string): GoogleConnectDisplayViewModel {
  return {
    provider: googleWorkspaceProvider,
    mode: "client",
    configured: false,
    showDeveloperDetails: false,
    runtimeId: "private",
    redirectUri: "/oauth/google/callback",
    heading: "Private Google connection",
    eyebrow: "Private Workspace connection",
    intro: googleWorkspaceProvider.summary,
    primaryButtonLabel: "Connect Google Workspace",
    error: message,
  };
}

const loadingView = privateView("Checking this private connection link…");
export function createUnavailableGoogleConnectView() {
  return privateView("This connection link is unavailable. Ask your Elmora agent for a fresh link.");
}
const unavailableView = createUnavailableGoogleConnectView();

export function GoogleConnectBootstrap({ fallbackView }: { fallbackView: GoogleConnectDisplayViewModel }) {
  const [view, setView] = useState<GoogleConnectDisplayViewModel>(loadingView);
  const fragmentToken = useRef<string | null | undefined>(undefined);

  useEffect(() => {
    if (fragmentToken.current === undefined) {
      const rawFragment = window.location.hash.startsWith("#")
        ? window.location.hash.slice(1)
        : window.location.hash;
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      const fragment = new URLSearchParams(rawFragment);
      const keys = [...fragment.keys()];
      fragmentToken.current =
        keys.length === 1 && keys[0] === "token" ? fragment.get("token") : null;
    }

    const token = fragmentToken.current;
    if (!token) {
      setView(fallbackView);
      return;
    }
    if (!tokenPattern.test(token)) {
      setView(unavailableView);
      return;
    }

    const controller = new AbortController();
    void fetch("/api/connect-sessions/resolve", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: token,
      cache: "no-store",
      credentials: "same-origin",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error("unavailable");
        }
        const payload = (await response.json()) as { view?: GoogleConnectDisplayViewModel };
        if (!payload.view?.configured || !payload.view.oauthUrl) {
          throw new Error("unavailable");
        }
        setView(payload.view);
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setView(unavailableView);
        }
      });

    return () => controller.abort();
  }, [fallbackView]);

  return <GoogleConnectContent view={view} />;
}
