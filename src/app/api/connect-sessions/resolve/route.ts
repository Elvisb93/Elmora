import { NextRequest, NextResponse } from "next/server";
import {
  getVercelKvConnectSessionStore,
  resolveGoogleConnectSessionViewModel,
  type ConnectSessionStore,
} from "../../../../lib/connectSessions";
import { isCanonicalConnectToken } from "../../../../lib/connectLink";
import type { GoogleConnectDisplayViewModel } from "../../../../lib/oauthConnect";
import { operationalErrorHeaders } from "../../../../lib/operationalTelemetry";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const maxBodyLength = 2_048;
const responseHeaders = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

function toPublicConnectView(
  view: Awaited<ReturnType<typeof resolveGoogleConnectSessionViewModel>>,
): GoogleConnectDisplayViewModel {
  return {
    provider: view.provider,
    mode: view.mode,
    configured: view.configured,
    showDeveloperDetails: view.showDeveloperDetails,
    clientSlug: view.clientSlug,
    runtimeId: "private",
    redirectUri: view.redirectUri,
    heading: view.heading,
    eyebrow: view.eyebrow,
    intro: view.intro,
    primaryButtonLabel: view.primaryButtonLabel,
    oauthUrl: view.oauthUrl,
    connectionSession: view.connectionSession
      ? {
          agentName: view.connectionSession.agentName,
          clientName: view.connectionSession.clientName,
          requestedEmail: view.connectionSession.requestedEmail,
          expiresAt: view.connectionSession.expiresAt,
        }
      : undefined,
  };
}

function jsonResponse(body: unknown, status: number, headers: Record<string, string> = {}) {
  return NextResponse.json(body, { status, headers: { ...responseHeaders, ...headers } });
}

function parseBody(rawBody: string): { token: string } | null {
  if (rawBody.length > maxBodyLength) {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(rawBody);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !isCanonicalConnectToken(record.token)) {
    return null;
  }
  return { token: record.token };
}

export async function handleResolveConnectSessionRequest(
  request: NextRequest,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
  env: Record<string, string | undefined> = process.env,
  now = new Date(),
) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  const contentLength = Number(request.headers["get"]("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maxBodyLength) {
    return jsonResponse({ error: "Request too large" }, 413);
  }
  const rawBody = await request.text().catch(() => "");
  if (rawBody.length > maxBodyLength) {
    return jsonResponse({ error: "Request too large" }, 413);
  }
  const body = parseBody(rawBody);
  if (!body) {
    return jsonResponse({ error: "Invalid request" }, 400);
  }

  try {
    const store = await getStore();
    const view = await resolveGoogleConnectSessionViewModel({
      store,
      rawToken: body.token,
      env,
      now,
    });
    if (!view.connectionSession) {
      return jsonResponse({ error: "Connection link unavailable" }, 404);
    }
    if (!view.configured || !view.oauthUrl || view.error) {
      return jsonResponse({ error: "Service temporarily unavailable" }, 503);
    }
    return jsonResponse({ view: toPublicConnectView(view) }, 200);
  } catch {
    return jsonResponse(
      { error: "Service temporarily unavailable" },
      503,
      operationalErrorHeaders("connect_session_resolve_unavailable"),
    );
  }
}

export async function POST(request: NextRequest) {
  return handleResolveConnectSessionRequest(request);
}
