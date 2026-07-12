import { NextRequest, NextResponse } from "next/server";
import {
  getVercelKvConnectSessionStore,
  resolveGoogleConnectSessionViewModel,
  type ConnectSessionStore,
} from "../../../../lib/connectSessions";
import type { GoogleConnectDisplayViewModel } from "../../../../lib/oauthConnect";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const tokenPattern = /^ecs_[A-Za-z0-9_-]{43}$/;
const privacyHeaders = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

async function readBoundedText(request: NextRequest, maxBytes: number): Promise<string | null> {
  if (!request.body) {
    return "";
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let total = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return text + decoder.decode();
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: privacyHeaders });
}

export async function handleResolveConnectSessionRequest(
  request: NextRequest,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
  env: Record<string, string | undefined> = process.env,
) {
  if (request.method !== "POST") {
    return jsonError("Method not allowed", 405);
  }

  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (
    contentType !== "text/plain" ||
    !Number.isSafeInteger(declaredLength) ||
    declaredLength < 0 ||
    declaredLength > 128
  ) {
    return jsonError("Invalid request", 400);
  }

  const rawToken = await readBoundedText(request, 128);
  if (rawToken === null || !tokenPattern.test(rawToken)) {
    return jsonError("Invalid request", 400);
  }

  try {
    const store = await getStore();
    const view = await resolveGoogleConnectSessionViewModel({ store, rawToken, env });
    if (!view.configured || view.error || !view.oauthUrl || !view.connectionSession) {
      return jsonError("Connection link unavailable", 404);
    }

    const connectionSession = view.connectionSession;
    const publicView: GoogleConnectDisplayViewModel = {
      provider: view.provider,
      mode: "client",
      configured: true,
      showDeveloperDetails: false,
      runtimeId: "private",
      redirectUri: view.redirectUri,
      heading: view.heading,
      eyebrow: view.eyebrow,
      intro: view.intro,
      primaryButtonLabel: view.primaryButtonLabel,
      oauthUrl: view.oauthUrl,
      connectionSession: {
        agentName: connectionSession.agentName,
        clientName: connectionSession.clientName,
        requestedEmail: connectionSession.requestedEmail,
        expiresAt: connectionSession.expiresAt,
      },
    };

    return NextResponse.json({ view: publicView }, { status: 200, headers: privacyHeaders });
  } catch {
    return jsonError("Service temporarily unavailable", 503);
  }
}

export async function POST(request: NextRequest) {
  return handleResolveConnectSessionRequest(request);
}
