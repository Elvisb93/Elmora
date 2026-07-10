import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentConnectRequest,
  connectSessionKey,
  getVercelKvConnectSessionStore,
  type ConnectSessionRecord,
  type ConnectSessionStore,
} from "../../../../../lib/connectSessions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type StatusRouteProps = {
  params: Promise<{ sessionId: string }>;
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

const sessionIdPattern = /^ocs_[A-Za-z0-9_-]{24}$/;

function jsonError(message: string, status: number, allow?: string) {
  return NextResponse.json(
    { error: message },
    { status, ...(allow ? { headers: { Allow: allow } } : {}) },
  );
}

export async function handleConnectSessionStatusRequest(
  request: NextRequest,
  { params }: StatusRouteProps,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
) {
  if (request.method !== "GET") {
    return jsonError("Method not allowed", 405, "GET");
  }

  const sessionId = await params.then((value) => value.sessionId).catch(() => null);
  if (typeof sessionId !== "string" || !sessionIdPattern.test(sessionId)) {
    return jsonError("Invalid request", 400);
  }

  try {
    const store = await getStore();
    const agent = await authorizeAgentConnectRequest({
      store,
      authorization: request.headers.get("authorization"),
    });
    if (!agent) {
      return jsonError("Unauthorized", 401);
    }

    const session = await store.get<ConnectSessionRecord>(connectSessionKey(sessionId));
    if (!session) {
      return jsonError("Not found", 404);
    }
    if (session.runtimeId !== agent.runtimeId) {
      return jsonError("Forbidden", 403);
    }

    return NextResponse.json({
      sessionId: session.id,
      provider: session.provider,
      runtimeId: session.runtimeId,
      status: session.status,
      expiresAt: session.expiresAt,
      usedAt: session.usedAt,
      connectedEmail: session.connectedEmail,
    });
  } catch {
    return jsonError("Service temporarily unavailable", 503);
  }
}

export async function GET(request: NextRequest, props: StatusRouteProps) {
  return handleConnectSessionStatusRequest(request, props);
}
