import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentConnectRequest,
  connectSessionKey,
  getVercelKvConnectSessionStore,
  type ConnectSessionRecord,
} from "../../../../../lib/connectSessions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type StatusRouteProps = {
  params: Promise<{ sessionId: string }>;
};

function jsonError(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status });
}

export async function GET(request: NextRequest, { params }: StatusRouteProps) {
  const agent = authorizeAgentConnectRequest({
    authorization: request.headers.get("authorization"),
  });
  if (!agent) {
    return jsonError("Unauthorized agent connect request", 401);
  }

  const { sessionId } = await params;
  const store = await getVercelKvConnectSessionStore();
  const session = await store.get<ConnectSessionRecord>(connectSessionKey(sessionId));
  if (!session) {
    return jsonError("Connect session not found", 404);
  }
  if (session.runtimeId !== agent.runtimeId) {
    return jsonError("Connect session does not belong to this agent", 403);
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
}
