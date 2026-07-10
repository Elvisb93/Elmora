import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentRegistryAdminRequest,
  getVercelKvConnectSessionStore,
  revokeAgentRuntime,
  type ConnectSessionStore,
} from "../../../../lib/connectSessions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type AgentRuntimeRouteProps = {
  params: Promise<{ runtimeId: string }>;
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

const runtimeIdPattern = /^[a-z][a-z0-9-]{2,62}$/;

function jsonError(message: string, status: number, allow?: string) {
  return NextResponse.json(
    { error: message },
    { status, ...(allow ? { headers: { Allow: allow } } : {}) },
  );
}

export async function handleRevokeAgentRuntimeRequest(
  request: NextRequest,
  { params }: AgentRuntimeRouteProps,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
) {
  if (request.method !== "DELETE") {
    return jsonError("Method not allowed", 405, "DELETE");
  }

  const runtimeId = await params.then((value) => value.runtimeId).catch(() => null);
  if (typeof runtimeId !== "string" || !runtimeIdPattern.test(runtimeId)) {
    return jsonError("Invalid request", 400);
  }

  if (
    !authorizeAgentRegistryAdminRequest({
      authorization: request.headers.get("authorization"),
      adminSecret: process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET,
    })
  ) {
    return jsonError("Unauthorized", 401);
  }

  try {
    const store = await getStore();
    const revoked = await revokeAgentRuntime({ store, runtimeId });
    if (!revoked) {
      return jsonError("Not found", 404);
    }
    return NextResponse.json({ runtimeId, status: "revoked" });
  } catch {
    return jsonError("Service temporarily unavailable", 503);
  }
}

export async function DELETE(request: NextRequest, props: AgentRuntimeRouteProps) {
  return handleRevokeAgentRuntimeRequest(request, props);
}
