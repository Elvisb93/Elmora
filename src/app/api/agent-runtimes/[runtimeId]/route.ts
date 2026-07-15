import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentRegistryAdminRequest,
  getAgentRuntime,
  getVercelKvConnectSessionStore,
  revokeAgentRuntime,
  type ConnectSessionStore,
} from "../../../../lib/connectSessions";
import { operationalErrorHeaders } from "../../../../lib/operationalTelemetry";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type AgentRuntimeRouteProps = {
  params: Promise<{ runtimeId: string }>;
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

const runtimeIdPattern = /^[a-z][a-z0-9-]{2,62}$/;

function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

export async function handleRevokeAgentRuntimeRequest(
  request: NextRequest,
  { params }: AgentRuntimeRouteProps,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
) {
  if (
    !authorizeAgentRegistryAdminRequest({
      authorization: request.headers["get"]("authorization"),
      adminSecret: process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET,
    })
  ) {
    return jsonError("Unauthorized", 401);
  }

  const runtimeId = await params.then((value) => value.runtimeId).catch(() => null);
  if (typeof runtimeId !== "string" || !runtimeIdPattern.test(runtimeId)) {
    return jsonError("Invalid request", 400);
  }

  try {
    const store = await getStore();
    const revoked = await revokeAgentRuntime({ store, runtimeId });
    if (!revoked) {
      return jsonError("Not found", 404);
    }
    return NextResponse.json({ runtimeId, status: "revoked" });
  } catch {
    return NextResponse.json(
      { error: "Service temporarily unavailable" },
      {
        status: 503,
        headers: operationalErrorHeaders("agent_registry_revoke_unavailable"),
      },
    );
  }
}

export async function handleGetAgentRuntimeStatusRequest(
  request: NextRequest,
  { params }: AgentRuntimeRouteProps,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
) {
  if (
    !authorizeAgentRegistryAdminRequest({
      authorization: request.headers["get"]("authorization"),
      adminSecret: process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET,
    })
  ) {
    return jsonError("Unauthorized", 401);
  }

  const runtimeId = await params.then((value) => value.runtimeId).catch(() => null);
  if (typeof runtimeId !== "string" || !runtimeIdPattern.test(runtimeId)) {
    return jsonError("Invalid request", 400);
  }

  try {
    const store = await getStore();
    const agent = await getAgentRuntime({ store, runtimeId });
    if (!agent) {
      return jsonError("Not found", 404);
    }
    return NextResponse.json(
      {
        runtimeId: agent.runtimeId,
        status: agent.status,
        registryEpoch: agent.registryEpoch,
        allowedProviders: agent.allowedProviders,
        createdAt: agent.createdAt,
        updatedAt: agent.updatedAt,
      },
      { headers: { "Cache-Control": "private, no-store" } },
    );
  } catch {
    return NextResponse.json(
      { error: "Service temporarily unavailable" },
      {
        status: 503,
        headers: operationalErrorHeaders("agent_runtime_status_unavailable"),
      },
    );
  }
}

export async function GET(request: NextRequest, props: AgentRuntimeRouteProps) {
  return handleGetAgentRuntimeStatusRequest(request, props);
}

export async function DELETE(request: NextRequest, props: AgentRuntimeRouteProps) {
  return handleRevokeAgentRuntimeRequest(request, props);
}
