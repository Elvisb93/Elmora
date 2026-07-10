import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentRegistryAdminRequest,
  getVercelKvConnectSessionStore,
  registerAgentRuntime,
  type ConnectSessionStore,
  type OAuthProviderSlug,
} from "../../../lib/connectSessions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ValidRegisterAgentRuntimeBody = {
  registryEpoch: number;
  runtimeId: string;
  agentName: string;
  clientName: string;
  allowedProviders: OAuthProviderSlug[];
  requestedEmail?: string;
  allowedDomains: string[];
  agentConnectSecret?: string;
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

const allowedBodyKeys = new Set([
  "registryEpoch",
  "runtimeId",
  "agentName",
  "clientName",
  "allowedProviders",
  "requestedEmail",
  "allowedDomains",
  "agentConnectSecret",
]);
const runtimeIdPattern = /^[a-z][a-z0-9-]{2,62}$/;
const controlCharacterPattern = /[\u0000-\u001f\u007f-\u009f]/;

function jsonError(message: string, status: number, allow?: string) {
  return NextResponse.json(
    { error: message },
    { status, ...(allow ? { headers: { Allow: allow } } : {}) },
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isCanonicalRuntimeId(value: unknown): value is string {
  return typeof value === "string" && runtimeIdPattern.test(value);
}

function isBoundedDisplayName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 100 &&
    value === value.trim() &&
    !controlCharacterPattern.test(value)
  );
}

function canonicalizeDomain(value: unknown): string | null {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 253 ||
    value !== value.trim() ||
    controlCharacterPattern.test(value)
  ) {
    return null;
  }
  const canonical = value.toLowerCase();
  const labels = canonical.split(".");
  if (labels.length < 2) {
    return null;
  }
  for (const label of labels) {
    if (
      label.length < 1 ||
      label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ) {
      return null;
    }
  }
  return canonical;
}

function canonicalizeEmail(value: unknown): string | null {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 254 ||
    value !== value.trim() ||
    controlCharacterPattern.test(value)
  ) {
    return null;
  }
  const separator = value.lastIndexOf("@");
  if (separator <= 0 || separator !== value.indexOf("@")) {
    return null;
  }
  const local = value.slice(0, separator);
  const domain = canonicalizeDomain(value.slice(separator + 1));
  if (
    !domain ||
    local.length > 64 ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)
  ) {
    return null;
  }
  return `${local.toLowerCase()}@${domain}`;
}

function parseRegisterAgentRuntimeBody(body: unknown): ValidRegisterAgentRuntimeBody | null {
  if (!isRecord(body) || Object.keys(body).some((key) => !allowedBodyKeys.has(key))) {
    return null;
  }
  if (
    !Number.isSafeInteger(body.registryEpoch) ||
    (body.registryEpoch as number) < 1 ||
    !isCanonicalRuntimeId(body.runtimeId) ||
    !isBoundedDisplayName(body.agentName) ||
    !isBoundedDisplayName(body.clientName)
  ) {
    return null;
  }

  let requestedEmail: string | undefined;
  if (body.requestedEmail !== undefined) {
    const canonicalEmail = canonicalizeEmail(body.requestedEmail);
    if (!canonicalEmail) {
      return null;
    }
    requestedEmail = canonicalEmail;
  }

  const requestedProviders = body.allowedProviders ?? ["google"];
  if (
    !Array.isArray(requestedProviders) ||
    requestedProviders.length === 0 ||
    requestedProviders.length > 1 ||
    requestedProviders.some((provider) => provider !== "google") ||
    new Set(requestedProviders).size !== requestedProviders.length
  ) {
    return null;
  }

  const requestedDomains = body.allowedDomains ?? [];
  if (!Array.isArray(requestedDomains) || requestedDomains.length > 32) {
    return null;
  }
  const allowedDomains: string[] = [];
  for (const domain of requestedDomains) {
    const canonical = canonicalizeDomain(domain);
    if (!canonical || allowedDomains.includes(canonical)) {
      return null;
    }
    allowedDomains.push(canonical);
  }

  const agentConnectSecret = body.agentConnectSecret;
  if (
    agentConnectSecret !== undefined &&
    (typeof agentConnectSecret !== "string" ||
      agentConnectSecret.length < 32 ||
      agentConnectSecret.length > 256 ||
      /\s/.test(agentConnectSecret) ||
      controlCharacterPattern.test(agentConnectSecret))
  ) {
    return null;
  }

  return {
    registryEpoch: body.registryEpoch as number,
    runtimeId: body.runtimeId,
    agentName: body.agentName,
    clientName: body.clientName,
    allowedProviders: requestedProviders as OAuthProviderSlug[],
    requestedEmail,
    allowedDomains,
    agentConnectSecret,
  };
}

export async function handleRegisterAgentRuntimeRequest(
  request: NextRequest,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
) {
  if (request.method !== "POST") {
    return jsonError("Method not allowed", 405, "POST");
  }

  if (
    !authorizeAgentRegistryAdminRequest({
      authorization: request.headers.get("authorization"),
      adminSecret: process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET,
    })
  ) {
    return jsonError("Unauthorized", 401);
  }

  const body = parseRegisterAgentRuntimeBody(await request.json().catch(() => null));
  if (!body) {
    return jsonError("Invalid request", 400);
  }

  try {
    const store = await getStore();
    const registered = await registerAgentRuntime({
      store,
      registryEpoch: body.registryEpoch,
      runtimeId: body.runtimeId,
      agentName: body.agentName,
      clientName: body.clientName,
      allowedProviders: body.allowedProviders,
      requestedEmail: body.requestedEmail,
      allowedDomains: body.allowedDomains,
      rawConnectSecret: body.agentConnectSecret,
    });

    return NextResponse.json(
      {
        registryEpoch: registered.agent.registryEpoch,
        runtimeId: registered.agent.runtimeId,
        agentName: registered.agent.agentName,
        clientName: registered.agent.clientName,
        status: registered.agent.status,
        allowedProviders: registered.agent.allowedProviders,
        requestedEmail: registered.agent.requestedEmail,
        allowedDomains: registered.agent.allowedDomains,
        createdAt: registered.agent.createdAt,
        updatedAt: registered.agent.updatedAt,
        ...(registered.rawConnectSecret
          ? {
              agentConnectSecret: registered.rawConnectSecret,
              secretNotice: "Store this in the agent runtime now. It will not be returned again.",
            }
          : {}),
      },
      { status: 201 },
    );
  } catch {
    return jsonError("Service temporarily unavailable", 503);
  }
}

export async function POST(request: NextRequest) {
  return handleRegisterAgentRuntimeRequest(request);
}
