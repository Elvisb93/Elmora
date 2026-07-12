import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentConnectRequest,
  createConnectSession,
  getVercelKvConnectSessionStore,
  type ConnectSessionStore,
  type OAuthProviderSlug,
} from "../../../lib/connectSessions";
import { getSiteUrl } from "../../../lib/oauthConnect";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ValidCreateConnectSessionBody = {
  provider: OAuthProviderSlug;
  requestedEmail?: string;
  ttlSeconds: number;
};

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;

const allowedBodyKeys = new Set(["provider", "requestedEmail", "ttlSeconds"]);
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

function canonicalizeDomain(value: string): string | null {
  if (
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

function parseCreateConnectSessionBody(body: unknown): ValidCreateConnectSessionBody | null {
  if (!isRecord(body) || Object.keys(body).some((key) => !allowedBodyKeys.has(key))) {
    return null;
  }
  if (body.provider !== "google") {
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

  const ttlSeconds = body.ttlSeconds === undefined ? 30 * 60 : body.ttlSeconds;
  if (
    typeof ttlSeconds !== "number" ||
    !Number.isFinite(ttlSeconds) ||
    !Number.isInteger(ttlSeconds) ||
    ttlSeconds < 300 ||
    ttlSeconds > 3600
  ) {
    return null;
  }

  return { provider: "google", requestedEmail, ttlSeconds };
}

export async function handleCreateConnectSessionRequest(
  request: NextRequest,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
) {
  if (request.method !== "POST") {
    return jsonError("Method not allowed", 405, "POST");
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

    const body = parseCreateConnectSessionBody(await request.json().catch(() => null));
    if (!body) {
      return jsonError("Invalid request", 400);
    }
    if (!agent.allowedProviders.includes(body.provider)) {
      return jsonError("Forbidden", 403);
    }
    if (
      agent.requestedEmail &&
      body.requestedEmail &&
      agent.requestedEmail.toLowerCase() !== body.requestedEmail
    ) {
      return jsonError("Forbidden", 403);
    }

    const requestedEmail = agent.requestedEmail?.toLowerCase() || body.requestedEmail;
    const created = await createConnectSession({
      store,
      provider: body.provider,
      runtimeId: agent.runtimeId,
      expectedAgentRegistryEpoch: agent.registryEpoch,
      expectedAgentRegistryVersion: agent.registryVersion,
      agentName: agent.agentName,
      clientName: agent.clientName,
      requestedEmail,
      allowedDomains: agent.allowedDomains,
      ttlSeconds: body.ttlSeconds,
    });
    const siteUrl = getSiteUrl(process.env);

    return NextResponse.json(
      {
        sessionId: created.session.id,
        provider: created.session.provider,
        runtimeId: created.session.runtimeId,
        expiresAt: created.session.expiresAt,
        connectUrl: `${siteUrl}/connect/${body.provider}#token=${encodeURIComponent(created.rawToken)}`,
      },
      { status: 201 },
    );
  } catch {
    return jsonError("Service temporarily unavailable", 503);
  }
}

export async function POST(request: NextRequest) {
  return handleCreateConnectSessionRequest(request);
}
