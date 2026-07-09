import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentConnectRequest,
  createConnectSession,
  getVercelKvConnectSessionStore,
  type OAuthProviderSlug,
} from "../../../lib/connectSessions";
import { getSiteUrl } from "../../../lib/oauthConnect";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type CreateConnectSessionBody = {
  provider?: string;
  requestedEmail?: string;
  ttlSeconds?: number;
};

function jsonError(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status });
}

function normalizeTtlSeconds(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 30 * 60;
  }
  return Math.min(Math.max(Math.floor(value), 5 * 60), 60 * 60);
}

export async function POST(request: NextRequest) {
  const agent = authorizeAgentConnectRequest({
    authorization: request.headers.get("authorization"),
  });
  if (!agent) {
    return jsonError("Unauthorized agent connect request", 401);
  }

  const body = (await request.json().catch(() => ({}))) as CreateConnectSessionBody;
  const provider = (body.provider || "google") as OAuthProviderSlug;
  if (!agent.allowedProviders.includes(provider)) {
    return jsonError(`Provider ${provider} is not enabled for this agent`, 403);
  }

  const requestedEmail = agent.requestedEmail || body.requestedEmail;
  const ttlSeconds = normalizeTtlSeconds(body.ttlSeconds);
  const store = await getVercelKvConnectSessionStore();
  const created = await createConnectSession({
    store,
    provider,
    runtimeId: agent.runtimeId,
    agentName: agent.agentName,
    clientName: agent.clientName,
    requestedEmail,
    allowedDomains: agent.allowedDomains,
    ttlSeconds,
  });
  const siteUrl = getSiteUrl(process.env);

  return NextResponse.json(
    {
      sessionId: created.session.id,
      provider: created.session.provider,
      runtimeId: created.session.runtimeId,
      expiresAt: created.session.expiresAt,
      connectUrl: `${siteUrl}/connect/${provider}/${created.rawToken}`,
    },
    { status: 201 },
  );
}
