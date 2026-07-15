import { NextRequest, NextResponse } from "next/server";
import {
  authorizeAgentRegistryAdminRequest,
  getVercelKvConnectSessionStore,
  type ConnectSessionStore,
} from "../../../lib/connectSessions";
import { assertGoogleTokenStorageConfiguration } from "../../../lib/googleOAuth";
import { defaultGoogleOAuthClientId } from "../../../lib/oauthConnect";
import { operationalErrorHeaders } from "../../../lib/operationalTelemetry";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ConnectSessionStoreFactory = () => Promise<ConnectSessionStore>;
type TokenReceiverProbe = (webhookUrl: URL) => Promise<boolean>;

const tokenReceiverProbeTimeoutMilliseconds = 5_000;

function isSafeConfigurationString(
  value: string | undefined,
  minimumLength: number,
  maximumLength = 8_192,
) {
  return (
    typeof value === "string" &&
    value.length >= minimumLength &&
    value.length <= maximumLength &&
    value === value.trim() &&
    !/[\u0000-\u0020\u007f-\u009f]/.test(value)
  );
}

function assertReadinessConfiguration(env: Record<string, string | undefined>) {
  const clientId =
    env.GOOGLE_OAUTH_CLIENT_ID ??
    env.NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID ??
    defaultGoogleOAuthClientId;
  if (
    !isSafeConfigurationString(env.ELMORA_STATE_SIGNING_SECRET, 32) ||
    !isSafeConfigurationString(env.GOOGLE_OAUTH_CLIENT_SECRET, 1, 4_096) ||
    !isSafeConfigurationString(clientId, 1, 512) ||
    !clientId.endsWith(".apps.googleusercontent.com")
  ) {
    throw new Error("Invalid OAuth readiness configuration");
  }
  const { webhookUrl } = assertGoogleTokenStorageConfiguration({
    storageWebhookUrl: env.ELMORA_TOKEN_WEBHOOK_URL,
    storageWebhookKeyId: env.ELMORA_TOKEN_WEBHOOK_KEY_ID,
    storageWebhookSecret: env.ELMORA_TOKEN_WEBHOOK_SECRET,
  });
  return webhookUrl;
}

async function probeTokenReceiverHealth(webhookUrl: URL): Promise<boolean> {
  const healthUrl = new URL(webhookUrl);
  healthUrl.pathname = "/healthz";
  healthUrl.search = "";
  healthUrl.hash = "";
  try {
    const response = await fetch(healthUrl, {
      method: "GET",
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(tokenReceiverProbeTimeoutMilliseconds),
    });
    return response.ok;
  } catch {
    return false;
  }
}

function unavailableResponse(outcome: "invalid_configuration" | "dependency_unavailable") {
  return NextResponse.json(
    { ready: false },
    {
      status: 503,
      headers: {
        "Cache-Control": "private, no-store",
        ...operationalErrorHeaders("readiness_check_failed", outcome),
      },
    },
  );
}

export async function handleReadinessRequest(
  request: NextRequest,
  getStore: ConnectSessionStoreFactory = getVercelKvConnectSessionStore,
  env: Record<string, string | undefined> = process.env,
  probeReceiver: TokenReceiverProbe = probeTokenReceiverHealth,
) {
  if (
    !authorizeAgentRegistryAdminRequest({
      authorization: request.headers.get("authorization"),
      adminSecret: env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET,
    })
  ) {
    return NextResponse.json(
      { error: "Unauthorized" },
      { status: 401, headers: { "Cache-Control": "private, no-store" } },
    );
  }

  let webhookUrl: URL;
  try {
    webhookUrl = assertReadinessConfiguration(env);
  } catch {
    return unavailableResponse("invalid_configuration");
  }

  try {
    const store = await getStore();
    if (!store.probeReadiness || !(await store.probeReadiness())) {
      throw new Error("KV readiness capability unavailable");
    }
    if (!(await probeReceiver(webhookUrl))) {
      throw new Error("Token receiver readiness probe failed");
    }
    return NextResponse.json(
      { ready: true },
      { headers: { "Cache-Control": "private, no-store" } },
    );
  } catch {
    return unavailableResponse("dependency_unavailable");
  }
}

export async function GET(request: NextRequest) {
  return handleReadinessRequest(request);
}
