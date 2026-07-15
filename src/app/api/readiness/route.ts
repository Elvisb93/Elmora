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
  assertGoogleTokenStorageConfiguration({
    storageWebhookUrl: env.ELMORA_TOKEN_WEBHOOK_URL,
    storageWebhookKeyId: env.ELMORA_TOKEN_WEBHOOK_KEY_ID,
    storageWebhookSecret: env.ELMORA_TOKEN_WEBHOOK_SECRET,
  });
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

  try {
    assertReadinessConfiguration(env);
  } catch {
    return unavailableResponse("invalid_configuration");
  }

  try {
    const store = await getStore();
    if (!store.probeReadiness || !(await store.probeReadiness())) {
      throw new Error("KV readiness capability unavailable");
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
