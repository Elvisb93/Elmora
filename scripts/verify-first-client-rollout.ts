import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { getGoogleOAuthScopes } from "../src/lib/connectSessions";

export type FirstClientRolloutOptions = {
  baseUrl: string;
  runtimeId: string;
  adminSecret: string;
  agentConnectSecret?: string;
};

export type FirstClientRolloutResult = {
  ready: true;
  checks: string[];
};

class RolloutVerificationError extends Error {
  constructor(readonly stage: string) {
    super("rollout verification failed");
    this.name = "RolloutVerificationError";
  }
}

const runtimeIdPattern = /^[a-z][a-z0-9-]{2,62}$/;
const connectTokenPattern = /^ecs_[A-Za-z0-9_-]{43}$/;
const googleClientIdPattern = /^[A-Za-z0-9][A-Za-z0-9-]{2,255}\.apps\.googleusercontent\.com$/;
const timeoutMilliseconds = 15_000;

function hasExpectedGoogleOAuthContract(oauthUrl: URL, baseUrl: URL) {
  const expectedParameterNames = [
    "access_type",
    "client_id",
    "nonce",
    "prompt",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
  ];
  const parameterNames = [...oauthUrl.searchParams.keys()].sort();
  const scopes = (oauthUrl.searchParams.get("scope") ?? "").split(/\s+/).filter(Boolean);
  const expectedScopes = getGoogleOAuthScopes();
  return (
    oauthUrl.username === "" &&
    oauthUrl.password === "" &&
    oauthUrl.hash === "" &&
    parameterNames.length === expectedParameterNames.length &&
    parameterNames.every((name, index) => name === expectedParameterNames[index]) &&
    oauthUrl.searchParams.get("response_type") === "code" &&
    googleClientIdPattern.test(oauthUrl.searchParams.get("client_id") ?? "") &&
    oauthUrl.searchParams.get("redirect_uri") === new URL("/oauth/google/callback", baseUrl).toString() &&
    oauthUrl.searchParams.get("access_type") === "offline" &&
    oauthUrl.searchParams.get("prompt") === "consent" &&
    /^[A-Za-z0-9._~-]{16,4096}$/.test(oauthUrl.searchParams.get("state") ?? "") &&
    /^[A-Za-z0-9_-]{32,128}$/.test(oauthUrl.searchParams.get("nonce") ?? "") &&
    scopes.length === expectedScopes.length &&
    new Set(scopes).size === expectedScopes.length &&
    expectedScopes.every((scope) => scopes.includes(scope))
  );
}

function assertConfiguration(options: FirstClientRolloutOptions) {
  const baseUrl = new URL(options.baseUrl);
  const localHttp =
    baseUrl.protocol === "http:" &&
    (baseUrl.hostname === "localhost" || baseUrl.hostname === "127.0.0.1");
  if (
    (baseUrl.protocol !== "https:" && !localHttp) ||
    baseUrl.pathname !== "/" ||
    baseUrl.username !== "" ||
    baseUrl.password !== "" ||
    baseUrl.search !== "" ||
    baseUrl.hash !== ""
  ) {
    throw new RolloutVerificationError("configuration-base-url");
  }
  if (!runtimeIdPattern.test(options.runtimeId)) {
    throw new RolloutVerificationError("configuration-runtime-id");
  }
  if (options.adminSecret.length < 32 || options.agentConnectSecret === "") {
    throw new RolloutVerificationError("configuration-credentials");
  }
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const value: unknown = await response.json().catch(() => null);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new RolloutVerificationError("response-schema");
  }
  return value as Record<string, unknown>;
}

function hasNoStore(response: Response) {
  return /(?:^|,)\s*(?:private\s*,\s*)?no-store(?:\s*,|$)/i.test(
    response.headers.get("cache-control") ?? "",
  );
}

function requestHeaders(secret: string) {
  return { Authorization: `Bearer ${secret}` };
}

export async function verifyFirstClientRollout(
  options: FirstClientRolloutOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<FirstClientRolloutResult> {
  assertConfiguration(options);
  const baseUrl = new URL(options.baseUrl);
  const checks: string[] = [];

  const readiness = await fetchImpl(new URL("/api/readiness", baseUrl), {
    headers: requestHeaders(options.adminSecret),
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMilliseconds),
  });
  const readinessBody = await readJson(readiness);
  if (!readiness.ok || readinessBody.ready !== true || !hasNoStore(readiness)) {
    throw new RolloutVerificationError("control-plane-readiness");
  }
  checks.push("control-plane-readiness");

  const runtime = await fetchImpl(new URL(`/api/agent-runtimes/${options.runtimeId}`, baseUrl), {
    headers: requestHeaders(options.adminSecret),
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMilliseconds),
  });
  const runtimeBody = await readJson(runtime);
  if (
    !runtime.ok ||
    runtimeBody.runtimeId !== options.runtimeId ||
    runtimeBody.status !== "active" ||
    !Number.isSafeInteger(runtimeBody.registryEpoch) ||
    (runtimeBody.registryEpoch as number) < 1 ||
    !Array.isArray(runtimeBody.allowedProviders) ||
    !runtimeBody.allowedProviders.includes("google") ||
    !hasNoStore(runtime)
  ) {
    throw new RolloutVerificationError("runtime-active");
  }
  checks.push("runtime-active");

  if (options.agentConnectSecret) {
    if (options.agentConnectSecret.length < 32) {
      throw new RolloutVerificationError("configuration-agent-credentials");
    }
    const created = await fetchImpl(new URL("/api/connect-sessions", baseUrl), {
      method: "POST",
      headers: {
        ...requestHeaders(options.agentConnectSecret),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ provider: "google", ttlSeconds: 300 }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMilliseconds),
    });
    const createdBody = await readJson(created);
    if (created.status !== 201 || createdBody.runtimeId !== options.runtimeId) {
      throw new RolloutVerificationError("connect-session-create");
    }
    const connectUrl = new URL(String(createdBody.connectUrl ?? ""));
    const fragment = connectUrl.hash.match(/^#token=([^&]+)$/);
    const rawToken = fragment ? decodeURIComponent(fragment[1] ?? "") : "";
    if (
      connectUrl.origin !== baseUrl.origin ||
      connectUrl.username !== "" ||
      connectUrl.password !== "" ||
      connectUrl.pathname !== "/connect/google" ||
      connectUrl.search !== "" ||
      !connectTokenPattern.test(rawToken)
    ) {
      throw new RolloutVerificationError("fragment-connect-link");
    }
    checks.push("fragment-connect-link");

    const resolved = await fetchImpl(new URL("/api/connect-sessions/resolve", baseUrl), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: rawToken }),
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(timeoutMilliseconds),
    });
    const resolvedBody = await readJson(resolved);
    const view = resolvedBody.view;
    const oauthUrlValue =
      view && typeof view === "object" && !Array.isArray(view)
        ? (view as Record<string, unknown>).oauthUrl
        : undefined;
    const oauthUrl = typeof oauthUrlValue === "string" ? new URL(oauthUrlValue) : null;
    if (
      !resolved.ok ||
      !view ||
      typeof view !== "object" ||
      Array.isArray(view) ||
      (view as Record<string, unknown>).configured !== true ||
      !oauthUrl ||
      oauthUrl.origin !== "https://accounts.google.com" ||
      oauthUrl.pathname !== "/o/oauth2/v2/auth" ||
      !hasExpectedGoogleOAuthContract(oauthUrl, baseUrl)
    ) {
      throw new RolloutVerificationError("connect-resolver");
    }
    checks.push("connect-resolver");

    const connectPage = await fetchImpl(new URL("/connect/google", baseUrl), {
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(timeoutMilliseconds),
    });
    const html = await connectPage.text();
    const referrerMeta =
      /<meta[^>]*name=["']referrer["'][^>]*content=["']no-referrer["'][^>]*>/i.test(html) ||
      /<meta[^>]*content=["']no-referrer["'][^>]*name=["']referrer["'][^>]*>/i.test(html);
    if (!connectPage.ok || !referrerMeta) {
      throw new RolloutVerificationError("connect-page-referrer-policy");
    }
    checks.push("connect-page-referrer-policy");
  }

  return { ready: true, checks };
}

async function main() {
  try {
    const result = await verifyFirstClientRollout({
      baseUrl: process.env.ELMORA_READINESS_BASE_URL ?? "",
      runtimeId: process.env.ELMORA_READINESS_RUNTIME_ID ?? "",
      adminSecret: process.env.ELMORA_AGENT_REGISTRY_ADMIN_SECRET ?? "",
      agentConnectSecret: process.env.ELMORA_READINESS_AGENT_CONNECT_SECRET,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const stage = error instanceof RolloutVerificationError ? error.stage : "unexpected";
    process.stderr.write(`${JSON.stringify({ ready: false, error: "rollout verification failed", stage })}\n`);
    process.exitCode = 1;
  }
}

const entryPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === entryPath) {
  void main();
}
