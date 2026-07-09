import { GoogleConnectContent } from "../../../../components/GoogleConnectContent";
import {
  getVercelKvConnectSessionStore,
  resolveGoogleConnectSessionViewModel,
} from "../../../../lib/connectSessions";
import { googleWorkspaceProvider } from "../../../../lib/oauthConnect";

export const metadata = {
  title: "Private Google Connection — Elmora",
  description: "Private one-time Google Workspace OAuth connection for an Elmora worker.",
};

export const dynamic = "force-dynamic";

type GoogleConnectSessionPageProps = {
  params: Promise<{ token: string }>;
};

export default async function GoogleConnectSessionPage({ params }: GoogleConnectSessionPageProps) {
  const { token } = await params;

  try {
    const store = await getVercelKvConnectSessionStore();
    const view = await resolveGoogleConnectSessionViewModel({ store, rawToken: token });
    return <GoogleConnectContent view={view} />;
  } catch (error) {
    return (
      <GoogleConnectContent
        view={{
          provider: googleWorkspaceProvider,
          mode: "client",
          configured: false,
          showDeveloperDetails: false,
          runtimeId: "pending",
          redirectUri: "/oauth/google/callback",
          heading: "Connection link unavailable",
          eyebrow: "Private Workspace connection",
          intro: googleWorkspaceProvider.summary,
          primaryButtonLabel: "Connect Google Workspace",
          error:
            error instanceof Error
              ? error.message
              : "This connection link is unavailable. Ask your Elmora agent for a fresh link.",
        }}
      />
    );
  }
}
