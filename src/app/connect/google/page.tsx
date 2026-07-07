import { GoogleConnectContent } from "../../../components/GoogleConnectContent";
import { resolveGoogleConnectViewModel } from "../../../lib/oauthConnect";

export const metadata = {
  title: "Connect Google Workspace — Elmora",
  description: "Connect Google Workspace to an Elmora worker through a secure OAuth flow.",
};

type GoogleConnectPageProps = {
  searchParams: Promise<{
    client?: string;
    debug?: string;
    runtime?: string;
  }>;
};

export default async function GoogleConnectPage({ searchParams }: GoogleConnectPageProps) {
  const params = await searchParams;
  const view = resolveGoogleConnectViewModel({
    searchParams: params,
  });

  return <GoogleConnectContent view={view} />;
}
