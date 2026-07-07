import { notFound } from "next/navigation";
import { GoogleConnectContent } from "../../../../../components/GoogleConnectContent";
import { resolveGoogleConnectViewModel } from "../../../../../lib/oauthConnect";

export const metadata = {
  title: "Connect Workspace — Elmora",
  description: "Connect a client workspace integration to an Elmora worker.",
};

type ClientProviderConnectPageProps = {
  params: Promise<{
    clientSlug: string;
    provider: string;
  }>;
  searchParams: Promise<{
    debug?: string;
    runtime?: string;
  }>;
};

export default async function ClientProviderConnectPage({
  params,
  searchParams,
}: ClientProviderConnectPageProps) {
  const resolvedParams = await params;
  const resolvedSearchParams = await searchParams;

  if (resolvedParams.provider !== "google") {
    notFound();
  }

  const view = resolveGoogleConnectViewModel({
    routeClientSlug: resolvedParams.clientSlug,
    searchParams: resolvedSearchParams,
  });

  return <GoogleConnectContent view={view} />;
}
