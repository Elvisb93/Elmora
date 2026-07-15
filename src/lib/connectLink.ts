const connectTokenPattern = /^ecs_[A-Za-z0-9_-]{43}$/;
const fragmentPattern = /^#token=([^&]+)$/;

export type ConnectBrowserLocation = {
  hash: string;
  pathname: string;
  search: string;
};

export type ConnectBrowserHistory = {
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
};

export function takeConnectTokenFromBrowserLocation(
  location: ConnectBrowserLocation,
  history: ConnectBrowserHistory,
): string | null {
  const fragment = location.hash;
  if (fragment) {
    history.replaceState(null, "", `${location.pathname}${location.search}`);
  }
  if (fragment.length > 128) {
    return null;
  }
  const match = fragmentPattern.exec(fragment);
  if (!match) {
    return null;
  }
  let token: string;
  try {
    token = decodeURIComponent(match[1]);
  } catch {
    return null;
  }
  return connectTokenPattern.test(token) ? token : null;
}

export function isCanonicalConnectToken(value: unknown): value is string {
  return typeof value === "string" && connectTokenPattern.test(value);
}
