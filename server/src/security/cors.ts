/**
 * Explicit CORS allow-list (D30).
 *
 * D8 left CORS at `origin: true`, which reflects whatever `Origin` a browser
 * sends. That is not a wildcard on paper but it behaves like one, and it was
 * documented as needing to be tightened before the API is exposed beyond
 * loopback. This module replaces it with an exact-match allow-list.
 *
 * Semantics, stated exactly:
 *
 * - An origin is `scheme://host[:port]`, compared as an exact string after
 *   normalisation (lower-cased, trailing slash removed). There are no wildcards,
 *   no substring matches and no regular expressions; `*` in the configuration is
 *   refused rather than honoured, and each rejected entry is named in a warning.
 * - The built-in list is the documented local dashboard origin, `5173` on
 *   `localhost`, `127.0.0.1` and `[::1]`. `HATCHERY_ALLOWED_ORIGINS` **adds** to
 *   it (comma-separated) rather than replacing it, so tightening the list never
 *   breaks the dashboard the README documents.
 * - A request with no `Origin` header (curl, the worker, the CLI, a server-side
 *   integration) is unaffected: no CORS header is added and nothing is blocked.
 *   CORS is a browser-side read restriction, not authentication.
 * - Credentials are not allowed (`Access-Control-Allow-Credentials` is never
 *   sent): the API authenticates with a bearer token in a header, not a cookie,
 *   so a browser cannot attach credentials cross-origin in the first place.
 * - `Vary: Origin` is always set, so a cache cannot serve one origin's response to
 *   another.
 */

/** The origins the README and the API banner document for the dashboard. */
export const DASHBOARD_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://[::1]:5173',
] as const;

/**
 * Normalise one configured origin, or explain why it was rejected.
 *
 * A path, a trailing slash, a wildcard or a non-http(s) scheme is not an origin
 * this API will allow-list, and it is never quietly converted into one.
 */
export function normaliseOrigin(raw: string): { origin: string | null; reason: string | null } {
  const trimmed = raw.trim();
  if (!trimmed) return { origin: null, reason: 'empty entry' };
  if (trimmed.includes('*')) {
    return { origin: null, reason: 'wildcards are not supported (list each origin exactly)' };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { origin: null, reason: 'not a URL origin' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { origin: null, reason: `unsupported scheme ${parsed.protocol}` };
  }
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    return { origin: null, reason: 'must be scheme://host[:port] with no path' };
  }
  return { origin: parsed.origin.toLowerCase(), reason: null };
}

export interface AllowedOrigins {
  origins: string[];
  rejected: Array<{ entry: string; reason: string }>;
  configured: boolean;
}

/**
 * Build the allow-list: the documented dashboard origins plus whatever
 * `HATCHERY_ALLOWED_ORIGINS` names. Never a wildcard, never a reflection.
 */
export function allowedOrigins(env: NodeJS.ProcessEnv = process.env): AllowedOrigins {
  const configured = (env.HATCHERY_ALLOWED_ORIGINS ?? '').trim();
  const origins = new Set<string>(DASHBOARD_ORIGINS);
  const rejected: Array<{ entry: string; reason: string }> = [];
  if (configured) {
    for (const entry of configured.split(',')) {
      const { origin, reason } = normaliseOrigin(entry);
      if (origin) origins.add(origin);
      else if (entry.trim()) rejected.push({ entry: entry.trim(), reason: reason ?? 'rejected' });
    }
  }
  return { origins: [...origins].sort(), rejected, configured: Boolean(configured) };
}

/** Exact-match membership after normalisation. No `Origin` means "not a browser". */
export function isOriginAllowed(
  requestOrigin: string | undefined,
  allowList: AllowedOrigins,
): boolean {
  if (!requestOrigin) return false;
  const { origin } = normaliseOrigin(requestOrigin);
  if (!origin) return false;
  return allowList.origins.includes(origin);
}

/** A one-line, secret-free summary for the startup log. */
export function describeAllowList(allowList: AllowedOrigins): string {
  const parts = [`${allowList.origins.length} allowed origin(s): ${allowList.origins.join(', ')}`];
  if (allowList.rejected.length > 0) {
    parts.push(
      `ignored ${allowList.rejected.length} HATCHERY_ALLOWED_ORIGINS entr(ies): ` +
        allowList.rejected.map((entry) => `"${entry.entry}" (${entry.reason})`).join(', '),
    );
  }
  return parts.join('; ');
}
