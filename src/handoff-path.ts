/**
 * Requested-path safety for trusted handoff (same rules as oidc_mfa_auth src/modules/handoff/handoff-path.ts).
 * The target re-checks the signed path with its own allowlist, where "*" stands for exactly one segment.
 */

const MAX_LENGTH = 512;
const ALLOWED_CHARS = /^\/[A-Za-z0-9\-._~/%!$&'()*+,;=:@?]*$/;

/** Returns the normalized path, or null when it is not a safe relative path. */
export function normalizeRelativePath(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const raw = input;
  if (!raw || raw.length > MAX_LENGTH) return null;
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return null;
  if (!ALLOWED_CHARS.test(raw)) return null;

  const [pathPart, query = ''] = splitOnce(raw, '?');
  if (pathPart.includes('#') || query.includes('#')) return null;

  let decoded: string;
  try {
    decoded = decodeURIComponent(pathPart);
  } catch {
    return null;
  }
  if (!decoded.startsWith('/') || decoded.startsWith('//') || /[\\\u0000-\u001f\u007f]/.test(decoded)) return null;
  const segments = decoded.split('/').slice(1);
  if (segments.some((s) => s === '.' || s === '..')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(segments[0] ?? '')) return null;

  return query ? `${pathPart}?${query}` : pathPart;
}

/** True when the (normalized) path matches one of the allowlist patterns. Query strings are ignored. */
export function isAllowedPath(path: string, patterns: string[]): boolean {
  const [pathPart] = splitOnce(path, '?');
  const segments = pathPart.split('/').slice(1);
  return patterns.some((pattern) => {
    const want = pattern.split('/').slice(1);
    if (want.length !== segments.length) return false;
    return want.every((w, i) => (w === '*' ? segments[i].length > 0 : w === segments[i]));
  });
}

function splitOnce(value: string, sep: string): [string, string?] {
  const i = value.indexOf(sep);
  return i < 0 ? [value] : [value.slice(0, i), value.slice(i + 1)];
}
