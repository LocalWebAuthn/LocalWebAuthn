/**
 * Framework-neutral HTTP helpers for host adapters.
 *
 * LocalWebAuthn does not set cookies or read `Origin` itself. These helpers
 * encode the cookie attributes and exact-origin checks described in SECURITY.md
 * so every starter (and the demo) shares one correct implementation.
 */

export type AuthCookieKind = 'challenge' | 'enrollment' | 'session';

export type AuthCookieNames = {
  challenge: string;
  enrollment: string;
  session: string;
};

/**
 * Attributes for an opaque auth cookie (challenge, enrollment, or session).
 *
 * Compatible with `hono/cookie` `setCookie` options and with manual
 * `Set-Cookie` construction. `__Host-` names are chosen by
 * {@link authCookieNames} when the public origin is HTTPS; those names require
 * `secure: true`, `path: '/'`, and no `Domain` attribute.
 */
export type CookieAttributes = {
  httpOnly: true;
  path: '/';
  sameSite: 'Strict';
  secure: boolean;
  /** Seconds until expiry; omit when clearing a cookie. */
  maxAge?: number;
};

export type CookieAttributesOptions = {
  /** Exact public origin of the app (`https://app.example.com` or local HTTP). */
  publicOrigin: string;
  /** Absolute expiry as a Unix millisecond timestamp (from LocalWebAuthn APIs). */
  expiresAt?: number;
  /** Override the clock (tests). */
  now?: () => number;
};

/**
 * Whether `publicOrigin` is HTTPS (so cookies may use the `__Host-` prefix).
 */
export function isHttpsPublicOrigin(publicOrigin: string): boolean {
  return new URL(publicOrigin).protocol === 'https:';
}

/**
 * Cookie names for the three opaque tokens.
 *
 * On HTTPS origins, names use the `__Host-` prefix (Secure, Path=/, no Domain).
 * On local HTTP (`http://localhost`, `http://127.0.0.1`), plain names are used
 * because browsers reject `__Host-` without `Secure`.
 *
 * @param namespace - Short prefix, default `lwa`. Demo uses `lwa_demo`.
 */
export function authCookieNames(publicOrigin: string, namespace = 'lwa'): AuthCookieNames {
  const base = namespace.replaceAll(/[^a-z0-9_-]/giu, '') || 'lwa';
  const host = isHttpsPublicOrigin(publicOrigin);
  const prefix = host ? `__Host-${base}` : base;
  return {
    challenge: `${prefix}_challenge`,
    enrollment: `${prefix}_enrollment`,
    session: `${prefix}_session`,
  };
}

/**
 * Cookie attributes for setting or clearing an opaque auth token.
 *
 * When `expiresAt` is provided, `maxAge` is derived in whole seconds (minimum 1).
 * When omitted, no `maxAge` is set (suitable for delete/clear).
 */
export function cookieAttributes(options: CookieAttributesOptions): CookieAttributes {
  const secure = isHttpsPublicOrigin(options.publicOrigin);
  const attributes: CookieAttributes = {
    httpOnly: true,
    path: '/',
    sameSite: 'Strict',
    secure,
  };
  if (options.expiresAt !== undefined) {
    const now = options.now?.() ?? Date.now();
    attributes.maxAge = Math.max(1, Math.ceil((options.expiresAt - now) / 1000));
  }
  return attributes;
}

/**
 * Exact-origin check for state-changing requests.
 *
 * Pass the `Origin` header value (or `null` if absent). Returns true only when
 * it exactly equals `expectedOrigin` (scheme + host + port, no path).
 */
export function isExactOrigin(
  requestOrigin: string | null | undefined,
  expectedOrigin: string,
): boolean {
  if (requestOrigin == null || requestOrigin === '') {
    return false;
  }
  try {
    return new URL(requestOrigin).origin === new URL(expectedOrigin).origin;
  } catch {
    return false;
  }
}

/**
 * Parse a `Cookie` header into a name → value map (first value wins).
 */
export function parseCookieHeader(header: string | null | undefined): Record<string, string> {
  if (!header) {
    return {};
  }
  const cookies: Record<string, string> = {};
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const separator = trimmed.indexOf('=');
    if (separator <= 0) {
      continue;
    }
    const name = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    if (name && !(name in cookies)) {
      cookies[name] = value;
    }
  }
  return cookies;
}

/**
 * Build a single `Set-Cookie` header value (for plain Node or undici adapters).
 */
export function serializeCookie(name: string, value: string, attributes: CookieAttributes): string {
  const segments = [`${name}=${value}`, 'HttpOnly', `Path=${attributes.path}`, 'SameSite=Strict'];
  if (attributes.secure) {
    segments.push('Secure');
  }
  if (attributes.maxAge !== undefined) {
    segments.push(`Max-Age=${String(attributes.maxAge)}`);
  }
  return segments.join('; ');
}

/**
 * `Set-Cookie` value that clears a cookie (empty value, maxAge 0).
 */
export function serializeClearedCookie(name: string, publicOrigin: string): string {
  return serializeCookie(name, '', {
    ...cookieAttributes({ publicOrigin }),
    maxAge: 0,
  });
}
