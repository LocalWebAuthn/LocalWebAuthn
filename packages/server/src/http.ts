/**
 * Framework-neutral HTTP helpers for host adapters.
 *
 * LocalWebAuthn does not set cookies or read `Origin` itself. These helpers
 * encode the cookie attributes and exact-origin checks described in SECURITY.md
 * so every starter (and the demo) shares one correct implementation.
 */

export type AuthCookieKind = 'challenge' | 'enrollment' | 'session';

export type AuthCookieNames = Record<AuthCookieKind, string>;

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

/** Loopback hosts where browsers allow WebAuthn and cookies without HTTPS. */
function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

/**
 * Reject a `publicOrigin` these helpers cannot make safe: plain HTTP anywhere
 * except loopback. WebAuthn itself refuses non-secure non-loopback origins, so
 * such a value is always a deployment mistake — fail loudly instead of
 * silently issuing cookies without `Secure` or `__Host-`.
 */
function assertSupportedPublicOrigin(publicOrigin: string): URL {
  const url = new URL(publicOrigin);
  if (url.protocol !== 'https:' && !isLoopbackHost(url.hostname)) {
    throw new Error(`publicOrigin must be HTTPS (or loopback for development): ${url.origin}`);
  }
  return url;
}

/**
 * Cookie names for the three opaque tokens.
 *
 * On HTTPS origins, names use the `__Host-` prefix (Secure, Path=/, no Domain).
 * On loopback HTTP (`http://localhost`, `http://127.0.0.1`), plain names are
 * used because browsers reject `__Host-` without `Secure`. Any other `http://`
 * origin throws — see {@link cookieAttributes}.
 *
 * @param namespace - Short prefix, default `lwa`. Demo uses `lwa_demo`.
 */
export function authCookieNames(publicOrigin: string, namespace = 'lwa'): AuthCookieNames {
  const base = namespace.replaceAll(/[^a-z0-9_-]/giu, '') || 'lwa';
  const host = assertSupportedPublicOrigin(publicOrigin).protocol === 'https:';
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
 *
 * Throws for a plain-HTTP `publicOrigin` that is not loopback: WebAuthn will
 * not run there, and issuing non-`Secure` cookies for it would only hide the
 * misconfiguration.
 */
export function cookieAttributes(options: CookieAttributesOptions): CookieAttributes {
  const secure = assertSupportedPublicOrigin(options.publicOrigin).protocol === 'https:';
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
 * Response headers for a page that displays credential material once — the
 * "here is your API key, copy it now" page.
 *
 * This is the same hardening every service with a show-once token page needs, and
 * it is deliberately a function for the same reason {@link cookieAttributes} is: a
 * checklist in prose gets three of six items right. What it sets, and why each one
 * is on the list:
 *
 * - `Content-Security-Policy` — `default-src 'self'` with no `unsafe-inline`, so a
 *   single injected or third-party script cannot read the key out of the DOM. This
 *   is the one that matters most; everything else is depth.
 * - `frame-ancestors 'none'` (and `X-Frame-Options: DENY` for older agents) — the
 *   page cannot be framed, so it cannot be clickjacked into revealing anything.
 * - `Cache-Control: no-store` plus `Pragma`/`Expires` — no shared cache, no disk
 *   cache, and no back-button redisplay of a secret.
 * - `Referrer-Policy: no-referrer` — nothing about this URL travels onward.
 * - `Permissions-Policy` — the page needs no camera, microphone or geolocation, so
 *   it asks for none.
 * - `Cross-Origin-Opener-Policy`/`-Embedder-Policy`/`-Resource-Policy` — isolate the
 *   browsing context so another origin cannot get a handle to this window.
 * - `X-Content-Type-Options: nosniff`.
 *
 * **Headers are necessary, not sufficient.** They cannot help if the page loads
 * third-party JavaScript, registers a service worker, or the value reaches a
 * clipboard, a download, an SSR payload or an error reporter — all of which outlive
 * the page. See the "provisioning pages" guidance in README-DETAIL.org, and prefer
 * generating a script's key *on the machine that will use it*, which removes this
 * page from the design entirely.
 *
 * @param options.scriptNonce - Per-response nonce for a `<script nonce>` tag, when
 *   the page cannot use only external scripts. Omit for a fully external bundle.
 * @param options.connectSelf - Origins the page may call, beyond `'self'`.
 */
export function provisioningPageHeaders(
  options: { scriptNonce?: string; connectSrc?: string[] } = {},
): Record<string, string> {
  const script = options.scriptNonce ? `'self' 'nonce-${options.scriptNonce}'` : `'self'`;
  const connect = ["'self'", ...(options.connectSrc ?? [])].join(' ');
  return {
    'Content-Security-Policy': [
      `default-src 'self'`,
      `script-src ${script}`,
      `style-src 'self'`,
      `img-src 'self' data:`,
      `connect-src ${connect}`,
      `font-src 'self'`,
      `object-src 'none'`,
      `base-uri 'none'`,
      `form-action 'none'`,
      `frame-ancestors 'none'`,
    ].join('; '),
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    Pragma: 'no-cache',
    Expires: '0',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  };
}

/**
 * Response headers that ask a DPoP client to retry with a server-issued nonce
 * (RFC 9449 section 8).
 *
 * Send these with a `401` when `verifyDpop` throws `dpop_nonce_required`, passing
 * the value of `auth.dpopNonce()`. Without a helper this is four things to get
 * right in every host — catch the code, fetch a nonce, name both headers exactly
 * — for one fixed protocol behaviour.
 *
 * The nonce is not a secret: the server hands the current one to any caller, and
 * its only property is being unguessable *in advance*. So answering a request
 * that failed authentication with one gives nothing away. `null` or `undefined`
 * (nonces not configured) yields the challenge without the nonce header, which is
 * a client-side bug worth surfacing rather than hiding.
 */
export function dpopChallenge(nonce?: string | null): Record<string, string> {
  const headers: Record<string, string> = { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' };
  if (nonce) {
    headers['DPoP-Nonce'] = nonce;
  }
  return headers;
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
 *
 * Values are returned raw, with no percent-decoding — LocalWebAuthn tokens are
 * URL-safe base32 and never need it. Do not use this as a general-purpose
 * cookie parser for values a framework may have percent-encoded.
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

/** RFC 6265 `token` for cookie names. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
/** RFC 6265 `cookie-octet`s: no control chars, whitespace, `"`, `,`, `;`, `\`. */
const COOKIE_VALUE = /^[\u0021\u0023-\u002B\u002D-\u003A\u003C-\u005B\u005D-\u007E]*$/u;

/**
 * Build a single `Set-Cookie` header value (for plain Node or undici adapters).
 *
 * Throws `TypeError` when `name` or `value` contains characters RFC 6265 does
 * not allow (which would otherwise corrupt or inject headers). LocalWebAuthn
 * tokens are URL-safe base32 and always pass.
 */
export function serializeCookie(name: string, value: string, attributes: CookieAttributes): string {
  if (!COOKIE_NAME.test(name)) {
    throw new TypeError(`Invalid cookie name: ${JSON.stringify(name)}`);
  }
  if (!COOKIE_VALUE.test(value)) {
    throw new TypeError('Invalid cookie value: not RFC 6265 cookie-octets.');
  }
  const segments = [
    `${name}=${value}`,
    `Path=${attributes.path}`,
    `SameSite=${attributes.sameSite}`,
  ];
  // CookieAttributes pins httpOnly to `true`; widen the type before changing this.
  segments.push('HttpOnly');
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
