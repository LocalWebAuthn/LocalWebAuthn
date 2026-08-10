import { describe, expect, it } from 'vitest';

import {
  authCookieNames,
  cookieAttributes,
  describeSignupPhase,
  dpopChallenge,
  isExactOrigin,
  isHttpsPublicOrigin,
  nextSignupStep,
  parseCookieHeader,
  provisioningPageHeaders,
  SELF_SERVE_SIGNUP_STEPS,
  serializeClearedCookie,
  serializeCookie,
  signupPhase,
} from '../../packages/server/src/index.js';

describe('HTTP cookie and origin helpers', () => {
  it('uses __Host- names only on HTTPS public origins', () => {
    expect(isHttpsPublicOrigin('https://app.example.com')).toBe(true);
    expect(isHttpsPublicOrigin('http://localhost:4173')).toBe(false);

    const https = authCookieNames('https://app.example.com');
    expect(https.session).toBe('__Host-lwa_session');
    expect(https.challenge).toMatch(/^__Host-lwa_/u);

    const local = authCookieNames('http://localhost:4173', 'lwa_demo');
    expect(local.session).toBe('lwa_demo_session');
    expect(local.session.startsWith('__Host-')).toBe(false);
  });

  it('sets Secure and maxAge from public origin and expiresAt', () => {
    const secure = cookieAttributes({
      publicOrigin: 'https://app.example.com',
      expiresAt: 1_000_000,
      now: () => 990_000,
    });
    expect(secure).toMatchObject({
      httpOnly: true,
      path: '/',
      sameSite: 'Strict',
      secure: true,
      maxAge: 10,
    });

    const local = cookieAttributes({ publicOrigin: 'http://127.0.0.1:4173' });
    expect(local.secure).toBe(false);
    expect(local.maxAge).toBeUndefined();
  });

  it('accepts only exact origins', () => {
    const expected = 'https://app.example.com';
    expect(isExactOrigin('https://app.example.com', expected)).toBe(true);
    expect(isExactOrigin('https://app.example.com/', expected)).toBe(true);
    expect(isExactOrigin('https://evil.example.com', expected)).toBe(false);
    expect(isExactOrigin('https://app.example.com:443', expected)).toBe(true);
    expect(isExactOrigin(null, expected)).toBe(false);
    expect(isExactOrigin('not a url', expected)).toBe(false);
  });

  it('rejects a non-loopback plain-HTTP public origin', () => {
    expect(() => authCookieNames('http://app.internal')).toThrow(/HTTPS/u);
    expect(() => cookieAttributes({ publicOrigin: 'http://10.0.0.5:8080' })).toThrow(/HTTPS/u);
    // Loopback development origins remain fine.
    expect(authCookieNames('http://127.0.0.1:4173').session).toBe('lwa_session');
    expect(authCookieNames('http://app.localhost:4173').session).toBe('lwa_session');
  });

  it('rejects cookie names and values RFC 6265 does not allow', () => {
    const attributes = {
      httpOnly: true as const,
      path: '/' as const,
      sameSite: 'Strict' as const,
      secure: true,
    };
    expect(() => serializeCookie('bad name', 'value', attributes)).toThrow(TypeError);
    expect(() => serializeCookie('name', 'semi;colon', attributes)).toThrow(TypeError);
    expect(() => serializeCookie('name', 'new\nline', attributes)).toThrow(TypeError);
    expect(serializeCookie('name', 'tokenb32value', attributes)).toContain('name=tokenb32value');
  });

  it('hardens a page that displays credential material once', () => {
    const headers = provisioningPageHeaders();
    const csp = headers['Content-Security-Policy'];

    // The one that matters: no inline script, so an injected tag cannot read the
    // key out of the DOM. Everything else is depth.
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    // Not framable, no plugins, no form posts anywhere, no base-tag rewriting.
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("form-action 'none'");

    // A secret must not sit in a cache or come back with the back button.
    expect(headers['Cache-Control']).toContain('no-store');
    expect(headers['Referrer-Policy']).toBe('no-referrer');
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
  });

  it('allows a script nonce and extra connect origins when a page needs them', () => {
    const withNonce = provisioningPageHeaders({
      scriptNonce: 'r4nd0m',
      connectSrc: ['https://api.example.com'],
    });
    const csp = withNonce['Content-Security-Policy'];
    expect(csp).toContain("script-src 'self' 'nonce-r4nd0m'");
    expect(csp).toContain("connect-src 'self' https://api.example.com");
    // A nonce permits *that* script, never inline script generally.
    expect(csp).not.toContain('unsafe-inline');
  });

  it('builds the RFC 9449 nonce challenge headers', () => {
    expect(dpopChallenge('nonce-1')).toEqual({
      'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
      'DPoP-Nonce': 'nonce-1',
    });
    // No nonce configured: still challenge, so the client is told why it failed
    // rather than being handed a header with an empty value.
    expect(dpopChallenge(null)).toEqual({ 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' });
    expect(dpopChallenge()).not.toHaveProperty('DPoP-Nonce');
  });

  it('parses and serializes cookies for plain Node adapters', () => {
    expect(parseCookieHeader('a=1; b=two; a=ignored')).toEqual({ a: '1', b: 'two' });
    const set = serializeCookie('lwa_session', 'token', {
      httpOnly: true,
      path: '/',
      sameSite: 'Strict',
      secure: true,
      maxAge: 60,
    });
    expect(set).toContain('lwa_session=token');
    expect(set).toContain('HttpOnly');
    expect(set).toContain('Secure');
    expect(set).toContain('Max-Age=60');
    expect(serializeClearedCookie('lwa_session', 'https://app.example.com')).toContain('Max-Age=0');
  });
});

describe('signup phase helper', () => {
  it('prefers enrolled when a credential exists', () => {
    expect(
      signupPhase({
        hasActiveCredential: true,
        hasPendingEnrollmentGrant: true,
        hasEnrollmentSession: true,
      }),
    ).toBe('enrolled');
  });

  it('orders exchanged before issued before created', () => {
    expect(
      signupPhase({
        hasActiveCredential: false,
        hasPendingEnrollmentGrant: true,
        hasEnrollmentSession: true,
      }),
    ).toBe('enrollment_exchanged');
    expect(
      signupPhase({
        hasActiveCredential: false,
        hasPendingEnrollmentGrant: true,
        hasEnrollmentSession: false,
      }),
    ).toBe('enrollment_issued');
    expect(
      signupPhase({
        hasActiveCredential: false,
        hasPendingEnrollmentGrant: false,
        hasEnrollmentSession: false,
      }),
    ).toBe('created');
  });

  it('describes next steps for each phase', () => {
    expect(nextSignupStep('created').action).toBe('issue_enrollment');
    expect(nextSignupStep('enrollment_issued').action).toBe('deliver_enrollment_url');
    expect(nextSignupStep('enrollment_exchanged').action).toBe('register_passkey');
    expect(nextSignupStep('enrolled').action).toBe('done');
    expect(describeSignupPhase('enrolled')).toMatch(/passkey/iu);
    expect(SELF_SERVE_SIGNUP_STEPS.length).toBeGreaterThan(3);
  });
});
