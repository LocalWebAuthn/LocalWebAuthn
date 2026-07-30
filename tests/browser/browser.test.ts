import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

import { describe, expect, it, vi } from 'vitest';

import {
  consumeEnrollmentToken,
  LocalWebAuthnBrowser,
  LocalWebAuthnBrowserError,
} from '../../packages/browser/src/index.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('LocalWebAuthnBrowser', () => {
  it('runs an authentication ceremony through the default protocol', async () => {
    const options = { challenge: 'challenge' } as PublicKeyCredentialRequestOptionsJSON;
    const response = {
      id: 'credential',
      rawId: 'credential',
      response: {},
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(jsonResponse(options))
      .mockResolvedValueOnce(jsonResponse({ verified: true }));
    const startAuthentication = vi.fn().mockResolvedValue(response);
    const client = new LocalWebAuthnBrowser({
      fetch,
      ceremonies: {
        startAuthentication,
        startRegistration: vi.fn(),
      },
    });

    await expect(client.signIn()).resolves.toEqual({ verified: true });
    expect(startAuthentication).toHaveBeenCalledWith({ optionsJSON: options });
    expect(fetch).toHaveBeenNthCalledWith(
      1,
      '/api/auth/login/options',
      expect.objectContaining({
        method: 'POST',
        credentials: 'same-origin',
        redirect: 'error',
      }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      '/api/auth/login/verify',
      expect.objectContaining({ body: JSON.stringify(response) }),
    );
  });

  it('runs registration and sends an optional local label', async () => {
    const options = { challenge: 'challenge' } as PublicKeyCredentialCreationOptionsJSON;
    const response = {
      id: 'credential',
      rawId: 'credential',
      response: {},
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(jsonResponse(options))
      .mockResolvedValueOnce(jsonResponse({ verified: true }));
    const startRegistration = vi.fn().mockResolvedValue(response);
    const client = new LocalWebAuthnBrowser({
      fetch,
      ceremonies: {
        startAuthentication: vi.fn(),
        startRegistration,
      },
    });

    await client.registerPasskey('Laptop');
    const verifyRequest = fetch.mock.calls[1][1] as RequestInit;
    expect(JSON.parse(verifyRequest.body as string)).toMatchObject({
      id: 'credential',
      localWebAuthnLabel: 'Laptop',
    });
  });

  it('returns stable service errors without exposing invalid response bodies', async () => {
    const client = new LocalWebAuthnBrowser({
      fetch: vi.fn().mockResolvedValue(
        jsonResponse(
          {
            error: 'invalid_enrollment',
            message: 'The enrollment link is invalid.',
          },
          403,
        ),
      ),
    });

    await expect(client.exchangeEnrollment('bad')).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnBrowserError>>({
        code: 'invalid_enrollment',
        status: 403,
      }),
    );
  });
});

describe('consumeEnrollmentToken', () => {
  it('extracts the fragment token and removes it from browser history', () => {
    const replaceState = vi.fn();
    const token = consumeEnrollmentToken(
      { pathname: '/enroll', hash: '#token=secret' } as Location,
      { replaceState },
    );
    expect(token).toBe('secret');
    expect(replaceState).toHaveBeenCalledWith(null, '', '/enroll');
  });

  it('ignores tokens on other paths', () => {
    expect(consumeEnrollmentToken({ pathname: '/', hash: '#token=secret' } as Location)).toBeNull();
  });
});
