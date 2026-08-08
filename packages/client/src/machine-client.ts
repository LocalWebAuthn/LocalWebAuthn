/**
 * A `fetch` that authenticates itself with a software Passkey.
 *
 * One ceremony per session, then a DPoP proof per request. The long-lived key
 * never crosses the wire; only signatures over server-chosen material do.
 */

import { createAssertionResponse, type SoftwareCredential } from './authenticator.js';
import { decodeBase64Url } from './bytes.js';
import { type CredentialPayload } from './credential-file.js';
import { createDpopProof } from './dpop.js';
import type { MachineKeyStore } from './keystore.js';

export type MachineClientOptions = {
  payload: CredentialPayload;
  keyStore: MachineKeyStore;
  /** Endpoint paths, relative to `payload.baseUrl`. */
  endpoints?: { options?: string; verify?: string };
  fetch?: typeof globalThis.fetch;
  /** Send `Authorization: DPoP` with a per-request proof. Defaults to `true`. */
  dpop?: boolean;
  now?: () => number;
};

export class MachineClientError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'MachineClientError';
    this.code = code;
    this.status = status;
  }
}

type Session = { token: string; expiresAt: number };

const DEFAULT_ENDPOINTS = {
  options: '/api/machine/v1/login/options',
  verify: '/api/machine/v1/login/verify',
};

export class MachineClient {
  readonly #payload;
  readonly #keyStore;
  readonly #endpoints;
  readonly #fetch;
  readonly #dpop;
  readonly #now;
  readonly #credential: SoftwareCredential;

  #session: Session | null = null;
  /** Latest `DPoP-Nonce`; the server may demand one at any point. */
  #nonce: string | undefined;

  constructor(options: MachineClientOptions) {
    this.#payload = options.payload;
    this.#keyStore = options.keyStore;
    this.#endpoints = { ...DEFAULT_ENDPOINTS, ...options.endpoints };
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#dpop = options.dpop ?? true;
    this.#now = options.now ?? Date.now;
    this.#credential = {
      credentialId: decodeBase64Url(options.payload.credentialId),
      userHandle: decodeBase64Url(options.payload.userHandle),
      rpId: options.payload.rpId,
      origin: options.payload.origin,
    };
  }

  /** Absolute URL for a path against the configured base. */
  url(path: string): string {
    return new URL(path, this.#payload.baseUrl).toString();
  }

  /**
   * Run the ceremony and hold the resulting session.
   *
   * Called automatically by {@link fetch}; exposed so a long-running process can
   * warm up, or re-authenticate deliberately for a step-up operation.
   */
  async authenticate(): Promise<Session> {
    const optionsResponse = await this.#fetch(this.url(this.#endpoints.options), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    const optionsBody = (await this.#json(optionsResponse)) as {
      options?: { challenge?: string };
      challengeToken?: string;
    };
    if (!optionsBody.options?.challenge || !optionsBody.challengeToken) {
      throw new MachineClientError(
        'invalid_response',
        'The server did not return a challenge.',
        optionsResponse.status,
      );
    }

    const assertion = await createAssertionResponse({
      keyStore: this.#keyStore,
      credential: this.#credential,
      challenge: optionsBody.options.challenge,
    });

    const verifyResponse = await this.#fetch(this.url(this.#endpoints.verify), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        response: assertion,
        challengeToken: optionsBody.challengeToken,
      }),
    });
    const verifyBody = (await this.#json(verifyResponse)) as {
      sessionToken?: string;
      expiresAt?: number;
    };
    if (!verifyBody.sessionToken) {
      throw new MachineClientError(
        'authentication_failed',
        'The server did not return a session token.',
        verifyResponse.status,
      );
    }
    this.#captureNonce(verifyResponse);
    this.#session = {
      token: verifyBody.sessionToken,
      expiresAt: verifyBody.expiresAt ?? this.#now() + 60_000,
    };
    return this.#session;
  }

  /**
   * Call an API endpoint, authenticating first if needed.
   *
   * Retries once on `401`, which covers both an expired session and a server that
   * has started demanding a `DPoP-Nonce` — in the latter case the retry carries
   * the nonce the failing response supplied.
   */
  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const first = await this.#send(path, init);
    if (first.status !== 401) {
      return first;
    }
    this.#captureNonce(first);
    // A nonce challenge does not invalidate the session; an expired session does.
    if (!first.headers.get('DPoP-Nonce')) {
      this.#session = null;
    }
    return this.#send(path, init);
  }

  async #send(path: string, init: RequestInit): Promise<Response> {
    const session = await this.#liveSession();
    const url = this.url(path);
    const method = (init.method ?? 'GET').toUpperCase();
    const headers = new Headers(init.headers);

    if (this.#dpop) {
      headers.set('Authorization', `DPoP ${session.token}`);
      headers.set(
        'DPoP',
        await createDpopProof({
          keyStore: this.#keyStore,
          method,
          url,
          accessToken: session.token,
          nonce: this.#nonce,
          now: this.#now,
        }),
      );
    } else {
      headers.set('Authorization', `Bearer ${session.token}`);
    }

    const response = await this.#fetch(url, { ...init, method, headers });
    this.#captureNonce(response);
    return response;
  }

  async #liveSession(): Promise<Session> {
    // Re-authenticate a little early rather than discover expiry mid-request.
    if (this.#session && this.#session.expiresAt - 5_000 > this.#now()) {
      return this.#session;
    }
    return this.authenticate();
  }

  #captureNonce(response: Response): void {
    const nonce = response.headers.get('DPoP-Nonce');
    if (nonce) {
      this.#nonce = nonce;
    }
  }

  async #json(response: Response): Promise<unknown> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new MachineClientError(
        'invalid_response',
        'The server returned a non-JSON response.',
        response.status,
      );
    }
    if (!response.ok) {
      const error = body as { error?: string; message?: string };
      throw new MachineClientError(
        error.error ?? 'request_failed',
        error.message ?? 'The request failed.',
        response.status,
      );
    }
    return body;
  }
}
