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

/**
 * Classify a `401` as a DPoP authentication rejection, or `null` if it is not one.
 *
 * `'nonce'` — the server demands a server-issued nonce (RFC 9449 section 8) and
 * supplied one; retry with the same session. `'session'` — a DPoP challenge with no
 * nonce error, so the session itself was refused; re-authenticate first.
 *
 * Only a `WWW-Authenticate: DPoP` challenge counts. A `DPoP-Nonce` header alone
 * does not: the server attaches the current nonce to *successful* responses too, so
 * treating it as a rejection signal would replay application failures.
 */
function dpopRejection(response: Response): 'nonce' | 'session' | null {
  // A response may carry several challenges; only the DPoP one is ours.
  const challenges = response.headers.get('WWW-Authenticate') ?? '';
  if (!/(?:^|[\s,])DPoP\b/iu.test(challenges)) {
    return null;
  }
  if (/error\s*=\s*"?use_dpop_nonce"?/iu.test(challenges)) {
    return response.headers.get('DPoP-Nonce') ? 'nonce' : null;
  }
  return 'session';
}

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
    // `parseCredentialPayload` checks this when the payload comes from a file, but a
    // payload can also be built by hand. A machine credential authenticates over the
    // network, and its assertions and DPoP proofs are only as private as the
    // transport, so refuse plain HTTP anywhere except loopback.
    const baseUrl = new URL(options.payload.baseUrl);
    const loopback =
      baseUrl.hostname === 'localhost' ||
      baseUrl.hostname.endsWith('.localhost') ||
      baseUrl.hostname === '127.0.0.1' ||
      baseUrl.hostname === '[::1]';
    if (baseUrl.protocol !== 'https:' && !(baseUrl.protocol === 'http:' && loopback)) {
      throw new MachineClientError(
        'insecure_base_url',
        `baseUrl must be HTTPS (or loopback HTTP for development): ${options.payload.baseUrl}`,
        0,
      );
    }
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
   * Retries a `401` **only** when the response positively identifies itself as an
   * authentication rejection made *before* the application handler ran:
   *
   * - an RFC 9449 nonce challenge — `WWW-Authenticate: DPoP …
   *   error="use_dpop_nonce"` — which the DPoP middleware emits instead of
   *   dispatching. The retry carries the supplied nonce and a fresh proof.
   * - a bare `WWW-Authenticate: DPoP` challenge with no nonce error, which means
   *   the session itself was refused; the retry re-authenticates first.
   *
   * Any other `401` is returned as-is. That matters more than it looks: a `401`
   * from the application's *own* handler carries no promise that the handler did
   * no work, and this client previously retried on any `401` that happened to
   * carry a `DPoP-Nonce` header — which authenticated responses legitimately do,
   * since the server rotates the nonce forward on success. A `POST` that failed
   * authorization after taking effect would have been sent twice. HTTP status is
   * not evidence of non-execution; the challenge header is.
   *
   * A retried request re-sends `init` unchanged, so a one-shot body (a
   * `ReadableStream`) cannot be replayed — pass `bodyFactory` to rebuild it, or the
   * retry is refused rather than silently sending a consumed body. Strings, byte
   * arrays and other reusable bodies need nothing.
   */
  async fetch(
    path: string,
    init: RequestInit & {
      /** Rebuilds a one-shot body for a retry. Required for stream bodies. */
      bodyFactory?: () => BodyInit;
    } = {},
  ): Promise<Response> {
    const { bodyFactory, ...request } = init;
    const first = await this.#send(path, request);
    if (first.status !== 401) {
      return first;
    }
    this.#captureNonce(first);

    const rejection = dpopRejection(first);
    if (!rejection) {
      // Not a pre-dispatch authentication refusal. Hand it back untouched.
      return first;
    }
    if (rejection === 'session') {
      // The session, not the proof, was refused: get a new one before retrying.
      this.#session = null;
    }

    const retry = this.#retryBody(request, bodyFactory);
    if (retry === null) {
      // A stream body was already consumed by the first attempt; resending would
      // transmit an empty body and look like a different request.
      throw new MachineClientError(
        'body_not_replayable',
        'The server asked for a retry, but this request body cannot be resent. Pass bodyFactory to rebuild it.',
        first.status,
      );
    }
    return this.#send(path, retry);
  }

  /** `init` for a retry, or `null` when the body cannot be produced again. */
  #retryBody(init: RequestInit, bodyFactory?: () => BodyInit): RequestInit | null {
    if (bodyFactory) {
      return { ...init, body: bodyFactory() };
    }
    const body: unknown = init.body;
    if (body === undefined || body === null || typeof body === 'string') {
      return init;
    }
    // Reusable: views over memory and form/blob bodies can all be sent twice.
    if (
      body instanceof ArrayBuffer ||
      ArrayBuffer.isView(body) ||
      body instanceof URLSearchParams ||
      (typeof Blob !== 'undefined' && body instanceof Blob) ||
      (typeof FormData !== 'undefined' && body instanceof FormData)
    ) {
      return init;
    }
    return null;
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
