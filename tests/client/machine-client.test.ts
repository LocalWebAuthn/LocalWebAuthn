/**
 * `MachineClient` behaviour, against a stub server.
 *
 * Driven from source rather than the built bundle, both so the retry and nonce
 * paths are measured and so editing the client cannot silently test a stale
 * `dist/`.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { CredentialPayload } from '../../packages/client/src/index.js';
import {
  createDpopProof,
  encodeBase64Url,
  ES256,
  MachineClient,
  MachineClientError,
  type MachineKeyStore,
} from '../../packages/client/src/index.js';
import { generateKeyStore } from '../../packages/client/src/file-key.js';

const ORIGIN = 'https://app.example.test';

function payloadFor(): CredentialPayload {
  return {
    v: 1,
    baseUrl: ORIGIN,
    rpId: 'app.example.test',
    origin: ORIGIN,
    credentialId: encodeBase64Url(new Uint8Array(32).fill(3)),
    userHandle: encodeBase64Url(new Uint8Array(32).fill(4)),
    alg: ES256,
  };
}

type Call = { url: string; method: string; headers: Headers };

/**
 * A stub server that completes the ceremony and then answers API calls.
 *
 * `apiStatus` lets a test make the first API call fail so the retry path runs.
 * `challenge` controls the `WWW-Authenticate` header on a 401, because that header
 * — not the status, and not an incidental `DPoP-Nonce` — is what marks a response
 * as an authentication refusal made before the application handler ran:
 *
 * - `'nonce'` (default when a nonce is set): the RFC 9449 nonce challenge.
 * - `'session'`: a bare DPoP challenge, i.e. the session was refused.
 * - `'none'`: no challenge at all — an application's own 401.
 *
 * `alwaysNonce` models the real server behaviour of rotating the nonce forward on
 * *every* response, including ones the application rejected.
 */
function stubServer(
  options: {
    apiStatus?: (call: number) => number;
    nonce?: string;
    challenge?: 'nonce' | 'session' | 'none';
    alwaysNonce?: boolean;
  } = {},
) {
  const calls: Call[] = [];
  let apiCalls = 0;
  let sessions = 0;

  const fetchStub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input as string | URL, init);
    calls.push({ url: request.url, method: request.method, headers: request.headers });
    const path = new URL(request.url).pathname;

    if (path.endsWith('/login/options')) {
      return Response.json({
        options: { challenge: encodeBase64Url(new Uint8Array(32).fill(9)) },
        challengeToken: 'challenge-token',
      });
    }
    if (path.endsWith('/login/verify')) {
      sessions += 1;
      return Response.json({
        sessionToken: `session-${String(sessions)}`,
        expiresAt: Date.now() + 900_000,
      });
    }

    apiCalls += 1;
    const status = options.apiStatus?.(apiCalls) ?? 200;
    const headers = new Headers();
    if (options.nonce && (status === 401 || options.alwaysNonce)) {
      headers.set('DPoP-Nonce', options.nonce);
    }
    const challenge = options.challenge ?? (options.nonce ? 'nonce' : 'session');
    if (status === 401 && challenge !== 'none') {
      headers.set(
        'WWW-Authenticate',
        challenge === 'nonce' ? 'DPoP error="use_dpop_nonce"' : 'DPoP',
      );
    }
    return new Response(JSON.stringify({ ok: status === 200, apiCalls }), { status, headers });
  });

  return { fetchStub, calls, sessionCount: () => sessions };
}

describe('the default entry point', () => {
  // The split is only worth having if the default entry stays clean: a consumer that
  // never imports `/file-key` must have no way to generate, read or write a raw
  // private key. Asserted against the module's own exports rather than trusted.
  it('exposes no raw private-key operation', async () => {
    const core: Record<string, unknown> = await import('../../packages/client/src/index.js');
    for (const name of [
      'generateKeyStore',
      'importKeyStore',
      'formatCredentialFile',
      'parseCredentialFile',
      'isKeystoreReference',
    ]) {
      expect(core, `${name} must live behind /file-key`).not.toHaveProperty(name);
    }
    // What it does offer: the opaque signer interface and everything built on it,
    // which a TPM, agent or KMS satisfies without exportable material.
    expect(core).toHaveProperty('MachineClient');
    expect(core).toHaveProperty('createDpopProof');
    expect(core).toHaveProperty('createAssertionResponse');
    // Public credential metadata is not key material, so it stays.
    expect(core).toHaveProperty('parseCredentialPayload');
  });

  it('keeps the raw-key operations available behind the explicit import', async () => {
    const fileKey: Record<string, unknown> = await import('../../packages/client/src/file-key.js');
    expect(fileKey).toHaveProperty('generateKeyStore');
    expect(fileKey).toHaveProperty('importKeyStore');
    expect(fileKey).toHaveProperty('formatCredentialFile');
    expect(fileKey).toHaveProperty('parseCredentialFile');
  });
});

describe('MachineClient', () => {
  let keyStore: MachineKeyStore;

  beforeEach(async () => {
    ({ keyStore } = await generateKeyStore(ES256));
  });

  it('runs the ceremony once and reuses the session', async () => {
    const server = stubServer();
    const client = new MachineClient({
      payload: payloadFor(),
      keyStore,
      fetch: server.fetchStub,
    });

    await client.fetch('/api/reports');
    await client.fetch('/api/reports');
    await client.fetch('/api/other');

    expect(server.sessionCount()).toBe(1);
    const apiCalls = server.calls.filter((call) => !call.url.includes('/login/'));
    expect(apiCalls).toHaveLength(3);
  });

  it('sends Authorization: DPoP with a distinct proof per request', async () => {
    const server = stubServer();
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });

    await client.fetch('/api/reports', { method: 'POST' });
    await client.fetch('/api/reports', { method: 'POST' });

    const proofs = server.calls
      .filter((call) => call.headers.has('DPoP'))
      .map((call) => call.headers.get('DPoP'));
    expect(proofs).toHaveLength(2);
    expect(server.calls.at(-1)?.headers.get('Authorization')).toMatch(/^DPoP session-1$/u);
    // Each proof carries a fresh jti, so no two are equal — which is what makes
    // the server's replay cache able to reject a captured one.
    expect(new Set(proofs).size).toBe(2);
  });

  it('falls back to a bearer token when DPoP is disabled', async () => {
    const server = stubServer();
    const client = new MachineClient({
      payload: payloadFor(),
      keyStore,
      fetch: server.fetchStub,
      dpop: false,
    });
    await client.fetch('/api/reports');
    const call = server.calls.at(-1);
    expect(call?.headers.get('Authorization')).toBe('Bearer session-1');
    expect(call?.headers.has('DPoP')).toBe(false);
  });

  it('re-authenticates once when the session is rejected', async () => {
    // 401 with no DPoP-Nonce means the session is gone, not that a nonce is due.
    const server = stubServer({ apiStatus: (call) => (call === 1 ? 401 : 200) });
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });

    const response = await client.fetch('/api/reports');
    expect(response.status).toBe(200);
    expect(server.sessionCount()).toBe(2);
  });

  it('retries with the nonce when the server demands one, keeping the session', async () => {
    const server = stubServer({
      apiStatus: (call) => (call === 1 ? 401 : 200),
      nonce: 'server-nonce-1',
    });
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });

    const response = await client.fetch('/api/reports');
    expect(response.status).toBe(200);
    // A nonce challenge is not an expiry, so no second ceremony.
    expect(server.sessionCount()).toBe(1);

    const retry = server.calls.at(-1);
    const proof = retry?.headers.get('DPoP') ?? '';
    const claims = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(proof.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')), (c) =>
          c.charCodeAt(0),
        ),
      ),
    ) as { nonce?: string };
    expect(claims.nonce).toBe('server-nonce-1');
  });

  it('does not replay an application 401 that merely carries a nonce', async () => {
    // The bug this guards: the server rotates DPoP-Nonce onto *successful*
    // authenticated responses, so a 401 from the application's own handler carries
    // one too. Retrying on that header alone re-sent the request — and a POST whose
    // handler had already taken effect would run twice.
    const server = stubServer({
      apiStatus: () => 401,
      nonce: 'server-nonce-1',
      alwaysNonce: true,
      challenge: 'none',
    });
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });

    const response = await client.fetch('/api/transfer', { method: 'POST', body: '{"amount":1}' });

    expect(response.status).toBe(401);
    // Exactly one dispatch of the operation, and no re-authentication.
    const apiCalls = server.calls.filter((call) => !call.url.includes('/login/'));
    expect(apiCalls).toHaveLength(1);
    expect(server.sessionCount()).toBe(1);
  });

  it('retries a POST once on an exact nonce challenge, dispatching it a second time', async () => {
    // The opposite case: a genuine RFC 9449 nonce challenge is produced *before*
    // the handler runs, so the operation never executed and retrying a POST is safe
    // regardless of idempotency.
    const server = stubServer({
      apiStatus: (call) => (call === 1 ? 401 : 200),
      nonce: 'server-nonce-1',
      challenge: 'nonce',
    });
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });

    const response = await client.fetch('/api/transfer', { method: 'POST', body: '{"amount":1}' });
    expect(response.status).toBe(200);
    expect(server.sessionCount()).toBe(1);

    const apiCalls = server.calls.filter((call) => !call.url.includes('/login/'));
    expect(apiCalls).toHaveLength(2);
    // A fresh proof identifier on the retry, or the server's replay cache refuses it.
    const proofs = apiCalls.map((call) => call.headers.get('DPoP'));
    expect(new Set(proofs).size).toBe(2);
  });

  it('stops after one retry when the server challenges again', async () => {
    const server = stubServer({ apiStatus: () => 401, nonce: 'n', challenge: 'nonce' });
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });

    const response = await client.fetch('/api/reports');
    expect(response.status).toBe(401);
    expect(server.calls.filter((call) => !call.url.includes('/login/'))).toHaveLength(2);
  });

  it('refuses to retry a one-shot stream body, and accepts a factory for one', async () => {
    const streamBody = () =>
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"amount":1}'));
          controller.close();
        },
      });

    // Without a factory the first attempt has already consumed the stream, so a
    // retry would silently transmit nothing. Fail instead.
    const refusing = stubServer({ apiStatus: (call) => (call === 1 ? 401 : 200), nonce: 'n' });
    const client = new MachineClient({
      payload: payloadFor(),
      keyStore,
      fetch: refusing.fetchStub,
    });
    await expect(
      client.fetch('/api/transfer', {
        method: 'POST',
        body: streamBody(),
        duplex: 'half',
      } as RequestInit),
    ).rejects.toMatchObject({ code: 'body_not_replayable' });

    // With a factory the retry rebuilds the body and succeeds.
    const accepting = stubServer({ apiStatus: (call) => (call === 1 ? 401 : 200), nonce: 'n' });
    const withFactory = new MachineClient({
      payload: payloadFor(),
      keyStore,
      fetch: accepting.fetchStub,
    });
    const response = await withFactory.fetch('/api/transfer', {
      method: 'POST',
      body: streamBody(),
      duplex: 'half',
      bodyFactory: () => '{"amount":1}',
    } as RequestInit & { bodyFactory: () => BodyInit });
    expect(response.status).toBe(200);
  });

  it('resends a reusable string body unchanged on a classified retry', async () => {
    const server = stubServer({ apiStatus: (call) => (call === 1 ? 401 : 200), nonce: 'n' });
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: server.fetchStub });
    const response = await client.fetch('/api/transfer', { method: 'POST', body: '{"amount":1}' });
    expect(response.status).toBe(200);
    expect(
      server.calls.filter((call) => call.method === 'POST' && !call.url.includes('/login/')),
    ).toHaveLength(2);
  });

  it('reports a server error as MachineClientError', async () => {
    const fetchStub = vi.fn(async () =>
      Response.json({ error: 'authentication_failed', message: 'nope' }, { status: 401 }),
    );
    const client = new MachineClient({ payload: payloadFor(), keyStore, fetch: fetchStub });
    await expect(client.fetch('/api/reports')).rejects.toBeInstanceOf(MachineClientError);
    await expect(client.fetch('/api/reports')).rejects.toMatchObject({
      code: 'authentication_failed',
      status: 401,
    });
  });

  it('builds a proof whose htu drops the query string', async () => {
    const proof = await createDpopProof({
      keyStore,
      method: 'get',
      url: `${ORIGIN}/api/reports?since=yesterday#top`,
      accessToken: 'token',
    });
    const claims = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(proof.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')), (c) =>
          c.charCodeAt(0),
        ),
      ),
    ) as { htu: string; htm: string };
    expect(claims.htu).toBe(`${ORIGIN}/api/reports`);
    expect(claims.htm).toBe('GET');
  });
});
