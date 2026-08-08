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
  generateKeyStore,
  MachineClient,
  MachineClientError,
  type MachineKeyStore,
} from '../../packages/client/src/index.js';

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
 */
function stubServer(options: { apiStatus?: (call: number) => number; nonce?: string } = {}) {
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
    if (status === 401 && options.nonce) {
      headers.set('DPoP-Nonce', options.nonce);
    }
    return new Response(JSON.stringify({ ok: status === 200, apiCalls }), { status, headers });
  });

  return { fetchStub, calls, sessionCount: () => sessions };
}

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
