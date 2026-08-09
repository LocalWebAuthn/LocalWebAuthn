import {
  CREDENTIAL_PAYLOAD_VERSION,
  EDDSA,
  ES256,
  concat,
  decodeBase64,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  encodeCborMap,
  parseCredentialPayload,
  randomBytes,
  rawSignatureToDer,
  sha256,
  utf8
} from "./chunk-UF6GTW5H.js";

// src/authenticator.ts
var FLAG_UP = 1;
var FLAG_UV = 4;
var FLAG_AT = 64;
var AAGUID = new Uint8Array(16);
function clientDataJSON(type, challenge, origin) {
  return utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}
async function authenticatorData(rpId, flags, attestedCredentialData) {
  const header = new Uint8Array(37);
  header.set(await sha256(rpId), 0);
  header[32] = flags;
  return attestedCredentialData ? concat(header, attestedCredentialData) : header;
}
async function createRegistrationResponse(input) {
  const credentialId = input.credentialId ?? randomBytes(32);
  const publicKeyCose = await input.keyStore.publicKeyCose();
  const credentialIdLength = new Uint8Array(2);
  new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length, false);
  const attestedCredentialData = concat(AAGUID, credentialIdLength, credentialId, publicKeyCose);
  const authData = await authenticatorData(
    input.rpId,
    FLAG_UP | FLAG_UV | FLAG_AT,
    attestedCredentialData
  );
  const attestationObject = encodeCborMap(
    /* @__PURE__ */ new Map([
      ["fmt", "none"],
      ["attStmt", /* @__PURE__ */ new Map()],
      ["authData", authData]
    ])
  );
  return {
    credentialId,
    response: {
      id: encodeBase64Url(credentialId),
      rawId: encodeBase64Url(credentialId),
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: encodeBase64Url(
          clientDataJSON("webauthn.create", input.challenge, input.origin)
        ),
        attestationObject: encodeBase64Url(attestationObject),
        transports: []
      }
    }
  };
}
async function createAssertionResponse(input) {
  const clientData = clientDataJSON("webauthn.get", input.challenge, input.credential.origin);
  const authData = await authenticatorData(input.credential.rpId, FLAG_UP | FLAG_UV);
  const signature = await input.keyStore.signWebAuthn(concat(authData, await sha256(clientData)));
  return {
    id: encodeBase64Url(input.credential.credentialId),
    rawId: encodeBase64Url(input.credential.credentialId),
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: encodeBase64Url(clientData),
      authenticatorData: encodeBase64Url(authData),
      signature: encodeBase64Url(signature),
      // Required: this project's server compares it against the stored user
      // handle, so a discoverable-credential assertion without it is refused.
      userHandle: encodeBase64Url(input.credential.userHandle)
    }
  };
}

// src/dpop.ts
function jwsAlgorithm(algorithm) {
  return algorithm === ES256 ? "ES256" : "EdDSA";
}
function targetUri(url) {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}
async function createDpopProof(input) {
  const header = {
    typ: "dpop+jwt",
    alg: jwsAlgorithm(input.keyStore.algorithm),
    jwk: await input.keyStore.publicJwk()
  };
  const payload = {
    jti: encodeBase64Url(randomBytes(16)),
    htm: input.method.toUpperCase(),
    htu: targetUri(input.url),
    iat: Math.floor((input.now?.() ?? Date.now()) / 1e3),
    ath: encodeBase64Url(await sha256(input.accessToken))
  };
  if (input.nonce !== void 0) {
    payload.nonce = input.nonce;
  }
  const signingInput = `${encodeBase64Url(utf8(JSON.stringify(header)))}.${encodeBase64Url(
    utf8(JSON.stringify(payload))
  )}`;
  const signature = await input.keyStore.signJws(utf8(signingInput));
  return `${signingInput}.${encodeBase64Url(signature)}`;
}

// src/machine-client.ts
var MachineClientError = class extends Error {
  code;
  status;
  constructor(code, message, status) {
    super(message);
    this.name = "MachineClientError";
    this.code = code;
    this.status = status;
  }
};
function dpopRejection(response) {
  const challenges = response.headers.get("WWW-Authenticate") ?? "";
  if (!/(?:^|[\s,])DPoP\b/iu.test(challenges)) {
    return null;
  }
  if (/error\s*=\s*"?use_dpop_nonce"?/iu.test(challenges)) {
    return response.headers.get("DPoP-Nonce") ? "nonce" : null;
  }
  return "session";
}
var DEFAULT_ENDPOINTS = {
  options: "/api/machine/v1/login/options",
  verify: "/api/machine/v1/login/verify"
};
var MachineClient = class {
  #payload;
  #keyStore;
  #endpoints;
  #fetch;
  #dpop;
  #now;
  #credential;
  #session = null;
  /** Latest `DPoP-Nonce`; the server may demand one at any point. */
  #nonce;
  constructor(options) {
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
      origin: options.payload.origin
    };
  }
  /** Absolute URL for a path against the configured base. */
  url(path) {
    return new URL(path, this.#payload.baseUrl).toString();
  }
  /**
   * Run the ceremony and hold the resulting session.
   *
   * Called automatically by {@link fetch}; exposed so a long-running process can
   * warm up, or re-authenticate deliberately for a step-up operation.
   */
  async authenticate() {
    const optionsResponse = await this.#fetch(this.url(this.#endpoints.options), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    });
    const optionsBody = await this.#json(optionsResponse);
    if (!optionsBody.options?.challenge || !optionsBody.challengeToken) {
      throw new MachineClientError(
        "invalid_response",
        "The server did not return a challenge.",
        optionsResponse.status
      );
    }
    const assertion = await createAssertionResponse({
      keyStore: this.#keyStore,
      credential: this.#credential,
      challenge: optionsBody.options.challenge
    });
    const verifyResponse = await this.#fetch(this.url(this.#endpoints.verify), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        response: assertion,
        challengeToken: optionsBody.challengeToken
      })
    });
    const verifyBody = await this.#json(verifyResponse);
    if (!verifyBody.sessionToken) {
      throw new MachineClientError(
        "authentication_failed",
        "The server did not return a session token.",
        verifyResponse.status
      );
    }
    this.#captureNonce(verifyResponse);
    this.#session = {
      token: verifyBody.sessionToken,
      expiresAt: verifyBody.expiresAt ?? this.#now() + 6e4
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
  async fetch(path, init = {}) {
    const { bodyFactory, ...request } = init;
    const first = await this.#send(path, request);
    if (first.status !== 401) {
      return first;
    }
    this.#captureNonce(first);
    const rejection = dpopRejection(first);
    if (!rejection) {
      return first;
    }
    if (rejection === "session") {
      this.#session = null;
    }
    const retry = this.#retryBody(request, bodyFactory);
    if (retry === null) {
      throw new MachineClientError(
        "body_not_replayable",
        "The server asked for a retry, but this request body cannot be resent. Pass bodyFactory to rebuild it.",
        first.status
      );
    }
    return this.#send(path, retry);
  }
  /** `init` for a retry, or `null` when the body cannot be produced again. */
  #retryBody(init, bodyFactory) {
    if (bodyFactory) {
      return { ...init, body: bodyFactory() };
    }
    const body = init.body;
    if (body === void 0 || body === null || typeof body === "string") {
      return init;
    }
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body) || body instanceof URLSearchParams || typeof Blob !== "undefined" && body instanceof Blob || typeof FormData !== "undefined" && body instanceof FormData) {
      return init;
    }
    return null;
  }
  async #send(path, init) {
    const session = await this.#liveSession();
    const url = this.url(path);
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    if (this.#dpop) {
      headers.set("Authorization", `DPoP ${session.token}`);
      headers.set(
        "DPoP",
        await createDpopProof({
          keyStore: this.#keyStore,
          method,
          url,
          accessToken: session.token,
          nonce: this.#nonce,
          now: this.#now
        })
      );
    } else {
      headers.set("Authorization", `Bearer ${session.token}`);
    }
    const response = await this.#fetch(url, { ...init, method, headers });
    this.#captureNonce(response);
    return response;
  }
  async #liveSession() {
    if (this.#session && this.#session.expiresAt - 5e3 > this.#now()) {
      return this.#session;
    }
    return this.authenticate();
  }
  #captureNonce(response) {
    const nonce = response.headers.get("DPoP-Nonce");
    if (nonce) {
      this.#nonce = nonce;
    }
  }
  async #json(response) {
    let body;
    try {
      body = await response.json();
    } catch {
      throw new MachineClientError(
        "invalid_response",
        "The server returned a non-JSON response.",
        response.status
      );
    }
    if (!response.ok) {
      const error = body;
      throw new MachineClientError(
        error.error ?? "request_failed",
        error.message ?? "The request failed.",
        response.status
      );
    }
    return body;
  }
};
export {
  CREDENTIAL_PAYLOAD_VERSION,
  EDDSA,
  ES256,
  MachineClient,
  MachineClientError,
  concat,
  createAssertionResponse,
  createDpopProof,
  createRegistrationResponse,
  decodeBase64,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  parseCredentialPayload,
  randomBytes,
  rawSignatureToDer,
  sha256,
  utf8
};
