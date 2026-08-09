// src/bytes.ts
function utf8(value) {
  return new TextEncoder().encode(value);
}
function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function toBinary(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}
function encodeBase64(bytes) {
  return btoa(toBinary(bytes));
}
function decodeBase64(value) {
  const binary = atob(value.replaceAll(/\s+/gu, ""));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function encodeBase64Url(bytes) {
  return encodeBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  return decodeBase64(normalized + "=".repeat((4 - normalized.length % 4) % 4));
}
function owned(bytes) {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}
async function sha256(value) {
  const bytes = typeof value === "string" ? utf8(value) : value;
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", owned(bytes)));
}
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

// src/cbor.ts
var MAJOR_UNSIGNED = 0;
var MAJOR_NEGATIVE = 1;
var MAJOR_BYTES = 2;
var MAJOR_TEXT = 3;
var MAJOR_MAP = 5;
function head(major, value) {
  if (value < 24) {
    return Uint8Array.of(major << 5 | value);
  }
  if (value < 256) {
    return Uint8Array.of(major << 5 | 24, value);
  }
  if (value < 65536) {
    return Uint8Array.of(major << 5 | 25, value >> 8, value & 255);
  }
  if (value <= 4294967295) {
    return Uint8Array.of(
      major << 5 | 26,
      value >>> 24 & 255,
      value >>> 16 & 255,
      value >>> 8 & 255,
      value & 255
    );
  }
  throw new RangeError("CBOR value too large for this encoder.");
}
function integer(value) {
  if (!Number.isInteger(value)) {
    throw new TypeError("CBOR integers must be integers.");
  }
  return value < 0 ? head(MAJOR_NEGATIVE, -value - 1) : head(MAJOR_UNSIGNED, value);
}
function byteString(value) {
  return concat(head(MAJOR_BYTES, value.length), value);
}
function textString(value) {
  const bytes = utf8(value);
  return concat(head(MAJOR_TEXT, bytes.length), bytes);
}
function encodeValue(value) {
  if (typeof value === "number") {
    return integer(value);
  }
  if (typeof value === "string") {
    return textString(value);
  }
  if (value instanceof Uint8Array) {
    return byteString(value);
  }
  return encodeCborMap(value);
}
function encodeCborMap(entries) {
  const parts = [head(MAJOR_MAP, entries.size)];
  for (const [key, value] of entries) {
    parts.push(typeof key === "number" ? integer(key) : textString(key));
    parts.push(encodeValue(value));
  }
  return concat(...parts);
}

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

// src/credential-file.ts
var CREDENTIAL_PAYLOAD_VERSION = 1;
var CREDENTIAL_VARIABLE = "LWA_CREDENTIAL";
var CREDENTIAL_KEY_VARIABLE = "LWA_CREDENTIAL_KEY";
function isKeystoreReference(value) {
  return value.startsWith("keystore:");
}
function formatCredentialFile(payload, key, comment) {
  const json = JSON.stringify(payload);
  if (json.includes("'")) {
    throw new Error("Credential payload fields must not contain an apostrophe.");
  }
  const lines = comment ? [`# ${comment.replaceAll(/[\r\n]+/gu, " ")}`] : [];
  lines.push(`${CREDENTIAL_VARIABLE}='${json}'`, `${CREDENTIAL_KEY_VARIABLE}=${key}`);
  return `${lines.join("\n")}
`;
}
function unquote(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'") || trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}
function parseCredentialFile(text) {
  let payload;
  let key;
  for (const line of text.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const separator = trimmed.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const name = trimmed.slice(0, separator).trim().replace(/^export\s+/u, "");
    const value = unquote(trimmed.slice(separator + 1));
    if (name === CREDENTIAL_VARIABLE) {
      payload = value;
    } else if (name === CREDENTIAL_KEY_VARIABLE) {
      key = value;
    }
  }
  return payload !== void 0 && key !== void 0 ? { payload, key } : null;
}
function parseCredentialPayload(json) {
  const parsed = JSON.parse(json);
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("LWA_CREDENTIAL is not a JSON object.");
  }
  const candidate = parsed;
  if (candidate.v !== CREDENTIAL_PAYLOAD_VERSION) {
    throw new Error(
      `Unsupported LWA_CREDENTIAL version ${String(candidate.v)}; this client understands ${String(
        CREDENTIAL_PAYLOAD_VERSION
      )}.`
    );
  }
  for (const field of ["baseUrl", "rpId", "origin", "credentialId", "userHandle"]) {
    if (typeof candidate[field] !== "string" || !candidate[field]) {
      throw new Error(`LWA_CREDENTIAL is missing ${field}.`);
    }
  }
  if (candidate.alg !== -7 && candidate.alg !== -8) {
    throw new Error(`Unsupported LWA_CREDENTIAL alg ${String(candidate.alg)}.`);
  }
  return candidate;
}

// src/ecdsa.ts
function derInteger(value) {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start += 1;
  }
  const trimmed = value.subarray(start);
  const body = (trimmed[0] & 128) === 0 ? trimmed : concat(Uint8Array.of(0), trimmed);
  return concat(Uint8Array.of(2, body.length), body);
}
function rawSignatureToDer(raw) {
  if (raw.length !== 64) {
    throw new TypeError(`Expected a 64-byte P-256 signature, received ${String(raw.length)}.`);
  }
  const body = concat(derInteger(raw.subarray(0, 32)), derInteger(raw.subarray(32, 64)));
  return concat(Uint8Array.of(48, body.length), body);
}

// src/keystore.ts
var ES256 = -7;
var EDDSA = -8;
function importParameters(algorithm) {
  return algorithm === ES256 ? { name: "ECDSA", namedCurve: "P-256" } : { name: "Ed25519" };
}
function signParameters(algorithm) {
  return algorithm === ES256 ? { name: "ECDSA", hash: "SHA-256" } : { name: "Ed25519" };
}
function publicMembers(jwk) {
  return jwk.kty === "EC" ? { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y } : { kty: "OKP", crv: jwk.crv, x: jwk.x };
}
function coseFromJwk(jwk, algorithm) {
  const entries = /* @__PURE__ */ new Map();
  if (algorithm === ES256) {
    if (!jwk.x || !jwk.y) {
      throw new TypeError("An EC public JWK must have x and y.");
    }
    entries.set(1, 2);
    entries.set(3, -7);
    entries.set(-1, 1);
    entries.set(-2, decodeBase64Url(jwk.x));
    entries.set(-3, decodeBase64Url(jwk.y));
    return entries;
  }
  if (!jwk.x) {
    throw new TypeError("An OKP public JWK must have x.");
  }
  entries.set(1, 1);
  entries.set(3, -8);
  entries.set(-1, 6);
  entries.set(-2, decodeBase64Url(jwk.x));
  return entries;
}
var WebCryptoKeyStore = class {
  algorithm;
  #privateKey;
  #publicJwk;
  constructor(algorithm, privateKey, publicJwk) {
    this.algorithm = algorithm;
    this.#privateKey = privateKey;
    this.#publicJwk = publicMembers(publicJwk);
  }
  async publicKeyCose() {
    return encodeCborMap(coseFromJwk(this.#publicJwk, this.algorithm));
  }
  async publicJwk() {
    return { ...this.#publicJwk };
  }
  async signJws(data) {
    const signature = await globalThis.crypto.subtle.sign(
      signParameters(this.algorithm),
      this.#privateKey,
      owned(data)
    );
    return new Uint8Array(signature);
  }
  async signWebAuthn(data) {
    const raw = await this.signJws(data);
    return this.algorithm === ES256 ? rawSignatureToDer(raw) : raw;
  }
};
async function generateKeyStore(algorithm = ES256, extractable = true) {
  const pair = await globalThis.crypto.subtle.generateKey(
    importParameters(algorithm),
    extractable,
    ["sign", "verify"]
  );
  const publicJwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    keyStore: new WebCryptoKeyStore(algorithm, pair.privateKey, publicJwk),
    exportPrivateKey: async () => {
      const pkcs8 = await globalThis.crypto.subtle.exportKey("pkcs8", pair.privateKey);
      return encodeBase64(new Uint8Array(pkcs8));
    }
  };
}
async function importKeyStore(privateKeyBase64, algorithm = ES256) {
  const pkcs8 = decodeBase64(privateKeyBase64);
  const parameters = importParameters(algorithm);
  const readable = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    owned(pkcs8),
    parameters,
    true,
    ["sign"]
  );
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", readable);
  const signingKey = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    owned(pkcs8),
    parameters,
    false,
    ["sign"]
  );
  return new WebCryptoKeyStore(algorithm, signingKey, jwk);
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
  CREDENTIAL_KEY_VARIABLE,
  CREDENTIAL_PAYLOAD_VERSION,
  CREDENTIAL_VARIABLE,
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
  formatCredentialFile,
  generateKeyStore,
  importKeyStore,
  isKeystoreReference,
  parseCredentialFile,
  parseCredentialPayload,
  randomBytes,
  rawSignatureToDer,
  sha256,
  utf8
};
