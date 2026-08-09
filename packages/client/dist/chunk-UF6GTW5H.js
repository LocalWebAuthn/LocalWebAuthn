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

export {
  CREDENTIAL_PAYLOAD_VERSION,
  CREDENTIAL_VARIABLE,
  CREDENTIAL_KEY_VARIABLE,
  isKeystoreReference,
  formatCredentialFile,
  parseCredentialFile,
  parseCredentialPayload,
  utf8,
  concat,
  encodeBase64,
  decodeBase64,
  encodeBase64Url,
  decodeBase64Url,
  sha256,
  randomBytes,
  encodeCborMap,
  rawSignatureToDer,
  ES256,
  EDDSA,
  generateKeyStore,
  importKeyStore
};
