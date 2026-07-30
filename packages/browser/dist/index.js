// src/index.ts
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
var LocalWebAuthnBrowserError = class extends Error {
  code;
  status;
  constructor(code, message, status) {
    super(message);
    this.name = "LocalWebAuthnBrowserError";
    this.code = code;
    this.status = status;
  }
};
var defaultEndpoints = {
  exchangeEnrollment: "/enrollment/exchange",
  registrationOptions: "/register/options",
  registrationVerify: "/register/verify",
  authenticationOptions: "/login/options",
  authenticationVerify: "/login/verify",
  logout: "/logout"
};
function endpoint(basePath, configuredPath) {
  return `${basePath.replace(/\/+$/u, "")}/${configuredPath.replace(/^\/+/u, "")}`;
}
var LocalWebAuthnBrowser = class {
  #fetch;
  #ceremonies;
  #endpoints;
  constructor(options = {}) {
    const basePath = options.basePath ?? "/api/auth";
    const configuredEndpoints = { ...defaultEndpoints, ...options.endpoints };
    this.#endpoints = Object.fromEntries(
      Object.entries(configuredEndpoints).map(([name, path]) => [name, endpoint(basePath, path)])
    );
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#ceremonies = options.ceremonies ?? { startRegistration, startAuthentication };
  }
  exchangeEnrollment(token) {
    return this.#post(this.#endpoints.exchangeEnrollment, { token });
  }
  async registerPasskey(label) {
    const options = await this.#post(
      this.#endpoints.registrationOptions
    );
    const response = await this.#ceremonies.startRegistration({ optionsJSON: options });
    return this.#post(this.#endpoints.registrationVerify, {
      ...response,
      ...label ? { localWebAuthnLabel: label } : {}
    });
  }
  async signIn() {
    const options = await this.#post(
      this.#endpoints.authenticationOptions
    );
    const response = await this.#ceremonies.startAuthentication({ optionsJSON: options });
    return this.#post(this.#endpoints.authenticationVerify, response);
  }
  signOut() {
    return this.#post(this.#endpoints.logout);
  }
  async #post(url, body) {
    let response;
    try {
      response = await this.#fetch(url, {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        headers: body === void 0 ? void 0 : { "Content-Type": "application/json" },
        body: body === void 0 ? void 0 : JSON.stringify(body)
      });
    } catch {
      throw new LocalWebAuthnBrowserError(
        "network_error",
        "The authentication service could not be reached.",
        0
      );
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new LocalWebAuthnBrowserError(
        "invalid_response",
        "The authentication service returned an invalid response.",
        response.status
      );
    }
    if (!response.ok) {
      const error = payload;
      throw new LocalWebAuthnBrowserError(
        error.error ?? "authentication_failed",
        error.message ?? "Authentication failed.",
        response.status
      );
    }
    return payload;
  }
};
function consumeEnrollmentToken(location, history, expectedPath = "/enroll") {
  const normalizedExpectedPath = expectedPath.endsWith("/") ? expectedPath.slice(0, -1) : expectedPath;
  const normalizedPath = location.pathname.endsWith("/") ? location.pathname.slice(0, -1) : location.pathname;
  if (normalizedPath !== normalizedExpectedPath) {
    return null;
  }
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (token && history) {
    history.replaceState(null, "", location.pathname);
  }
  return token;
}
export {
  LocalWebAuthnBrowser,
  LocalWebAuthnBrowserError,
  consumeEnrollmentToken
};
