import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';

import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

export type LocalWebAuthnBrowserEndpoints = {
  exchangeEnrollment: string;
  registrationOptions: string;
  registrationVerify: string;
  authenticationOptions: string;
  authenticationVerify: string;
  logout: string;
};

export type EnrollmentIdentity = {
  id?: string;
  name: string;
  displayName?: string;
  email?: string;
};

export type LocalWebAuthnBrowserOptions = {
  basePath?: string;
  endpoints?: Partial<LocalWebAuthnBrowserEndpoints>;
  fetch?: typeof globalThis.fetch;
  ceremonies?: {
    startRegistration: typeof startRegistration;
    startAuthentication: typeof startAuthentication;
  };
};

export class LocalWebAuthnBrowserError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'LocalWebAuthnBrowserError';
    this.code = code;
    this.status = status;
  }
}

type ErrorBody = {
  error?: string;
  message?: string;
};

const defaultEndpoints: LocalWebAuthnBrowserEndpoints = {
  exchangeEnrollment: '/enrollment/exchange',
  registrationOptions: '/register/options',
  registrationVerify: '/register/verify',
  authenticationOptions: '/login/options',
  authenticationVerify: '/login/verify',
  logout: '/logout',
};

function endpoint(basePath: string, configuredPath: string): string {
  return `${basePath.replace(/\/+$/u, '')}/${configuredPath.replace(/^\/+/u, '')}`;
}

export class LocalWebAuthnBrowser {
  readonly #fetch;
  readonly #ceremonies;
  readonly #endpoints;

  constructor(options: LocalWebAuthnBrowserOptions = {}) {
    const basePath = options.basePath ?? '/api/auth';
    const configuredEndpoints = { ...defaultEndpoints, ...options.endpoints };
    this.#endpoints = Object.fromEntries(
      Object.entries(configuredEndpoints).map(([name, path]) => [name, endpoint(basePath, path)]),
    ) as LocalWebAuthnBrowserEndpoints;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#ceremonies = options.ceremonies ?? { startRegistration, startAuthentication };
  }

  exchangeEnrollment(token: string): Promise<EnrollmentIdentity> {
    return this.#post<EnrollmentIdentity>(this.#endpoints.exchangeEnrollment, { token });
  }

  async registerPasskey(label?: string): Promise<{ verified: true }> {
    const options = await this.#post<PublicKeyCredentialCreationOptionsJSON>(
      this.#endpoints.registrationOptions,
    );
    const response = await this.#ceremonies.startRegistration({ optionsJSON: options });
    return this.#post<{ verified: true }>(this.#endpoints.registrationVerify, {
      ...response,
      ...(label ? { localWebAuthnLabel: label } : {}),
    });
  }

  async signIn(): Promise<{ verified: true }> {
    const options = await this.#post<PublicKeyCredentialRequestOptionsJSON>(
      this.#endpoints.authenticationOptions,
    );
    const response = await this.#ceremonies.startAuthentication({ optionsJSON: options });
    return this.#post<{ verified: true }>(this.#endpoints.authenticationVerify, response);
  }

  signOut(): Promise<{ signed_out: true }> {
    return this.#post<{ signed_out: true }>(this.#endpoints.logout);
  }

  async #post<Result>(url: string, body?: unknown): Promise<Result> {
    let response: Response;
    try {
      response = await this.#fetch(url, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        redirect: 'error',
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new LocalWebAuthnBrowserError(
        'network_error',
        'The authentication service could not be reached.',
        0,
      );
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new LocalWebAuthnBrowserError(
        'invalid_response',
        'The authentication service returned an invalid response.',
        response.status,
      );
    }
    if (!response.ok) {
      const error = payload as ErrorBody;
      throw new LocalWebAuthnBrowserError(
        error.error ?? 'authentication_failed',
        error.message ?? 'Authentication failed.',
        response.status,
      );
    }
    return payload as Result;
  }
}

export function consumeEnrollmentToken(
  location: Pick<Location, 'pathname' | 'hash'>,
  history?: Pick<History, 'replaceState'>,
  expectedPath = '/enroll',
): string | null {
  const normalizedExpectedPath = expectedPath.endsWith('/')
    ? expectedPath.slice(0, -1)
    : expectedPath;
  const normalizedPath = location.pathname.endsWith('/')
    ? location.pathname.slice(0, -1)
    : location.pathname;
  if (normalizedPath !== normalizedExpectedPath) {
    return null;
  }

  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token && history) {
    history.replaceState(null, '', location.pathname);
  }
  return token;
}

export type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
};
