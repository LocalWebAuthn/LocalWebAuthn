import type { LocalWebAuthnOptions } from './types.js';

import { LocalWebAuthnError } from './errors.js';

export type NormalizedCredentialKind = {
  interactive: boolean;
  canRegister: boolean;
  sessionAbsoluteMs: number;
};

export type NormalizedConfig = {
  rpName: string;
  rpId: string;
  expectedOrigins: string[];
  publicOrigin: string;
  enrollmentPath: string;
  durations: {
    enrollmentGrantMs: number;
    enrollmentSessionMs: number;
    challengeMs: number;
    sessionIdleMs: number;
    sessionAbsoluteMs: number;
  };
  /** Declared kinds only; an undeclared kind falls back to {@link defaultKindPolicy}. */
  credentialKinds: Record<string, NormalizedCredentialKind>;
  /** `null` when nonce issuance was not configured. */
  dpopNonce: { rotationMs: number } | null;
};

const DEFAULTS = {
  enrollmentGrantMs: 30 * 60_000,
  enrollmentSessionMs: 10 * 60_000,
  challengeMs: 5 * 60_000,
  sessionIdleMs: 30 * 60_000,
  sessionAbsoluteMs: 8 * 60 * 60_000,
};

function configurationError(message: string): never {
  throw new LocalWebAuthnError('invalid_configuration', message, 500);
}

export function normalizeConfig(options: LocalWebAuthnOptions): NormalizedConfig {
  const rpName = options.rpName.trim();
  const rpId = options.rpId.trim().toLowerCase();
  const configuredOrigins =
    typeof options.expectedOrigins === 'string'
      ? [options.expectedOrigins]
      : options.expectedOrigins;

  if (!rpName || !rpId || configuredOrigins.length === 0) {
    configurationError('rpName, rpId, and at least one expected origin are required.');
  }

  // rpId must be a valid bare hostname (no protocol, port, path, or query).
  try {
    const url = new URL(`https://${rpId}`);
    if (url.hostname !== rpId) {
      configurationError('rpId must be a bare hostname (no protocol, port, or path).');
    }
  } catch {
    configurationError('rpId must be a valid hostname.');
  }

  const expectedOrigins = configuredOrigins.map((configuredOrigin) => {
    const url = new URL(configuredOrigin);
    const origin = url.origin;
    const isLocalHttp =
      url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');

    if (configuredOrigin !== origin || (url.protocol !== 'https:' && !isLocalHttp)) {
      configurationError('Expected origins must be exact HTTPS origins or local HTTP origins.');
    }
    if (url.hostname !== rpId && !url.hostname.endsWith(`.${rpId}`)) {
      configurationError('Every expected origin hostname must equal or be beneath the RP ID.');
    }
    return origin;
  });

  const publicOrigin = options.publicOrigin ?? expectedOrigins[0];
  if (
    !expectedOrigins.includes(new URL(publicOrigin).origin) ||
    publicOrigin !== new URL(publicOrigin).origin
  ) {
    configurationError('publicOrigin must exactly match one of the expected origins.');
  }

  const enrollmentPath = options.enrollmentPath ?? '/enroll';
  if (
    !enrollmentPath.startsWith('/') ||
    enrollmentPath.includes('#') ||
    enrollmentPath.includes('?')
  ) {
    configurationError('enrollmentPath must be an absolute URL path without a query or fragment.');
  }

  const durations = { ...DEFAULTS, ...options.durations };
  for (const [name, duration] of Object.entries(durations)) {
    if (!Number.isSafeInteger(duration) || duration <= 0) {
      configurationError(`${name} must be a positive integer number of milliseconds.`);
    }
  }
  if (durations.sessionIdleMs > durations.sessionAbsoluteMs) {
    configurationError('sessionIdleMs cannot exceed sessionAbsoluteMs.');
  }

  const credentialKinds: Record<string, NormalizedCredentialKind> = {};
  for (const [kind, policy] of Object.entries(options.credentialKinds ?? {})) {
    if (!kind.trim()) {
      configurationError('A credential kind cannot be an empty string.');
    }
    // Only the absolute lifetime is per-kind. The global idle window applies to
    // every kind and may legitimately exceed a kind's shortened absolute
    // lifetime: absolute expiry is stamped on the session row at creation and
    // wins, so the excess is simply unreachable rather than a misconfiguration.
    const sessionAbsoluteMs = policy.sessionAbsoluteMs ?? durations.sessionAbsoluteMs;
    if (!Number.isSafeInteger(sessionAbsoluteMs) || sessionAbsoluteMs <= 0) {
      configurationError(
        `credentialKinds.${kind}.sessionAbsoluteMs must be a positive integer number of milliseconds.`,
      );
    }
    credentialKinds[kind] = {
      interactive: policy.interactive ?? true,
      canRegister: policy.canRegister ?? true,
      sessionAbsoluteMs,
    };
  }

  let dpopNonce: { rotationMs: number } | null = null;
  if (options.dpopNonce) {
    const rotationMs = options.dpopNonce.rotationMs ?? 5 * 60_000;
    if (!Number.isSafeInteger(rotationMs) || rotationMs <= 0) {
      configurationError('dpopNonce.rotationMs must be a positive integer number of milliseconds.');
    }
    dpopNonce = { rotationMs };
  }

  return {
    rpName,
    rpId,
    expectedOrigins,
    publicOrigin,
    enrollmentPath,
    durations,
    credentialKinds,
    dpopNonce,
  };
}

/**
 * Policy for a kind the host never declared, including `null`.
 *
 * Permissive on purpose: an undeclared kind must behave exactly as it did before
 * `credentialKinds` existed, or adding the option would silently change
 * behaviour for every deployment that ignores it.
 */
export function defaultKindPolicy(config: NormalizedConfig): NormalizedCredentialKind {
  return {
    interactive: true,
    canRegister: true,
    sessionAbsoluteMs: config.durations.sessionAbsoluteMs,
  };
}

/** Effective policy for `kind`, falling back to {@link defaultKindPolicy}. */
export function kindPolicy(
  config: NormalizedConfig,
  kind: string | null,
): NormalizedCredentialKind {
  return (kind === null ? undefined : config.credentialKinds[kind]) ?? defaultKindPolicy(config);
}
