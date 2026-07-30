import type { LocalWebAuthnOptions } from './types.js';

import { LocalWebAuthnError } from './errors.js';

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

  return {
    rpName,
    rpId,
    expectedOrigins,
    publicOrigin,
    enrollmentPath,
    durations,
  };
}
