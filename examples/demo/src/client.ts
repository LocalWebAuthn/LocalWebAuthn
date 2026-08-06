import { consumeEnrollmentToken, LocalWebAuthnBrowser } from '@localwebauthn/browser';
import { parseSignupFragment } from '@localwebauthn/channels-core';
import {
  Check,
  CirclePlus,
  Copy,
  createIcons,
  KeyRound,
  Link,
  LockKeyhole,
  LogOut,
  MonitorOff,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UserPlus,
  X,
} from 'lucide';

type DemoClient = {
  id: string;
  email: string;
  displayName: string;
  role: 'administrator' | 'client';
  active: boolean;
  createdAt: number;
  passkeyCount: number;
};

type Passkey = {
  id: string;
  label: string;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  createdAt: number;
  lastUsedAt: number | null;
};

type Session = {
  client: DemoClient;
  passkeys: Passkey[];
};

type EnrollmentIdentity = {
  name: string;
  displayName?: string;
};

type IssuedEnrollment = {
  clientName: string;
  url: string;
  expiresAt: number;
  kind: 'new' | 'recovery';
};

const auth = new LocalWebAuthnBrowser();
const root = document.querySelector<HTMLDivElement>('#app');
if (!root) {
  throw new Error('Application root is unavailable.');
}
const applicationRoot = root;

type SimulatedMessage = {
  channel: 'email' | 'phone';
  to: string;
  subject?: string;
  body: string;
};

type SignupInbox = {
  signupId: string;
  recovery: boolean;
  expiresAt: number;
  messages: SimulatedMessage[];
};

type SignupProof = {
  signupId: string;
  channel: 'email' | 'phone';
  otp: string;
  /** From the link's display-only intent flag; the server enforces reality. */
  recovery: boolean;
  status: 'ready' | 'waiting' | 'pending' | 'claimable' | 'canceled';
  missing?: string[];
  claimableAt?: number;
  enrollmentToken?: string;
  user?: { name: string; displayName: string };
};

type ProveResult = {
  complete: boolean;
  canceled?: boolean;
  pending?: boolean;
  claimableAt?: number;
  kind?: 'signup' | 'recovery';
  enrollmentToken?: string;
  user?: { name: string; displayName: string };
  proved?: string[];
  missing?: string[];
};

const state: {
  session?: Session;
  clients: DemoClient[];
  enrollment?: EnrollmentIdentity;
  issued?: IssuedEnrollment;
  signup?: SignupInbox;
  proof?: SignupProof;
  checking: boolean;
  busy: boolean;
  error: string;
  notice: string;
} = {
  clients: [],
  checking: true,
  busy: false,
  error: '',
  notice: '',
};

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function formatDate(value: number | null): string {
  if (!value) {
    return 'Never';
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(value);
}

async function request<Result>(path: string, init?: RequestInit): Promise<Result> {
  const headers = new Headers(init?.headers);
  if (init?.body) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(path, {
    cache: 'no-store',
    credentials: 'same-origin',
    ...init,
    headers,
  });
  const body = (await response.json()) as Result & { message?: string };
  if (!response.ok) {
    throw new Error(body.message ?? 'The request failed.');
  }
  return body;
}

function iconMarkup(name: string, size = 18): string {
  return `<i aria-hidden="true" data-lucide="${name}" width="${String(size)}" height="${String(size)}"></i>`;
}

function alerts(): string {
  return `
    ${state.error ? `<div class="alert error" role="alert">${escapeHtml(state.error)}</div>` : ''}
    ${state.notice ? `<div class="alert success" role="status">${iconMarkup('check', 17)}${escapeHtml(state.notice)}</div>` : ''}
  `;
}

function authScreen(): string {
  const enrolling = state.enrollment !== undefined;
  const displayName = state.enrollment?.displayName ?? state.enrollment?.name ?? '';
  return `
    <div class="auth-shell">
      <header class="auth-brand">
        <div class="brand-symbol">${iconMarkup('key-round', 26)}</div>
        <div>
          <strong>LocalWebAuthn</strong>
          <span>Passkey lifecycle demo</span>
        </div>
      </header>
      <main class="auth-main">
        <section class="auth-panel" aria-labelledby="auth-title">
          <div class="auth-icon">${iconMarkup(enrolling ? 'shield-check' : 'lock-keyhole', 28)}</div>
          <h1 id="auth-title">${enrolling ? 'Create your passkey' : 'Sign in with a passkey'}</h1>
          ${
            enrolling
              ? `<p class="auth-lede">No password. Your device will create a passkey bound to this site; only the public key is stored here.</p>
                   <div class="enrollment-client">
                   <strong>${escapeHtml(displayName)}</strong>
                   <span>${escapeHtml(state.enrollment?.name ?? '')}</span>
                 </div>`
              : `<p class="auth-lede">This demo has no passwords and no third-party login. Sign-in uses a passkey you already registered for this site.</p>
                 <p class="auth-hint">First visit? Open the <strong>enrollment URL</strong> printed by <code>make demo</code> (or issued by an administrator). This page alone cannot create a first passkey.</p>`
          }
          <button class="button primary auth-button" id="${enrolling ? 'enroll' : 'sign-in'}" type="button" ${state.busy ? 'disabled' : ''}>
            ${iconMarkup('key-round')}
            ${state.busy ? 'Waiting for passkey' : enrolling ? 'Create passkey' : 'Continue with passkey'}
          </button>
          ${alerts()}
        </section>
        ${enrolling ? '' : signupSection()}
      </main>
    </div>
  `;
}

/** Wrap the one URL in a simulated message body in a clickable new-tab link. */
function linkifySimulated(body: string): string {
  const match = /https?:\/\/\S+/u.exec(body);
  if (!match) {
    return escapeHtml(body);
  }
  const url = match[0];
  const before = body.slice(0, match.index);
  const after = body.slice(match.index + url.length);
  return `${escapeHtml(before)}<a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a>${escapeHtml(after)}`;
}

/**
 * Self-serve signup with simulated delivery: the "inbox" below stands in for
 * the person's real email and SMS. Each link opens a proof page (new tab);
 * after every channel is confirmed, the same links open passkey setup.
 */
function signupSection(): string {
  if (!state.signup) {
    return `
      <section class="auth-panel signup-panel" aria-labelledby="signup-title">
        <h2 id="signup-title">Self-serve signup</h2>
        <p class="auth-hint">Simulated delivery: the confirmation messages appear here instead of being
          sent. One link per channel — confirm both, then the same links open passkey setup.
          Re-using an existing (non-administrator) email demonstrates recovery by re-proofing.</p>
        <form id="signup-form">
          <label>Display name <input id="signup-name" maxlength="120" required /></label>
          <label>Email <input id="signup-email" type="email" required /></label>
          <label>Mobile phone <span class="field-note">(E.164, e.g. +15551234567)</span>
            <input id="signup-phone" placeholder="+15551234567" required /></label>
          <button class="button secondary" type="submit" ${state.busy ? 'disabled' : ''}>
            Start signup
          </button>
        </form>
      </section>
    `;
  }
  const cards = state.signup.messages
    .map(
      (message) => `
        <article class="sim-message">
          <strong>${message.channel === 'email' ? 'Email' : 'SMS'} to ${escapeHtml(message.to)}</strong>
          ${message.subject ? `<span class="sim-subject">${escapeHtml(message.subject)}</span>` : ''}
          <p>${linkifySimulated(message.body)}</p>
        </article>
      `,
    )
    .join('');
  return `
    <section class="auth-panel signup-panel" aria-labelledby="sim-title">
      <h2 id="sim-title">Simulated messages${state.signup.recovery ? ' (account recovery)' : ''}</h2>
      <p class="auth-hint">Open each link in its own tab and confirm. Once both are confirmed, the
        same links open passkey setup — finish on the device you prefer.</p>
      <div class="sim-inbox">${cards}</div>
    </section>
  `;
}

/** One channel's proof page — a client of the server-side signup state machine. */
function proofScreen(): string {
  const proof = state.proof;
  if (!proof) {
    return '';
  }
  const channelLabel = proof.channel === 'email' ? 'email address' : 'phone number';
  const cancelButton = `
    <button class="button quiet danger-text" id="cancel-signup" type="button" ${state.busy ? 'disabled' : ''}>
      This wasn&rsquo;t me &mdash; cancel it
    </button>
  `;
  let body: string;
  if (proof.status === 'ready') {
    body = proof.recovery
      ? `
      <p class="auth-lede"><strong>Someone started re-enrollment</strong> for the account bound to
        this ${channelLabel}. Confirming helps <strong>replace this account&rsquo;s passkeys</strong>.
        Only continue if you started this yourself, moments ago.</p>
      <button class="button primary auth-button" id="confirm-proof" type="button" ${state.busy ? 'disabled' : ''}>
        ${iconMarkup('check')}
        I started this &mdash; confirm
      </button>
      ${cancelButton}
    `
      : `
      <p class="auth-lede">Someone is signing up with this ${channelLabel}. Press confirm if that
        was you. Confirming proves you control this channel; setup finishes only after every
        channel is confirmed.</p>
      <button class="button primary auth-button" id="confirm-proof" type="button" ${state.busy ? 'disabled' : ''}>
        ${iconMarkup('check')}
        Confirm this ${proof.channel === 'email' ? 'email' : 'phone'}
      </button>
      ${cancelButton}
    `;
  } else if (proof.status === 'waiting') {
    body = `
      <p class="auth-lede">Confirmed. Still waiting for: <strong>${escapeHtml((proof.missing ?? []).join(', '))}</strong> —
        open the link we sent there too. This page updates by itself when the last
        confirmation lands.</p>
      ${cancelButton}
    `;
  } else if (proof.status === 'pending') {
    const seconds = Math.max(0, Math.ceil(((proof.claimableAt ?? 0) - Date.now()) / 1000));
    body = `
      <p class="auth-lede">All channels confirmed. Because this account already has passkeys,
        re-enrollment waits <strong>${String(seconds)}s</strong> before it can finish. Nothing
        changes until then — existing passkeys keep working, signing in with one cancels this,
        and so does the button below.</p>
      ${cancelButton}
    `;
  } else if (proof.status === 'canceled') {
    body = `
      <p class="auth-lede">This ${proof.recovery ? 're-enrollment' : 'signup'} was <strong>canceled</strong>.
        The account is unchanged. If you did not start or cancel it, someone else has access to
        one of your channels — review your email and phone security.</p>
    `;
  } else {
    body = `
      <p class="auth-lede">All channels confirmed. Create your passkey on this device — or open
        the link from the other channel on the device you prefer. The setup link works once.</p>
      <button class="button primary auth-button" id="claim-enroll" type="button" ${state.busy ? 'disabled' : ''}>
        ${iconMarkup('key-round')}
        Create my passkey here
      </button>
    `;
  }
  return `
    <div class="auth-shell">
      <header class="auth-brand">
        <div class="brand-symbol">${iconMarkup('key-round', 26)}</div>
        <div>
          <strong>LocalWebAuthn</strong>
          <span>Passkey lifecycle demo</span>
        </div>
      </header>
      <main class="auth-main">
        <section class="auth-panel" aria-labelledby="proof-title">
          <div class="auth-icon">${iconMarkup('shield-check', 28)}</div>
          <h1 id="proof-title">${proof.status === 'claimable' ? 'Create your passkey' : `Confirm your ${channelLabel}`}</h1>
          ${body}
          ${alerts()}
        </section>
      </main>
    </div>
  `;
}

function enrollmentCallout(): string {
  if (!state.issued) {
    return '';
  }
  const recovery = state.issued.kind === 'recovery';
  return `
    <section class="enrollment-callout" aria-labelledby="issued-title">
      <div>
        <span class="section-kicker">${recovery ? 'Recovery link' : 'Enrollment ready'}</span>
        <h2 id="issued-title">${escapeHtml(state.issued.clientName)}</h2>
        <p class="callout-help">
          ${
            recovery
              ? 'Previous passkeys and sessions were revoked. Open this one-time link on the person&rsquo;s device to register a new passkey.'
              : 'Open this one-time link in another browser profile or device. Whoever opens it first can create a passkey for this person.'
          }
          Expires ${escapeHtml(formatDate(state.issued.expiresAt))}.
        </p>
      </div>
      <div class="enrollment-link-row">
        <input aria-label="Enrollment URL" id="enrollment-url" readonly value="${escapeHtml(state.issued.url)}" />
        <button class="icon-button" id="copy-enrollment" title="Copy enrollment URL" aria-label="Copy enrollment URL" type="button">
          ${iconMarkup('copy')}
        </button>
        <button class="icon-button" id="dismiss-enrollment" title="Dismiss" aria-label="Dismiss enrollment URL" type="button">
          ${iconMarkup('x')}
        </button>
      </div>
    </section>
  `;
}

function clientRows(): string {
  return state.clients
    .map((client) => {
      const enrolled = client.passkeyCount > 0;
      const isCurrent = client.id === state.session?.client.id;
      return `
        <tr>
          <td>
            <div class="client-identity">
              <strong>${escapeHtml(client.displayName)}</strong>
              <span>${escapeHtml(client.email)}</span>
            </div>
          </td>
          <td><span class="role-label">${client.role === 'administrator' ? 'Administrator' : 'Client'}</span></td>
          <td>
            <span class="status ${enrolled ? 'active' : 'pending'}">
              ${enrolled ? iconMarkup('shield-check', 15) : iconMarkup('refresh-cw', 15)}
              ${enrolled ? 'Enrolled' : 'Pending'}
            </span>
          </td>
          <td>${String(client.passkeyCount)}</td>
          <td>
            <div class="row-actions">
              ${
                isCurrent
                  ? '<span class="muted-note">You</span>'
                  : enrolled
                    ? `<button class="button quiet re-enroll" data-client-id="${escapeHtml(client.id)}" data-client-name="${escapeHtml(client.displayName)}" type="button" title="Revoke passkeys, then issue a recovery enrollment link">
                         ${iconMarkup('refresh-cw', 16)}
                         Re-enroll
                       </button>
                       <button class="icon-button sign-out-client" data-client-id="${escapeHtml(client.id)}" data-client-name="${escapeHtml(client.displayName)}" title="End every session; passkeys stay valid" aria-label="Sign out ${escapeHtml(client.displayName)} everywhere" type="button">
                         ${iconMarkup('monitor-off', 17)}
                       </button>
                       <button class="icon-button danger revoke-client" data-client-id="${escapeHtml(client.id)}" title="Revoke all passkeys without issuing a new link" aria-label="Revoke authentication for ${escapeHtml(client.displayName)}" type="button">
                         ${iconMarkup('trash-2', 17)}
                       </button>`
                    : `<button class="button quiet issue-link" data-client-id="${escapeHtml(client.id)}" data-client-name="${escapeHtml(client.displayName)}" type="button" title="Issue a one-time enrollment link">
                         ${iconMarkup('link', 16)}
                         Issue link
                       </button>`
              }
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

function clientsSection(): string {
  if (state.session?.client.role !== 'administrator') {
    return '';
  }
  return `
    <section class="workspace-section" aria-labelledby="clients-title">
      <div class="section-heading">
        <div>
          <span class="section-kicker">Administrator</span>
          <h2 id="clients-title">People</h2>
          <p class="section-help">Invite someone with a one-time enrollment link. There is no password reset email — recovery is re-enrollment after you confirm who they are.</p>
        </div>
        <button class="button primary" id="open-client-dialog" type="button">
          ${iconMarkup('user-plus')}
          Add person
        </button>
      </div>
      <div class="table-frame">
        <table>
          <thead>
            <tr>
              <th>Person</th>
              <th>Role</th>
              <th>Passkeys</th>
              <th>Count</th>
              <th><span class="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>${clientRows()}</tbody>
        </table>
      </div>
    </section>
  `;
}

function passkeysSection(): string {
  const passkeys = state.session?.passkeys ?? [];
  return `
    <section class="workspace-section" aria-labelledby="passkeys-title">
      <div class="section-heading">
        <div>
          <span class="section-kicker">Your account</span>
          <h2 id="passkeys-title">Passkeys</h2>
          <p class="section-help">Add a second device or security key while signed in — no enrollment link required. Keep at least one passkey so you are not locked out.</p>
        </div>
        <div class="heading-actions">
          <button class="button quiet" id="sign-out-others" type="button" ${state.busy ? 'disabled' : ''} title="End your sessions on every other device; this one stays signed in">
            ${iconMarkup('monitor-off')}
            Sign out other devices
          </button>
          <button class="button secondary" id="add-passkey" type="button" ${state.busy ? 'disabled' : ''}>
            ${iconMarkup('circle-plus')}
            Add passkey
          </button>
        </div>
      </div>
      <div class="passkey-grid">
        ${passkeys
          .map(
            (passkey) => `
              <article class="passkey-item">
                <div class="passkey-symbol">${iconMarkup('key-round', 20)}</div>
                <div class="passkey-copy">
                  <strong>${escapeHtml(passkey.label)}</strong>
                  <span>${passkey.backedUp ? 'Synced' : 'Device-bound'} · Last used ${escapeHtml(formatDate(passkey.lastUsedAt))}</span>
                </div>
                <button class="icon-button danger revoke-passkey" data-credential-id="${escapeHtml(passkey.id)}"
                  title="${passkeys.length === 1 ? 'The final passkey cannot be revoked' : 'Revoke passkey'}"
                  aria-label="Revoke ${escapeHtml(passkey.label)}"
                  type="button" ${passkeys.length === 1 ? 'disabled' : ''}>
                  ${iconMarkup('trash-2', 17)}
                </button>
              </article>
            `,
          )
          .join('')}
      </div>
    </section>
  `;
}

function clientDialog(): string {
  return `
    <dialog aria-labelledby="client-dialog-title" id="client-dialog">
      <form id="client-form">
        <div class="dialog-heading">
          <div>
            <span class="section-kicker">Invitation</span>
            <h2 id="client-dialog-title">Add person</h2>
          </div>
          <button class="icon-button" id="close-client-dialog" aria-label="Close" title="Close" type="button">${iconMarkup('x')}</button>
        </div>
        <p class="dialog-help">Creates an application user and a one-time enrollment link. Email is only a label in this demo — not a login or password-reset channel.</p>
        <label>
          Display name
          <input autocomplete="name" id="client-name" maxlength="120" required />
        </label>
        <label>
          Email <span class="field-note">(identifier only)</span>
          <input autocomplete="email" id="client-email" required type="email" />
        </label>
        <div class="dialog-actions">
          <button class="button quiet" id="cancel-client" type="button">Cancel</button>
          <button class="button primary" type="submit">${iconMarkup('user-plus')}Create and issue link</button>
        </div>
      </form>
    </dialog>
  `;
}

function dashboard(): string {
  const current = state.session?.client;
  if (!current) {
    return '';
  }
  return `
    <div class="app-shell">
      <header class="app-header">
        <div class="app-brand">
          <div class="brand-symbol">${iconMarkup('key-round', 23)}</div>
          <div>
            <strong>LocalWebAuthn</strong>
            <span>Passkeys only · no passwords · no IdP</span>
          </div>
        </div>
        <div class="current-client">
          <div>
            <strong>${escapeHtml(current.displayName)}</strong>
            <span>${escapeHtml(current.email)}</span>
          </div>
          <button class="icon-button" id="sign-out" title="Sign out" aria-label="Sign out" type="button">${iconMarkup('log-out')}</button>
        </div>
      </header>
      <main>
        <section class="summary-band" aria-labelledby="page-title">
          <div>
            <span class="section-kicker">${current.role === 'administrator' ? 'Administrator' : 'Signed in'}</span>
            <h1 id="page-title">${current.role === 'administrator' ? 'Manage access' : 'Your access'}</h1>
            <p class="summary-help">Authentication is a passkey on your device. This app stores public keys and session hashes only — never a password.</p>
          </div>
          <dl>
            <div><dt>${current.role === 'administrator' ? 'People' : 'Account'}</dt><dd>${current.role === 'administrator' ? String(state.clients.length) : 'You'}</dd></div>
            <div><dt>Your passkeys</dt><dd>${String(state.session?.passkeys.length ?? 0)}</dd></div>
            <div><dt>Session</dt><dd class="connected">${iconMarkup('shield-check', 17)}Active</dd></div>
          </dl>
        </section>
        <div class="workspace">
          ${alerts()}
          ${enrollmentCallout()}
          ${clientsSection()}
          ${passkeysSection()}
        </div>
      </main>
      ${clientDialog()}
    </div>
  `;
}

function render(): void {
  applicationRoot.innerHTML = state.checking
    ? `<main class="loading-state">${iconMarkup('refresh-cw', 22)}<span>Checking session</span></main>`
    : state.proof
      ? proofScreen()
      : state.session
        ? dashboard()
        : authScreen();
  createIcons({
    icons: {
      Check,
      CirclePlus,
      Copy,
      KeyRound,
      Link,
      LockKeyhole,
      LogOut,
      MonitorOff,
      RefreshCw,
      ShieldCheck,
      Trash2,
      UserPlus,
      X,
    },
  });
  bindEvents();
}

async function refreshSession(): Promise<void> {
  const session = await request<Session>('/api/session');
  state.session = session;
  state.enrollment = undefined;
  if (session.client.role === 'administrator') {
    const result = await request<{ clients: DemoClient[] }>('/api/clients');
    state.clients = result.clients;
  } else {
    state.clients = [];
  }
}

let proofPoll: number | undefined;

function stopProofPolling(): void {
  if (proofPoll !== undefined) {
    window.clearInterval(proofPoll);
    proofPoll = undefined;
  }
}

function applyProofResult(result: ProveResult): boolean {
  const proof = state.proof;
  if (!proof) {
    return false;
  }
  const previousStatus = proof.status;
  if (result.canceled) {
    proof.status = 'canceled';
    stopProofPolling();
  } else if (result.complete && result.enrollmentToken) {
    proof.status = 'claimable';
    proof.enrollmentToken = result.enrollmentToken;
    proof.user = result.user;
    stopProofPolling();
  } else if (result.pending) {
    proof.status = 'pending';
    proof.claimableAt = result.claimableAt;
    startProofPolling();
  } else {
    proof.status = 'waiting';
    proof.missing = result.missing ?? [];
    startProofPolling();
  }
  // The pending countdown re-renders every poll tick.
  return proof.status !== previousStatus || proof.status === 'pending';
}

async function presentProof(): Promise<ProveResult> {
  const proof = state.proof;
  if (!proof) {
    throw new Error('No signup confirmation is in progress.');
  }
  return request<ProveResult>('/api/signup/prove', {
    method: 'POST',
    body: JSON.stringify({ signupId: proof.signupId, channel: proof.channel, otp: proof.otp }),
  });
}

/**
 * All open proof pages cooperate on one server-side state machine: this page
 * re-presents its own OTP to observe progress, and flips to "create your
 * passkey" the moment the final channel confirms (the `completed` claim).
 */
function startProofPolling(): void {
  if (proofPoll !== undefined) {
    return;
  }
  proofPoll = window.setInterval(() => {
    void (async () => {
      const status = state.proof?.status;
      if (status !== 'waiting' && status !== 'pending') {
        stopProofPolling();
        return;
      }
      try {
        if (applyProofResult(await presentProof())) {
          render();
        }
      } catch (error) {
        stopProofPolling();
        state.proof = undefined;
        state.error = error instanceof Error ? error.message : 'This signup expired. Start over.';
        render();
      }
    })();
  }, 2500);
}

async function perform(action: () => Promise<void>): Promise<void> {
  state.busy = true;
  state.error = '';
  state.notice = '';
  render();
  try {
    await action();
  } catch (error) {
    state.error = error instanceof Error ? error.message : 'The operation failed.';
  } finally {
    state.busy = false;
    render();
  }
}

function bindEvents(): void {
  document.querySelector<HTMLFormElement>('#signup-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const displayName = document.querySelector<HTMLInputElement>('#signup-name')?.value ?? '';
    const email = document.querySelector<HTMLInputElement>('#signup-email')?.value ?? '';
    const phone = document.querySelector<HTMLInputElement>('#signup-phone')?.value ?? '';
    void perform(async () => {
      const result = await request<{
        signupId: string;
        expiresAt: number;
        recovery: boolean;
        simulated: SimulatedMessage[];
      }>('/api/signup/start', {
        method: 'POST',
        body: JSON.stringify({ displayName, email, phone }),
      });
      state.signup = {
        signupId: result.signupId,
        expiresAt: result.expiresAt,
        recovery: result.recovery,
        messages: result.simulated,
      };
    });
  });
  document.querySelector('#confirm-proof')?.addEventListener('click', () => {
    void perform(async () => {
      applyProofResult(await presentProof());
    });
  });
  document.querySelector('#cancel-signup')?.addEventListener('click', () => {
    void perform(async () => {
      const proof = state.proof;
      if (!proof) {
        return;
      }
      stopProofPolling();
      await request('/api/signup/cancel', {
        method: 'POST',
        body: JSON.stringify({ signupId: proof.signupId, channel: proof.channel, otp: proof.otp }),
      });
      proof.status = 'canceled';
    });
  });
  document.querySelector('#claim-enroll')?.addEventListener('click', () => {
    void perform(async () => {
      const token = state.proof?.enrollmentToken;
      if (!token) {
        return;
      }
      stopProofPolling();
      try {
        state.enrollment = await auth.exchangeEnrollment(token);
        state.proof = undefined;
      } catch {
        throw new Error(
          'This setup link was already used or has expired. If that was not you, contact your administrator.',
        );
      }
    });
  });
  document.querySelector('#sign-in')?.addEventListener('click', () => {
    void perform(async () => {
      await auth.signIn();
      await refreshSession();
    });
  });
  document.querySelector('#enroll')?.addEventListener('click', () => {
    void perform(async () => {
      await auth.registerPasskey('Initial passkey');
      window.history.replaceState(null, '', '/');
      await refreshSession();
    });
  });
  document.querySelector('#sign-out')?.addEventListener('click', () => {
    void perform(async () => {
      await auth.signOut();
      state.session = undefined;
      state.clients = [];
    });
  });
  document.querySelector('#add-passkey')?.addEventListener('click', () => {
    void perform(async () => {
      await auth.registerPasskey('Additional passkey');
      await refreshSession();
      state.notice = 'Additional passkey registered.';
    });
  });
  document.querySelector('#sign-out-others')?.addEventListener('click', () => {
    void perform(async () => {
      const result = await request<{ revokedSessions: number }>('/api/session/revoke-others', {
        method: 'POST',
      });
      state.notice =
        result.revokedSessions === 0
          ? 'No other sessions to sign out.'
          : `Signed out ${String(result.revokedSessions)} other ${result.revokedSessions === 1 ? 'session' : 'sessions'}. Your passkeys are unchanged.`;
    });
  });

  const dialog = document.querySelector<HTMLDialogElement>('#client-dialog');
  document
    .querySelector('#open-client-dialog')
    ?.addEventListener('click', () => dialog?.showModal());
  for (const id of ['close-client-dialog', 'cancel-client']) {
    document.querySelector(`#${id}`)?.addEventListener('click', () => dialog?.close());
  }
  document.querySelector<HTMLFormElement>('#client-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const displayName = document.querySelector<HTMLInputElement>('#client-name')?.value ?? '';
    const email = document.querySelector<HTMLInputElement>('#client-email')?.value ?? '';
    dialog?.close();
    void perform(async () => {
      const result = await request<{
        client: DemoClient;
        enrollmentUrl: string;
        expiresAt: number;
      }>('/api/clients', {
        method: 'POST',
        body: JSON.stringify({ displayName, email }),
      });
      await refreshSession();
      state.issued = {
        clientName: result.client.displayName,
        url: result.enrollmentUrl,
        expiresAt: result.expiresAt,
        kind: 'new',
      };
    });
  });

  for (const button of document.querySelectorAll<HTMLButtonElement>('.issue-link')) {
    button.addEventListener('click', () => {
      void perform(async () => {
        const result = await request<{ enrollmentUrl: string; expiresAt: number }>(
          `/api/clients/${encodeURIComponent(button.dataset.clientId ?? '')}/enrollment`,
          { method: 'POST' },
        );
        state.issued = {
          clientName: button.dataset.clientName ?? 'Person',
          url: result.enrollmentUrl,
          expiresAt: result.expiresAt,
          kind: 'new',
        };
      });
    });
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>('.re-enroll')) {
    button.addEventListener('click', () => {
      const name = button.dataset.clientName ?? 'this person';
      if (
        !window.confirm(
          `Re-enroll ${name}?\n\nThis revokes every passkey and session for them, then issues a one-time recovery link. Confirm their identity out of band before sharing the link.`,
        )
      ) {
        return;
      }
      void perform(async () => {
        const result = await request<{
          enrollmentUrl: string;
          expiresAt: number;
        }>(`/api/clients/${encodeURIComponent(button.dataset.clientId ?? '')}/re-enroll`, {
          method: 'POST',
        });
        await refreshSession();
        state.issued = {
          clientName: name,
          url: result.enrollmentUrl,
          expiresAt: result.expiresAt,
          kind: 'recovery',
        };
        state.notice = 'Passkeys revoked and recovery enrollment issued.';
      });
    });
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>('.sign-out-client')) {
    button.addEventListener('click', () => {
      const name = button.dataset.clientName ?? 'this person';
      void perform(async () => {
        const result = await request<{ revokedSessions: number }>(
          `/api/clients/${encodeURIComponent(button.dataset.clientId ?? '')}/revoke-sessions`,
          { method: 'POST' },
        );
        await refreshSession();
        state.notice = `Ended ${String(result.revokedSessions)} ${result.revokedSessions === 1 ? 'session' : 'sessions'} for ${name}. Passkeys remain valid — no re-enrollment needed.`;
      });
    });
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>('.revoke-client')) {
    button.addEventListener('click', () => {
      if (
        !window.confirm(
          'Revoke all passkeys and sessions for this person without issuing a new link? They will be locked out until you re-enroll them.',
        )
      ) {
        return;
      }
      void perform(async () => {
        await request(
          `/api/clients/${encodeURIComponent(button.dataset.clientId ?? '')}/revoke-authentication`,
          { method: 'POST' },
        );
        await refreshSession();
        state.notice = 'Authentication revoked. Issue a re-enrollment link when ready.';
      });
    });
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>('.revoke-passkey')) {
    button.addEventListener('click', () => {
      void perform(async () => {
        await request(
          `/api/passkeys/${encodeURIComponent(button.dataset.credentialId ?? '')}/revoke`,
          { method: 'POST' },
        );
        await refreshSession();
        state.notice = 'Passkey revoked.';
      });
    });
  }

  document.querySelector('#copy-enrollment')?.addEventListener('click', () => {
    if (state.issued) {
      void navigator.clipboard.writeText(state.issued.url);
      state.notice = 'Enrollment URL copied.';
      render();
    }
  });
  document.querySelector('#dismiss-enrollment')?.addEventListener('click', () => {
    state.issued = undefined;
    render();
  });
}

async function initialize(): Promise<void> {
  const signupProof = parseSignupFragment(window.location.hash);
  if (signupProof && (signupProof.channel === 'email' || signupProof.channel === 'phone')) {
    // Same hygiene as enrollment fragments: take the OTP out of the URL bar.
    window.history.replaceState(null, '', '/signup');
    state.proof = {
      signupId: signupProof.signupId,
      channel: signupProof.channel,
      otp: signupProof.otp,
      recovery: signupProof.recovery,
      status: 'ready',
    };
    state.checking = false;
    render();
    return;
  }
  const enrollmentToken = consumeEnrollmentToken(window.location, window.history);
  if (enrollmentToken) {
    try {
      state.enrollment = await auth.exchangeEnrollment(enrollmentToken);
    } catch (error) {
      state.error = error instanceof Error ? error.message : 'The enrollment link is invalid.';
    }
  } else {
    try {
      await refreshSession();
    } catch {
      state.session = undefined;
    }
  }
  state.checking = false;
  render();
}

void initialize();
