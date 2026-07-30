# `@localwebauthn/browser`

Browser client for LocalWebAuthn's default HTTP protocol.

```ts
import { consumeEnrollmentToken, LocalWebAuthnBrowser } from '@localwebauthn/browser';

const auth = new LocalWebAuthnBrowser();
const token = consumeEnrollmentToken(window.location, window.history);

if (token) {
  await auth.exchangeEnrollment(token);
  await auth.registerPasskey();
} else {
  await auth.signIn();
}
```

The enrollment fragment is removed from browser history before exchange. Ceremony and session
tokens remain in host-managed HTTP-only cookies and are never exposed to this package.

See the repository's [lifecycle demo](../../examples/demo/README.md) for initial enrollment,
passkey sign-in, administrator-issued client links, and authenticated additional-passkey
registration.
