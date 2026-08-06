# Demo Media

The README combines two forms of evidence:

- `demo.cast` presents a fresh clone entering the Nix development environment and starting
  the demo server.
- The browser screenshots come from the same Playwright lifecycle test used in CI. The
  test uses Chromium virtual authenticators and exercises real WebAuthn browser APIs.

Terminal recorders cannot capture native passkey prompts. Browser automation also cannot
make a portable image of operating-system passkey UI. The screenshots therefore show the
application state immediately before and after those native ceremonies.

## Recreate Browser Screenshots

Install the Playwright Chromium browser once, then run:

```console
nix develop
npx playwright install chromium
npm run demo:screenshots
```

The command resets its isolated database and replaces:

- `docs/images/demo-enrollment.png`
- `docs/images/demo-administration.png`
- `docs/images/demo-passkeys-mobile.png`
- `docs/images/demo-signup-inbox.png`
- `docs/images/demo-recovery-pending.png`

The signup screenshots contain proof-link OTPs from the throwaway e2e database; by the
end of the capturing run that signup's enrollment is claimed and exchanged and the
recovery is canceled, so no captured link is live.

Enrollment fragments are consumed before Playwright captures a page. The administration
screenshot is taken after the issued link is dismissed and the client has enrolled, so
committed screenshots contain no live bearer tokens.

## Recreate The Terminal Recording

Record a clean checkout at 100 columns by 22 rows:

```console
asciinema record --window-size 100x22 --idle-time-limit 1 docs/demo.cast
```

Run the clone, `nix develop`, and `make demo` commands shown in the README. Stop the server
after it prints the bootstrap URL, exit the development shell, and exit the recording
shell. Use a disposable demo database because the printed enrollment fragment is a bearer
token until it expires or is consumed.

Normalize the cast before publishing it: remove package-manager warnings, dependency
progress, build-size output, shutdown commands, and shell-specific prompts. Redact the
enrollment token and express its expiry as a duration. Keep the useful output within the
22-row terminal so it never scrolls.

Render the GitHub-compatible animation with
[agg](https://docs.asciinema.org/manual/agg/):

```console
agg \
  --theme github-dark \
  --font-size 15 \
  --idle-time-limit 1 \
  --last-frame-duration 8 \
  docs/demo.cast \
  docs/images/quickstart.gif
```

The source cast is committed so reviewers can play, inspect, or re-render it without
depending on asciinema.org.
