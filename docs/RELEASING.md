# Releasing LocalWebAuthn

**All three packages** — `@localwebauthn/server`, `@localwebauthn/browser` and
`@localwebauthn/client` — are versioned and released together. Publishing is triggered by the GitHub
Release **published** event — `.github/workflows/publish.yml` runs
`on: release: types: [published]` — for a Release whose tag is `vX.Y.Z`.

Be precise about the two objects involved. The _tag_ is an ordinary Git ref pointing at
the release commit on `main`; the _Release_ is the GitHub object attached to that tag
(title, notes, and a published event). Pushing the tag alone publishes nothing — like
ordinary branch pushes, it runs no publish job. Only publishing the Release fires the
workflow. This is deliberate: every immutable npm version must map to an explicit Git tag
and a GitHub Release a maintainer chose to publish.

## One-Time Bootstrap

1. Confirm the public `LocalWebAuthn/LocalWebAuthn` GitHub repository is available.
2. Create the `localwebauthn` organization on npm.
3. Enable publishing two-factor authentication on the maintainer npm account.
4. From the flake shell, run `make release-check` (or `make nix-release-check`).
5. Publish the first package records interactively:

   ```console
   npm publish --workspace @localwebauthn/server
   npm publish --workspace @localwebauthn/browser
   npm publish --workspace @localwebauthn/client
   ```

6. Open **each of the three** packages on npm and configure its Trusted Publisher:

   - Provider: GitHub Actions
   - Organization or user: `LocalWebAuthn`
   - Repository: `LocalWebAuthn`
   - Workflow filename: `publish.yml`
   - Environment: `npm`
   - Allowed action: `npm publish`

7. Create the `npm` environment in GitHub repository settings.
8. Restrict that environment to `v*` release tags. Add required reviewers if releases
   should require a separate approval after the GitHub Release is published.
9. Enable private vulnerability reporting and repository branch protection.

No npm write token is stored in GitHub. Trusted Publishing exchanges GitHub's short-lived
OIDC identity for publish authorization. npm automatically generates provenance for public
packages published from the public repository through this workflow.

## Bootstrapping a New Package Record (`@localwebauthn/client`)

A package that has never been published has **no npm record**, so it has no Trusted Publisher
to configure and the automated workflow cannot publish it. The first version must be pushed by
a human, once. Do this **before** the v3 tag exists — otherwise server and browser become
immutable at `3.0.0` and the run then fails on the client, forcing an immediate `3.0.1`.

Publish the client **first** of the three. It is the least-proven record, so any scope,
permission or provenance problem surfaces before the two established packages are touched.

```console
nix develop
npm whoami                       # confirm the account that owns the localwebauthn scope
make release-check               # full gate + all three tarballs
npm pack --workspace @localwebauthn/client   # inspect the real tarball, not a dry run
tar -tzf localwebauthn-client-*.tgz          # expect LICENSE, README.md, package.json, dist/
```

Then publish it as a prerelease, so the bootstrap cannot become anyone's default install:

```console
npm publish --workspace @localwebauthn/client --tag next
```

Notes on the flags and the likely failures:

- **`--tag next` matters more than it looks.** Without a `--tag`, npm marks the version `latest`,
  which is what a bare `npm install @localwebauthn/client` resolves. Bootstrapping under `next`
  keeps the record honest: nothing is `latest` until a final version ships.
- **`--access public` is not needed here**: `packages/client/package.json` already sets
  `publishConfig.access: "public"`. (A scoped package without that would need the flag, or npm
  attempts a private publish and fails with `402` on a free account.)
- **Do not pass `--provenance` from a laptop.** Provenance needs a supported CI OIDC context and
  errors outside one. The workflow attests every subsequent release; the bootstrap version simply
  will not have provenance, which is acceptable for an rc.
- **2FA**: with publishing 2FA enabled npm prompts for an OTP; `--otp=NNNNNN` avoids the prompt
  in a non-TTY shell.
- **`E403` / name unavailable**: confirm the scope exists and your account may publish to it
  (`npm org ls localwebauthn`).
- **Every version you publish is permanent.** `npm unpublish` is not an undo — it burns the
  number. Bootstrap a prerelease (`3.0.0-rc.1`), not a placeholder like `2.2.0`, and let the
  final `3.0.0` come from the workflow.

Immediately after the bootstrap publish, configure the client's Trusted Publisher exactly as
for the other two (GitHub Actions · `LocalWebAuthn` · `LocalWebAuthn` · `publish.yml` ·
environment `npm`), then verify:

```console
npm dist-tag ls @localwebauthn/client         # expect `next`, and NO `latest`
npm view @localwebauthn/client@next version

mkdir /tmp/lwa-consumer && cd /tmp/lwa-consumer && npm init -y
npm install @localwebauthn/client@next       # @next is required while no latest exists
node --input-type=module -e "import { ES256 } from '@localwebauthn/client'; console.log(ES256)"
```

Install `@next` explicitly: with no `latest` dist-tag, a bare `npm install @localwebauthn/client`
resolves `@latest` and fails. That is the intended state for a prerelease-only package — and the
reason to confirm it with `npm dist-tag ls` rather than assume. If a `latest` did get set by
accident, `npm dist-tag add @localwebauthn/client@3.0.0 latest` on the real release fixes the
default, but the stray version stays published forever.

That consumer check is the one a workspace cannot make: inside the workspace, `dist/` resolves
through a symlink whether or not the tarball contained it. Installing the tarball is what proves
the published artifact resolves, imports and runs.

## Regular Release

1. Update all three package versions to the same SemVer value, and update the example
   dependency pins (`examples/*/package.json` pin `@localwebauthn/*` exactly) so
   examples copied out of the workspace install the release that actually has
   the APIs they use.
2. Update the changelog and migration notes.
3. Run `npm install --package-lock-only` and `make release-check` (or `make nix-release-check`).
4. Merge the release commit to the protected default branch.
5. Tag that commit and publish a GitHub Release on the tag:

   ```console
   git tag vX.Y.Z <merge-commit> && git push origin vX.Y.Z
   gh release create vX.Y.Z --verify-tag --title "vX.Y.Z" --notes "…"
   ```

   `gh release create` without a pre-pushed tag also works (it creates the tag on the
   default branch head); if you point it elsewhere, `--target` accepts a branch name or
   full commit SHA — not an abbreviated SHA. Either way, it is the Release being
   published — not the tag existing — that triggers `publish.yml`.

6. Approve the `npm` environment deployment if required reviewers are configured.
7. Confirm all three npm packages show the new version and provenance.
8. Verify installation into a clean Node and Workers example.

Before publishing anything, the workflow asserts the tag name equals `v` + the shared
package version and re-runs the full gate (`npm run check`, with a PostgreSQL service so
the conformance suite cannot silently skip). A mismatched tag or failing gate stops the
release with nothing published.

## Recovery

**No multi-package publish is atomic.** The workflow publishes in order — server, browser,
client — and each `npm publish` is an independent, immutable act. Any prefix of that sequence
can succeed while the rest fails.

The rule, whatever failed: **never overwrite and never unpublish what succeeded.** Correct the
problem, increment _all three_ versions to the next patch, and publish a new release. A version
that reached npm is a permanent artifact; `npm unpublish` is not an undo (it burns the version
number and breaks anyone who already installed it).

| What happened                              | What to do                                       |
| ------------------------------------------ | ------------------------------------------------ |
| server failed (nothing published)          | fix, re-run the Release; no version bump needed  |
| server ok, browser failed                  | bump all three to `X.Y.Z+1`, new tag and Release |
| server + browser ok, client failed         | bump all three to `X.Y.Z+1`, new tag and Release |
| all three ok but the gate flagged an issue | ship a fix as `X.Y.Z+1`; do not retag            |

The workflow re-runs the full gate _before_ the first publish, so the common failure mode is a
gate failure with nothing published. The dangerous mode is a per-package authorization problem,
which is why every package's Trusted Publisher must be configured **before** the first v3 tag
exists — see the bootstrap section, and the note there about publishing the newest package
record first.
