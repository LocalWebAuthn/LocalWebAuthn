# Releasing LocalWebAuthn

Both packages are versioned and released together. Publishing is triggered by the GitHub
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
4. Run `npm run release:check` from a clean checkout.
5. Publish the first package records interactively:

   ```console
   npm publish --workspace @localwebauthn/server
   npm publish --workspace @localwebauthn/browser
   ```

6. Open each package on npm and configure its Trusted Publisher:

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

## Regular Release

1. Update both package versions to the same SemVer value.
2. Update the changelog and migration notes.
3. Run `npm install --package-lock-only` and `npm run release:check`.
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
7. Confirm both npm packages show the new version and provenance.
8. Verify installation into a clean Node and Workers example.

Before publishing anything, the workflow asserts the tag name equals `v` + the shared
package version and re-runs the full gate (`npm run check`, with a PostgreSQL service so
the conformance suite cannot silently skip). A mismatched tag or failing gate stops the
release with nothing published.

## Recovery

If the server publish succeeds and the browser publish fails, do not overwrite or unpublish
the server version. Correct the problem, increment both package versions, and publish a new
release. npm package versions are immutable release artifacts.
