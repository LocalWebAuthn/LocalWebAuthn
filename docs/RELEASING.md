# Releasing LocalWebAuthn

Both packages are versioned and released together. A GitHub Release tagged with the shared
package version triggers `.github/workflows/publish.yml`.

## One-Time Bootstrap

1. Create or enable the public `pjkundert/LocalWebAuthn` GitHub repository.
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
   - Organization or user: `pjkundert`
   - Repository: `LocalWebAuthn`
   - Workflow filename: `publish.yml`
   - Environment: `npm`
   - Allowed action: `npm publish`

7. Create the `npm` environment in GitHub repository settings.
8. Restrict that environment to protected release tags and add required reviewers.
9. Enable private vulnerability reporting and repository branch protection.

No npm write token is stored in GitHub. Trusted Publishing exchanges GitHub's short-lived
OIDC identity for publish authorization. npm automatically generates provenance for public
packages published from the public repository through this workflow.

## Regular Release

1. Update both package versions to the same SemVer value.
2. Update the changelog and migration notes.
3. Run `npm install --package-lock-only` and `npm run release:check`.
4. Merge the release commit to the protected default branch.
5. Create a GitHub Release tagged `vX.Y.Z`.
6. Approve the protected `npm` environment deployment.
7. Confirm both npm packages show the new version and provenance.
8. Verify installation into a clean Node and Workers example.

The workflow rejects a tag that does not exactly equal the shared package version.

## Recovery

If the server publish succeeds and the browser publish fails, do not overwrite or unpublish
the server version. Correct the problem, increment both package versions, and publish a new
release. npm package versions are immutable release artifacts.
