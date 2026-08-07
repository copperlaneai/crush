# Releasing Crush

Releases are built only by `.github/workflows/release.yml` from an annotated
version tag. Do not upload locally built replacement archives to an existing
release.

## Prepare a release

1. Confirm the full compatibility, tmux, performance, security, and restoration
   gates in [testing.md](testing.md).
2. Update `CHANGELOG.md`: move Unreleased entries under the exact version and
   date, and add comparison links.
3. Ensure `Cargo.toml` contains the same version and `Cargo.lock` is current.
4. Run the required checks in [CONTRIBUTING.md](../CONTRIBUTING.md) on a clean
   tree.
5. Confirm the repository is public. The stable one-line installer URL cannot
   be downloaded anonymously from a private repository.
6. Create and push a signed annotated tag whose value exactly matches the Cargo
   version:

   ```sh
   git tag -s v0.1.0 -m 'crush 0.1.0'
   git push origin v0.1.0
   ```

The workflow validates the tag/version match, builds six target archives,
enforces the binary-size gate, creates SHA-256 checksums and an SPDX JSON SBOM,
adds GitHub build provenance, creates Sigstore bundles, and publishes the GitHub
release. The tag must already exist and be annotated; the workflow never creates
or moves it. A manual re-run must be dispatched with that tag selected as the
workflow ref so the Sigstore identity remains bound to `refs/tags/VERSION`.

`scripts/prepare-release-assets.sh` validates the complete target set, copies
the stable installer asset, and creates the checksum manifest used by the
release workflow.

## Release assets

Each version publishes:

- `crush-VERSION-TARGET.tar.gz` for:
  - `x86_64-unknown-linux-gnu`
  - `x86_64-unknown-linux-musl`
  - `aarch64-unknown-linux-gnu`
  - `aarch64-unknown-linux-musl`
  - `x86_64-apple-darwin`
  - `aarch64-apple-darwin`
- `SHA256SUMS`
- `crush-installer.sh`
- `crush-VERSION.spdx.json`
- one `.sigstore.json` bundle beside the installer, every archive, checksum
  manifest, and SBOM.

Every archive contains `crush`, `README.md`, `LICENSE-MIT`, and
`LICENSE-APACHE` at its root. `crush-installer.sh` has a stable asset name so
the latest release is installable with one command:

```sh
curl -fsSL https://github.com/copperlaneai/crush/releases/latest/download/crush-installer.sh | sh
```

On Linux, `install.sh` always selects the static musl archive. GNU target
archives remain available for explicit manual download and source-oriented
users, but releases do not claim a minimum glibc runtime version for those
artifacts.

## Verify a release

Download an archive, `SHA256SUMS`, and their Sigstore bundles from the same
release. Authenticate the checksum manifest before trusting its digest:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github.com/copperlaneai/crush/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  SHA256SUMS
```

Then verify the selected archive:

```sh
grep 'crush-0.1.0-aarch64-apple-darwin.tar.gz$' SHA256SUMS | shasum -a 256 -c -

cosign verify-blob \
  --bundle crush-0.1.0-aarch64-apple-darwin.tar.gz.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp \
    '^https://github.com/copperlaneai/crush/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  crush-0.1.0-aarch64-apple-darwin.tar.gz
```

GitHub provenance is independently verifiable with the GitHub CLI:

```sh
gh attestation verify \
  crush-0.1.0-aarch64-apple-darwin.tar.gz \
  --repo copperlaneai/crush
```

On GNU/Linux, replace `shasum -a 256` with `sha256sum` if needed.

## Recovery

- If a build or test fails, fix it and create a new commit before re-running the
  existing tag workflow only when the tag still points at that same commit.
- If the tag points to wrong source or version metadata, delete the unpublished
  tag and create the correct tag. Never move a tag after any release asset has
  been published.
- If any published artifact is wrong, mark the release withdrawn, document the
  problem, and issue a new patch version. Do not replace assets in place.
- Treat signing, provenance, checksum, or SBOM failures as release failures, not
  optional post-release work.
