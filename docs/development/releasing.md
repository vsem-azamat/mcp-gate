# Releasing

[Docs](../README.md) / [Development](README.md) / **Releasing**

A release is a `v*` tag on `main`. Only the maintainer creates tags. Pushing the tag runs [`.github/workflows/release.yml`](../../.github/workflows/release.yml), whose checkout keeps no credentials, since the build and the tests run third-party code. Then:

1. It stops unless the tagged commit is on `main`.
2. `make test` and `make vuln` (govulncheck): a known vulnerability that the code reaches stops the release.
3. [GoReleaser](https://goreleaser.com) (pinned in the workflow) builds the binaries from [`.goreleaser.yaml`](../../.goreleaser.yaml):
   - `mcp-gate` for Linux and macOS, on amd64 and arm64;
   - with `CGO_ENABLED=0` and `-trimpath`;
   - with `-X github.com/vsem-azamat/mcp-gate/internal/version.Version=<tag>`, so `mcp-gate version` prints the tag;
   - with the file times of the tagged commit.
   After each build, a hook runs the [binary smoke test](testing.md#binary-smoke-test) against the binary when it is for the build machine's OS and architecture, so a broken linux/amd64 binary stops the release.
   GoReleaser is given the pushed tag (`GORELEASER_CURRENT_TAG`), so a final tag on the commit of an rc tag builds the final version.
4. It packs `mcp-gate_<version>_<os>_<arch>.tar.gz` with `LICENSE`, `README.md` and the [systemd units](../operations/systemd.md) `packaging/systemd/mcp-gate.service` and `packaging/systemd/user/mcp-gate.service` (every file with the commit's date as file time and `root:root` as owner, so the same commit gives the same archives), writes `checksums.txt` (SHA-256), and publishes a GitHub release with a changelog from the commits since the previous tag: `feat` commits under Features, `fix` under Fixes, the rest under Other changes, leaving out `chore`, `docs`, `test` and `ci`. A pre-release tag such as `v0.2.0-rc.1` gives a pre-release.
5. A separate job, the only one that can sign, downloads the published archives and `checksums.txt`, checks the archives against the checksums, and [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance) signs SLSA build provenance for each of them and stores it with the repository's attestations. The tests and the build run third-party code, so they never hold the signing token. The attestation sits beside the files; it changes neither them nor their checksums.

A build that was given no version, such as `go build` from a checkout or a snapshot, prints `dev` from `mcp-gate version`, followed by the commit when the toolchain recorded one.

CI runs the same GoReleaser with `check` and `release --snapshot --clean` on every pull request (the `Release config` job, see [Checks and tooling](checks.md)). A snapshot builds, packs and checksums every target; the changelog and publishing run only on a real tag. To try it locally without publishing (output goes to `dist/`, which git ignores):

```sh
make release-check
```

GoReleaser is pinned by version in `ci.yml`, `release.yml` and the Makefile, and Dependabot does not update it: upgrade all three together by hand. `make repo` fails while they differ.

When a release fails midway, GoReleaser may leave a draft release; delete it on the Releases page. When the cause was outside the repository, re-run the workflow for the tag. When it is in the tagged commit, fix it on `main` and push a new version tag. When only the Build provenance job failed, the release is already published, without an attestation; re-run that job alone.

## Verifying A Release

Check an archive against `checksums.txt`, and that both were built by this repository's release workflow from a tag:

```sh
sha256sum --check --ignore-missing checksums.txt
gh attestation verify mcp-gate_<version>_linux_amd64.tar.gz --repo vsem-azamat/mcp-gate
gh attestation verify checksums.txt --repo vsem-azamat/mcp-gate
```

On macOS, `shasum -a 256 --check --ignore-missing checksums.txt` replaces the first line. `gh attestation verify` prints the workflow, the tag and the commit the file was built from. A release without an attestation can be checked only against its checksums.
