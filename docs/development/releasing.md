# Releasing

[Docs](../README.md) / [Development](README.md) / **Releasing**

A release is a `v*` tag on `main`. Only the maintainer creates tags. Pushing the tag runs [`.github/workflows/release.yml`](../../.github/workflows/release.yml), whose checkout keeps no credentials, since the build and the tests run third-party code. Then:

1. It stops unless the tagged commit is on `main`.
2. `make test`.
3. [GoReleaser](https://goreleaser.com) (pinned in the workflow) builds the binaries from [`.goreleaser.yaml`](../../.goreleaser.yaml):
   - `mcp-gate` for Linux and macOS, on amd64 and arm64;
   - with `CGO_ENABLED=0` and `-trimpath`;
   - with `-X github.com/vsem-azamat/mcp-gate/internal/version.Version=<tag>`, so `mcp-gate version` prints the tag;
   - with the file times of the tagged commit.
   GoReleaser is given the pushed tag (`GORELEASER_CURRENT_TAG`), so a final tag on the commit of an rc tag builds the final version.
4. It packs `mcp-gate_<version>_<os>_<arch>.tar.gz` with `LICENSE` and `README.md` (every file with the commit's date as file time and `root:root` as owner, so the same commit gives the same archives), writes `checksums.txt` (SHA-256), and publishes a GitHub release with a changelog from the commits since the previous tag. A pre-release tag such as `v0.2.0-rc.1` gives a pre-release.

A build that was given no version, such as `go build` from a checkout or a snapshot, prints `dev` from `mcp-gate version`, followed by the commit when the toolchain recorded one.

CI runs the same GoReleaser with `check` and `release --snapshot --clean` on every pull request (the `Release config` job, see [Checks and tooling](checks.md)). A snapshot builds, packs and checksums every target; the changelog and publishing run only on a real tag. To try it locally without publishing (output goes to `dist/`, which git ignores):

```sh
make release-check
```

GoReleaser is pinned by version in `ci.yml`, `release.yml` and the Makefile, and Dependabot does not update it: upgrade all three together by hand. `make repo` fails while they differ.

When a release fails midway, GoReleaser may leave a draft release; delete it on the Releases page. When the cause was outside the repository, re-run the workflow for the tag. When it is in the tagged commit, fix it on `main` and push a new version tag.
