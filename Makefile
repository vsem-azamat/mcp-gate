# One entry point for the checks CI runs. Every tool but GoReleaser is pinned in tools/go.mod or
# tools/lint/go.mod and runs through `go tool`, so nothing needs a global install besides Go,
# Git and Bash. `make check` runs every CI job but Release config, which is `make release-check`.
# See docs/development/README.md.

SHELL := bash

TOOL := go tool -modfile=tools/go.mod
LINT := go tool -modfile=tools/lint/go.mod golangci-lint

# The GoReleaser of the workflows; make repo checks that all of them name the same version.
GORELEASER_VERSION := v2.19.0
GORELEASER := go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

# Every Go module in the repository: the product and the pinned tools.
MODULES := . tools tools/lint

.PHONY: check fmt lint test vuln tidy tidy-check repo release-check hooks help

## check: every CI job but Release config (see release-check)
check: repo tidy-check lint test vuln

## hooks: use the versioned git hooks in .githooks/ (run once after cloning)
hooks:
	git config core.hooksPath .githooks

## fmt: apply the Go formatters (gofumpt, goimports)
fmt:
	$(LINT) fmt

## lint: Go linters and formatting (golangci-lint)
lint:
	$(LINT) config verify
	$(LINT) run

## test: unit tests with the race detector, in random order
test:
	go test -race -shuffle=on ./...

## vuln: known vulnerabilities in the code and its dependencies (govulncheck, needs network)
vuln:
	$(TOOL) govulncheck ./...

## tidy: run go mod tidy in every module
tidy:
	@for m in $(MODULES); do echo "go mod tidy ($$m)"; go -C $$m mod tidy || exit 1; done

## tidy-check: go.mod and go.sum are tidy in every module
tidy-check:
	@for m in $(MODULES); do \
		go -C $$m mod tidy -diff || { echo "$$m: go.mod or go.sum is not tidy: run make tidy" >&2; exit 1; }; \
	done

## repo: repository policy, Markdown links, editorconfig and workflow checks
repo:
	scripts/repo-policy-check.sh
	scripts/docs-check.sh
	$(TOOL) editorconfig-checker
	$(TOOL) actionlint

## release-check: the GoReleaser config is valid and a snapshot builds into dist/ (slow; CI's Release config job)
release-check:
	$(GORELEASER) check
	$(GORELEASER) release --snapshot --clean

## help: list the targets
help:
	@awk '/^## /{l=substr($$0,4); i=index(l,": "); printf "  %-14s %s\n", substr(l,1,i-1), substr(l,i+2)}' $(MAKEFILE_LIST)
