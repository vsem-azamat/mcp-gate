#!/usr/bin/env bash
# Rejects tracked files that the repository rules forbid: tool-specific agent instruction
# files, OpenSpec change folders, scratch or temporary output, and workflow actions that are not
# pinned to a commit SHA.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
err() { echo "repo-policy: $*" >&2; fail=1; }

while IFS= read -r path; do
  case "$path" in
    CLAUDE.md | */CLAUDE.md | CLAUDE.local.md | */CLAUDE.local.md | GEMINI.md | */GEMINI.md | .cursorrules)
      err "$path: AGENTS.md is the only agent instruction file" ;;
    openspec/changes/*)
      err "$path: specs are edited in place; openspec/changes/ is not committed" ;;
    tmp/* | */tmp/* | scratch/* | */scratch/* | plans/* | */plans/* | *.log | *.tmp | *.bak | *.orig | .env | .env.*)
      err "$path: scratch, plan, temporary or local environment file" ;;
  esac
done < <(git ls-files)

# A tag or branch can be moved to other code; a full commit SHA cannot. Local actions (./...) are
# part of the repository. Only the plain `uses: <ref>` form is read, so any other spelling of the
# key is rejected rather than skipped.
actions=0
while IFS= read -r line; do
  loc=$(cut -d: -f1,2 <<<"$line")
  body=${line#*:*:}
  [[ "$body" =~ ^[[:space:]]*# ]] && continue
  if ! [[ "$body" =~ ^[[:space:]-]*uses:[[:space:]] ]]; then
    err "$loc: write the action as a plain 'uses: <ref>' line"
    continue
  fi
  actions=$((actions + 1))
  ref=${body#*uses:}
  ref=${ref%%#*}
  ref=$(tr -d " \t\r\"'" <<<"$ref")
  case "$ref" in
    ./*) continue ;;
    docker://*) err "$loc: Docker actions are not used; $ref" ;;
    *) [[ "$ref" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$ ]] ||
      err "$loc: action $ref is not pinned to a commit SHA" ;;
  esac
done < <(git ls-files -z '.github/workflows/*.yml' '.github/workflows/*.yaml' \
  '.github/actions/*.yml' '.github/actions/*.yaml' | xargs -0r grep -nH -E "(^|[^[:alnum:]_-])uses[\"']?[[:space:]]*:")
# The workflows use actions, so finding none means this check read nothing.
[ "$actions" -gt 0 ] || err "no 'uses:' line found in .github/workflows; the action pin check read nothing"

[ "$fail" = 0 ] && echo "repo-policy: ok"
exit "$fail"
