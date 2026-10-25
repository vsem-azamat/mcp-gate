#!/usr/bin/env bash
# Checks the Markdown in the repository:
# - every relative link in a tracked .md file resolves, inline ([x](target)) and reference-style
#   ([x]: target); links inside code spans and fenced code blocks are ignored;
# - every docs/ directory has a README.md index that links each page and subdirectory in it;
# - every docs/ page but docs/README.md starts with a breadcrumb line "[Docs](<path>)" whose
#   target is docs/README.md.
set -euo pipefail
# Written for bash 3.2 (the macOS default) and BSD userland as well as GNU.
cd "$(dirname "$0")/.."
fail=0
err() { echo "docs-check: $*" >&2; fail=1; }

# prose <file>: the file without fenced code blocks and code spans
prose() {
  awk '/^[[:space:]]*(```|~~~)/ { code = !code; next } !code' "$1" | sed -E 's/`[^`]*`//g'
}

# resolve <path>: the physical absolute path of an existing file, or nothing
resolve() {
  [ -e "$1" ] || return 0
  (cd "$(dirname "$1")" && echo "$(pwd -P)/$(basename "$1")")
}

# links <file>: the link targets in a Markdown file, one per line, outside code
links() {
  local text
  text=$(prose "$1")
  { grep -oE '\]\([^)[:space:]]+' <<<"$text" | cut -c3- || true; } | tr -d '<>'
  # reference definitions; [^label]: is a footnote, not a link
  { grep -E '^ {0,3}\[[^]^][^]]*\]:[[:space:]]*[^[:space:]]+' <<<"$text" |
    sed -E 's/^ {0,3}\[[^]]+\]:[[:space:]]*([^[:space:]]+).*/\1/' || true; } | tr -d '<>'
}

while IFS= read -r -d '' file; do
  dir=$(dirname "$file")
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    case "$target" in
      http://* | https://* | mailto:* | '#'*) continue ;;
    esac
    path=${target%%#*}
    [ -e "$dir/$path" ] || err "$file: broken link $target"
  done < <(links "$file")
done < <(git ls-files -z '*.md')

if [ -d docs ]; then
  [ -f docs/README.md ] || err "missing docs/README.md index"
  index=$(resolve docs/README.md)
  while IFS= read -r dir; do
    if [ ! -f "$dir/README.md" ]; then
      err "missing $dir/README.md index"
      continue
    fi
    indexed=$(links "$dir/README.md")
    for entry in "$dir"/*; do
      name=$(basename "$entry")
      [ "$name" = README.md ] && continue
      if [ -d "$entry" ]; then
        grep -qxF "$name/README.md" <<<"$indexed" || err "$dir/README.md does not link $name/README.md"
      elif [[ "$name" == *.md ]]; then
        grep -qxF "$name" <<<"$indexed" || err "$dir/README.md does not link $name"
      fi
    done
  done < <(find docs -type d)

  while IFS= read -r page; do
    [ "$page" = docs/README.md ] && continue
    crumb=$(head -n 6 "$page" | grep -m1 -oE '^\[Docs\]\([^)]+\)' || true)
    if [ -z "$crumb" ]; then
      err "$page: missing breadcrumb line [Docs](...) under the title"
      continue
    fi
    target=${crumb#'[Docs]('}
    target=${target%)}
    [ -n "$index" ] && [ "$(resolve "$(dirname "$page")/$target")" = "$index" ] ||
      err "$page: breadcrumb [Docs]($target) does not point to docs/README.md"
  done < <(find docs -type f -name '*.md')
fi

[ "$fail" = 0 ] && echo "docs-check: ok"
exit "$fail"
