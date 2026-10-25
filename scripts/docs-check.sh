#!/usr/bin/env bash
# Checks the Markdown in the repository: every relative link in a tracked .md file resolves,
# and every page in docs/ is linked from docs/README.md. Links inside code spans and fenced
# code blocks are ignored.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
err() { echo "docs-check: $*" >&2; fail=1; }

# links <file>: the link targets in a Markdown file, one per line, outside code
links() {
  awk '/^[[:space:]]*(```|~~~)/ { code = !code; next } !code' "$1" |
    sed -E 's/`[^`]*`//g' |
    grep -oE '\]\([^)[:space:]]+' |
    cut -c3- || true
}

while IFS= read -r -d '' file; do
  dir=$(dirname "$file")
  while IFS= read -r target; do
    case "$target" in
      http://* | https://* | mailto:* | '#'*) continue ;;
    esac
    path=${target%%#*}
    [ -e "$dir/$path" ] || err "$file: broken link $target"
  done < <(links "$file")
done < <(git ls-files -z '*.md')

if [ -d docs ]; then
  [ -f docs/README.md ] || err "missing docs/README.md index"
  indexed=$(links docs/README.md)
  while IFS= read -r -d '' page; do
    name=${page#docs/}
    [ "$name" = README.md ] && continue
    grep -qxF "$name" <<<"$indexed" || err "docs/README.md does not link $name"
  done < <(git ls-files -z 'docs/*.md')
fi

[ "$fail" = 0 ] && echo "docs-check: ok"
exit "$fail"
