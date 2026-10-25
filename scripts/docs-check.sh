#!/usr/bin/env bash
# Checks the Markdown in the repository: every relative link in a tracked .md file resolves,
# and docs/ is an indexed tree (see below). Links inside code spans and fenced
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

# Every docs directory has a README.md index that links each page and subdirectory in it, and
# every page but docs/README.md has a breadcrumb line that starts with "[Docs](".
if [ -d docs ]; then
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
        head -n 6 "$entry" | grep -q '^\[Docs\](' || err "$entry: missing breadcrumb line under the title"
      fi
    done
  done < <(find docs -type d)
fi

[ "$fail" = 0 ] && echo "docs-check: ok"
exit "$fail"
